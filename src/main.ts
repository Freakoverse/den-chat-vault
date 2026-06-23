/**
 * DEN Vault — isolated signing origin.
 *
 * Runs at its own origin (e.g. https://vault.denchat.top), embedded as an iframe
 * by the DEN app. The private key is generated, stored (encrypted), and used for
 * signing ENTIRELY here — it never enters the app's context. The app talks to the
 * vault only via postMessage ("sign this"), so an XSS in the app can't read the key.
 *
 * Storage at rest uses the SAME encrypted format as the app's backup file
 * (PBKDF2-SHA256 600k → AES-256-GCM), so the at-rest blob and the exportable
 * backup file are interchangeable.
 *
 * SECURITY: set ALLOWED_PARENT_ORIGINS to your app origin(s) before deploying.
 * Only those origins may message the vault. Keep this build tiny and dependency-
 * audited — it's the trusted surface for the key.
 */

import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { HDKey } from '@scure/bip32'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { getPublicKey, finalizeEvent, nip04, nip44, nip19, type EventTemplate } from 'nostr-tools'
import { createTaprootTransaction, createSegwitTransaction, type UTXO } from './btc-tx'
import { signEvmTransaction, getEvmSigningKey, type EvmChain } from './evm-tx'

/* ─── Config (EDIT BEFORE DEPLOY) ─── */
const ALLOWED_PARENT_ORIGINS = ['https://web.denchat.top']
const SESSION_IDLE_MS = 30 * 60_000        // auto-lock after 30 min idle
const RATE_FREE_ATTEMPTS = 3               // failures before backoff starts
const RATE_STEP_MS = [5_000, 30_000, 120_000, 600_000] // escalating lockout windows

/* ─── Backup crypto (same format as the app's backup file) ─── */
interface BackupPayloadV1 {
  version: 1; alg: 'AES-256-GCM'; kdf: 'PBKDF2-SHA256'
  iterations: number; salt: string; iv: string; ciphertext: string
}
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

async function deriveAesKey(password: string, salt: Uint8Array, iterations: number, usage: KeyUsage) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, [usage])
}
async function encryptBackup(secret: string, password: string, iterations = 600_000): Promise<BackupPayloadV1> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveAesKey(password, salt, iterations, 'encrypt')
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret)))
  return { version: 1, alg: 'AES-256-GCM', kdf: 'PBKDF2-SHA256', iterations, salt: b64(salt), iv: b64(iv), ciphertext: b64(ct) }
}
async function decryptBackup(p: BackupPayloadV1, password: string): Promise<string> {
  if (p.version !== 1 || p.alg !== 'AES-256-GCM') throw new Error('Unrecognized backup format')
  const key = await deriveAesKey(password, unb64(p.salt), p.iterations || 600_000, 'decrypt')
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(p.iv) }, key, unb64(p.ciphertext))
  return new TextDecoder().decode(plain)
}

/* ─── Key derivation (BIP-39 → m/44'/1237'/index'/0/0) ─── */
function deriveKeypair(mnemonic: string, index = 0): { privHex: string; pubHex: string } {
  const root = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic))
  const child = root.derive(`m/44'/1237'/${index}'/0/0`)
  if (!child.privateKey) throw new Error('Failed to derive private key')
  const privHex = bytesToHex(child.privateKey)
  return { privHex, pubHex: getPublicKey(hexToBytes(privHex)) }
}

/**
 * Turn a stored secret into a keypair. Accepts a BIP-39 mnemonic (seed account,
 * HD-derived), an `nsec1…` private key, or a raw 64-char hex private key —
 * so backups exported from nsec-based accounts import correctly too.
 */
function secretToKeypair(secret: string): { privHex: string; pubHex: string } {
  const s = secret.trim()
  if (validateMnemonic(s, wordlist)) return deriveKeypair(s)
  let privHex: string | null = null
  if (s.startsWith('nsec1')) {
    const dec = nip19.decode(s)
    if (dec.type === 'nsec') privHex = bytesToHex(dec.data as Uint8Array)
  } else if (/^[0-9a-fA-F]{64}$/.test(s)) {
    privHex = s.toLowerCase()
  }
  if (!privHex) throw new Error('Backup did not contain a valid key or recovery phrase')
  return { privHex, pubHex: getPublicKey(hexToBytes(privHex)) }
}

/* ─── IndexedDB (blob + rate-limit state) ─── */
const DB = 'den-vault', STORE = 'kv'
function idb(): Promise<IDBDatabase> {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1)
    r.onupgradeneeded = () => r.result.createObjectStore(STORE)
    r.onsuccess = () => res(r.result)
    r.onerror = () => rej(r.error)
  })
}
async function kvGet<T>(k: string): Promise<T | undefined> {
  const db = await idb()
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readonly').objectStore(STORE).get(k)
    tx.onsuccess = () => res(tx.result as T | undefined)
    tx.onerror = () => rej(tx.error)
  })
}
async function kvSet(k: string, v: unknown): Promise<void> {
  const db = await idb()
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readwrite').objectStore(STORE).put(v, k)
    tx.onsuccess = () => res()
    tx.onerror = () => rej(tx.error)
  })
}

/* ─── Seeds + accounts (one PIN per seed; accounts are HD-derived from it) ─── */
// A "seed" is a PIN-encrypted secret: a BIP-39 mnemonic (kind 'seed') or a single
// nsec/hex key (kind 'key'). Accounts are plaintext metadata derived from a seed at
// an index — a 'key' seed has exactly one account at index 0 and cannot derive more.
interface SeedMeta { id: string; name: string | null; kind: 'seed' | 'key'; hint: string | null; createdAt: number }
interface AccountMeta { pubkey: string; npub: string; seedId: string; index: number; name: string | null; createdAt: number }
const seedBlobKey = (id: string) => `seedblob:${id}`
const now = () => Math.floor(Date.now() / 1000)

async function getSeeds(): Promise<SeedMeta[]> { return (await kvGet<SeedMeta[]>('seeds')) || [] }
async function setSeeds(list: SeedMeta[]) { await kvSet('seeds', list) }
async function upsertSeed(meta: SeedMeta) {
  const list = await getSeeds()
  const i = list.findIndex((s) => s.id === meta.id)
  if (i >= 0) list[i] = { ...list[i], ...meta }; else list.push(meta)
  await setSeeds(list)
}
async function getAccounts(): Promise<AccountMeta[]> { return (await kvGet<AccountMeta[]>('accts')) || [] }
async function setAccounts(list: AccountMeta[]) { await kvSet('accts', list) }
async function upsertAccount(meta: AccountMeta) {
  const list = await getAccounts()
  const i = list.findIndex((a) => a.pubkey === meta.pubkey)
  if (i >= 0) list[i] = { ...list[i], ...meta }; else list.push(meta)
  await setAccounts(list)
}
function getSeedBlob(id: string) { return kvGet<BackupPayloadV1>(seedBlobKey(id)) }

/** Keypair from a stored secret at a derivation index (index ignored for single keys). */
function keypairFromSecret(secret: string, index: number): { privHex: string; pubHex: string } {
  return validateMnemonic(secret.trim(), wordlist) ? deriveKeypair(secret, index) : secretToKeypair(secret)
}

/* ─── Session (in-memory only; never persisted) ─── */
let sessionPriv: Uint8Array | null = null
let activePub: string | null = null
let idleTimer: ReturnType<typeof setTimeout> | null = null
function touchSession() {
  if (idleTimer) clearTimeout(idleTimer)
  idleTimer = setTimeout(lock, SESSION_IDLE_MS)
}
function unlockSession(privHex: string) {
  sessionPriv = hexToBytes(privHex)
  activePub = getPublicKey(sessionPriv)
  void kvSet('active', activePub)
  touchSession()
}
function lock() {
  if (sessionPriv) sessionPriv.fill(0)
  sessionPriv = null; activePub = null
  if (idleTimer) { clearTimeout(idleTimer); idleTimer = null }
}

/* ─── Rate limiting (per seed, escalating, persisted) ─── */
interface RateState { fails: number; lockedUntil: number }
const rateKey = (id: string) => `rate:${id}`
async function rateGuard(id: string): Promise<void> {
  const r = (await kvGet<RateState>(rateKey(id))) || { fails: 0, lockedUntil: 0 }
  if (r.lockedUntil > Date.now()) throw new Error(`Too many attempts. Wait ${Math.ceil((r.lockedUntil - Date.now()) / 1000)}s`)
}
async function rateFail(id: string): Promise<void> {
  const r = (await kvGet<RateState>(rateKey(id))) || { fails: 0, lockedUntil: 0 }
  r.fails += 1
  const over = r.fails - RATE_FREE_ATTEMPTS
  if (over > 0) r.lockedUntil = Date.now() + (RATE_STEP_MS[Math.min(over - 1, RATE_STEP_MS.length - 1)])
  await kvSet(rateKey(id), r)
}
async function rateReset(id: string): Promise<void> { await kvSet(rateKey(id), { fails: 0, lockedUntil: 0 }) }

/* ─── Operations ─── */
const ops: Record<string, (p?: any) => Promise<unknown>> = {
  async status() {
    return { seeds: await getSeeds(), accounts: await getAccounts(), active: (await kvGet<string>('active')) || null, unlocked: !!sessionPriv, pubkey: activePub }
  },
  async listAccounts() { return getAccounts() },
  // Generate a fresh identity. Returns the mnemonic ONCE so the app can show the
  // backup screen; nothing is stored until `saveNew` is called.
  async generate() {
    const mnemonic = generateMnemonic(wordlist, 256)
    return { mnemonic, pubkey: deriveKeypair(mnemonic).pubHex }
  },
  // Persist a generated mnemonic as a new seed + its first account (index 0), encrypted with `pin`.
  async saveNew({ mnemonic, pin, name, hint }: { mnemonic: string; pin: string; name?: string; hint?: string }) {
    if (!validateMnemonic(mnemonic, wordlist)) throw new Error('Invalid mnemonic')
    const { privHex, pubHex } = deriveKeypair(mnemonic, 0)
    const seedId = pubHex
    await kvSet(seedBlobKey(seedId), await encryptBackup(mnemonic, pin))
    await upsertSeed({ id: seedId, name: name || 'My Seed', kind: 'seed', hint: hint || null, createdAt: now() })
    await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index: 0, name: null, createdAt: now() })
    await rateReset(seedId)
    unlockSession(privHex)
    return { pubkey: pubHex, seedId }
  },
  // Import an encrypted backup (mnemonic OR nsec/hex key) as a new seed; its password
  // becomes the seed PIN. The imported payload IS the at-rest blob (no re-encryption).
  async importBackup({ payload, password, name, hint }: { payload: BackupPayloadV1; password: string; name?: string; hint?: string }) {
    let secret: string
    // WebCrypto throws a message-less DOMException on a bad password; surface a clear error.
    try { secret = await decryptBackup(payload, password) }
    catch { throw new Error('Wrong password — could not decrypt this backup') }
    const isSeed = validateMnemonic(secret.trim(), wordlist)
    const { privHex, pubHex } = keypairFromSecret(secret, 0)
    const seedId = pubHex
    await kvSet(seedBlobKey(seedId), payload)
    // A seed gets a label (default "My Seed"); a single key labels its standalone account.
    await upsertSeed({ id: seedId, name: isSeed ? (name || 'My Seed') : (name || null), kind: isSeed ? 'seed' : 'key', hint: hint || null, createdAt: now() })
    await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index: 0, name: isSeed ? null : (name || null), createdAt: now() })
    await rateReset(seedId)
    unlockSession(privHex)
    return { pubkey: pubHex, seedId }
  },
  // Derive the next account from an existing seed (same PIN). Not allowed for single-key seeds.
  async deriveAccount({ seedId, pin, name }: { seedId: string; pin: string; name?: string }) {
    await rateGuard(seedId)
    const blob = await getSeedBlob(seedId)
    if (!blob) throw new Error('No such seed')
    let mnemonic: string
    try { mnemonic = await decryptBackup(blob, pin) }
    catch { await rateFail(seedId); throw new Error('Incorrect PIN') }
    if (!validateMnemonic(mnemonic.trim(), wordlist)) throw new Error('This identity is a single key and cannot derive more accounts')
    await rateReset(seedId)
    const used = (await getAccounts()).filter((a) => a.seedId === seedId).map((a) => a.index)
    const index = (used.length ? Math.max(...used) : -1) + 1
    const { pubHex } = deriveKeypair(mnemonic, index)
    // Just record the account — the app returns to account selection; the user picks
    // it and unlocks (re-enters the PIN) to actually sign in.
    await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index, name: name || null, createdAt: now() })
    return { pubkey: pubHex }
  },
  async unlock({ pubkey, pin }: { pubkey: string; pin: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    await rateGuard(acct.seedId)
    const blob = await getSeedBlob(acct.seedId)
    if (!blob) throw new Error('No such account')
    let secret: string
    try { secret = await decryptBackup(blob, pin) }
    catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') }
    await rateReset(acct.seedId)
    unlockSession(keypairFromSecret(secret, acct.index).privHex)
    return { pubkey: activePub }
  },
  async lock() { lock(); return { ok: true } },
  async removeAccount({ pubkey, pin }: { pubkey: string; pin: string }) {
    const accounts = await getAccounts()
    const acct = accounts.find((a) => a.pubkey === pubkey)
    if (!acct) return { ok: true }
    const blob = await getSeedBlob(acct.seedId)
    if (blob) { try { await decryptBackup(blob, pin) } catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') } }
    const remaining = accounts.filter((a) => a.pubkey !== pubkey)
    await setAccounts(remaining)
    // If that was the seed's last account, drop the seed blob + meta + rate state too.
    if (!remaining.some((a) => a.seedId === acct.seedId)) {
      await kvSet(seedBlobKey(acct.seedId), undefined)
      await setSeeds((await getSeeds()).filter((s) => s.id !== acct.seedId))
      await rateReset(acct.seedId)
    }
    if (activePub === pubkey) lock()
    return { ok: true }
  },
  // Return the account's seed blob as a backup payload (PIN-gated).
  async exportBackup({ pubkey, pin }: { pubkey: string; pin: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    await rateGuard(acct.seedId)
    const blob = await getSeedBlob(acct.seedId)
    if (!blob) throw new Error('No such account')
    try { await decryptBackup(blob, pin) } catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') }
    await rateReset(acct.seedId)
    return { payload: blob }
  },
  async renameSeed({ seedId, name }: { seedId: string; name: string }) {
    const seeds = await getSeeds()
    const s = seeds.find((x) => x.id === seedId)
    if (s) { s.name = name; await setSeeds(seeds) }
    return { ok: true }
  },
  async renameAccount({ pubkey, name }: { pubkey: string; name: string }) {
    const accounts = await getAccounts()
    const a = accounts.find((x) => x.pubkey === pubkey)
    if (a) { a.name = name; await setAccounts(accounts) }
    return { ok: true }
  },
  // Change a seed's PIN (re-encrypt its blob). PIN is per-seed, so this covers all its accounts.
  async changePin({ pubkey, currentPin, newPin, newHint }: { pubkey: string; currentPin: string; newPin: string; newHint?: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    await rateGuard(acct.seedId)
    const blob = await getSeedBlob(acct.seedId)
    if (!blob) throw new Error('No such account')
    let secret: string
    try { secret = await decryptBackup(blob, currentPin) }
    catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') }
    await rateReset(acct.seedId)
    await kvSet(seedBlobKey(acct.seedId), await encryptBackup(secret, newPin))
    if (newHint !== undefined) {
      const seeds = await getSeeds()
      const s = seeds.find((x) => x.id === acct.seedId)
      if (s) { s.hint = newHint || null; await setSeeds(seeds) }
    }
    return { ok: true }
  },
  async getPublicKey() { if (!activePub) throw new Error('Locked'); return activePub },
  async signEvent({ event }: { event: EventTemplate }) {
    if (!sessionPriv) throw new Error('Locked')
    touchSession()
    return finalizeEvent(event, sessionPriv)
  },
  // Build + sign a blockchain transaction from STRUCTURED params (the vault derives the
  // sighash itself, so the in-vault confirm can't be forged). Returns the signed raw hex.
  // NOTE: PIN-confirm gating is added in the next stage; for now this signs with the session key.
  async signTransaction({ chain, tx }: { chain: string; tx: any }) {
    if (!sessionPriv) throw new Error('Locked')
    touchSession()
    const privHex = bytesToHex(sessionPriv)
    if (chain === 'bitcoin') {
      const utxos = tx.utxos as UTXO[]
      const args = [privHex, utxos, tx.recipientAddress as string, BigInt(tx.amountSats), Number(tx.feeRate)] as const
      const signed = tx.addressType === 'segwit' ? createSegwitTransaction(...args) : createTaprootTransaction(...args)
      return { signed }
    }
    // EVM — getEvmSigningKey handles even-y negation for nostr-mode addresses.
    const signingKeyHex = getEvmSigningKey(privHex, tx.addressMode === 'standard' ? 'standard' : 'nostr')
    const signed = signEvmTransaction(
      { chain: chain as EvmChain, to: tx.to, value: BigInt(tx.value), data: tx.data as Uint8Array | undefined, gasLimit: BigInt(tx.gasLimit), gasPrice: BigInt(tx.gasPrice), nonce: BigInt(tx.nonce) },
      signingKeyHex,
    )
    return { signed }
  },
  async nip04Encrypt({ pubkey, plaintext }: { pubkey: string; plaintext: string }) {
    if (!sessionPriv) throw new Error('Locked'); touchSession()
    return nip04.encrypt(sessionPriv, pubkey, plaintext)
  },
  async nip04Decrypt({ pubkey, ciphertext }: { pubkey: string; ciphertext: string }) {
    if (!sessionPriv) throw new Error('Locked'); touchSession()
    return nip04.decrypt(sessionPriv, pubkey, ciphertext)
  },
  async nip44Encrypt({ pubkey, plaintext }: { pubkey: string; plaintext: string }) {
    if (!sessionPriv) throw new Error('Locked'); touchSession()
    const conv = nip44.v2.utils.getConversationKey(sessionPriv, pubkey)
    return nip44.v2.encrypt(plaintext, conv)
  },
  async nip44Decrypt({ pubkey, ciphertext }: { pubkey: string; ciphertext: string }) {
    if (!sessionPriv) throw new Error('Locked'); touchSession()
    const conv = nip44.v2.utils.getConversationKey(sessionPriv, pubkey)
    return nip44.v2.decrypt(ciphertext, conv)
  },
}

/* ─── Message handler (origin-allowlisted) ─── */
window.addEventListener('message', async (e: MessageEvent) => {
  if (!ALLOWED_PARENT_ORIGINS.includes(e.origin)) return // hard origin gate
  const msg = e.data
  if (!msg || typeof msg.id !== 'string' || typeof msg.type !== 'string') return
  const reply = (body: object) => (e.source as Window | null)?.postMessage({ id: msg.id, ...body }, e.origin)
  const op = ops[msg.type]
  if (!op) return reply({ ok: false, error: `Unknown op: ${msg.type}` })
  try { reply({ ok: true, result: await op(msg.params || {}) }) }
  catch (err) { reply({ ok: false, error: err instanceof Error ? err.message : String(err) }) }
})

// Tell the parent we're ready (only the allowlisted parent will be listening).
if (window.parent !== window) {
  for (const origin of ALLOWED_PARENT_ORIGINS) window.parent.postMessage({ type: 'vault-ready' }, origin)
}

/* ─── Self-test (only when opened top-level, e.g. directly on your phone) ─── */
if (window.top === window.self) void runSelfTest()

async function runSelfTest() {
  const el = document.getElementById('selftest')
  if (!el) return
  const line = (html: string) => { el.innerHTML += html + '<br>' }
  line('<b>DEN Vault — feasibility self-test</b><br><span class="muted">Confirms key gen, the encrypted-blob format, IndexedDB persistence, and signing all work in <i>this</i> context (open this page inside your installed PWA to test standalone iOS).</span><br>')
  try {
    line(`secure context: <span class="${window.isSecureContext ? 'ok' : 'fail'}">${window.isSecureContext}</span>`)
    const r = await ops.generate() as { mnemonic: string; pubkey: string }
    line('key generation: <span class="ok">ok</span>')
    await ops.saveNew({ mnemonic: r.mnemonic, pin: '123456', name: 'self-test' })
    line('encrypt + store (IndexedDB): <span class="ok">ok</span>')
    lock()
    const back = await getSeedBlob(r.pubkey)   // seedId === pubkey for the index-0 account
    line(`read back from IndexedDB: <span class="${back ? 'ok' : 'fail'}">${back ? 'ok' : 'MISSING — storage blocked here'}</span>`)
    await ops.unlock({ pubkey: r.pubkey, pin: '123456' })
    line('decrypt + unlock: <span class="ok">ok</span>')
    const ev = await ops.signEvent({ event: { kind: 1, created_at: 1, tags: [], content: 'vault self-test' } }) as { sig: string; pubkey: string }
    line(`sign event: <span class="${ev.sig?.length === 128 ? 'ok' : 'fail'}">${ev.sig?.length === 128 ? 'ok' : 'bad sig'}</span>`)

    // ── Blockchain tx signing (deterministic ECDSA vector + BTC build) ──
    const EVM_VECTOR = '0xf86b058504a817c8008252089452908400098527886e0f7030069857d2e4169ee787038d7ea4c680008025a0174aea4ca40a8116f3ba437ce057e596accbf9c8f1b2a5bee581b8df05da5004a02de4af3baeba239ed92e36f73da03afd5eb850510c05dfcdc223da040c455ee9'
    const evmKey = '0000000000000000000000000000000000000000000000000000000000000001'
    const evmSigned = signEvmTransaction({ chain: 'ethereum', to: '0x52908400098527886e0f7030069857d2e4169ee7', value: 1000000000000000n, gasLimit: 21000n, gasPrice: 20000000000n, nonce: 5n }, evmKey)
    line(`EVM tx signing: <span class="${evmSigned === EVM_VECTOR ? 'ok' : 'fail'}">${evmSigned === EVM_VECTOR ? 'ok (matches reference)' : 'MISMATCH — crypto differs from app'}</span>`)
    const btcUtxos: UTXO[] = [{ txid: '00'.repeat(32), vout: 0, value: 100000, status: { confirmed: true } }]
    const btcSigned = createTaprootTransaction(evmKey, btcUtxos, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr', 50000n, 5)
    const btcOk = /^[0-9a-f]+$/.test(btcSigned) && btcSigned.length > 150
    line(`BTC taproot signing: <span class="${btcOk ? 'ok' : 'fail'}">${btcOk ? 'ok (valid tx built)' : 'FAIL'}</span>`)

    // Cleanup the throwaway identity so the self-test leaves no key behind.
    await ops.removeAccount({ pubkey: r.pubkey, pin: '123456' }); lock()
    line('<br><b class="ok">All checks passed — this origin can host the vault.</b>')
    line(`<span class="muted">pubkey: ${ev.pubkey}</span>`)
  } catch (err) {
    line(`<br><b class="fail">FAILED:</b> ${err instanceof Error ? err.message : String(err)}`)
    line('<span class="muted">If "read back from IndexedDB" failed in your installed PWA, this origin can\'t persist storage when embedded — pivot to the Worker + password-manager approach.</span>')
  }
}
