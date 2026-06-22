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

/* ─── Account index (plaintext metadata; one encrypted blob per account) ─── */
interface AccountMeta { pubkey: string; npub: string; name: string | null; createdAt: number }
const acctKey = (pub: string) => `acct:${pub}`
async function getAccounts(): Promise<AccountMeta[]> { return (await kvGet<AccountMeta[]>('accounts')) || [] }
async function setAccounts(list: AccountMeta[]) { await kvSet('accounts', list) }
async function upsertAccount(meta: AccountMeta) {
  const list = await getAccounts()
  const i = list.findIndex((a) => a.pubkey === meta.pubkey)
  if (i >= 0) list[i] = { ...list[i], ...meta }
  else list.push(meta)
  await setAccounts(list)
}
function getBlob(pub: string) { return kvGet<BackupPayloadV1>(acctKey(pub)) }

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

/* ─── Rate limiting (per account, escalating, persisted) ─── */
interface RateState { fails: number; lockedUntil: number }
const rateKey = (pub: string) => `rate:${pub}`
async function rateGuard(pub: string): Promise<void> {
  const r = (await kvGet<RateState>(rateKey(pub))) || { fails: 0, lockedUntil: 0 }
  if (r.lockedUntil > Date.now()) throw new Error(`Too many attempts. Wait ${Math.ceil((r.lockedUntil - Date.now()) / 1000)}s`)
}
async function rateFail(pub: string): Promise<void> {
  const r = (await kvGet<RateState>(rateKey(pub))) || { fails: 0, lockedUntil: 0 }
  r.fails += 1
  const over = r.fails - RATE_FREE_ATTEMPTS
  if (over > 0) r.lockedUntil = Date.now() + (RATE_STEP_MS[Math.min(over - 1, RATE_STEP_MS.length - 1)])
  await kvSet(rateKey(pub), r)
}
async function rateReset(pub: string): Promise<void> { await kvSet(rateKey(pub), { fails: 0, lockedUntil: 0 }) }

/* ─── Operations ─── */
const ops: Record<string, (p?: any) => Promise<unknown>> = {
  async status() {
    return { accounts: await getAccounts(), active: (await kvGet<string>('active')) || null, unlocked: !!sessionPriv, pubkey: activePub }
  },
  async listAccounts() { return getAccounts() },
  // Generate a fresh identity. Returns the mnemonic ONCE so the app can show the
  // backup screen; nothing is stored until `saveNew` is called.
  async generate() {
    const mnemonic = generateMnemonic(wordlist, 256)
    return { mnemonic, pubkey: deriveKeypair(mnemonic).pubHex }
  },
  // Persist a generated/known mnemonic as a new account (encrypted with `pin`) and unlock.
  async saveNew({ mnemonic, pin, name }: { mnemonic: string; pin: string; name?: string }) {
    if (!validateMnemonic(mnemonic, wordlist)) throw new Error('Invalid mnemonic')
    const { privHex, pubHex } = deriveKeypair(mnemonic)
    await kvSet(acctKey(pubHex), await encryptBackup(mnemonic, pin))
    await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), name: name || null, createdAt: Math.floor(Date.now() / 1000) })
    await rateReset(pubHex)
    unlockSession(privHex)
    return { pubkey: pubHex }
  },
  // Import an encrypted backup file (same format). Its password becomes the account
  // PIN; the imported payload IS the at-rest blob (no re-encryption needed).
  async importBackup({ payload, password, name }: { payload: BackupPayloadV1; password: string; name?: string }) {
    const mnemonic = await decryptBackup(payload, password) // throws if wrong password
    if (!validateMnemonic(mnemonic, wordlist)) throw new Error('Backup did not contain a valid recovery phrase')
    const { privHex, pubHex } = deriveKeypair(mnemonic)
    await kvSet(acctKey(pubHex), payload)
    await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), name: name || null, createdAt: Math.floor(Date.now() / 1000) })
    await rateReset(pubHex)
    unlockSession(privHex)
    return { pubkey: pubHex }
  },
  async unlock({ pubkey, pin }: { pubkey: string; pin: string }) {
    await rateGuard(pubkey)
    const blob = await getBlob(pubkey)
    if (!blob) throw new Error('No such account')
    let mnemonic: string
    try { mnemonic = await decryptBackup(blob, pin) }
    catch { await rateFail(pubkey); throw new Error('Incorrect PIN') }
    await rateReset(pubkey)
    unlockSession(deriveKeypair(mnemonic).privHex)
    return { pubkey: activePub }
  },
  async lock() { lock(); return { ok: true } },
  async removeAccount({ pubkey, pin }: { pubkey: string; pin: string }) {
    const blob = await getBlob(pubkey)
    if (!blob) return { ok: true }
    try { await decryptBackup(blob, pin) } catch { await rateFail(pubkey); throw new Error('Incorrect PIN') }
    await kvSet(acctKey(pubkey), undefined as unknown as BackupPayloadV1)
    await setAccounts((await getAccounts()).filter((a) => a.pubkey !== pubkey))
    await rateReset(pubkey)
    if (activePub === pubkey) lock()
    return { ok: true }
  },
  // Return an account's at-rest blob as a backup payload (PIN-gated).
  async exportBackup({ pubkey, pin }: { pubkey: string; pin: string }) {
    await rateGuard(pubkey)
    const blob = await getBlob(pubkey)
    if (!blob) throw new Error('No such account')
    try { await decryptBackup(blob, pin) } catch { await rateFail(pubkey); throw new Error('Incorrect PIN') }
    await rateReset(pubkey)
    return { payload: blob }
  },
  async getPublicKey() { if (!activePub) throw new Error('Locked'); return activePub },
  async signEvent({ event }: { event: EventTemplate }) {
    if (!sessionPriv) throw new Error('Locked')
    touchSession()
    return finalizeEvent(event, sessionPriv)
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
    const back = await getBlob(r.pubkey)
    line(`read back from IndexedDB: <span class="${back ? 'ok' : 'fail'}">${back ? 'ok' : 'MISSING — storage blocked here'}</span>`)
    await ops.unlock({ pubkey: r.pubkey, pin: '123456' })
    line('decrypt + unlock: <span class="ok">ok</span>')
    const ev = await ops.signEvent({ event: { kind: 1, created_at: 1, tags: [], content: 'vault self-test' } }) as { sig: string; pubkey: string }
    line(`sign event: <span class="${ev.sig?.length === 128 ? 'ok' : 'fail'}">${ev.sig?.length === 128 ? 'ok' : 'bad sig'}</span>`)
    // Cleanup the throwaway identity so the self-test leaves no key behind.
    await ops.removeAccount({ pubkey: r.pubkey, pin: '123456' }); lock()
    line('<br><b class="ok">All checks passed — this origin can host the vault.</b>')
    line(`<span class="muted">pubkey: ${ev.pubkey}</span>`)
  } catch (err) {
    line(`<br><b class="fail">FAILED:</b> ${err instanceof Error ? err.message : String(err)}`)
    line('<span class="muted">If "read back from IndexedDB" failed in your installed PWA, this origin can\'t persist storage when embedded — pivot to the Worker + password-manager approach.</span>')
  }
}
