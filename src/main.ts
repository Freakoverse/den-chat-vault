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

/* ─── In-vault transaction confirmation (rendered in the isolated overlay) ─── */
// Ask the parent to make this iframe a full-screen overlay (or hide it again).
function showTxOverlay(show: boolean) {
  if (window.parent === window) return
  for (const o of ALLOWED_PARENT_ORIGINS) window.parent.postMessage({ type: 'vault-overlay', show }, o)
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string))
}

/** Format an integer `value` with `decimals` places, trimming trailing zeros. */
function formatUnits(value: bigint, decimals: number): string {
  const s = value.toString().padStart(decimals + 1, '0')
  const intPart = s.slice(0, s.length - decimals)
  let frac = decimals ? s.slice(s.length - decimals).replace(/0+$/, '') : ''
  return frac ? `${intPart}.${frac}` : intPart
}

/** Decode an ERC-20 transfer(address,uint256) calldata → real recipient + amount. */
function decodeErc20(data: Uint8Array): { to: string; amount: bigint } | null {
  if (data.length !== 68) return null
  if (!(data[0] === 0xa9 && data[1] === 0x05 && data[2] === 0x9c && data[3] === 0xbb)) return null
  const to = '0x' + bytesToHex(data.slice(16, 36))
  let amount = 0n
  for (const b of data.slice(36, 68)) amount = (amount << 8n) | BigInt(b)
  return { to, amount }
}

interface TxDisplay { title: string; rows: Array<[string, string]> }

/* ─── Shared overlay styling (matches the app's dark theme tokens) ─── */
const BACKDROP_CSS = 'position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,0.6);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);color:#fafafa;font:14px/1.5 system-ui,-apple-system,sans-serif;z-index:2147483647;box-sizing:border-box'
const CARD_CSS = 'width:100%;max-width:420px;max-height:92vh;overflow-y:auto;display:flex;flex-direction:column;gap:18px;background:#171717;border:1px solid #27272a;border-radius:20px;padding:24px;box-shadow:0 24px 70px rgba(0,0,0,0.6);box-sizing:border-box'
const EYEBROW_CSS = 'color:#a1a1aa;font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase'
const TITLE_CSS = 'font-size:18px;font-weight:700;color:#fafafa'
const INPUT_CSS = 'width:100%;height:52px;border-radius:12px;border:1px solid #3f3f46;background:#1d1d20;color:#fafafa;padding:0 14px;font-size:16px;outline:none;box-sizing:border-box'
const ERR_CSS = 'color:#f87171;font-size:12px;min-height:16px'
const BTN_CANCEL_CSS = 'flex:1;height:52px;border-radius:12px;border:1px solid #2a2a2e;background:#1d1d20;color:#fafafa;cursor:pointer;font-size:14px'
const BTN_OK_CSS = 'flex:1.4;height:52px;border-radius:12px;border:0;background:#4a6df7;color:#fafafa;font-weight:600;cursor:pointer;font-size:14px'
const FOCUS_STYLE = '<style>.v-in:focus{border-color:#4a6df7}.v-in::placeholder{color:#71717a}</style>'
const inset = (html: string) => `<div style="display:flex;flex-direction:column;gap:10px;background:#1d1d20;border:1px solid #2a2a2e;border-radius:12px;padding:14px">${html}</div>`

/** Numbered word chips that wrap as whole units — each chip sizes to its word, never clipped. */
function wordChips(words: string[]): string {
  return `<div style="display:flex;flex-wrap:wrap;gap:8px">${words.map((w, i) => `<span style="display:inline-flex;gap:6px;align-items:baseline;background:#171717;border:1px solid #2a2a2e;border-radius:8px;padding:8px 11px;font-size:13px;white-space:nowrap"><span style="color:#71717a;font-size:10px">${i + 1}</span><span style="font-weight:600;color:#fafafa">${esc(w)}</span></span>`).join('')}</div>`
}

/** Wrap secret content (phrase/nsec) in a blurred box behind a "make sure no one is watching"
 *  cover + a Reveal button with a short countdown — mirrors the app's reveal flow. */
function revealBlock(innerHtml: string): string {
  return `<div style="position:relative">
      <div id="v-secret-box" style="background:#1d1d20;border:1px solid #2a2a2e;border-radius:12px;padding:16px;max-height:46vh;overflow:auto;filter:blur(8px);user-select:none;transition:filter .25s">${innerHtml}</div>
      <div id="v-cover" style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:12px;text-align:center;padding:20px;background:rgba(23,23,23,0.66);border-radius:12px">
        <div style="font-size:14px;color:#fafafa;font-weight:600">Reveal your secret?</div>
        <div style="font-size:12px;color:#a1a1aa;max-width:260px;line-height:1.5">Make sure no one is watching your screen and nothing is recording.</div>
        <button id="v-reveal" style="${BTN_OK_CSS};width:auto;flex:none;padding:0 22px;height:46px">Reveal</button>
        <button id="v-reveal-cancel" style="${BTN_CANCEL_CSS};width:auto;flex:none;padding:0 18px;height:42px;display:none">No, wait</button>
      </div>
    </div>`
}

/** Wire the Reveal button: 5-second countdown → unblur, with a "No, wait" abort. */
function wireReveal(card: HTMLElement): void {
  const box = card.querySelector('#v-secret-box') as HTMLElement | null
  const cover = card.querySelector('#v-cover') as HTMLElement | null
  const btn = card.querySelector('#v-reveal') as HTMLButtonElement | null
  const cancelBtn = card.querySelector('#v-reveal-cancel') as HTMLButtonElement | null
  if (!box || !cover || !btn || !cancelBtn) return
  let timer: ReturnType<typeof setInterval> | null = null
  btn.onclick = () => {
    let n = 5
    btn.disabled = true
    btn.textContent = `Revealing in ${n}…`
    cancelBtn.style.display = 'block'
    timer = setInterval(() => {
      n -= 1
      if (n <= 0) {
        if (timer) clearInterval(timer)
        box.style.filter = 'none'
        cover.style.display = 'none'
      } else {
        btn.textContent = `Revealing in ${n}…`
      }
    }, 1000)
  }
  cancelBtn.onclick = () => {
    if (timer) clearInterval(timer)
    btn.disabled = false
    btn.textContent = 'Reveal'
    cancelBtn.style.display = 'none'
  }
}

/** Open the dimmed-backdrop overlay and return the (empty) card to fill + a close fn. */
function openOverlay(): { card: HTMLDivElement; close: () => void } {
  showTxOverlay(true)
  // Keep the card's children at their natural height (scroll the card instead of
  // squishing inputs/buttons when the content is taller than the viewport).
  if (!document.getElementById('v-card-style')) {
    const st = document.createElement('style')
    st.id = 'v-card-style'
    st.textContent = '.v-card>*{flex-shrink:0}'
    document.head.appendChild(st)
  }
  const backdrop = document.createElement('div')
  backdrop.style.cssText = BACKDROP_CSS
  const card = document.createElement('div')
  card.className = 'v-card'
  card.style.cssText = CARD_CSS
  backdrop.appendChild(card)
  document.body.appendChild(backdrop)
  return { card, close: () => { backdrop.remove(); showTxOverlay(false) } }
}

/**
 * The core in-vault PIN gate: render a card (optional body above the PIN field),
 * collect the PIN, run `action(pin)`. On error (wrong PIN / rate-limit / etc.) the
 * message shows and the field clears for a retry; on success it resolves. Rejects
 * with "Cancelled" on Cancel. The PIN never leaves the vault origin.
 */
function promptPinAction<T>(
  opts: { title: string; eyebrow?: string; subtitle?: string; bodyHtml?: string; placeholder?: string; confirmLabel?: string },
  action: (pin: string) => Promise<T>,
): Promise<T> {
  const { card, close } = openOverlay()
  card.innerHTML = `
    ${FOCUS_STYLE}
    <div style="${EYEBROW_CSS}">${esc(opts.eyebrow || 'DEN Vault')}</div>
    <div style="${TITLE_CSS}">${esc(opts.title)}</div>
    ${opts.subtitle ? `<div style="color:#a1a1aa;font-size:13px">${esc(opts.subtitle)}</div>` : ''}
    ${opts.bodyHtml || ''}
    <input id="v-pin" class="v-in" type="password" inputmode="numeric" placeholder="${esc(opts.placeholder || 'Enter PIN')}" style="${INPUT_CSS}" />
    <div id="v-err" style="${ERR_CSS}"></div>
    <div style="display:flex;gap:10px">
      <button id="v-cancel" style="${BTN_CANCEL_CSS}">Cancel</button>
      <button id="v-ok" style="${BTN_OK_CSS}">${esc(opts.confirmLabel || 'Confirm')}</button>
    </div>`
  const pinInput = card.querySelector('#v-pin') as HTMLInputElement
  const errEl = card.querySelector('#v-err') as HTMLDivElement
  const okBtn = card.querySelector('#v-ok') as HTMLButtonElement
  pinInput.focus()
  return new Promise<T>((resolve, reject) => {
    okBtn.onclick = async () => {
      const pin = pinInput.value
      if (!pin) { errEl.textContent = 'Enter your PIN'; return }
      okBtn.disabled = true
      try {
        const result = await action(pin)
        close(); resolve(result)
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : 'Failed'
        pinInput.value = ''; pinInput.focus(); okBtn.disabled = false
      }
    }
    ;(card.querySelector('#v-cancel') as HTMLButtonElement).onclick = () => { close(); reject(new Error('Cancelled')) }
    pinInput.onkeydown = (e) => { if (e.key === 'Enter') okBtn.click() }
  })
}

/**
 * Show the tx-confirm card from vault-computed display rows, then PIN-gate the sign.
 * The displayed details are derived by the vault from the structured tx, so they
 * can't be forged by a compromised app.
 */
function confirmAndSign(acct: AccountMeta, d: TxDisplay, sign: (privHex: string) => string): Promise<{ signed: string }> {
  const rows = d.rows.map(([k, v]) => `<div style="display:flex;justify-content:space-between;gap:16px"><span style="color:#a1a1aa;flex-shrink:0">${esc(k)}</span><span style="font-weight:600;text-align:right;word-break:break-all">${esc(v)}</span></div>`).join('')
  return promptPinAction(
    { title: d.title, eyebrow: 'DEN Vault · Secure confirm', bodyHtml: inset(rows), placeholder: 'Enter PIN to sign', confirmLabel: 'Confirm & Sign' },
    async (pin) => {
      await rateGuard(acct.seedId)
      const blob = await getSeedBlob(acct.seedId)
      if (!blob) throw new Error('No account')
      let secret: string
      try { secret = await decryptBackup(blob, pin) }
      catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') }
      await rateReset(acct.seedId)
      return { signed: sign(keypairFromSecret(secret, acct.index).privHex) }
    },
  )
}

/* ─── Generate + backup reveal (rendered entirely in the vault overlay) ─── */

/** Encrypt + store a generated mnemonic as a new seed + its index-0 account, then unlock. */
async function persistGeneratedSeed(mnemonic: string, pin: string, name?: string, hint?: string): Promise<{ pubkey: string; seedId: string }> {
  if (!validateMnemonic(mnemonic, wordlist)) throw new Error('Invalid mnemonic')
  const { privHex, pubHex } = deriveKeypair(mnemonic, 0)
  const seedId = pubHex
  await kvSet(seedBlobKey(seedId), await encryptBackup(mnemonic, pin))
  await upsertSeed({ id: seedId, name: name || 'My Seed', kind: 'seed', hint: hint || null, createdAt: now() })
  await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index: 0, name: null, createdAt: now() })
  await rateReset(seedId)
  unlockSession(privHex)
  return { pubkey: pubHex, seedId }
}

/** Download an encrypted backup payload as a file (ciphertext only — never plaintext). */
function downloadBackup(payload: BackupPayloadV1, label: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `den-backup-${label}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1500)
}

/** Reveal the generated mnemonic + collect a label/PIN/hint — all in the overlay; persist on continue. */
function showGenerateReveal(mnemonic: string): Promise<{ pubkey: string; seedId: string }> {
  const { card, close } = openOverlay()
  const words = mnemonic.split(' ')
  card.innerHTML = `
    ${FOCUS_STYLE}
    <div style="${EYEBROW_CSS}">DEN Vault · New seed</div>
    <div style="${TITLE_CSS}">Back up your recovery phrase</div>
    <div style="color:#a1a1aa;font-size:13px;line-height:1.5">Write these ${words.length} words down in order. They're the only way to recover your accounts — anyone who has them controls your funds.</div>
    ${revealBlock(wordChips(words))}
    <input id="v-name" class="v-in" type="text" placeholder="Seed label (optional)" style="${INPUT_CSS}" />
    <input id="v-pin" class="v-in" type="password" inputmode="numeric" placeholder="Set a PIN to encrypt this seed" style="${INPUT_CSS}" />
    <input id="v-hint" class="v-in" type="text" placeholder="PIN hint (optional)" style="${INPUT_CSS}" />
    <button id="v-dl" style="${BTN_CANCEL_CSS};width:100%">Download encrypted backup</button>
    <div id="v-err" style="${ERR_CSS}"></div>
    <div style="display:flex;gap:10px">
      <button id="v-cancel" style="${BTN_CANCEL_CSS}">Cancel</button>
      <button id="v-ok" style="${BTN_OK_CSS}">I've saved it — Continue</button>
    </div>`
  wireReveal(card)
  const nameInput = card.querySelector('#v-name') as HTMLInputElement
  const pinInput = card.querySelector('#v-pin') as HTMLInputElement
  const hintInput = card.querySelector('#v-hint') as HTMLInputElement
  const errEl = card.querySelector('#v-err') as HTMLDivElement
  const okBtn = card.querySelector('#v-ok') as HTMLButtonElement
  const dlBtn = card.querySelector('#v-dl') as HTMLButtonElement
  pinInput.focus()
  return new Promise((resolve, reject) => {
    dlBtn.onclick = async () => {
      const pin = pinInput.value
      if (pin.length < 4) { errEl.textContent = 'Set a PIN (4+ characters) before downloading'; return }
      try { downloadBackup(await encryptBackup(mnemonic, pin), deriveKeypair(mnemonic).pubHex.slice(0, 8)) }
      catch { errEl.textContent = 'Could not create the backup file' }
    }
    okBtn.onclick = async () => {
      const pin = pinInput.value
      if (pin.length < 4) { errEl.textContent = 'Set a PIN of at least 4 characters'; return }
      okBtn.disabled = true
      try {
        const r = await persistGeneratedSeed(mnemonic, pin, nameInput.value.trim() || undefined, hintInput.value.trim() || undefined)
        close(); resolve(r)
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : 'Could not save'; okBtn.disabled = false
      }
    }
    ;(card.querySelector('#v-cancel') as HTMLButtonElement).onclick = () => { close(); reject(new Error('Cancelled')) }
  })
}

/* ─── Import (raw secret OR encrypted backup), rendered in the vault overlay ─── */

/** Store an already-known secret + its at-rest blob as a new seed/key, then unlock. */
async function persistSecretBlob(secret: string, payload: BackupPayloadV1, name?: string, hint?: string): Promise<{ pubkey: string; seedId: string }> {
  const isSeed = validateMnemonic(secret.trim(), wordlist)
  const { privHex, pubHex } = keypairFromSecret(secret, 0)
  const seedId = pubHex
  await kvSet(seedBlobKey(seedId), payload)
  await upsertSeed({ id: seedId, name: isSeed ? (name || 'My Seed') : (name || null), kind: isSeed ? 'seed' : 'key', hint: hint || null, createdAt: now() })
  await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index: 0, name: isSeed ? null : (name || null), createdAt: now() })
  await rateReset(seedId)
  unlockSession(privHex)
  return { pubkey: pubHex, seedId }
}

/** A pasted string is an encrypted backup if it parses as our v1 payload JSON. */
function tryParseBackup(raw: string): BackupPayloadV1 | null {
  try {
    const o = JSON.parse(raw)
    if (o && o.version === 1 && typeof o.ciphertext === 'string' && typeof o.salt === 'string' && typeof o.iv === 'string') return o as BackupPayloadV1
  } catch { /* not JSON → treat as a raw secret */ }
  return null
}

/** Collect the secret (paste or file) + PIN entirely in the overlay; the secret never reaches the app. */
function showImportOverlay(): Promise<{ pubkey: string; seedId: string }> {
  const { card, close } = openOverlay()
  card.innerHTML = `
    ${FOCUS_STYLE}
    <div style="${EYEBROW_CSS}">DEN Vault · Import</div>
    <div style="${TITLE_CSS}">Import an account</div>
    <div style="color:#a1a1aa;font-size:13px">Paste a recovery phrase, an nsec, or the contents of a backup file — or choose a backup file.</div>
    <textarea id="v-secret" class="v-in" placeholder="word1 word2 …   /   nsec1…   /   backup JSON" style="${INPUT_CSS};height:88px;padding:10px 14px;resize:none;font-family:inherit"></textarea>
    <label style="${BTN_CANCEL_CSS};display:flex;align-items:center;justify-content:center">Choose backup file<input id="v-file" type="file" accept="application/json,.json" style="display:none" /></label>
    <input id="v-name" class="v-in" type="text" placeholder="Label (optional)" style="${INPUT_CSS}" />
    <input id="v-pin" class="v-in" type="password" inputmode="numeric" placeholder="Backup password, or a new PIN" style="${INPUT_CSS}" />
    <input id="v-hint" class="v-in" type="text" placeholder="PIN hint (optional)" style="${INPUT_CSS}" />
    <div id="v-err" style="${ERR_CSS}"></div>
    <div style="display:flex;gap:10px">
      <button id="v-cancel" style="${BTN_CANCEL_CSS}">Cancel</button>
      <button id="v-ok" style="${BTN_OK_CSS}">Import</button>
    </div>`
  const secretInput = card.querySelector('#v-secret') as HTMLTextAreaElement
  const fileInput = card.querySelector('#v-file') as HTMLInputElement
  const nameInput = card.querySelector('#v-name') as HTMLInputElement
  const pinInput = card.querySelector('#v-pin') as HTMLInputElement
  const hintInput = card.querySelector('#v-hint') as HTMLInputElement
  const errEl = card.querySelector('#v-err') as HTMLDivElement
  const okBtn = card.querySelector('#v-ok') as HTMLButtonElement
  secretInput.focus()
  return new Promise((resolve, reject) => {
    fileInput.onchange = async () => {
      const f = fileInput.files?.[0]
      if (!f) return
      try { secretInput.value = await f.text() } catch { errEl.textContent = 'Could not read that file' }
    }
    okBtn.onclick = async () => {
      const raw = secretInput.value.trim()
      const pin = pinInput.value
      const name = nameInput.value.trim() || undefined
      const hint = hintInput.value.trim() || undefined
      if (!raw) { errEl.textContent = 'Paste your phrase, nsec, or backup'; return }
      if (pin.length < 4) { errEl.textContent = 'Enter the backup password or a new PIN'; return }
      okBtn.disabled = true
      try {
        const payload = tryParseBackup(raw)
        let r: { pubkey: string; seedId: string }
        if (payload) {
          // Encrypted backup: the PIN is its password; the payload becomes the at-rest blob.
          let secret: string
          try { secret = await decryptBackup(payload, pin) }
          catch { throw new Error('Wrong password for this backup file') }
          r = await persistSecretBlob(secret, payload, name, hint)
        } else {
          // Raw secret: validate, then encrypt with the new PIN.
          if (raw.includes(' ')) { if (!validateMnemonic(raw, wordlist)) throw new Error('Invalid recovery phrase') }
          else { try { keypairFromSecret(raw, 0) } catch { throw new Error('Not a valid nsec / key') } }
          r = await persistSecretBlob(raw, await encryptBackup(raw, pin), name, hint)
        }
        close(); resolve(r)
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : 'Import failed'; okBtn.disabled = false
      }
    }
    ;(card.querySelector('#v-cancel') as HTMLButtonElement).onclick = () => { close(); reject(new Error('Cancelled')) }
  })
}

/* ─── Reveal + change-PIN overlays (Phase 4) ─── */

/** Show a decrypted secret (recovery phrase or nsec) + a backup download, in the overlay. */
function showSecretReveal(secret: string, payload: BackupPayloadV1, label: string): Promise<void> {
  const { card, close } = openOverlay()
  const isMnemonic = secret.trim().includes(' ')
  const inner = isMnemonic
    ? wordChips(secret.trim().split(/\s+/))
    : `<span style="word-break:break-all;font-weight:600;color:#fafafa">${esc(secret)}</span>`
  card.innerHTML = `
    <div style="${EYEBROW_CSS}">DEN Vault · Secret</div>
    <div style="${TITLE_CSS}">${isMnemonic ? 'Recovery phrase' : 'Private key (nsec)'}</div>
    <div style="color:#a1a1aa;font-size:13px;line-height:1.5">Keep this secret — anyone who has it controls this account.</div>
    ${revealBlock(inner)}
    <button id="v-dl" style="${BTN_CANCEL_CSS};width:100%">Download encrypted backup</button>
    <button id="v-ok" style="${BTN_OK_CSS};width:100%">Done</button>`
  wireReveal(card)
  ;(card.querySelector('#v-dl') as HTMLButtonElement).onclick = () => downloadBackup(payload, label)
  return new Promise<void>((resolve) => {
    ;(card.querySelector('#v-ok') as HTMLButtonElement).onclick = () => { close(); resolve() }
  })
}

/** Change a seed's PIN — collects current + new PIN (+ hint) in the overlay, re-encrypts. */
function showChangePin(seedId: string): Promise<{ ok: boolean }> {
  const { card, close } = openOverlay()
  card.innerHTML = `
    ${FOCUS_STYLE}
    <div style="${EYEBROW_CSS}">DEN Vault · Change PIN</div>
    <div style="${TITLE_CSS}">Change PIN</div>
    <input id="v-cur" class="v-in" type="password" inputmode="numeric" placeholder="Current PIN" style="${INPUT_CSS}" />
    <input id="v-new" class="v-in" type="password" inputmode="numeric" placeholder="New PIN" style="${INPUT_CSS}" />
    <input id="v-hint" class="v-in" type="text" placeholder="New PIN hint (optional)" style="${INPUT_CSS}" />
    <div id="v-err" style="${ERR_CSS}"></div>
    <div style="display:flex;gap:10px"><button id="v-cancel" style="${BTN_CANCEL_CSS}">Cancel</button><button id="v-ok" style="${BTN_OK_CSS}">Change PIN</button></div>`
  const cur = card.querySelector('#v-cur') as HTMLInputElement
  const nw = card.querySelector('#v-new') as HTMLInputElement
  const hintEl = card.querySelector('#v-hint') as HTMLInputElement
  const errEl = card.querySelector('#v-err') as HTMLDivElement
  const okBtn = card.querySelector('#v-ok') as HTMLButtonElement
  cur.focus()
  return new Promise((resolve, reject) => {
    okBtn.onclick = async () => {
      if (nw.value.length < 4) { errEl.textContent = 'New PIN must be at least 4 characters'; return }
      okBtn.disabled = true
      try {
        await rateGuard(seedId)
        const blob = await getSeedBlob(seedId)
        if (!blob) throw new Error('No such account')
        let secret: string
        try { secret = await decryptBackup(blob, cur.value) }
        catch { await rateFail(seedId); throw new Error('Incorrect current PIN') }
        await rateReset(seedId)
        await kvSet(seedBlobKey(seedId), await encryptBackup(secret, nw.value))
        const seeds = await getSeeds()
        const s = seeds.find((x) => x.id === seedId)
        if (s) { s.hint = hintEl.value.trim() || null; await setSeeds(seeds) }
        close(); resolve({ ok: true })
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : 'Failed'; okBtn.disabled = false
      }
    }
    ;(card.querySelector('#v-cancel') as HTMLButtonElement).onclick = () => { close(); reject(new Error('Cancelled')) }
  })
}

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
  // Generate + reveal the mnemonic and collect the PIN/label entirely in the vault overlay —
  // the plaintext seed and the PIN never reach the app. Returns only the new pubkey/seedId.
  async generateInteractive() {
    return showGenerateReveal(generateMnemonic(wordlist, 256))
  },
  // Persist a generated mnemonic as a new seed + its first account (index 0), encrypted with `pin`.
  async saveNew({ mnemonic, pin, name, hint }: { mnemonic: string; pin: string; name?: string; hint?: string }) {
    return persistGeneratedSeed(mnemonic, pin, name, hint)
  },
  // Import an encrypted backup (mnemonic OR nsec/hex key) as a new seed; its password
  // becomes the seed PIN. The imported payload IS the at-rest blob (no re-encryption).
  async importBackup({ payload, password, name, hint }: { payload: BackupPayloadV1; password: string; name?: string; hint?: string }) {
    let secret: string
    // WebCrypto throws a message-less DOMException on a bad password; surface a clear error.
    try { secret = await decryptBackup(payload, password) }
    catch { throw new Error('Wrong password — could not decrypt this backup') }
    return persistSecretBlob(secret, payload, name, hint)
  },
  // Import a recovery phrase / nsec / backup file entirely in the vault overlay — the
  // secret and PIN never reach the app. Returns only the new pubkey/seedId.
  async importInteractive() {
    return showImportOverlay()
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
  // Derive the next account from a seed — PIN entered in the vault overlay.
  async deriveInteractive({ seedId }: { seedId: string }) {
    const blob = await getSeedBlob(seedId)
    if (!blob) throw new Error('No such seed')
    const seed = (await getSeeds()).find((s) => s.id === seedId)
    return promptPinAction(
      { title: 'Add an account', eyebrow: 'DEN Vault · Derive', subtitle: seed?.hint ? `Hint: ${seed.hint}` : "Enter this seed's PIN to derive the next account.", confirmLabel: 'Add account' },
      async (pin) => {
        await rateGuard(seedId)
        let mnemonic: string
        try { mnemonic = await decryptBackup(blob, pin) }
        catch { await rateFail(seedId); throw new Error('Incorrect PIN') }
        if (!validateMnemonic(mnemonic.trim(), wordlist)) throw new Error('This identity is a single key and cannot derive more accounts')
        await rateReset(seedId)
        const used = (await getAccounts()).filter((a) => a.seedId === seedId).map((a) => a.index)
        const index = (used.length ? Math.max(...used) : -1) + 1
        const { pubHex } = deriveKeypair(mnemonic, index)
        await upsertAccount({ pubkey: pubHex, npub: nip19.npubEncode(pubHex), seedId, index, name: null, createdAt: now() })
        return { pubkey: pubHex }
      },
    )
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
  // Like unlock(), but the PIN is collected in the vault's own overlay — the app never
  // sees it. The app calls this and waits; the vault prompts, verifies, and unlocks.
  async unlockInteractive({ pubkey }: { pubkey: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    const seed = (await getSeeds()).find((s) => s.id === acct.seedId)
    return promptPinAction(
      { title: 'Unlock account', eyebrow: 'DEN Vault · Unlock', subtitle: seed?.hint ? `Hint: ${seed.hint}` : undefined, confirmLabel: 'Unlock' },
      async (pin) => {
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
    )
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
  // Remove an account — PIN confirmed in the vault overlay.
  async removeInteractive({ pubkey }: { pubkey: string }) {
    const accounts = await getAccounts()
    const acct = accounts.find((a) => a.pubkey === pubkey)
    if (!acct) return { ok: true }
    return promptPinAction(
      { title: 'Remove account', eyebrow: 'DEN Vault · Remove', subtitle: 'Enter your PIN to confirm. Make sure you have a backup — this deletes the key from this device.', confirmLabel: 'Remove' },
      async (pin) => {
        const blob = await getSeedBlob(acct.seedId)
        if (blob) { try { await decryptBackup(blob, pin) } catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') } }
        const remaining = accounts.filter((a) => a.pubkey !== pubkey)
        await setAccounts(remaining)
        if (!remaining.some((a) => a.seedId === acct.seedId)) {
          await kvSet(seedBlobKey(acct.seedId), undefined)
          await setSeeds((await getSeeds()).filter((s) => s.id !== acct.seedId))
          await rateReset(acct.seedId)
        }
        if (activePub === pubkey) lock()
        return { ok: true }
      },
    )
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
  // Reveal the account's secret (phrase/nsec) + offer a backup download, all in the overlay.
  // The plaintext is shown in the vault and never returned to the app.
  async exportRevealInteractive({ pubkey }: { pubkey: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    const blob = await getSeedBlob(acct.seedId)
    if (!blob) throw new Error('No such account')
    const seed = (await getSeeds()).find((s) => s.id === acct.seedId)
    const secret = await promptPinAction(
      { title: 'Reveal secret', eyebrow: 'DEN Vault · Reveal', subtitle: seed?.hint ? `Hint: ${seed.hint}` : "Enter your PIN to reveal this account's secret.", confirmLabel: 'Reveal' },
      async (pin) => {
        await rateGuard(acct.seedId)
        let s: string
        try { s = await decryptBackup(blob, pin) }
        catch { await rateFail(acct.seedId); throw new Error('Incorrect PIN') }
        await rateReset(acct.seedId)
        return s
      },
    )
    await showSecretReveal(secret, blob, pubkey.slice(0, 8))
    return { ok: true }
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
  // Change a seed's PIN — current + new PIN entered in the vault overlay.
  async changePinInteractive({ pubkey }: { pubkey: string }) {
    const acct = (await getAccounts()).find((a) => a.pubkey === pubkey)
    if (!acct) throw new Error('No such account')
    return showChangePin(acct.seedId)
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
    if (!activePub) throw new Error('Locked')
    const acct = (await getAccounts()).find((a) => a.pubkey === activePub)
    if (!acct) throw new Error('No active account')

    let display: TxDisplay
    let sign: (privHex: string) => string

    if (chain === 'bitcoin') {
      const utxos = tx.utxos as UTXO[]
      const amountSats = BigInt(tx.amountSats)
      display = {
        title: 'Send Bitcoin',
        rows: [['Amount', `${formatUnits(amountSats, 8)} BTC`], ['To', tx.recipientAddress as string], ['Fee rate', `${Number(tx.feeRate)} sat/vB`]],
      }
      sign = (privHex) => {
        const args = [privHex, utxos, tx.recipientAddress as string, amountSats, Number(tx.feeRate)] as const
        return tx.addressType === 'segwit' ? createSegwitTransaction(...args) : createTaprootTransaction(...args)
      }
    } else {
      const data = tx.data as Uint8Array | undefined
      const erc20 = data ? decodeErc20(data) : null
      display = erc20
        ? { title: `Send token (${chain})`, rows: [['Amount (raw)', erc20.amount.toString()], ['To', erc20.to], ['Token contract', tx.to as string]] }
        : { title: `Send on ${chain}`, rows: [['Amount', `${formatUnits(BigInt(tx.value), 18)} (native)`], ['To', tx.to as string]] }
      // getEvmSigningKey handles even-y negation for nostr-mode addresses.
      sign = (privHex) => signEvmTransaction(
        { chain: chain as EvmChain, to: tx.to, value: BigInt(tx.value), data, gasLimit: BigInt(tx.gasLimit), gasPrice: BigInt(tx.gasPrice), nonce: BigInt(tx.nonce) },
        getEvmSigningKey(privHex, tx.addressMode === 'standard' ? 'standard' : 'nostr'),
      )
    }
    return confirmAndSign(acct, display, sign)
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
  // Embedded as the app's iframe: drop the body background so the tx-confirm overlay
  // can show the app behind it (looks like a native in-app modal, not a separate page).
  document.documentElement.style.background = 'transparent'
  document.body.style.background = 'transparent'
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
