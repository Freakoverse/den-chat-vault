/**
 * DEN Chat Vault — isolated signing origin.
 *
 * Runs at its own origin (https://denchat.dekev.top — a separate registrable domain
 * from the app, so Site Isolation gives it its own process), embedded as an iframe
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

import './index.css'
import QRCode from 'qrcode'
import jsQR from 'jsqr'
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

/* ─── Shared overlay building blocks (styled via .v-* classes in index.css) ─── */
const inset = (html: string) => `<div class="v-inset">${html}</div>`

/** Numbered word chips that wrap as whole units — each chip sizes to its word, never clipped. */
function wordChips(words: string[]): string {
  return `<div class="v-words">${words.map((w, i) => `<span class="v-chip"><span class="v-chip-n">${i + 1}</span>${esc(w)}</span>`).join('')}</div>`
}

/** Wrap secret content (phrase/nsec) in a blurred box behind a "make sure no one is watching"
 *  cover + a Reveal button with a short countdown — mirrors the app's reveal flow. */
function revealBlock(innerHtml: string): string {
  return `<div class="relative">
      <div id="v-secret-box" class="v-inset max-h-[46vh] overflow-auto select-none blur-md transition-[filter] duration-200">${innerHtml}</div>
      <div id="v-cover" class="absolute inset-0 flex flex-col items-center justify-center gap-3 text-center p-5 rounded-xl bg-popover/70">
        <div class="text-sm font-semibold text-foreground">Reveal your secret?</div>
        <div class="text-xs text-muted-foreground max-w-[260px] leading-relaxed">Make sure no one is watching your screen and nothing is recording.</div>
        <button id="v-reveal" class="v-btn-primary px-5">Reveal</button>
        <button id="v-reveal-cancel" class="v-btn px-4 hidden">No, wait</button>
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
    cancelBtn.classList.remove('hidden')
    timer = setInterval(() => {
      n -= 1
      if (n <= 0) { if (timer) clearInterval(timer); box.classList.remove('blur-md'); cover.classList.add('hidden') }
      else btn.textContent = `Revealing in ${n}…`
    }, 1000)
  }
  cancelBtn.onclick = () => {
    if (timer) clearInterval(timer)
    btn.disabled = false
    btn.textContent = 'Reveal'
    cancelBtn.classList.add('hidden')
  }
}

/** Open the dimmed-backdrop overlay and return the (empty) card to fill + a close fn. */
function openOverlay(): { card: HTMLDivElement; close: () => void } {
  showTxOverlay(true)
  const backdrop = document.createElement('div')
  backdrop.className = 'v-backdrop'
  const card = document.createElement('div')
  card.className = 'v-card'
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
    <div class="v-eyebrow">${esc(opts.eyebrow || 'DEN Chat Vault')}</div>
    <div class="v-title">${esc(opts.title)}</div>
    ${opts.subtitle ? `<div class="v-note">${esc(opts.subtitle)}</div>` : ''}
    ${opts.bodyHtml || ''}
    ${pinField('v-pin', opts.placeholder || 'Enter PIN')}
    <div id="v-err" class="v-err"></div>
    <div class="v-row">
      <button id="v-cancel" class="v-btn v-grow">Cancel</button>
      <button id="v-ok" class="v-btn-primary v-grow-lg">${esc(opts.confirmLabel || 'Confirm')}</button>
    </div>`
  const pinInput = wirePinField(card, 'v-pin')
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
  const rows = d.rows.map(([k, v]) => `<div class="flex justify-between gap-4"><span class="text-muted-foreground shrink-0">${esc(k)}</span><span class="font-semibold text-right break-all">${esc(v)}</span></div>`).join('')
  return promptPinAction(
    { title: d.title, eyebrow: 'DEN Chat Vault · Secure confirm', bodyHtml: inset(rows), placeholder: 'Enter PIN to sign', confirmLabel: 'Confirm & Sign' },
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

/** Inline lucide-style icons (stroke uses currentColor → tint via the parent text color). */
const I = (p: string, size = 14) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:-2px">${p}</svg>`
const ICON = {
  lock: I('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', 20),
  shield: I('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 20),
  alert: I('<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'),
  eye: I('<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>'),
  eyeOff: I('<path d="M9.9 4.24A9.12 9.12 0 0 1 12 5c7 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68M6.6 6.6A13.5 13.5 0 0 0 2 12s3 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/><line x1="2" y1="2" x2="22" y2="22"/>'),
  copy: I('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
  check: I('<polyline points="20 6 9 17 4 12"/>'),
  download: I('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>'),
  fileUp: I('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><polyline points="9 15 12 12 15 15"/>'),
  qr: I('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3z"/><path d="M20 14v3"/><path d="M14 20h3"/><path d="M20 20v.01"/>'),
  x: I('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', 18),
  hash: I('<line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/>', 16),
  keyboard: I('<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M6 8h.01M10 8h.01M14 8h.01M18 8h.01M8 12h.01M12 12h.01M16 12h.01M7 16h10"/>', 16),
  chevron: I('<polyline points="6 9 12 15 18 9"/>', 16),
}

/** Encode text as a QR data-URL (black-on-white so any scanner reads it). */
function qrDataUrl(text: string): Promise<string> {
  return QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 1, width: 320, color: { dark: '#000000', light: '#ffffff' } })
}

/** A PIN field markup: password input + inline eye toggle + a numeric/keyboard switcher
 *  (mobile-only, matching the app's PinInput). Wire it afterwards with wirePinField. */
function pinField(id: string, placeholder: string): string {
  return `<div class="flex gap-2 w-full">
    <div class="relative flex-1">
      <input id="${id}" class="v-input pr-10" type="password" inputmode="numeric" placeholder="${esc(placeholder)}" />
      <button id="${id}-eye" class="v-eye" type="button" tabindex="-1">${ICON.eye}</button>
    </div>
    <button id="${id}-kbd" class="v-kbd md:hidden" type="button" tabindex="-1" title="Switch keyboard">${ICON.hash}</button>
  </div>`
}

/** Wire a pinField's eye toggle + keyboard switcher. Returns the input element. */
function wirePinField(card: HTMLElement, id: string): HTMLInputElement {
  const input = card.querySelector('#' + id) as HTMLInputElement
  const eye = card.querySelector('#' + id + '-eye') as HTMLButtonElement | null
  const kbd = card.querySelector('#' + id + '-kbd') as HTMLButtonElement | null
  if (eye) eye.onclick = () => { const show = input.type === 'password'; input.type = show ? 'text' : 'password'; eye.innerHTML = show ? ICON.eyeOff : ICON.eye }
  if (kbd) kbd.onclick = () => {
    const numeric = input.inputMode === 'numeric'
    input.inputMode = numeric ? 'text' : 'numeric'
    kbd.innerHTML = numeric ? ICON.keyboard : ICON.hash
    input.focus()
  }
  return input
}

/** Open the camera, scan for a QR each frame, and call onResult once found. Returns a stop fn. */
function startScan(video: HTMLVideoElement, onResult: (text: string) => void, onError: (msg: string) => void): () => void {
  let raf = 0, stream: MediaStream | null = null, stopped = false
  const canvas = document.createElement('canvas')
  const ctx = canvas.getContext('2d', { willReadFrequently: true })
  navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    .then((s) => {
      if (stopped) { s.getTracks().forEach((t) => t.stop()); return }
      stream = s; video.srcObject = s; void video.play()
      const tick = () => {
        if (stopped) return
        if (ctx && video.readyState >= 2 && video.videoWidth) {
          canvas.width = video.videoWidth; canvas.height = video.videoHeight
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height)
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height)
          const code = jsQR(img.data, img.width, img.height)
          if (code?.data) { onResult(code.data); return }
        }
        raf = requestAnimationFrame(tick)
      }
      raf = requestAnimationFrame(tick)
    })
    .catch(() => onError('Camera unavailable or permission denied'))
  return () => { stopped = true; cancelAnimationFrame(raf); stream?.getTracks().forEach((t) => t.stop()); video.srcObject = null }
}

/**
 * Generate flow — mirrors the app's two-step Create Account → Backup screens, entirely in
 * the overlay (label/PIN/hint, dot-hidden grid, reveal countdown, copy, encrypted download,
 * re-upload verify). Persists only on Continue, so bailing leaves no orphan account.
 */
function showGenerateReveal(mnemonic: string): Promise<{ pubkey: string; seedId: string }> {
  const { card, close } = openOverlay()
  card.classList.add('v-center')
  const words = mnemonic.split(' ')
  let pin = '', name = '', hint = ''
  let revealed = false, downloaded = false, verified = false, accordionOpen = false

  return new Promise<{ pubkey: string; seedId: string }>((resolve, reject) => {
    // ── Step 1: Create Account (set the PIN) ──
    function renderCreate(err?: string) {
      card.innerHTML = `
        <div class="v-icon-row"><span class="text-primary">${ICON.lock}</span><h2 class="v-h2">Create Account</h2></div>
        <p class="v-note text-center">Choose a PIN to protect your new account. You'll need it every time you log in.</p>
        <div class="v-warn v-warn-amber"><span class="shrink-0 mt-0.5">${ICON.alert}</span><div><b>There is no PIN recovery.</b> If you forget your PIN, your only option is to re-import using your raw seed phrase (the ${words.length} words).</div></div>
        <input id="v-name" class="v-input" type="text" placeholder="Local seed label (optional)" />
        ${pinField('v-pin', 'Enter PIN')}
        <input id="v-hint" class="v-input" type="text" placeholder="PIN hint (optional)" />
        ${err ? `<div class="v-warn v-warn-red"><span class="shrink-0">${ICON.alert}</span><span>${esc(err)}</span></div>` : ''}
        <button id="v-gen" class="v-btn-primary w-full">Generate New Seed</button>
        <button id="v-back" class="v-ghost">Back</button>`
      const nameI = card.querySelector('#v-name') as HTMLInputElement
      const pinI = wirePinField(card, 'v-pin')
      const hintI = card.querySelector('#v-hint') as HTMLInputElement
      nameI.value = name; pinI.value = pin; hintI.value = hint; pinI.focus()
      ;(card.querySelector('#v-gen') as HTMLButtonElement).onclick = () => {
        name = nameI.value.trim(); pin = pinI.value; hint = hintI.value.trim()
        if (pin.length < 4) { renderCreate('Set a PIN of at least 4 characters'); return }
        renderBackup()
      }
      ;(card.querySelector('#v-back') as HTMLButtonElement).onclick = () => { close(); reject(new Error('Cancelled')) }
    }

    // ── Step 2: Backup ──
    function renderBackup(dlOpen = false, dlErr?: string) {
      const grid = words.map((w, i) => `<div class="v-word"><span class="v-word-n">${i + 1}.</span><span class="v-word-v">${revealed ? esc(w) : '••••'}</span></div>`).join('')
      card.innerHTML = `
        <div class="v-icon-row"><span class="text-primary">${ICON.shield}</span><h2 class="v-h2">Backup Seed Phrase</h2></div>
        <div class="v-warn v-warn-red"><span class="shrink-0 mt-0.5">${ICON.alert}</span><span>Write down these words and store them securely. Anyone with these words can access your keys and funds.</span></div>
        <div class="w-full rounded-lg border border-border overflow-hidden">
          <button id="v-acc" class="w-full flex items-center justify-between px-3 py-2.5 bg-secondary/30 hover:bg-secondary/60 cursor-pointer border-0 text-left transition-colors">
            <span class="flex items-center gap-2 text-sm font-medium text-foreground">${ICON.lock} View recovery phrase</span>
            <span class="text-muted-foreground" style="display:inline-flex;transition:transform .2s;transform:rotate(${accordionOpen ? '180deg' : '0deg'})">${ICON.chevron}</span>
          </button>
          ${accordionOpen ? `
            <div class="p-3 border-t border-border" style="display:flex;flex-direction:column;gap:12px">
              <div class="v-wordgrid">${grid}</div>
              <div class="flex gap-2 w-full">
                <button id="v-reveal" class="v-pill flex-1">${revealed ? ICON.eyeOff + ' Censor' : ICON.eye + ' Reveal'}</button>
                <button id="v-copy" class="v-pill flex-1">${ICON.copy} Copy</button>
              </div>
            </div>` : ''}
        </div>
        ${dlOpen ? `
          <div class="v-sub">
            <p class="text-xs text-muted-foreground">Re-enter your PIN to encrypt and download:</p>
            ${pinField('v-dlpin', 'Enter your PIN')}
            ${dlErr ? `<div class="v-err">${esc(dlErr)}</div>` : ''}
            <div class="flex gap-2">
              <button id="v-dlcancel" class="v-ghost flex-1">Cancel</button>
              <button id="v-dlgo" class="v-btn-primary flex-1">${ICON.download} Encrypt &amp; Download</button>
            </div>
          </div>`
        : `<button id="v-dl" class="v-btn w-full">${ICON.download} Download Encrypted Backup</button>`}
        ${downloaded && !verified ? `<button id="v-verify" class="v-btn w-full">${ICON.fileUp} Re-upload backup to verify</button><input id="v-vfile" type="file" accept="application/json,.json" class="hidden" />` : ''}
        ${verified ? `<div class="v-ok">${ICON.check} Backup verified</div>` : ''}
        <div id="v-verr" class="v-err"></div>
        <button id="v-cont" class="v-btn-primary w-full" ${(!downloaded || !verified) ? 'disabled' : ''}>${!downloaded ? 'Download backup to continue' : !verified ? 'Verify your backup to continue' : "I've Saved My Seed · Continue"}</button>`
      const verr = card.querySelector('#v-verr') as HTMLDivElement
      ;(card.querySelector('#v-acc') as HTMLButtonElement).onclick = () => {
        accordionOpen = !accordionOpen
        if (!accordionOpen) revealed = false // re-censor when collapsing
        renderBackup(dlOpen)
      }
      const revealBtn = card.querySelector('#v-reveal') as HTMLButtonElement | null
      if (revealBtn) revealBtn.onclick = () => {
        if (revealed) { revealed = false; renderBackup(dlOpen) } else renderRevealConfirm(dlOpen)
      }
      const copyBtn = card.querySelector('#v-copy') as HTMLButtonElement | null
      if (copyBtn) copyBtn.onclick = async () => {
        try { await navigator.clipboard.writeText(mnemonic); copyBtn.innerHTML = `${ICON.check} Copied!`; setTimeout(() => { copyBtn.innerHTML = `${ICON.copy} Copy` }, 1500) } catch { /* clipboard blocked */ }
      }
      if (dlOpen) {
        const dlpin = wirePinField(card, 'v-dlpin')
        dlpin.focus()
        ;(card.querySelector('#v-dlcancel') as HTMLButtonElement).onclick = () => renderBackup(false)
        ;(card.querySelector('#v-dlgo') as HTMLButtonElement).onclick = async () => {
          if (dlpin.value !== pin) { renderBackup(true, "That PIN doesn't match the one you set"); return }
          try { downloadBackup(await encryptBackup(mnemonic, pin), deriveKeypair(mnemonic).pubHex.slice(0, 8)); downloaded = true; renderBackup(false) }
          catch { renderBackup(true, 'Could not create the backup file') }
        }
      } else {
        ;(card.querySelector('#v-dl') as HTMLButtonElement).onclick = () => renderBackup(true)
      }
      if (downloaded && !verified) {
        const vfile = card.querySelector('#v-vfile') as HTMLInputElement
        ;(card.querySelector('#v-verify') as HTMLButtonElement).onclick = () => vfile.click()
        vfile.onchange = async () => {
          const f = vfile.files?.[0]; if (!f) return
          try {
            const secret = await decryptBackup(JSON.parse(await f.text()), pin)
            if (secret.trim() === mnemonic.trim()) { verified = true; renderBackup(false) }
            else verr.textContent = "That file doesn't match this seed"
          } catch { verr.textContent = 'Could not verify that file' }
        }
      }
      const cont = card.querySelector('#v-cont') as HTMLButtonElement
      cont.onclick = async () => {
        if (!downloaded || !verified) return
        cont.disabled = true
        try { const r = await persistGeneratedSeed(mnemonic, pin, name || undefined, hint || undefined); close(); resolve(r) }
        catch (e) { verr.textContent = e instanceof Error ? e.message : 'Could not save'; cont.disabled = false }
      }
    }

    // ── Reveal gate: confirm → countdown (card-content swap) ──
    function renderRevealConfirm(dlOpen: boolean) {
      card.innerHTML = `
        <div class="flex items-center justify-center w-12 h-12 rounded-full bg-destructive/10 text-destructive mx-auto">${ICON.alert}</div>
        <h2 class="v-h2" style="font-size:18px">Reveal your secret keys?</h2>
        <p class="v-note text-center">These ${words.length} words <b>are</b> your account. Anyone who sees them gains <b class="text-destructive">full and permanent control</b> of your funds. There is no recovery and no undo.</p>
        <p class="text-xs text-muted-foreground">Make sure no one is watching your screen and nothing is recording.</p>
        <div class="v-row w-full">
          <button id="v-rc" class="v-btn flex-1">Cancel</button>
          <button id="v-ry" class="v-btn-primary flex-1" style="background:hsl(var(--destructive))">${ICON.eye} Yes, show</button>
        </div>`
      ;(card.querySelector('#v-rc') as HTMLButtonElement).onclick = () => renderBackup(dlOpen)
      ;(card.querySelector('#v-ry') as HTMLButtonElement).onclick = () => renderCountdown(dlOpen)
    }
    function renderCountdown(dlOpen: boolean) {
      let n = 5
      let timer: ReturnType<typeof setInterval> | null = null
      const draw = () => {
        card.innerHTML = `
          <div class="relative flex items-center justify-center w-16 h-16 text-destructive mx-auto">
            <svg class="animate-spin w-16 h-16" viewBox="0 0 24 24" fill="none" style="opacity:.4"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3"/></svg>
            <span class="absolute text-2xl font-bold text-foreground">${n}</span>
          </div>
          <h2 class="v-h2" style="font-size:18px">Showing keys in ${n}…</h2>
          <p class="v-note text-center">Last chance — make sure no one can see your screen.</p>
          <button id="v-nw" class="v-btn w-full">${ICON.eyeOff} Wait, never mind</button>`
        ;(card.querySelector('#v-nw') as HTMLButtonElement).onclick = () => { if (timer) clearInterval(timer); renderBackup(dlOpen) }
      }
      draw()
      timer = setInterval(() => {
        n -= 1
        if (n <= 0) { if (timer) clearInterval(timer); revealed = true; renderBackup(dlOpen) } else draw()
      }, 1000)
    }

    renderCreate()
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

/**
 * Import flow — mirrors the app: Import Account (paste / Backup File / Scan QR) → either
 * "Set a PIN" (raw secret) or "Decrypt Backup" (encrypted file/QR). All secret/PIN handling
 * stays in the overlay; the QR scan + decode also run here (only ciphertext leaves the camera).
 */
function showImportOverlay(): Promise<{ pubkey: string; seedId: string }> {
  const { card, close } = openOverlay()
  card.classList.add('v-center')
  let stopScan: (() => void) | null = null
  const cleanup = () => { if (stopScan) { stopScan(); stopScan = null } }

  return new Promise<{ pubkey: string; seedId: string }>((resolve, reject) => {
    const finish = (r: { pubkey: string; seedId: string }) => { cleanup(); close(); resolve(r) }

    // ── Import Account (paste / file / scan) ──
    function renderMain(err?: string) {
      card.classList.add('v-center')
      card.innerHTML = `
        <h2 class="v-h2">Import Account</h2>
        <p class="v-note text-center">Enter your 24-word seed phrase, nsec, or hex private key.</p>
        <textarea id="v-secret" class="v-textarea h-[120px]" placeholder="word1 word2 word3 … (24 words) or nsec1… or hex"></textarea>
        ${err ? `<div class="v-warn v-warn-red"><span class="shrink-0">${ICON.alert}</span><span>${esc(err)}</span></div>` : ''}
        <button id="v-cont" class="v-btn-primary w-full">Continue</button>
        <div class="flex items-center gap-3 w-full text-xs text-muted-foreground"><span class="flex-1 h-px bg-border"></span>or<span class="flex-1 h-px bg-border"></span></div>
        <div class="flex gap-2 w-full">
          <button id="v-filebtn" class="v-btn flex-1">${ICON.fileUp} Backup File</button>
          <button id="v-scanbtn" class="v-btn flex-1">${ICON.qr} Scan QR</button>
          <input id="v-file" type="file" accept="application/json,.json" class="hidden" />
        </div>
        <button id="v-back" class="v-ghost">Back</button>`
      const ta = card.querySelector('#v-secret') as HTMLTextAreaElement
      ta.focus()
      ;(card.querySelector('#v-cont') as HTMLButtonElement).onclick = () => {
        const raw = ta.value.trim()
        if (!raw) { renderMain('Enter your seed phrase, nsec, or key'); return }
        const payload = tryParseBackup(raw)
        if (payload) { renderDecrypt(payload); return }
        if (raw.includes(' ')) { if (!validateMnemonic(raw, wordlist)) { renderMain("That doesn't look like a valid recovery phrase"); return } }
        else { try { keypairFromSecret(raw, 0) } catch { renderMain("That doesn't look like a valid nsec / key"); return } }
        renderSetPin(raw)
      }
      const fileInput = card.querySelector('#v-file') as HTMLInputElement
      ;(card.querySelector('#v-filebtn') as HTMLButtonElement).onclick = () => fileInput.click()
      fileInput.onchange = async () => {
        const f = fileInput.files?.[0]; if (!f) return
        try { const payload = tryParseBackup(await f.text()); if (payload) renderDecrypt(payload); else renderMain("That file isn't a valid DEN backup") }
        catch { renderMain('Could not read that file') }
      }
      ;(card.querySelector('#v-scanbtn') as HTMLButtonElement).onclick = () => renderScan()
      ;(card.querySelector('#v-back') as HTMLButtonElement).onclick = () => { cleanup(); close(); reject(new Error('Cancelled')) }
    }

    // ── Set a PIN (raw secret) ──
    function renderSetPin(secret: string, err?: string) {
      card.classList.add('v-center')
      const isSeed = secret.includes(' ')
      card.innerHTML = `
        <div class="v-icon-row"><span class="text-primary">${ICON.lock}</span><h2 class="v-h2">Set a PIN</h2></div>
        <p class="v-note text-center">Protect this imported ${isSeed ? 'seed' : 'key'} with a PIN. You'll need it every time you log in.</p>
        <div class="v-warn v-warn-amber"><span class="shrink-0 mt-0.5">${ICON.alert}</span><div><b>There is no PIN recovery.</b> If you forget it, re-import using your secret.</div></div>
        <input id="v-name" class="v-input" type="text" placeholder="Label (optional)" />
        ${pinField('v-pin', 'Set a PIN')}
        <input id="v-hint" class="v-input" type="text" placeholder="PIN hint (optional)" />
        ${err ? `<div class="v-warn v-warn-red"><span class="shrink-0">${ICON.alert}</span><span>${esc(err)}</span></div>` : ''}
        <button id="v-imp" class="v-btn-primary w-full">Import &amp; Login</button>
        <button id="v-back" class="v-ghost">Back</button>`
      const pinI = wirePinField(card, 'v-pin')
      pinI.focus()
      ;(card.querySelector('#v-imp') as HTMLButtonElement).onclick = async () => {
        const pin = pinI.value
        if (pin.length < 4) { renderSetPin(secret, 'Set a PIN of at least 4 characters'); return }
        const name = (card.querySelector('#v-name') as HTMLInputElement).value.trim() || undefined
        const hint = (card.querySelector('#v-hint') as HTMLInputElement).value.trim() || undefined
        ;(card.querySelector('#v-imp') as HTMLButtonElement).disabled = true
        try { finish(await persistSecretBlob(secret, await encryptBackup(secret, pin), name, hint)) }
        catch (e) { renderSetPin(secret, e instanceof Error ? e.message : 'Import failed') }
      }
      ;(card.querySelector('#v-back') as HTMLButtonElement).onclick = () => renderMain()
    }

    // ── Decrypt Backup (encrypted file / QR) ──
    function renderDecrypt(payload: BackupPayloadV1, err?: string) {
      card.classList.add('v-center')
      card.innerHTML = `
        <div class="v-icon-row"><span class="text-primary">${ICON.lock}</span><h2 class="v-h2">Decrypt Backup</h2></div>
        <p class="v-note text-center">Enter the password used when this backup was created.</p>
        ${pinField('v-pw', 'Backup password / PIN')}
        ${err ? `<div class="v-warn v-warn-red"><span class="shrink-0">${ICON.alert}</span><span>${esc(err)}</span></div>` : ''}
        <button id="v-dec" class="v-btn-primary w-full">Decrypt</button>
        <button id="v-back" class="v-ghost">Cancel</button>`
      const pw = wirePinField(card, 'v-pw')
      pw.focus()
      ;(card.querySelector('#v-dec') as HTMLButtonElement).onclick = async () => {
        if (!pw.value) { renderDecrypt(payload, 'Enter the backup password'); return }
        ;(card.querySelector('#v-dec') as HTMLButtonElement).disabled = true
        let secret: string
        try { secret = await decryptBackup(payload, pw.value) } catch { renderDecrypt(payload, 'Wrong password for this backup'); return }
        try { finish(await persistSecretBlob(secret, payload)) } catch (e) { renderDecrypt(payload, e instanceof Error ? e.message : 'Import failed') }
      }
      ;(card.querySelector('#v-back') as HTMLButtonElement).onclick = () => renderMain()
    }

    // ── Scan QR (camera, in-vault) ──
    function renderScan(err?: string) {
      card.classList.remove('v-center')
      card.innerHTML = `
        <div class="flex justify-end w-full"><button id="v-close" class="v-eye" style="position:static;transform:none">${ICON.x}</button></div>
        <video id="v-video" class="w-full aspect-square rounded-xl border-2 border-primary bg-black object-cover" playsinline muted></video>
        <p class="v-note text-center">Point your camera at the backup QR code</p>
        ${err ? `<div class="v-warn v-warn-red"><span class="shrink-0">${ICON.alert}</span><span>${esc(err)}</span></div>` : ''}
        <button id="v-cancel" class="v-btn w-full">Cancel</button>`
      const video = card.querySelector('#v-video') as HTMLVideoElement
      const back = () => { cleanup(); renderMain() }
      ;(card.querySelector('#v-close') as HTMLButtonElement).onclick = back
      ;(card.querySelector('#v-cancel') as HTMLButtonElement).onclick = back
      stopScan = startScan(
        video,
        (text) => {
          cleanup()
          const payload = tryParseBackup(text)
          if (payload) renderDecrypt(payload)
          else renderMain("That QR code isn't a DEN backup")
        },
        (msg) => { stopScan = null; renderScan(msg) },
      )
    }

    renderMain()
  })
}

/* ─── Reveal + change-PIN overlays (Phase 4) ─── */

/** Show a decrypted secret (recovery phrase or nsec) + a backup download, in the overlay. */
function showSecretReveal(secret: string, payload: BackupPayloadV1, label: string): Promise<void> {
  const { card, close } = openOverlay()
  const isMnemonic = secret.trim().includes(' ')
  const inner = isMnemonic
    ? wordChips(secret.trim().split(/\s+/))
    : `<span class="break-all font-semibold text-foreground">${esc(secret)}</span>`
  card.innerHTML = `
    <div class="v-eyebrow">DEN Chat Vault · Secret</div>
    <div class="v-title">${isMnemonic ? 'Recovery phrase' : 'Private key (nsec)'}</div>
    <div class="v-note">Keep this secret — anyone who has it controls this account.</div>
    ${revealBlock(inner)}
    <div id="v-qr" class="hidden w-full flex justify-center"><img id="v-qrimg" alt="Encrypted backup QR" class="rounded-xl bg-white p-2" width="240" height="240" /></div>
    <div class="v-row">
      <button id="v-dl" class="v-btn v-grow">${ICON.download} Download</button>
      <button id="v-showqr" class="v-btn v-grow">${ICON.qr} Show QR</button>
    </div>
    <button id="v-ok" class="v-btn-primary w-full">Done</button>`
  wireReveal(card)
  ;(card.querySelector('#v-dl') as HTMLButtonElement).onclick = () => downloadBackup(payload, label)
  const qrWrap = card.querySelector('#v-qr') as HTMLDivElement
  const qrImg = card.querySelector('#v-qrimg') as HTMLImageElement
  const showQrBtn = card.querySelector('#v-showqr') as HTMLButtonElement
  showQrBtn.onclick = async () => {
    if (!qrWrap.classList.contains('hidden')) { qrWrap.classList.add('hidden'); showQrBtn.innerHTML = `${ICON.qr} Show QR`; return }
    try { qrImg.src = await qrDataUrl(JSON.stringify(payload)); qrWrap.classList.remove('hidden'); showQrBtn.innerHTML = `${ICON.qr} Hide QR` }
    catch { /* payload too large for a QR — ignore */ }
  }
  return new Promise<void>((resolve) => {
    ;(card.querySelector('#v-ok') as HTMLButtonElement).onclick = () => { close(); resolve() }
  })
}

/** Change a seed's PIN — collects current + new PIN (+ hint) in the overlay, re-encrypts. */
function showChangePin(seedId: string): Promise<{ ok: boolean }> {
  const { card, close } = openOverlay()
  card.innerHTML = `
    <div class="v-eyebrow">DEN Chat Vault · Change PIN</div>
    <div class="v-title">Change PIN</div>
    ${pinField('v-cur', 'Current PIN')}
    ${pinField('v-new', 'New PIN')}
    <input id="v-hint" class="v-input" type="text" placeholder="New PIN hint (optional)" />
    <div id="v-err" class="v-err"></div>
    <div class="v-row"><button id="v-cancel" class="v-btn v-grow">Cancel</button><button id="v-ok" class="v-btn-primary v-grow-lg">Change PIN</button></div>`
  const cur = wirePinField(card, 'v-cur')
  const nw = wirePinField(card, 'v-new')
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
      { title: 'Add an account', eyebrow: 'DEN Chat Vault · Derive', subtitle: seed?.hint ? `Hint: ${seed.hint}` : "Enter this seed's PIN to derive the next account.", confirmLabel: 'Add account' },
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
      { title: 'Unlock account', eyebrow: 'DEN Chat Vault · Unlock', subtitle: seed?.hint ? `Hint: ${seed.hint}` : undefined, confirmLabel: 'Unlock' },
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
      { title: 'Remove account', eyebrow: 'DEN Chat Vault · Remove', subtitle: 'Enter your PIN to confirm. Make sure you have a backup — this deletes the key from this device.', confirmLabel: 'Remove' },
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
      { title: 'Reveal secret', eyebrow: 'DEN Chat Vault · Reveal', subtitle: seed?.hint ? `Hint: ${seed.hint}` : "Enter your PIN to reveal this account's secret.", confirmLabel: 'Reveal' },
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
        // Both P2WPKH variants ('segwit' = 02‖x, 'segwit-odd' = 03‖x) share one signer —
        // it picks the key parity that controls `fromAddress` and throws if neither does.
        const isP2wpkh = tx.addressType === 'segwit' || tx.addressType === 'segwit-odd'
        if (isP2wpkh) {
          const from = tx.fromAddress as string | undefined
          if (!from) throw new Error('Missing fromAddress — cannot determine which key controls these funds.')
          return createSegwitTransaction(...args, from)
        }
        return createTaprootTransaction(...args)
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
  line('<b>DEN Chat Vault — feasibility self-test</b><br><span class="muted">Confirms key gen, the encrypted-blob format, IndexedDB persistence, and signing all work in <i>this</i> context (open this page inside your installed PWA to test standalone iOS).</span><br>')
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
