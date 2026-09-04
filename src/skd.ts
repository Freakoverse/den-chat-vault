/**
 * NIP-SKD — Sub-Key Derivation (vault / remote-signer implementation)
 *
 * Lets the vault derive application-scoped sub-keypairs from the stored identity
 * key and act as them (sign / nip44) WITHOUT the sub-key private material ever
 * leaving this origin — exactly what NIP-CHAT v2 needs to sign as the pseudonyms
 * `O` (owner), `P` (member), `Pf` (facilitated) and the sealed-join throwaway key.
 *
 * This MUST be byte-for-byte identical to the DEN client's reference impl
 * (client `src/lib/crypto/skd.ts`, salt `"nip-skd-v1"`, 48-byte HKDF wide
 * reduction, form-tagged info), verified against the NIP-SKD §8 test vectors —
 * otherwise a vault user derives mismatched pseudonyms and can neither be found
 * in the roster nor decrypt hub content. Three derivation forms, each with a
 * form-tagged HKDF `info` = "nip-skd:" ‖ form ‖ 0x1F ‖ context (NIP-SKD §1):
 *
 *   - self    : HKDF( root_priv,               … ) → seed·G
 *   - shared  : HKDF( ECDH_x(root_priv, peer),  … ) → seed·G
 *   - blinded : HKDF( ECDH_x(root_priv, peer),  … ) → root_pub + seed·G   (peer verifies, can't sign)
 *
 * A 48-byte (384-bit) HKDF output is reduced mod n (wide reduction, 0→1 pin);
 * for self/shared it IS the sub-key private scalar, for blinded it is the tweak
 * `t` added to the even-y-normalized root key. NIP-CHAT v2 uses `self` (O) and
 * `blinded` (P/Pf/join); it does not use `shared`.
 */

import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { getSharedSecret, getPublicKey, Point } from '@noble/secp256k1'

/** NIP-SKD scheme salt (frozen). Family `skd`, version `1`. */
const SKD_SALT = 'nip-skd-v1'

/** secp256k1 group order n. */
const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

const enc = new TextEncoder()

// ── HKDF-SHA256 (RFC 5869), implemented manually to match the client byte-for-byte ──
function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const prk = hmac(sha256, salt, ikm)
  const hashLen = 32
  const n = Math.ceil(length / hashLen)
  const okm = new Uint8Array(n * hashLen)
  let prev = new Uint8Array(0)
  for (let i = 0; i < n; i++) {
    const input = new Uint8Array(prev.length + info.length + 1)
    input.set(prev, 0)
    input.set(info, prev.length)
    input[prev.length + info.length] = i + 1
    prev = hmac(sha256, prk, input)
    okm.set(prev, i * hashLen)
  }
  return okm.slice(0, length)
}

function hkdfWithSalt(ikm: Uint8Array, salt: string, info: string, length: number): Uint8Array {
  return hkdfSha256(ikm, enc.encode(salt), enc.encode(info), length)
}

function bytesToBigIntBE(b: Uint8Array): bigint {
  let n = 0n
  for (const byte of b) n = (n << 8n) | BigInt(byte)
  return n
}

function scalarToBytes(d: bigint): Uint8Array {
  return hexToBytes(d.toString(16).padStart(64, '0'))
}

/** Reduce a wide 48-byte HKDF output to a valid secp256k1 private scalar in [1, n-1] (unbiased). */
function seedToPrivKey(seed: Uint8Array): Uint8Array {
  let d = bytesToBigIntBE(seed) % SECP256K1_N
  if (d === 0n) d = 1n // ~2^-384 chance; keep the derivation total
  return scalarToBytes(d)
}

/** NIP-SKD unit separator between the form tag and the context in the HKDF `info` (NIP-SKD §1). */
const SKD_FORM_SEP = '\x1f'

/** HKDF `info` = form-tagged context (NIP-SKD §1) — no two forms share a seed on the same inputs. */
function skdInfo(form: 'self' | 'shared' | 'blinded', context: string): string {
  return `nip-skd:${form}${SKD_FORM_SEP}${context}`
}

/** Reconstruct the even-`y` point from an x-only key (BIP-340) — the base for a blinded derivation. */
function liftEvenY(xonlyHex: string) {
  return Point.fromHex('02' + xonlyHex)
}

/** x-only (32-byte hex) of a curve point. */
function pointToXonly(p: { x: bigint }): string {
  return p.x.toString(16).padStart(64, '0')
}

/**
 * Raw ECDH x-coordinate (32 bytes) between a private key and a Nostr x-only pubkey.
 * The RAW x (same value NIP-44 feeds its KDF), NOT sha256(x) — NIP-SKD pins the raw x.
 */
function ecdhX(rootPriv: Uint8Array, peerPubXOnlyHex: string): Uint8Array {
  // x-only pubkey → even-y compressed (02 prefix); shared point comes back compressed (33 bytes).
  const point = getSharedSecret(rootPriv, hexToBytes('02' + peerPubXOnlyHex), true)
  return point.slice(1) // drop the 02/03 prefix → 32-byte x-coordinate
}

export interface SubKey {
  /** 32-byte sub-key private key (never leaves the vault). */
  privBytes: Uint8Array
  /** 32-byte x-only public key hex — the sub-key identifier. */
  pubHex: string
}

/**
 * Derive a NIP-SKD sub-key from the vault's identity private key.
 *
 * @param rootPriv    32-byte identity private key (bytes)
 * @param context     NIP-SKD info string — MUST be non-empty and namespaced
 * @param peerPubHex  optional peer x-only pubkey → shared (ECDH) form; omit for self
 */
export function deriveSubKey(rootPriv: Uint8Array, context: string, peerPubHex?: string): SubKey {
  if (!context) throw new Error('NIP-SKD: context must be non-empty')
  const form = peerPubHex ? 'shared' : 'self'
  const ikm = peerPubHex ? ecdhX(rootPriv, peerPubHex) : rootPriv
  const seed = hkdfWithSalt(ikm, SKD_SALT, skdInfo(form, context), 48)
  const privBytes = seedToPrivKey(seed)
  const pubHex = bytesToHex(getPublicKey(privBytes, true).slice(1)) // x-only (drop 02/03 prefix)
  return { privBytes, pubHex }
}

/**
 * Blinded derivation (NIP-SKD §1) — the vault's OWN blinded key, base = the vault's root, blinded toward
 * `peerPub`: `blinded_priv = root_priv_evenY + t`, `blinded_pub = xonly(lift_even_y(root_pub) + t·G)`.
 * The counterparty can re-derive `blinded_pub` via {@link deriveBlindedPubForPeer} but never
 * `blinded_priv`. Byte-identical to the client's `deriveBlindedLocal` (NIP-SKD §8 vectors).
 */
export function deriveBlinded(rootPriv: Uint8Array, context: string, peerPubHex: string): SubKey {
  if (!context) throw new Error('NIP-SKD: context must be non-empty')
  const seed = hkdfWithSalt(ecdhX(rootPriv, peerPubHex), SKD_SALT, skdInfo('blinded', context), 48)
  const t = bytesToBigIntBE(seedToPrivKey(seed)) // reduce(seed) with the 0→1 pin
  const rootPubComp = getPublicKey(rootPriv, true) // 33-byte compressed (02/03 ‖ x)
  const dRaw = bytesToBigIntBE(rootPriv)
  const dEven = (rootPubComp[0] & 1) === 1 ? SECP256K1_N - dRaw : dRaw // normalize to even-y base
  let priv = (dEven + t) % SECP256K1_N
  if (priv === 0n) priv = 1n // ~2^-256 invalid-key edge
  const rootXonly = bytesToHex(rootPubComp.slice(1))
  const pubHex = pointToXonly(liftEvenY(rootXonly).add(Point.BASE.multiply(t)))
  return { privBytes: scalarToBytes(priv), pubHex }
}

/**
 * Verifier-side blinded derivation (NIP-SKD §1, `getPeerBlindedPubkey`) — a PEER's blinded key toward
 * the vault: base = `peerBaseXonly`, ECDH with the vault's root. Returns the **public key only** (no
 * private key here). Byte-identical to the client's `deriveBlindedPubForPeer`.
 */
export function deriveBlindedPubForPeer(rootPriv: Uint8Array, context: string, peerBaseXonlyHex: string): string {
  if (!context) throw new Error('NIP-SKD: context must be non-empty')
  const seed = hkdfWithSalt(ecdhX(rootPriv, peerBaseXonlyHex), SKD_SALT, skdInfo('blinded', context), 48)
  const t = bytesToBigIntBE(seedToPrivKey(seed))
  return pointToXonly(liftEvenY(peerBaseXonlyHex).add(Point.BASE.multiply(t)))
}
