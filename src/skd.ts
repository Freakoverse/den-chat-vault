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
 * reduction), verified against the NIP-SKD §8 test vectors — otherwise a vault
 * user derives mismatched pseudonyms and can neither be found in the roster nor
 * decrypt hub content. Two derivation forms:
 *
 *   - self   : HKDF( root_priv,               salt="nip-skd-v1", info=context )
 *   - shared : HKDF( ECDH_x(root_priv, peer), salt="nip-skd-v1", info=context )
 *
 * A 48-byte (384-bit) HKDF output is reduced mod n to a secp256k1 private key
 * (RFC 9380 §5 wide reduction → unbiased by construction); its x-only public key
 * is the sub-key identifier.
 */

import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { getSharedSecret, getPublicKey } from '@noble/secp256k1'

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
  const ikm = peerPubHex ? ecdhX(rootPriv, peerPubHex) : rootPriv
  const seed = hkdfWithSalt(ikm, SKD_SALT, context, 48)
  const privBytes = seedToPrivKey(seed)
  const pubHex = bytesToHex(getPublicKey(privBytes, true).slice(1)) // x-only (drop 02/03 prefix)
  return { privBytes, pubHex }
}
