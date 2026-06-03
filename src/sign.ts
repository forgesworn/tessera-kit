// KFLT blob signing + verification — Schnorr (BIP340) provenance over the
// serialized filter (spec §7.3, §10 invariant 5).
//
// WHY THIS EXISTS: a `KFLT` blob is just bytes a stranger served you over HTTPS.
// A FORGED filter is a doxxing primitive — an attacker who can make you trust an
// arbitrary membership set can make `testMembership` report a friend as
// "present" on a server they never joined (or hide them). The Schnorr signature
// binds the blob to a signer keypair so a tampered or attacker-authored filter
// is detectable BEFORE any membership result is trusted.
//
// SIGNED-MESSAGE CONSTRUCTION (must match byte-for-byte on sign + verify):
//   preimage = blob[0..64)  ‖  sha256(blob[128..end))
//   digest   = sha256(preimage)             // 32 bytes; the Schnorr message
//   sig      = schnorr.sign(digest, priv)   // 64 bytes, written at [64,128)
//
//   - blob[0..64) is the header fields (0..31) PLUS the signer_pubkey (32..63).
//     Including the signer_pubkey BINDS the signer's identity into the signature:
//     swapping in a different pubkey changes the digest, so a forged-key swap can
//     never produce a self-consistent blob (see verifyFilterBlob test (b)).
//   - The 64-byte sig region [64,128) is EXCLUDED from the preimage (a signature
//     cannot cover itself). On verify we slice [0,64) directly — since the sig
//     lives at [64,128) it is naturally outside the slice; nothing to zero.
//   - blob[128..end) is the fingerprint array, folded in via sha256 so any
//     fingerprint tamper invalidates the signature.
//
// NO console output, no new runtime deps — `@noble/curves` + `@noble/hashes`
// only. The private key bytes are zeroized in a `finally` after signing.

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js'
// Reuse the ONE definition of the byte layout from the codec — never re-hardcode
// 32 / 64 / 128 here.
import { OFF_SIGNER_PUBKEY, OFF_SIGNATURE, OFF_FINGERPRINTS } from './codec.js'

const HEX64 = /^[0-9a-f]{64}$/

/**
 * Compute the 32-byte Schnorr digest for a (signed or unsigned) KFLT blob.
 * `digest = sha256( blob[0..64) ‖ sha256(blob[128..end)) )`. Identical on the
 * signing and verifying side — the ONLY place the preimage is constructed.
 */
function computeDigest(blob: Uint8Array): Uint8Array {
  const head = blob.subarray(0, OFF_SIGNATURE) // [0,64): header + signer_pubkey
  const fingerprintHash = sha256(blob.subarray(OFF_FINGERPRINTS)) // sha256([128,end))
  return sha256(concatBytes(head, fingerprintHash))
}

/**
 * Sign an unsigned KFLT blob (output of `serializeFilter`) IN PLACE: writes the
 * 32-byte x-only signer pubkey into [32,64) and the 64-byte Schnorr signature
 * into [64,128), then returns the same (now-mutated) buffer.
 *
 * MUTATES THE CALLER'S BUFFER. The serialized blob is freshly allocated by
 * `serializeFilter` and signing it in place is the expected flow; if you need the
 * original bytes, pass a copy.
 *
 * @param unsignedBlob  A serialized KFLT blob (>= 128 bytes). The signer_pubkey
 *                      and sig regions are overwritten regardless of prior value.
 * @param signerPrivHex 64 lowercase-or-uppercase hex chars (32-byte secret key).
 * @returns the signed blob (same reference as `unsignedBlob`).
 * @throws if `signerPrivHex` is not 64 hex chars or the blob is shorter than 128.
 */
export function signFilterBlob(
  unsignedBlob: Uint8Array,
  signerPrivHex: string,
): Uint8Array {
  if (unsignedBlob.length < OFF_FINGERPRINTS) {
    throw new Error('signFilterBlob: blob shorter than KFLT header (128 bytes)')
  }
  const priv = signerPrivHex.toLowerCase()
  if (!HEX64.test(priv)) {
    throw new Error('signFilterBlob: signer private key must be 64 hex chars')
  }

  const privBytes = hexToBytes(priv)
  try {
    // Derive the x-only pubkey and write it into [32,64) BEFORE digesting — it is
    // inside [0,64) so it is covered by the signature (binds signer identity).
    const signerPub = schnorr.getPublicKey(privBytes) // 32-byte x-only
    unsignedBlob.set(signerPub, OFF_SIGNER_PUBKEY)

    const digest = computeDigest(unsignedBlob)
    const sig = schnorr.sign(digest, privBytes) // 64-byte compact BIP340 sig
    unsignedBlob.set(sig, OFF_SIGNATURE)

    return unsignedBlob
  } finally {
    // Zeroize the private key copy regardless of success/throw.
    privBytes.fill(0)
  }
}

/**
 * Verify a KFLT blob's embedded Schnorr signature and return the embedded signer
 * pubkey. Recomputes the digest with the exact same construction as signing.
 *
 * ⚠️ CRITICAL — `ok: true` IS NOT TRUST. It means ONLY: "this blob carries an
 * internally-consistent BIP340 Schnorr signature by `signerPubkeyHex`." Anyone
 * can mint a validly-self-signed blob under their OWN key (see the threat-model
 * test in sign.test.ts) — a forged filter is a doxxing primitive. The consumer
 * **MUST** compare `signerPubkeyHex` against a PINNED / out-of-band-known server
 * key before trusting ANY membership result (spec §10 invariant 5). The pinned-
 * key comparison — not `ok` alone — is what defeats forged-filter doxxing:
 *
 *   const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
 *   if (!ok || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
 *
 * Never throws on malformed/hostile input: a too-short blob returns
 * `{ signerPubkeyHex: '', ok: false }`, and any sig/pubkey that the verifier
 * rejects (or that fails noble's argument validation) yields `ok: false`.
 *
 * @param blob the raw (signed) KFLT blob.
 * @returns the embedded signer pubkey (hex; `''` if the blob is too short) and
 *          whether the signature is internally valid under that pubkey (`ok`).
 */
export function verifyFilterBlob(blob: Uint8Array): {
  signerPubkeyHex: string
  ok: boolean
} {
  // A malformed too-short blob must not crash — report invalid with no signer.
  if (blob.length < OFF_FINGERPRINTS) {
    return { signerPubkeyHex: '', ok: false }
  }

  const signerPub = blob.subarray(OFF_SIGNER_PUBKEY, OFF_SIGNATURE) // [32,64)
  const sig = blob.subarray(OFF_SIGNATURE, OFF_FINGERPRINTS) // [64,128)
  const signerPubkeyHex = bytesToHex(signerPub)

  let ok = false
  try {
    const digest = computeDigest(blob)
    ok = schnorr.verify(sig, digest, signerPub)
  } catch {
    // A malformed sig/pubkey (e.g. failing noble's argument type validation) must
    // yield ok:false, not throw. No console output.
    ok = false
  }

  return { signerPubkeyHex, ok }
}
