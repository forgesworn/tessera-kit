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
import { OFF_SIGNER_PUBKEY, OFF_SIGNATURE, OFF_FINGERPRINTS, parseFilter } from './codec.js'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import type { MembershipFilter } from './types.js'

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
 * Never throws on malformed/hostile input: a too-short OR too-long blob returns
 * `{ signerPubkeyHex: '', ok: false }`, and any sig/pubkey that the verifier
 * rejects (or that fails noble's argument validation) yields `ok: false`.
 *
 * L1 AUDIT FIX — the size cap is checked BEFORE any hashing. `computeDigest`
 * SHA-256s the entire `blob[128..end)` fingerprint region; on a raw-HTTPS (not
 * `parseFilter`-gated) path, an untrusted blob could previously reach that hash
 * BEFORE any size check ran (`parseFilter`'s `KFLT_MAX_BLOB_BYTES` check only
 * fires later, in `verifyAndParseFilter`, and only after this function already
 * did the hashing/verify work) — a ~200 MB hostile blob cost real CPU (measured
 * ~870 ms of hashing) before ever being rejected. `verifyFilterBlob` now rejects
 * `blob.length > KFLT_MAX_BLOB_BYTES` up front, alongside the existing too-short
 * check, so a hostile oversized blob is turned away before any hashing happens
 * — this protects every caller of `verifyFilterBlob`, including
 * `verifyAndParseFilter` below (which calls it first).
 *
 * @param blob the raw (signed) KFLT blob.
 * @returns the embedded signer pubkey (hex; `''` if the blob is too short or
 *          too long) and whether the signature is internally valid under that
 *          pubkey (`ok`).
 */
export function verifyFilterBlob(blob: Uint8Array): {
  signerPubkeyHex: string
  ok: boolean
} {
  // A malformed too-short blob must not crash — report invalid with no signer.
  // A too-LONG blob is rejected here too, and BEFORE any hashing (L1 audit
  // fix) — `computeDigest` below would otherwise SHA-256 the whole fingerprint
  // region of an attacker-supplied blob of unbounded size before any cap ever
  // applied.
  if (blob.length < OFF_FINGERPRINTS || blob.length > KFLT_MAX_BLOB_BYTES) {
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

/**
 * Combined pin-verify + parse + freshness helper (audit fix / TK-8 — B4).
 *
 * Doing `verifyFilterBlob` and `parseFilter` as two separate calls left the
 * mandatory pinned-key comparison as something a consumer had to remember to
 * bolt on themselves (`verifyFilterBlob` alone never throws — see its doc
 * comment), and left "freshness" entirely unaddressed: nothing in this kit
 * checked a filter's signed `epoch` against the last one a consumer had seen,
 * so an OLDER, validly-signed blob could be replayed (a rollback). This helper
 * makes the safe path the only path: it throws unless the blob is both
 * pin-verified AND (optionally) no older than `minEpoch`.
 *
 * L1 AUDIT FIX — this function calls `verifyFilterBlob` FIRST, which now
 * rejects an oversized blob (`length > KFLT_MAX_BLOB_BYTES`) before any
 * hashing (see `verifyFilterBlob`'s doc comment) — so an untrusted, huge blob
 * handed to this function is turned away cheaply, rather than paying for a
 * full SHA-256 over the fingerprint region before `parseFilter`'s own size
 * check (which only runs afterwards) would have caught it.
 *
 * IMPORTANT — use the blob's SIGNED `epoch` (this function's freshness check),
 * NOT a Nostr `["epoch"]` *tag* on any wrapping event. A tag is signed only by
 * the Nostr publisher key, never by the pinned blob-signing key, and is never
 * cross-checked against the blob's own signed `epoch` — relying on it for
 * freshness lets a relay/MITM replay a stale blob under a freshly-tagged event.
 * Track the highest `epoch` you've accepted per `(pinnedPubkeyHex)` and pass it
 * back in as `minEpoch` on the next check.
 *
 * ALSO NOTE — a `KFLT` blob does not name the server/namespace it belongs to
 * (there is no such field in the header; see `types.ts`/PROTOCOL.md §3). Pinning
 * a key here defeats a THIRD PARTY's forged filter, but if you reuse ONE signing
 * key across several servers or namespaces, a relay/MITM can serve server A's
 * validly-signed blob as server B's and this helper will happily accept it (both
 * pin-check and epoch check pass — the substitution is invisible at this layer).
 * Use a DISTINCT signing key per server/namespace if that distinction matters.
 *
 * @param blob             the raw (signed) KFLT blob.
 * @param opts.pinnedPubkeyHex the known/pinned server signing key (case-insensitive).
 *                         MUST be 64 hex chars (x-only pubkey shape) — validated
 *                         up front so a malformed pin can't accidentally compare
 *                         unequal-but-still-truthy to every signer (audit fix).
 * @param opts.minEpoch    optional: the last-seen epoch for this pinned key. A
 *                         parsed filter whose `epoch < minEpoch` is rejected as
 *                         stale/rolled-back. MUST be a non-negative safe integer
 *                         when given — a `NaN`/negative/fractional `minEpoch`
 *                         throws rather than silently comparing false against
 *                         every `epoch` and accepting a stale blob (audit fix:
 *                         `filter.epoch < NaN` is always `false`, the same
 *                         footgun `testWithCapability`'s expiry check had — B5).
 * @returns the parsed `MembershipFilter` — only on success.
 * @throws if `pinnedPubkeyHex` is not 64 hex chars, `minEpoch` is given but not a
 *         non-negative safe integer, the signature is invalid, the signer
 *         doesn't match `pinnedPubkeyHex`, the blob fails to parse (malformed
 *         structure), or the parsed `epoch` is older than `minEpoch`.
 */
export function verifyAndParseFilter(
  blob: Uint8Array,
  opts: { pinnedPubkeyHex: string; minEpoch?: number },
): MembershipFilter {
  if (typeof opts.pinnedPubkeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(opts.pinnedPubkeyHex)) {
    throw new Error('verifyAndParseFilter: pinnedPubkeyHex must be 64 hex chars')
  }
  if (
    opts.minEpoch !== undefined &&
    (!Number.isSafeInteger(opts.minEpoch) || opts.minEpoch < 0)
  ) {
    throw new Error('verifyAndParseFilter: minEpoch must be a non-negative safe integer')
  }
  const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
  if (!ok || signerPubkeyHex.toLowerCase() !== opts.pinnedPubkeyHex.toLowerCase()) {
    throw new Error(
      'verifyAndParseFilter: signature invalid or signer does not match the pinned key',
    )
  }
  // Only parse (which allocates/validates structure) AFTER the pin check passes
  // — no reason to spend structural-validation work on a blob we'd reject anyway.
  const filter = parseFilter(blob)
  if (opts.minEpoch !== undefined && filter.epoch < opts.minEpoch) {
    throw new Error('verifyAndParseFilter: filter epoch is older than minEpoch (stale/rollback)')
  }
  return filter
}
