// KFLT blob signing + verification — Schnorr (BIP340) provenance over the
// serialized filter (spec §4.1, PROTOCOL.md §4.2), BOUND to a caller-supplied
// deployment `context` (spec §4.1/§4.3).
//
// WHY THIS EXISTS: a `KFLT` blob is just bytes a stranger served you over HTTPS.
// A FORGED filter is a doxxing primitive — an attacker who can make you trust an
// arbitrary membership set can make `testMembership` report a friend as
// "present" on a server they never joined (or hide them). The Schnorr signature
// binds the blob to a signer keypair so a tampered or attacker-authored filter
// is detectable BEFORE any membership result is trusted.
//
// CONTEXT BINDING (audit fix — closes the "blob does not name its server" gap):
// the 128-byte KFLT header (codec.ts) has no field identifying which server or
// namespace a filter belongs to. Before this fix, `pinnedPubkeyHex` alone was
// the ONLY binding a consumer had — if one signing key was ever reused across
// several servers/namespaces, a relay/MITM could serve server A's validly-signed
// blob in place of server B's, and pin-verification could not tell (the
// substitution was "invisible at this layer" — the old doc language for this
// exact gap). `context` closes it CRYPTOGRAPHICALLY: it is folded into the
// signed digest itself, so a blob signed for one context can never verify
// under a different one, REGARDLESS of whether the signing key is shared.
// Distinct signing keys per server are now DEFENCE IN DEPTH, not the only
// mitigation — `context` is the primary one.
//
// WHAT TO PASS AS `context`: the STABLE ADDRESS the verifier already knows
// independently of the blob itself — i.e. something you'd have to already know
// in order to go fetch this filter in the first place, so a MITM/relay cannot
// simply relabel a different blob and have it pass. For the kindred convention
// (PROTOCOL.md §6), that is the `d`-tag value itself:
// `kindred:members:<namespace>:<serverId>`. A tessera-kit-only server not using
// that convention should use its own equivalent stable, out-of-band-known
// identifier for the deployment. tessera-kit does NOT invent a default — the
// caller always supplies `context` explicitly (this module knows nothing about
// kindred's addressing convention; see nostr.ts's module note).
//
// SIGNED-MESSAGE CONSTRUCTION (must match byte-for-byte on sign + verify):
//   digest = sha256( utf8("tessera-kflt-sig:v1") ‖ 0x00 ‖ u32be(byteLen(ctx)) ‖
//                     utf8(ctx) ‖ blob[0..64) ‖ sha256(blob[128..end)) )
//   sig    = schnorr.sign(digest, priv)   // 64 bytes, written at [64,128)
//
//   - `"tessera-kflt-sig:v1"` is a fixed domain-separation tag — without it, a
//     signature over this digest could in principle be confused with a
//     signature intended for some OTHER protocol that also happens to sign
//     `sha256(prefix ‖ context ‖ ...)`-shaped messages under the same key.
//   - The `0x00` byte separates the fixed tag from the length-prefixed
//     `context` that follows, and the `u32be` length prefix makes the
//     concatenation of tag+len+context+header unambiguous (no context value
//     can be crafted to make two different (context, blob) pairs hash the
//     same way by shifting field boundaries — the same delimiter-injection
//     reasoning as capability.ts's colon-free `serverId` guard, but solved
//     here with an explicit length prefix instead of a forbidden character).
//   - `blob[0..64)` is the header fields (0..31) PLUS the signer_pubkey
//     (32..63). Including the signer_pubkey BINDS the signer's identity into
//     the signature: swapping in a different pubkey changes the digest, so a
//     forged-key swap can never produce a self-consistent blob (see
//     verifyFilterBlob test (b)).
//   - The 64-byte sig region [64,128) is EXCLUDED from the digest input (a
//     signature cannot cover itself). On verify we slice [0,64) directly —
//     since the sig lives at [64,128) it is naturally outside the slice;
//     nothing to zero.
//   - blob[128..end) is the fingerprint array, folded in via sha256 so any
//     fingerprint tamper invalidates the signature.
//
// KFLT_VERSION stays 1 — this is a change to the SIGNED DIGEST only (how the
// existing header+sig bytes are interpreted for signing purposes), not to the
// on-wire blob layout (codec.ts is unchanged). A blob signed under the OLD
// (pre-context) digest formula will not verify under this code, and vice versa
// — that is the intended breaking change (0.2.0, never published).
//
// NO console output, no new runtime deps — `@noble/curves` + `@noble/hashes`
// only. The private key bytes are zeroized in a `finally` after signing.

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
// Reuse the ONE definition of the byte layout from the codec — never re-hardcode
// 32 / 64 / 128 here.
import { OFF_SIGNER_PUBKEY, OFF_SIGNATURE, OFF_FINGERPRINTS, parseFilter } from './codec.js'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import { hasLoneSurrogate } from './text.js'
import { TesseraError } from './errors.js'
import type { MembershipFilter } from './types.js'
import type { TesseraErrorCode } from './errors.js'

const HEX64 = /^[0-9a-f]{64}$/

// Fixed domain-separation tag for the signed digest (see the module note).
const DIGEST_PREFIX = utf8ToBytes('tessera-kflt-sig:v1')
const DIGEST_SEPARATOR = new Uint8Array([0x00])

// `context` MUST be non-empty and its UTF-8 encoding MUST be <= this many
// bytes. 1024 is generous for any realistic deployment address (a kindred
// d-tag is well under 200 bytes) while keeping the length-prefixed field
// small and bounded — this is a caller-supplied config value, not
// attacker-controlled blob data, so the bound exists to catch a usage bug
// (e.g. accidentally passing a whole document as `context`), not to defend
// against hostile input the way `parseFilter`'s bounds do.
const MAX_CONTEXT_UTF8_BYTES = 1024

/** Big-endian 4-byte encoding of a non-negative 32-bit integer. Used only for
 *  the digest's length-prefixed `context` field — distinct from the on-wire
 *  header's little-endian u32 fields (codec.ts). */
function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

/**
 * True iff `ctx` is a valid signing `context` (spec §4.1): a non-empty
 * string, well-formed UTF-16 (no lone/unpaired surrogate), whose UTF-8
 * encoding is at most `MAX_CONTEXT_UTF8_BYTES` (1024) bytes. `ctx` is
 * `unknown`, not `string`, so this doubles as a type guard/runtime check for
 * a caller who hasn't already narrowed the type — e.g. kenspeckle validating
 * a config value up front, before ever calling `signFilterBlob` /
 * `verifyFilterBlob`.
 *
 * `signFilterBlob` and `verifyFilterBlob` use this EXACT function internally
 * (via `assertContext` below) — this is the ONE source of truth for "is this
 * a valid context," not a parallel, independently-maintained copy of the same
 * three rules. `assertContext` calls it as the primary gate and only
 * re-derives which SPECIFIC rule failed (for its `SIGN_CONTEXT_*` /
 * `VERIFY_CONTEXT_*` error code) on the rejection path.
 *
 * Byte-exact, NO Unicode normalisation (matches `capability.ts`'s `serverId`
 * policy, spec §5.3): two canonically-equivalent but byte-different strings
 * (e.g. NFC vs NFD) are DIFFERENT contexts. A cross-language re-implementer
 * MUST NOT normalise `context` either.
 */
export function isValidFilterContext(ctx: unknown): boolean {
  if (typeof ctx !== 'string' || ctx.length === 0) return false
  if (hasLoneSurrogate(ctx)) return false
  return utf8ToBytes(ctx).length <= MAX_CONTEXT_UTF8_BYTES
}

/**
 * Validate `context` and return its UTF-8 bytes. Shared by `signFilterBlob`,
 * `verifyFilterBlob`, and (indirectly, via `verifyFilterBlob`)
 * `verifyAndParseFilter` — the ONE place this validation happens, so sign and
 * verify can never accidentally apply different rules to the same field.
 * Built on `isValidFilterContext` above (the same three rules, spec §4.1):
 * non-empty string, well-formed UTF-16 (no lone/unpaired surrogate — reuses
 * the SAME check `capability.ts`'s `serverId` uses, via `text.ts`'s
 * `hasLoneSurrogate`, for the identical reason: `utf8ToBytes` would otherwise
 * silently map two DIFFERENT strings to the SAME UTF-8 bytes and so the same
 * digest), UTF-8 encoding <= `MAX_CONTEXT_UTF8_BYTES`.
 *
 * @param context the caller-supplied context string.
 * @param fnName  the calling function's name, used ONLY to prefix the error
 *                message (so a caller sees which entry point rejected it) —
 *                this is a usage-error message, never shown to a peer, and is
 *                unrelated to the "don't reveal which check failed" rule for
 *                signature verification (see `verifyAndParseFilter`'s doc
 *                comment) — that rule concerns a WRONG-but-well-formed
 *                context, which this function accepts and lets fail at the
 *                signature-verify step instead.
 * @param codes   the `SIGN_CONTEXT_*` or `VERIFY_CONTEXT_*` code triple to use
 *                — distinct per caller (`signFilterBlob` vs `verifyFilterBlob`)
 *                so a consumer can tell which side rejected a malformed
 *                context, even though a WRONG-but-well-formed context (the
 *                security-sensitive case) is never distinguished this way.
 */
function assertContext(
  context: string,
  fnName: string,
  codes: {
    empty: TesseraErrorCode
    notWellFormed: TesseraErrorCode
    tooLong: TesseraErrorCode
  },
): Uint8Array {
  // Primary gate: the ONE source of truth (see its doc comment). The happy
  // path never needs to know WHICH rule would have failed.
  if (isValidFilterContext(context)) {
    return utf8ToBytes(context)
  }
  // Rejected — re-run the same three rules, in the same order, ONLY to pick
  // the specific error code; `isValidFilterContext` already decided "invalid".
  if (typeof context !== 'string' || context.length === 0) {
    throw new TesseraError(codes.empty, `${fnName}: context must be a non-empty string`)
  }
  if (hasLoneSurrogate(context)) {
    throw new TesseraError(
      codes.notWellFormed,
      `${fnName}: context must not contain an unpaired UTF-16 surrogate (not well-formed text)`,
    )
  }
  throw new TesseraError(
    codes.tooLong,
    `${fnName}: context must be at most ${MAX_CONTEXT_UTF8_BYTES} UTF-8 bytes`,
  )
}

const SIGN_CONTEXT_CODES = {
  empty: 'SIGN_CONTEXT_EMPTY',
  notWellFormed: 'SIGN_CONTEXT_NOT_WELL_FORMED',
  tooLong: 'SIGN_CONTEXT_TOO_LONG',
} as const
const VERIFY_CONTEXT_CODES = {
  empty: 'VERIFY_CONTEXT_EMPTY',
  notWellFormed: 'VERIFY_CONTEXT_NOT_WELL_FORMED',
  tooLong: 'VERIFY_CONTEXT_TOO_LONG',
} as const

/**
 * Compute the 32-byte Schnorr digest for a (signed or unsigned) KFLT blob,
 * bound to `contextBytes` (the caller's already-validated UTF-8 context
 * bytes — see `assertContext`). Identical on the signing and verifying side —
 * the ONLY place the digest is constructed. See the module note for the exact
 * byte layout.
 */
function computeDigest(blob: Uint8Array, contextBytes: Uint8Array): Uint8Array {
  const head = blob.subarray(0, OFF_SIGNATURE) // [0,64): header + signer_pubkey
  const fingerprintHash = sha256(blob.subarray(OFF_FINGERPRINTS)) // sha256([128,end))
  return sha256(
    concatBytes(
      DIGEST_PREFIX,
      DIGEST_SEPARATOR,
      u32be(contextBytes.length),
      contextBytes,
      head,
      fingerprintHash,
    ),
  )
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
 * @param context       REQUIRED. The stable, out-of-band-known deployment
 *                      address this filter is being signed FOR (see the module
 *                      note for what to pass). Folded into the signed digest —
 *                      a blob signed for one context never verifies under a
 *                      different one. Non-empty, well-formed UTF-16, UTF-8
 *                      encoding <= 1024 bytes.
 * @returns the signed blob (same reference as `unsignedBlob`).
 * @throws if `signerPrivHex` is not 64 hex chars, the blob is shorter than
 *         128, or `context` fails validation.
 */
export function signFilterBlob(
  unsignedBlob: Uint8Array,
  signerPrivHex: string,
  context: string,
): Uint8Array {
  // Type guards (follow-up review fix) — checked BEFORE any field access
  // below. A non-Uint8Array `unsignedBlob` previously reached `.length` and
  // threw a raw TypeError; a non-string `signerPrivHex` previously reached
  // `.toLowerCase()` and did the same.
  if (!(unsignedBlob instanceof Uint8Array)) {
    throw new TesseraError('SIGN_BLOB_TYPE', 'signFilterBlob: unsignedBlob must be a Uint8Array')
  }
  if (unsignedBlob.length < OFF_FINGERPRINTS) {
    throw new TesseraError(
      'SIGN_BLOB_TOO_SHORT',
      'signFilterBlob: blob shorter than KFLT header (128 bytes)',
    )
  }
  const contextBytes = assertContext(context, 'signFilterBlob', SIGN_CONTEXT_CODES)
  if (typeof signerPrivHex !== 'string') {
    throw new TesseraError('SIGN_PRIVATE_KEY_TYPE', 'signFilterBlob: signer private key must be a string')
  }
  const priv = signerPrivHex.toLowerCase()
  if (!HEX64.test(priv)) {
    throw new TesseraError(
      'SIGN_PRIVATE_KEY_INVALID',
      'signFilterBlob: signer private key must be 64 hex chars',
    )
  }

  const privBytes = hexToBytes(priv)
  try {
    // Derive the x-only pubkey and write it into [32,64) BEFORE digesting — it is
    // inside [0,64) so it is covered by the signature (binds signer identity).
    // Follow-up review fix — a 64-hex key that is out of range for the
    // secp256k1 scalar field (zero, or >= the curve order) previously escaped
    // as a raw @noble RangeError/Error from `getPublicKey`. Wrapped here.
    let signerPub: Uint8Array
    try {
      signerPub = schnorr.getPublicKey(privBytes) // 32-byte x-only
    } catch {
      throw new TesseraError(
        'SIGN_PRIVATE_KEY_OUT_OF_RANGE',
        'signFilterBlob: signer private key is not a valid secp256k1 scalar (zero or >= curve order)',
      )
    }
    unsignedBlob.set(signerPub, OFF_SIGNER_PUBKEY)

    const digest = computeDigest(unsignedBlob, contextBytes)
    const sig = schnorr.sign(digest, privBytes) // 64-byte compact BIP340 sig
    unsignedBlob.set(sig, OFF_SIGNATURE)

    return unsignedBlob
  } finally {
    // Zeroize the private key copy regardless of success/throw.
    privBytes.fill(0)
  }
}

/**
 * Verify a KFLT blob's embedded Schnorr signature against `context`, and
 * return the embedded signer pubkey. Recomputes the digest with the exact
 * same construction as signing, bound to `context`.
 *
 * WHEN TO CALL THIS INSTEAD OF `verifyAndParseFilter` (PROTOCOL.md §4.3) —
 * use `verifyFilterBlob` directly (and compare `signerPubkeyHex` yourself,
 * then call `parseFilter`) when the trusted signer key is NOT a static pin
 * you already hold, but is instead authenticated some OTHER way that only
 * becomes known once other data has arrived — e.g. kenspeckle's
 * `requireAuthorIsSigner`, which derives the trusted key from the outer
 * Nostr event's author `pubkey` rather than a fixed constant. If you DO
 * already hold a fixed `pinnedPubkeyHex` for this `context`, prefer
 * `verifyAndParseFilter` instead — it does the pin comparison for you.
 *
 * ⚠️ CRITICAL — `ok: true` IS NOT TRUST. It means ONLY: "this blob carries an
 * internally-consistent BIP340 Schnorr signature by `signerPubkeyHex`, over
 * THIS `context`." Anyone can mint a validly-self-signed blob under their OWN
 * key for any context they like (see the threat-model test in sign.test.ts) —
 * a forged filter is a doxxing primitive. The consumer **MUST** compare
 * `signerPubkeyHex` against a PINNED / out-of-band-known server key before
 * trusting ANY membership result (PROTOCOL.md §4.2). The pinned-key
 * comparison — not `ok` alone — is what defeats forged-filter doxxing:
 *
 *   const { signerPubkeyHex, ok } = verifyFilterBlob(blob, context)
 *   if (!ok || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
 *
 * CONTEXT — `context` MUST be the verifier's own stable, out-of-band-known
 * deployment address (see sign.ts's module note); passing the WRONG context
 * (or the right blob under a DIFFERENT deployment's context) makes `ok: false`
 * exactly as a bad signature or wrong signer would — this function does not
 * (and cannot) distinguish "wrong context" from "wrong signature" internally,
 * since context is baked into the digest before verification ever runs.
 *
 * `context` itself IS validated up front (throws on a malformed context —
 * empty, not well-formed UTF-16, or over 1024 UTF-8 bytes) — that is a caller
 * CONFIGURATION error, not hostile blob input, so it is not covered by the
 * "never throws" guarantee below (which is about `blob`'s CONTENT/length,
 * not its JS type or `context`). `blob` itself DOES throw
 * (`VERIFY_BLOB_TYPE`) if it is not a `Uint8Array` at all — that is a caller
 * TYPE bug, the same category as a malformed `context`, not "hostile bytes a
 * relay served."
 *
 * Never throws on malformed/hostile BLOB CONTENT (once it IS a Uint8Array): a
 * too-short OR too-long blob returns `{ signerPubkeyHex: '', ok: false }`,
 * and any sig/pubkey that the verifier rejects (or that fails noble's
 * argument validation) yields `ok: false`.
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
 * @param blob    the raw (signed) KFLT blob.
 * @param context REQUIRED. The verifier's own stable deployment address — see
 *                the module note. Validated the same way as `signFilterBlob`'s
 *                `context`.
 * @returns the embedded signer pubkey (hex; `''` if the blob is too short or
 *          too long) and whether the signature is internally valid under that
 *          pubkey AND context (`ok`).
 */
export function verifyFilterBlob(
  blob: Uint8Array,
  context: string,
): {
  signerPubkeyHex: string
  ok: boolean
} {
  const contextBytes = assertContext(context, 'verifyFilterBlob', VERIFY_CONTEXT_CODES)

  // Type guard (follow-up review fix) — a non-Uint8Array `blob` (null, a
  // number, a plain object) previously reached `.length` and threw a raw
  // TypeError. This is a caller TYPE error, not "hostile blob content" (the
  // "never throws" guarantee below is about a well-typed blob's LENGTH/bytes,
  // not its JS type), so it is validated and thrown here rather than folded
  // into the `ok:false` no-throw path.
  if (!(blob instanceof Uint8Array)) {
    throw new TesseraError('VERIFY_BLOB_TYPE', 'verifyFilterBlob: blob must be a Uint8Array')
  }

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
    const digest = computeDigest(blob, contextBytes)
    ok = schnorr.verify(sig, digest, signerPub)
  } catch {
    // A malformed sig/pubkey (e.g. failing noble's argument type validation) must
    // yield ok:false, not throw. No console output.
    ok = false
  }

  return { signerPubkeyHex, ok }
}

/**
 * Combined pin-verify + context-bind + parse + freshness helper (audit fix /
 * TK-8 — B4, extended with context binding).
 *
 * WHEN TO CALL THIS (PROTOCOL.md §4.3) — use `verifyAndParseFilter` when you
 * already hold a fixed, out-of-band-known `pinnedPubkeyHex` for this
 * `context` (the common case). If the trusted signer key is instead
 * authenticated some OTHER way that only becomes known once other data has
 * arrived — e.g. kenspeckle's `requireAuthorIsSigner`, which derives the
 * trusted key from the outer Nostr event's author `pubkey` rather than a
 * fixed constant — call `verifyFilterBlob(blob, context)` directly instead,
 * compare its returned `signerPubkeyHex` against whatever your own mechanism
 * determined the trusted key to be, and only THEN call `parseFilter(blob)`.
 * Both paths perform the exact same three checks (signature, signer,
 * context); the difference is only where the trusted key comes from.
 *
 * Doing `verifyFilterBlob` and `parseFilter` as two separate calls left the
 * mandatory pinned-key comparison as something a consumer had to remember to
 * bolt on themselves (`verifyFilterBlob` alone never throws — see its doc
 * comment), and left "freshness" entirely unaddressed: nothing in this kit
 * checked a filter's signed `epoch` against the last one a consumer had seen,
 * so an OLDER, validly-signed blob could be replayed (a rollback). This helper
 * makes the safe path the only path: it throws unless the blob is both
 * pin-verified for the given `context` AND (optionally) no older than
 * `minEpoch`.
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
 * Track the highest `epoch` you've accepted per `(pinnedPubkeyHex, context)`
 * and pass it back in as `minEpoch` on the next check.
 *
 * CONTEXT BINDING (replaces the old "invisible at this layer" limitation) —
 * `opts.context` MUST be the caller's own stable, out-of-band-known deployment
 * address (see sign.ts's module note; for the kindred convention, PROTOCOL.md
 * §6's d-tag value `kindred:members:<namespace>:<serverId>`). Because context
 * is now folded into the SIGNED DIGEST itself, a blob signed for a DIFFERENT
 * deployment fails HERE — cryptographically — even if it was signed by the
 * exact same key as the one pinned. **A wrong context fails with the SAME
 * generic error as a wrong signer or a tampered signature** — this function
 * deliberately does not distinguish "signature invalid," "signer doesn't
 * match," and "context doesn't match" in its thrown message, so a caller
 * cannot probe which check failed. Using a DISTINCT signing key per
 * server/namespace is now DEFENCE IN DEPTH on top of context binding, not the
 * only mitigation for cross-server substitution.
 *
 * @param blob             the raw (signed) KFLT blob.
 * @param opts.pinnedPubkeyHex the known/pinned server signing key (case-insensitive).
 *                         MUST be 64 hex chars (x-only pubkey shape) — validated
 *                         up front so a malformed pin can't accidentally compare
 *                         unequal-but-still-truthy to every signer (audit fix).
 * @param opts.context     REQUIRED. The verifier's own stable deployment
 *                         address — see the module note. A wrong (but
 *                         well-formed) value fails exactly like a bad
 *                         signature (see above); a malformed value (empty,
 *                         not well-formed UTF-16, over 1024 UTF-8 bytes)
 *                         throws its own distinct usage error, the same as a
 *                         malformed `pinnedPubkeyHex` does.
 * @param opts.minEpoch    optional: the last-seen epoch for this pinned key. A
 *                         parsed filter whose `epoch < minEpoch` is rejected as
 *                         stale/rolled-back. MUST be a non-negative safe integer
 *                         when given — a `NaN`/negative/fractional `minEpoch`
 *                         throws rather than silently comparing false against
 *                         every `epoch` and accepting a stale blob (audit fix:
 *                         `filter.epoch < NaN` is always `false`, the same
 *                         footgun `testWithCapability`'s expiry check had — B5).
 * @returns the parsed `MembershipFilter` — only on success.
 * @throws if `pinnedPubkeyHex` is not 64 hex chars, `context` is malformed,
 *         `minEpoch` is given but not a non-negative safe integer, the
 *         signature is invalid, the signer doesn't match `pinnedPubkeyHex`,
 *         the context doesn't match (all THREE of these share one generic
 *         message — see above), the blob fails to parse (malformed
 *         structure), or the parsed `epoch` is older than `minEpoch`.
 */
export function verifyAndParseFilter(
  blob: Uint8Array,
  opts: { pinnedPubkeyHex: string; context: string; minEpoch?: number },
): MembershipFilter {
  // Type guard (follow-up review fix) — a non-object `opts` (null, a number)
  // previously reached `opts.pinnedPubkeyHex` and threw a raw TypeError.
  // `blob`'s own type is validated inside `verifyFilterBlob` below.
  if (opts === null || typeof opts !== 'object') {
    throw new TesseraError('VERIFY_OPTS_TYPE', 'verifyAndParseFilter: opts must be an object')
  }
  if (typeof opts.pinnedPubkeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(opts.pinnedPubkeyHex)) {
    throw new TesseraError(
      'VERIFY_PINNED_PUBKEY_INVALID',
      'verifyAndParseFilter: pinnedPubkeyHex must be 64 hex chars',
    )
  }
  if (
    opts.minEpoch !== undefined &&
    (!Number.isSafeInteger(opts.minEpoch) || opts.minEpoch < 0)
  ) {
    throw new TesseraError(
      'VERIFY_MIN_EPOCH_INVALID',
      'verifyAndParseFilter: minEpoch must be a non-negative safe integer',
    )
  }
  // `context`'s SHAPE is validated by `verifyFilterBlob` (via `assertContext`)
  // below — a malformed context throws its own distinct usage error there, the
  // same as the checks above. A WRONG-but-well-formed context is not
  // distinguished from a bad signature/signer — see the doc comment.
  const { signerPubkeyHex, ok } = verifyFilterBlob(blob, opts.context)
  if (!ok || signerPubkeyHex.toLowerCase() !== opts.pinnedPubkeyHex.toLowerCase()) {
    throw new TesseraError(
      'VERIFY_SIGNATURE_OR_SIGNER_MISMATCH',
      'verifyAndParseFilter: signature invalid or signer does not match the pinned key',
    )
  }
  // Only parse (which allocates/validates structure) AFTER the pin check passes
  // — no reason to spend structural-validation work on a blob we'd reject anyway.
  const filter = parseFilter(blob)
  if (opts.minEpoch !== undefined && filter.epoch < opts.minEpoch) {
    throw new TesseraError(
      'VERIFY_STALE_EPOCH',
      'verifyAndParseFilter: filter epoch is older than minEpoch (stale/rollback)',
    )
  }
  return filter
}
