// Public membership-filter API — a thin wrapper around the Binary Fuse 16 core
// (`fuse.ts`). This is the surface most consumers touch: build a filter over a
// set of member keys, then test arbitrary values against it locally.
//
// IMPORTANT — this module does NOT salt/transform the caller's member keys.
// `buildMembershipFilter` receives member keys that the CALLER has already passed
// through `memberKey()` (spec §1: the server decides open vs keyed and calls
// `memberKey(pk)` or `memberKey(pk, salt)` before handing the array here). We
// only record `keyed = opts.salt !== undefined` so the on-wire blob flag (TK-4)
// reflects how the keys were derived; we never re-hash with the salt. Symmetrically,
// `testMembership(f, valueHex)` tests the given (already-transformed) value as-is
// — the discovery layer is responsible for transforming its query the same way
// the pool was built.
//
// The ONE set-level transform we apply is size-bucket PADDING (spec §2.8,
// `padding.ts`): when `padToBucket` is on (default), we ADD decoy keys to round
// the set size up to a power-of-two bucket. Decoys are extra inserted keys; they
// never alter or replace a real member, and a decoy testing true is harmless (it
// corresponds to no real subject). `_memberCountBand` always records the TRUE
// count's bucket, never the padded size.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { BinaryFuse16 } from './fuse.js'
import { nextPowerOfTwoBand, padMembersToBucket } from './padding.js'
import { isValidSaltHex } from './member-key.js'
import { TesseraError } from './errors.js'
import type { FilterBuildOptions, MembershipFilter } from './types.js'

/** Every member key handed to `buildMembershipFilter` must already be a
 *  `memberKey()` output: exactly 64 hex chars, case-insensitive (lowercased
 *  before use). Anything else — non-hex, odd-length, 66-hex, etc. — throws
 *  (audit fix: previously any string was accepted, so a case-variant duplicate
 *  or a wrong-length key could reach fuse construction, either breaking peel
 *  convergence or building an untestable member). */
const HEX64_CI = /^[0-9a-f]{64}$/i

/** `decoySeedHex` must be even-length hex of at least 16 bytes (32 hex chars)
 *  when supplied (audit fix: an empty or too-short seed produced public,
 *  predictable decoys; an odd-length seed leaked a raw @noble `RangeError`). */
function assertDecoySeedHex(decoySeedHex: string): void {
  if (
    typeof decoySeedHex !== 'string' ||
    !/^[0-9a-f]*$/i.test(decoySeedHex) ||
    decoySeedHex.length % 2 !== 0
  ) {
    throw new TesseraError('BUILD_DECOY_SEED_HEX_INVALID', 'tessera-kit: decoySeedHex must be even-length hex')
  }
  if (decoySeedHex.length < 32) {
    throw new TesseraError('BUILD_DECOY_SEED_HEX_TOO_SHORT', 'tessera-kit: decoySeedHex must be at least 16 bytes (32 hex chars)')
  }
}

/** `opts.salt`, when supplied, must be non-empty even-length hex (audit fix,
 *  L4). `buildMembershipFilter` never uses `salt`'s bytes for anything — it
 *  only tests `salt !== undefined` to set the on-wire `keyed` flag (module
 *  note above) — but an unvalidated `salt: ''` or `salt: 'zz'` previously set
 *  `keyed: true` on a blob whose caller may not have salted anything at all,
 *  silently mislabeling the pool. This defers to `isValidSaltHex` — the SAME
 *  predicate `memberKey` (`member-key.ts`) uses for its own `saltHex`
 *  argument — rather than a second, independently-maintained copy of the same
 *  regex (follow-up audit fix): "keyed" now always implies the caller passed
 *  something that could plausibly BE a real salt, by the one rule that
 *  defines what a salt looks like everywhere in this kit. */
function assertBuildSalt(salt: string): void {
  if (typeof salt !== 'string' || !isValidSaltHex(salt)) {
    throw new TesseraError('BUILD_SALT_INVALID', 'tessera-kit: opts.salt must be non-empty even-length hex')
  }
}

/** Big-endian 8-byte encoding of a non-negative safe-integer epoch. Used only by
 *  the per-epoch decoy-seed derivation below (§B2) — distinct from the on-wire
 *  `epoch` field, which is little-endian (codec.ts). */
function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false)
  return b
}

/**
 * Derive the PER-EPOCH decoy seed actually passed to `padMembersToBucket`:
 *
 *   effectiveSeedHex = hex( sha256( utf8("tessera-decoy:v1:") ‖ bytes(seedHex) ‖ u64be(epoch) ) )
 *
 * Audit fix (B2): a fixed `decoySeedHex` produces the SAME decoy set every
 * epoch. Fuse slots are XOR-shared across all inserted keys, so a stable decoy
 * set makes the fingerprint array itself diffable across epochs — a non-holder
 * who diffs two published blobs observes 0 changed slots when membership didn't
 * change and ~3 changed slots when exactly one member swapped (measured), which
 * leaks an activity signal despite the decoys never being individually
 * identified. Rekeying the seed by epoch keeps a REBUILD of the SAME epoch
 * byte-identical (determinism is preserved within an epoch — required for the
 * golden-vector contract and for a server that rebuilds without changing
 * anything) while giving every NEW epoch a fresh, uncorrelated decoy set, which
 * is what actually defeats the diffing attack. `deriveDecoys` / `padMembersToBucket`
 * themselves are unchanged — this only changes WHICH seed they are called with.
 */
function deriveEpochDecoySeedHex(seedHex: string, epoch: number): string {
  const preimage = concatBytes(
    utf8ToBytes('tessera-decoy:v1:'),
    hexToBytes(seedHex.toLowerCase()),
    u64be(epoch),
  )
  return bytesToHex(sha256(preimage))
}

/**
 * Build a membership filter over already-`memberKey`-transformed hex values.
 *
 * @param memberKeysHex  Member keys ALREADY produced by `memberKey()` (open or
 *                       keyed). Not re-salted here. Every key MUST be 64 hex
 *                       chars (case-insensitive; lowercased before use) or this
 *                       throws naming the offending index (audit fix). Duplicates
 *                       (post-lowercasing) are tolerated — they are de-duplicated
 *                       before construction because fuse peeling requires
 *                       distinct keys.
 * @param opts           `epoch` is required and MUST be a non-negative safe
 *                       integer (audit fix — a negative epoch previously wrapped
 *                       to 2^64-1 on the wire). `fingerprintBits` defaults to 16
 *                       (only 16 is implemented this phase); `salt` presence
 *                       only sets the `keyed` flag. `padToBucket` defaults to
 *                       TRUE — the deduped set is padded with decoys up to the
 *                       next power-of-two bucket before building, so the on-wire
 *                       array size reveals only the coarse bucket, not the fine
 *                       count (spec §2.8). Pass `decoySeedHex` (even-length hex,
 *                       ≥16 bytes) for STABLE-PER-EPOCH decoys: rebuilding the
 *                       SAME epoch with the SAME seed reproduces the identical
 *                       blob, but each new epoch gets a fresh decoy set derived
 *                       from `(decoySeedHex, epoch)` — see
 *                       `deriveEpochDecoySeedHex` above and `padding.ts`. Omit it
 *                       for the CSPRNG path (padding still happens, but decoys
 *                       are unstable even within an epoch). Pass
 *                       `padToBucket: false` to build over the deduped members
 *                       only with no decoys.
 */
export function buildMembershipFilter(
  memberKeysHex: string[],
  opts: FilterBuildOptions,
): MembershipFilter {
  // Follow-up review fix — type guards BEFORE any field/element access. A
  // non-array `memberKeysHex` previously reached `.length` and threw a raw
  // TypeError; a non-object `opts` previously reached `opts.fingerprintBits`
  // and did the same.
  if (!Array.isArray(memberKeysHex)) {
    throw new TesseraError('BUILD_MEMBER_KEYS_TYPE', 'tessera-kit: memberKeysHex must be an array')
  }
  if (opts === null || typeof opts !== 'object') {
    throw new TesseraError('BUILD_OPTS_TYPE', 'tessera-kit: opts must be an object')
  }
  const fingerprintBits = opts.fingerprintBits ?? 16
  if (fingerprintBits !== 16) {
    // 8/20/32 are reserved in the KFLT byte format for forward-compat but are
    // not implemented. Fail loud rather than silently building a 16-bit filter.
    throw new TesseraError('BUILD_FINGERPRINT_BITS_UNSUPPORTED', 'tessera-kit: only fingerprintBits=16 implemented')
  }

  // `epoch` must be a non-negative safe integer (audit fix — see `codec.ts`
  // parseFilter's mirrored range check on the read side).
  if (!Number.isSafeInteger(opts.epoch) || opts.epoch < 0) {
    throw new TesseraError('BUILD_EPOCH_INVALID', 'tessera-kit: epoch must be a non-negative safe integer')
  }

  if (opts.decoySeedHex !== undefined) {
    assertDecoySeedHex(opts.decoySeedHex)
  }

  // `opts.salt` audit fix (L4) — validated even though buildMembershipFilter
  // never uses its bytes (see assertBuildSalt's doc comment above).
  if (opts.salt !== undefined) {
    assertBuildSalt(opts.salt)
  }

  // Validate EVERY key as 64-hex (case-insensitive) BEFORE lowercasing/dedup —
  // a clear, index-naming error beats a raw @noble `RangeError` or a peel
  // failure 100 attempts later (audit fix). Lowercase BEFORE dedup so a
  // case-variant duplicate (`AB..` / `ab..`) collapses to one entry instead of
  // surviving as two distinct strings that hash to the same u64 and break fuse
  // peeling.
  const seen = new Set<string>()
  const deduped: string[] = []
  for (let i = 0; i < memberKeysHex.length; i++) {
    const k = memberKeysHex[i] as string
    if (typeof k !== 'string' || !HEX64_CI.test(k)) {
      throw new TesseraError('BUILD_MEMBER_KEY_INVALID', `tessera-kit: memberKeysHex[${i}] must be 64 hex chars`)
    }
    const lower = k.toLowerCase()
    if (!seen.has(lower)) {
      seen.add(lower)
      deduped.push(lower)
    }
  }

  // Band ALWAYS reflects the TRUE (deduped) member count rounded up to a power
  // of two — NOT the padded array size. This coarse count "leaks by design"
  // (spec §2.8); padding hides only the fine count, not the bucket.
  const _memberCountBand = nextPowerOfTwoBand(deduped.length)

  // Padding (spec §2.8): default ON. Pad the deduped set with decoys up to the
  // size bucket so the serialized array size reveals only the coarse bucket.
  // `decoySeedHex` set ⇒ STABLE-PER-EPOCH decoys (deterministic within an epoch,
  // fresh across epochs — defeats churn-diffing, see `deriveEpochDecoySeedHex`
  // above); omitted ⇒ CSPRNG decoys (still padded, but unstable even within an
  // epoch). `padMembersToBucket` keeps the set a true set, so real members are
  // never displaced by a decoy collision.
  const padToBucket = opts.padToBucket ?? true
  const effectiveSeedHex =
    opts.decoySeedHex !== undefined
      ? deriveEpochDecoySeedHex(opts.decoySeedHex, opts.epoch)
      : undefined
  const keysToBuild = padToBucket
    ? padMembersToBucket(deduped, _memberCountBand, effectiveSeedHex)
    : deduped

  const _fuse = BinaryFuse16.build(keysToBuild)

  return {
    fingerprintBits,
    keyed: opts.salt !== undefined,
    epoch: opts.epoch,
    type: 1, // 1 = fuse
    _fuse,
    _memberCountBand,
    _padded: padToBucket,
  }
}

/** Exactly 64 hex chars (32 bytes). `testMembership` validates its input against this so a malformed
 *  value surfaces a KIT-SHAPED error at the public boundary rather than a raw @noble `RangeError`.
 *  Case-insensitive (the value is lowercased before the fuse lookup). */
const HEX64 = /^[0-9a-f]{64}$/i

/**
 * Test whether `valueHex` is a member of `f`.
 *
 * `valueHex` is tested as-is (the caller must have transformed it the same way
 * the pool was built — see the module note). It is VALIDATED to be exactly 64 hex
 * chars first (the `memberKey` output shape): an odd-length / non-hex / wrong-length
 * value throws a kit-shaped `Error` (matching `memberKey`'s style) instead of leaking
 * a raw @noble `RangeError` — or, worse, silently testing `false` for a non-hex string.
 * Every internal caller already passes `memberKey(...)` output (always 64-hex), so the
 * guard is a no-op for them; it only rejects a hand-built bad value at the boundary.
 * The validated value is lowercased so case-variant hex still matches.
 *
 * False negatives are impossible after a successful build; false positives occur
 * at ≈ 2^-16.
 */
export function testMembership(f: MembershipFilter, valueHex: string): boolean {
  // Follow-up review fix — a non-MembershipFilter `f` previously reached
  // `f._fuse.contains(...)` and threw a raw TypeError. Checked first.
  if (f === null || typeof f !== 'object' || !f._fuse) {
    throw new TesseraError('TEST_FILTER_TYPE', 'tessera-kit: testMembership filter (f) must be a MembershipFilter')
  }
  if (typeof valueHex !== 'string' || !HEX64.test(valueHex)) {
    throw new TesseraError('TEST_VALUE_INVALID', 'tessera-kit: testMembership value must be 64 hex chars')
  }
  return f._fuse.contains(valueHex.toLowerCase())
}
