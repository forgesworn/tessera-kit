// Public membership-filter API — a thin wrapper around the Binary Fuse 16 core
// (`fuse.ts`). This is the surface most consumers touch: build a filter over a
// set of member keys, then test arbitrary values against it locally.
//
// IMPORTANT — this module does NOT salt/transform the caller's member keys.
// `buildMembershipFilter` receives member keys that the CALLER has already passed
// through `memberKey()` (spec §12.2: the server decides open vs keyed and calls
// `memberKey(pk)` or `memberKey(pk, salt)` before handing the array here). We
// only record `keyed = opts.salt !== undefined` so the on-wire blob flag (TK-4)
// reflects how the keys were derived; we never re-hash with the salt. Symmetrically,
// `testMembership(f, valueHex)` tests the given (already-transformed) value as-is
// — the discovery layer is responsible for transforming its query the same way
// the pool was built.
//
// The ONE set-level transform we apply is size-bucket PADDING (spec §7.5,
// `padding.ts`): when `padToBucket` is on (default), we ADD decoy keys to round
// the set size up to a power-of-two bucket. Decoys are extra inserted keys; they
// never alter or replace a real member, and a decoy testing true is harmless (it
// corresponds to no real subject). `_memberCountBand` always records the TRUE
// count's bucket, never the padded size.

import { BinaryFuse16 } from './fuse.js'
import { nextPowerOfTwoBand, padMembersToBucket } from './padding.js'
import type { FilterBuildOptions, MembershipFilter } from './types.js'

/**
 * Build a membership filter over already-`memberKey`-transformed hex values.
 *
 * @param memberKeysHex  Member keys ALREADY produced by `memberKey()` (open or
 *                       keyed). Not re-salted here. Duplicates are tolerated —
 *                       they are de-duplicated before construction because fuse
 *                       peeling requires distinct keys.
 * @param opts           `epoch` is required; `fingerprintBits` defaults to 16
 *                       (only 16 is implemented this phase); `salt` presence
 *                       only sets the `keyed` flag. `padToBucket` defaults to
 *                       TRUE — the deduped set is padded with decoys up to the
 *                       next power-of-two bucket before building, so the on-wire
 *                       array size reveals only the coarse bucket, not the fine
 *                       count (spec §7.5). Pass `decoySeedHex` for STABLE decoys
 *                       (deterministic across rebuilds — defeats churn-diffing);
 *                       omit it for the UNSTABLE CSPRNG path (padding still
 *                       happens, but churn is diffable across epochs — see
 *                       `padding.ts`). Pass `padToBucket: false` to build over
 *                       the deduped members only with no decoys.
 */
export function buildMembershipFilter(
  memberKeysHex: string[],
  opts: FilterBuildOptions,
): MembershipFilter {
  const fingerprintBits = opts.fingerprintBits ?? 16
  if (fingerprintBits !== 16) {
    // 8/20/32 are reserved in the KFLT byte format for forward-compat but are
    // not implemented. Fail loud rather than silently building a 16-bit filter.
    throw new Error('tessera-kit: only fingerprintBits=16 implemented')
  }

  // De-duplicate while preserving first-seen order (determinism). Distinct keys
  // are a hard precondition of fuse construction.
  const seen = new Set<string>()
  const deduped: string[] = []
  for (const k of memberKeysHex) {
    if (!seen.has(k)) {
      seen.add(k)
      deduped.push(k)
    }
  }

  // Band ALWAYS reflects the TRUE (deduped) member count rounded up to a power
  // of two — NOT the padded array size. This coarse count "leaks by design"
  // (spec §7.5); padding hides only the fine count, not the bucket.
  const _memberCountBand = nextPowerOfTwoBand(deduped.length)

  // Padding (spec §7.5): default ON. Pad the deduped set with decoys up to the
  // size bucket so the serialized array size reveals only the coarse bucket.
  // `decoySeedHex` set ⇒ STABLE decoys (deterministic across rebuilds — defeats
  // version-diffing of churn); omitted ⇒ UNSTABLE CSPRNG decoys (still padded,
  // but churn becomes diffable across epochs). `padMembersToBucket` keeps the set
  // a true set, so real members are never displaced by a decoy collision.
  const padToBucket = opts.padToBucket ?? true
  const keysToBuild = padToBucket
    ? padMembersToBucket(deduped, _memberCountBand, opts.decoySeedHex)
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
  if (typeof valueHex !== 'string' || !HEX64.test(valueHex)) {
    throw new Error('tessera-kit: testMembership value must be 64 hex chars')
  }
  return f._fuse.contains(valueHex.toLowerCase())
}
