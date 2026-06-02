// Public membership-filter API — a thin, allocation-free wrapper around the
// Binary Fuse 16 core (`fuse.ts`). This is the surface most consumers touch:
// build a filter over a set of member keys, then test arbitrary values against
// it locally.
//
// IMPORTANT — this module does NOT salt/transform inputs. `buildMembershipFilter`
// receives member keys that the CALLER has already passed through `memberKey()`
// (spec §12.2: the server decides open vs keyed and calls `memberKey(pk)` or
// `memberKey(pk, salt)` before handing the array here). We only record
// `keyed = opts.salt !== undefined` so the on-wire blob flag (TK-4) reflects how
// the keys were derived; we never re-hash with the salt. Symmetrically,
// `testMembership(f, valueHex)` tests the given (already-transformed) value as-is
// — the discovery layer is responsible for transforming its query the same way
// the pool was built.

import { BinaryFuse16 } from './fuse.js'
import type { FilterBuildOptions, MembershipFilter } from './types.js'

/** Smallest power of two ≥ n (n ≥ 0). nextPow2(0)=1, (1)=1, (5)=8, (8)=8, (9)=16.
 *  Inlined here for TK-3; TK-6 introduces the shared `nextPowerOfTwoBand`. */
function nextPow2(n: number): number {
  let p = 1
  while (p < n) p *= 2
  return p
}

/**
 * Build a membership filter over already-`memberKey`-transformed hex values.
 *
 * @param memberKeysHex  Member keys ALREADY produced by `memberKey()` (open or
 *                       keyed). Not re-salted here. Duplicates are tolerated —
 *                       they are de-duplicated before construction because fuse
 *                       peeling requires distinct keys.
 * @param opts           `epoch` is required; `fingerprintBits` defaults to 16
 *                       (only 16 is implemented this phase); `salt` presence
 *                       only sets the `keyed` flag.
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

  const _fuse = BinaryFuse16.build(deduped)

  // Band reflects the TRUE (deduped) member count rounded up to a power of two.
  // Padding to the band (TK-6) may grow the on-wire array but not this number.
  const _memberCountBand = nextPow2(deduped.length)

  return {
    fingerprintBits,
    keyed: opts.salt !== undefined,
    epoch: opts.epoch,
    type: 1, // 1 = fuse
    _fuse,
    _memberCountBand,
    _padded: false, // padding is TK-6
  }
}

/**
 * Test whether `valueHex` is a member of `f`.
 *
 * `valueHex` is tested as-is (the caller must have transformed it the same way
 * the pool was built — see the module note). The input is lowercased for safety
 * so that case-variant hex matches; we intentionally do NOT reject non-64-hex
 * input — `memberKey` outputs are always 64-hex, and leniency here avoids
 * surprising the discovery layer (the fuse hashes arbitrary hex uniformly).
 *
 * False negatives are impossible after a successful build; false positives occur
 * at ≈ 2^-16.
 */
export function testMembership(f: MembershipFilter, valueHex: string): boolean {
  return f._fuse.contains(valueHex.toLowerCase())
}
