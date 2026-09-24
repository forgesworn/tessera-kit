// Size-bucket padding + decoy pool (spec §2.8).
//
// WHAT THIS BUYS (and what it does NOT):
//   A published filter's on-wire array size is a function of the number of keys
//   inserted. Without padding, that size leaks the *fine* member count. Padding
//   rounds the inserted-key count up to the next power-of-two bucket by adding
//   DECOY keys, so the serialized size reveals only the coarse bucket.
//   `_memberCountBand` still records the TRUE count's bucket — that coarse count
//   "leaks by design" (spec §2.8); padding hides only the fine count.
//
// DECOY STABILITY IS A DOUBLE-EDGED PROPERTY (audit fix — read before choosing):
//   Fuse fingerprint slots are XOR-SHARED across every inserted key (member AND
//   decoy alike) — no slot "belongs" to one key. That means a FIXED decoy set,
//   reused byte-for-byte across epochs, does NOT hide churn the way a per-key
//   mental model would suggest. Measured on a 700-member pool at bucket 1024: a
//   STABLE seed with 0 membership changes between epochs diffs at exactly **0**
//   fingerprint slots, and with exactly 1 member swapped diffs at only **~3**
//   slots (≥2 swaps diffs ~1000). A non-salt-holder who diffs two published blobs
//   therefore learns, with high confidence, whether membership changed at all —
//   and whether it was a single swap — purely from array-diff magnitude, with
//   NO per-key attribution needed. That is a real activity-leak, not a false
//   alarm: a perfectly stable decoy set makes the WHOLE array a version-diffing
//   oracle for churn events, even though no individual decoy is ever identified.
//
//   What actually defeats this: EITHER unstable decoys (CSPRNG-random, this
//   module's default when no seed is given — every rebuild picks new decoys, so
//   diff magnitude carries no signal), OR decoys that are stable WITHIN an epoch
//   but change ACROSS epochs (what `buildMembershipFilter` now does by deriving
//   a fresh effective seed from `(decoySeedHex, epoch)` before calling
//   `padMembersToBucket` here — see `filter.ts`). Either option keeps a REBUILD
//   of the same unchanged epoch byte-identical (useful for caching, and required
//   by the golden-vector contract) while denying an attacker a fixed baseline to
//   diff two DIFFERENT epochs against.
//
//   DEGENERATE CASE: when the true member count already equals the bucket size
//   (`n == band`), `padMembersToBucket` adds ZERO decoys (see `need <= 0` below)
//   — there is nothing to pad. In that case the fingerprint array diffs EXACTLY
//   regardless of decoy mode: every slot change is a genuine membership change,
//   because there are no decoys in the mix to begin with.
//
//   This module itself is unchanged by the fix — `deriveDecoys` and
//   `padMembersToBucket` still do exactly what they did before. What changed is
//   WHICH seed `buildMembershipFilter` passes in (per-epoch, not the caller's raw
//   `decoySeedHex`). A caller invoking this module directly still gets the raw,
//   epoch-unaware behaviour documented here — the epoch-rekeying is applied one
//   layer up.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js'
import { TesseraError } from './errors.js'

/**
 * Smallest power of two ≥ n (n ≥ 0).
 *
 *   nextPowerOfTwoBand(0) === 1
 *   nextPowerOfTwoBand(1) === 1
 *   nextPowerOfTwoBand(3) === 4
 *   nextPowerOfTwoBand(1000) === 1024
 *   nextPowerOfTwoBand(1024) === 1024
 *
 * This is the single source of truth for the size-bucket function — both the
 * member_count_band (TK-3/`filter.ts`) and the padding target (this module) use
 * it, so the two can never drift apart.
 */
export function nextPowerOfTwoBand(n: number): number {
  // Follow-up review fix — previously any value silently "worked": a
  // non-number `n` coerces to NaN in `p < n`, which is always false, so the
  // loop never runs and `1` is returned with no signal the input was
  // nonsense (e.g. a caller error passing a string where a count belongs).
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) {
    throw new TesseraError('INPUT_BAND_INVALID', 'nextPowerOfTwoBand: n must be a non-negative finite number')
  }
  let p = 1
  while (p < n) p *= 2
  return p
}

/**
 * Derive `count` deterministic decoy keys from a stable seed.
 *
 * `decoy_i = bytesToHex(sha256(hexToBytes(decoySeedHex) || LE32(i)))` for
 * i in [0, count). Same `(decoySeedHex, count)` ⇒ identical decoys, and the
 * first k of a longer run are a prefix of the longer run — so a build that needs
 * more decoys next epoch reuses the same leading decoys (stability across bucket
 * growth within a fixed seed).
 *
 * `decoySeedHex` MUST be non-empty, even-length hex (audit fix, L4): an empty
 * seed previously produced PUBLIC, PREDICTABLE decoys (`hexToBytes('')` is a
 * silently-valid zero-length seed), and an odd-length/non-hex seed leaked a raw
 * `RangeError` from `@noble/hashes` rather than a kit-shaped error. This
 * function is a public export (`.` barrel and `./padding` internal), reachable
 * directly by a caller who bypasses `buildMembershipFilter` — so it validates
 * on its own rather than relying on `filter.ts`'s `assertDecoySeedHex` (which
 * additionally enforces a >=16-byte minimum for the build path specifically;
 * that stronger minimum is NOT re-imposed here, since `deriveDecoys` itself has
 * no such requirement — only "not empty, well-formed hex").
 *
 * @param decoySeedHex  Even-length, non-empty hex seed (a per-context secret the caller holds).
 * @param count         Number of decoys to derive (≥ 0).
 */
export function deriveDecoys(decoySeedHex: string, count: number): string[] {
  if (
    typeof decoySeedHex !== 'string' ||
    decoySeedHex.length === 0 ||
    !/^[0-9a-f]*$/i.test(decoySeedHex) ||
    decoySeedHex.length % 2 !== 0
  ) {
    throw new TesseraError(
      'INPUT_DECOY_SEED_HEX_INVALID',
      'deriveDecoys: decoySeedHex must be non-empty, even-length hex',
    )
  }
  // Follow-up review fix — `count` previously reached `new Array(count)`
  // unguarded: `new Array(NaN)` throws a raw RangeError ("Invalid array
  // length"), and a non-number `count` (e.g. a string) does NOT trigger
  // `Array`'s length-setting special case, so it silently returned a
  // 1-element array containing that value instead of `count` decoys — a
  // corrupt, mis-typed "valid return" that's worse than a throw.
  if (typeof count !== 'number' || !Number.isSafeInteger(count)) {
    throw new TesseraError('INPUT_DECOY_COUNT_INVALID', 'deriveDecoys: count must be a safe integer')
  }
  if (count <= 0) return []
  const seedBytes = hexToBytes(decoySeedHex.toLowerCase())
  const out: string[] = new Array(count)
  for (let i = 0; i < count; i++) {
    out[i] = bytesToHex(sha256(concatBytes(seedBytes, le32(i))))
  }
  return out
}

/** 4-byte little-endian encoding of a non-negative 32-bit integer. */
function le32(i: number): Uint8Array {
  const b = new Uint8Array(4)
  // Manual LE write — avoids a DataView allocation in the decoy loop.
  b[0] = i & 0xff
  b[1] = (i >>> 8) & 0xff
  b[2] = (i >>> 16) & 0xff
  b[3] = (i >>> 24) & 0xff
  return b
}

/**
 * Pad a deduped member set up to `targetSize` with decoys, keeping the result a
 * true set (no decoy equal to a real member or to another decoy).
 *
 * The returned array is `[...dedupedMembers, ...decoys]` — members first in their
 * given order, decoys appended in derivation order. This ordering is deterministic
 * for the STABLE case, which is what makes the serialized blob byte-identical
 * across rebuilds.
 *
 * Collision handling: a generated decoy that collides with a real member or a
 * prior decoy is SKIPPED and the next index is tried, so the set never shrinks
 * and a real member can never be displaced (it was inserted before any decoy and
 * stays in the output). With sha256/CSPRNG output over a 256-bit space, a
 * collision is astronomically unlikely in normal use — the skip path exists for
 * correctness (and is exercised when a caller deliberately seeds members that
 * match the decoy stream).
 *
 * @param dedupedMembers  Already-deduplicated member keys (first-seen order).
 * @param targetSize      Desired total set size (= nextPowerOfTwoBand(count)).
 * @param decoySeedHex    When set → STABLE decoys via `deriveDecoys`. When
 *                        undefined → UNSTABLE CSPRNG-random decoys (see module
 *                        note: churn becomes diffable across epochs). Never throws,
 *                        never logs in the unstable case.
 * @returns The padded member array (length === targetSize when targetSize ≥
 *          dedupedMembers.length; otherwise the unchanged members).
 */
export function padMembersToBucket(
  dedupedMembers: string[],
  targetSize: number,
  decoySeedHex?: string,
): string[] {
  const need = targetSize - dedupedMembers.length
  if (need <= 0) return dedupedMembers.slice()

  // Track the full set so decoys stay distinct from members AND each other.
  const used = new Set(dedupedMembers)
  const padded = dedupedMembers.slice()

  if (decoySeedHex !== undefined) {
    // STABLE path: walk the deterministic decoy stream by index. Over-derive a
    // little headroom each batch so the rare skip (collision) doesn't fall short;
    // re-derive from the current index forward until we've added `need` decoys.
    const seedLower = decoySeedHex.toLowerCase()
    let index = 0
    while (padded.length < targetSize) {
      const remaining = targetSize - padded.length
      // Derive a batch starting at `index`; +8 headroom absorbs skips.
      const batch = deriveDecoys(seedLower, index + remaining + 8)
      for (let i = index; i < batch.length && padded.length < targetSize; i++) {
        const d = batch[i] as string
        if (!used.has(d)) {
          used.add(d)
          padded.push(d)
        }
      }
      index = batch.length
    }
  } else {
    // UNSTABLE path: CSPRNG-random decoys. Allowed, but churn is diffable across
    // epochs (module note). No throw, no log.
    while (padded.length < targetSize) {
      const d = bytesToHex(randomBytes(32))
      if (!used.has(d)) {
        used.add(d)
        padded.push(d)
      }
    }
  }

  return padded
}
