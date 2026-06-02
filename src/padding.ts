// Size-bucket padding + decoy pool (spec §7.5).
//
// WHAT THIS BUYS (and what it does NOT):
//   A published filter's on-wire array size is a function of the number of keys
//   inserted. Without padding, that size leaks the *fine* member count. Padding
//   rounds the inserted-key count up to the next power-of-two bucket by adding
//   DECOY keys, so the serialized size reveals only the coarse bucket.
//   `_memberCountBand` still records the TRUE count's bucket — that coarse count
//   "leaks by design" (spec §7.5); padding hides only the fine count.
//
// DECOY STABILITY (the load-bearing privacy property):
//   Decoys MUST be STABLE across rebuilds within the same context+bucket. If the
//   decoy set changes every epoch, an attacker who collects two published blobs
//   can diff their array contents: the keys that stay are decoys, the keys that
//   churn are real members joining/leaving. A STABLE decoy set (derived from a
//   fixed `decoySeedHex`) defeats this version-diffing attack — the padding bytes
//   are identical across rebuilds, so only genuine membership changes show up.
//
//   tessera-kit has no notion of a serverId, so it cannot derive the seed itself.
//   The caller supplies `decoySeedHex` (e.g. a per-server secret). Padding WITHOUT
//   a seed is allowed (CSPRNG-random decoys) but is the UNSTABLE case: an attacker
//   CAN track churn by diffing array contents across epochs. This module never
//   logs and never throws on the unstable path — the instability is a documented
//   trade-off the caller opts into by omitting the seed.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js'

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
 * @param decoySeedHex  Even-length hex seed (a per-context secret the caller holds).
 * @param count         Number of decoys to derive (≥ 0).
 */
export function deriveDecoys(decoySeedHex: string, count: number): string[] {
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
