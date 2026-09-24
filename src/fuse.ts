// Binary Fuse 16 filter — clean-room TypeScript port of Graf & Lemire (2022),
// "Binary Fuse Filters: Fast and Smaller Than Xor Filters".
// Reference C: Lemire `binaryfusefilter.h`, `binary_fuse16_t`.
//
// All 64-bit arithmetic is done with BigInt and masked to 64 bits after every
// add/multiply/shift that could overflow (`& MASK64`). `Number(...)` is used
// only when converting a value already known to fit a 32-bit array index.
//
// SEED WIDTH (load-bearing reconciliation with the KFLT codec, TK-4):
// the on-wire KFLT header reserves a 4-byte seed field and must stay exactly
// 128 bytes, so the retry seed is a 32-bit value (`seed ∈ [0, 2^32)`), advanced
// by a 32-bit Weyl step between attempts. Inside `mix()` the 32-bit seed is
// zero-extended to 64 bits. Construction needs ~1–3 attempts in practice, so a
// 2^32 seed space is far more than enough.
//
// This module is filter-only: it operates on `string[]` of hex member keys and
// knows nothing about relationships, personas, salts, or Nostr events.

import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { TesseraError } from './errors.js'

const MASK64 = (1n << 64n) - 1n

const ARITY = 3
const MAX_ATTEMPTS = 100
const SEGMENT_LENGTH_CAP = 1 << 18

/** Map a hex member key → a uniform 64-bit BigInt via sha256, big-endian first 8 bytes. */
function keyToU64(hex: string): bigint {
  const h = sha256(hexToBytes(hex))
  let v = 0n
  for (let i = 0; i < 8; i++) {
    // h has length 32; indices 0..7 are always present.
    v = (v << 8n) | BigInt(h[i] as number)
  }
  return v & MASK64
}

/** murmur64-style finalizer, then add the (zero-extended 32-bit) seed first. */
function mix(k64: bigint, seed32: number): bigint {
  let h = (k64 + BigInt(seed32 >>> 0)) & MASK64
  h ^= h >> 33n
  h = (h * 0xff51afd7ed558ccdn) & MASK64
  h ^= h >> 33n
  h = (h * 0xc4ceb9fe1a85ec53n) & MASK64
  h ^= h >> 33n
  return h & MASK64
}

/** 16-bit fingerprint of a 64-bit mixed hash. */
function fingerprint16(h: bigint): number {
  return Number((h ^ (h >> 32n)) & 0xffffn)
}

/** Advance a 32-bit seed by the golden-ratio Weyl increment (keeps seed in [0, 2^32)). */
function next32(seed: number): number {
  return (seed + 0x9e3779b9) >>> 0
}

/** Sizing parameters derived from the input count `n` (arity = 3). */
interface FuseGeometry {
  segmentLength: number
  segmentLengthMask: number
  segmentCount: number
  segmentCountLength: number
  arrayLength: number
}

function computeGeometry(n: number): FuseGeometry {
  let segmentLength =
    n === 0 ? 4 : 1 << Math.floor(Math.log(n) / Math.log(3.33) + 2.25)
  if (segmentLength > SEGMENT_LENGTH_CAP) segmentLength = SEGMENT_LENGTH_CAP
  if (segmentLength < 4) segmentLength = 4

  const sizeFactor =
    n <= 1 ? 0 : Math.max(1.125, 0.875 + (0.25 * Math.log(1_000_000)) / Math.log(n))
  const capacity = n <= 1 ? 0 : Math.round(n * sizeFactor)

  const initSegmentCount =
    Math.floor((capacity + segmentLength - 1) / segmentLength) - (ARITY - 1)
  let arrayLength = (initSegmentCount + ARITY - 1) * segmentLength

  let segmentCount =
    Math.floor((arrayLength + segmentLength - 1) / segmentLength) - (ARITY - 1)
  if (segmentCount < 1) segmentCount = 1
  arrayLength = (segmentCount + ARITY - 1) * segmentLength

  // Degenerate-n guard: ensure room for arity * segmentLength even when the
  // formulas above produced something smaller (n = 0,1,2,3).
  const minArray = segmentLength * ARITY
  if (arrayLength < minArray) {
    arrayLength = minArray
    segmentCount =
      Math.floor((arrayLength + segmentLength - 1) / segmentLength) - (ARITY - 1)
    if (segmentCount < 1) segmentCount = 1
    arrayLength = (segmentCount + ARITY - 1) * segmentLength
  }

  const segmentCountLength = segmentCount * segmentLength
  const segmentLengthMask = segmentLength - 1
  return { segmentLength, segmentLengthMask, segmentCount, segmentCountLength, arrayLength }
}

export class BinaryFuse16 {
  readonly seed: number
  readonly segmentLength: number
  readonly segmentLengthMask: number
  readonly segmentCount: number
  readonly segmentCountLength: number
  readonly arrayLength: number
  readonly fingerprints: Uint16Array

  private constructor(g: {
    seed: number
    segmentLength: number
    segmentLengthMask: number
    segmentCount: number
    segmentCountLength: number
    arrayLength: number
    fingerprints: Uint16Array
  }) {
    this.seed = g.seed >>> 0
    this.segmentLength = g.segmentLength
    this.segmentLengthMask = g.segmentLengthMask
    this.segmentCount = g.segmentCount
    this.segmentCountLength = g.segmentCountLength
    this.arrayLength = g.arrayLength
    this.fingerprints = g.fingerprints
  }

  /** Return the three slot indices (h0,h1,h2) for a mixed hash `h`. */
  private static hashToSlots(
    h: bigint,
    geom: FuseGeometry,
  ): [number, number, number] {
    const hi = (h * BigInt(geom.segmentCountLength)) >> 64n // ∈ [0, segmentCountLength)
    const h0 = Number(hi)
    let h1 = h0 + geom.segmentLength
    let h2 = h1 + geom.segmentLength
    h1 ^= Number((h >> 18n) & BigInt(geom.segmentLengthMask))
    h2 ^= Number(h & BigInt(geom.segmentLengthMask))
    return [h0, h1, h2]
  }

  /** Build a Binary Fuse 16 filter over the given (distinct) hex member keys.
   *  Throws if peeling fails to converge within MAX_ATTEMPTS seeded attempts.
   *  Callers SHOULD de-duplicate key STRINGS first (`buildMembershipFilter`
   *  does) — but see the HASH-level dedup below, which this function performs
   *  regardless, since a string-level dedup alone is not enough (audit fix M1). */
  static build(memberKeys: string[]): BinaryFuse16 {
    const rawN = memberKeys.length

    // Precompute the 64-bit key hashes once (independent of seed input).
    const rawHashes = new BigUint64Array(rawN)
    for (let i = 0; i < rawN; i++) {
      rawHashes[i] = keyToU64(memberKeys[i] as string)
    }

    // De-duplicate by 64-bit HASH, not by key string (audit fix M1). Two
    // distinct member keys can collide on `keyToU64` (sha256-derived; ~2^-64
    // per pair by chance, but findable by a targeted birthday search over
    // ~2^32 attempts — see review.md M1, and `coll.mjs` in the audit
    // scratchpad, which demonstrates the attack against a truncated-hash
    // stand-in). A colliding pair lands in the SAME three slots on every seed
    // (the slots are a pure function of the hash), so every count at those
    // slots stays >= 2 forever and peeling never converges — `build()` throws
    // on every call once such a pair is present in the input, for as long as
    // both keys remain. The Lemire reference C removes duplicate raw keys
    // before `populate()` for exactly this reason
    // (`binary_fuse_sort_and_remove_dup` in the upstream `hashing.h`); this
    // port did not, until now.
    //
    // Dropping the duplicate here is SAFE and changes nothing observable:
    // `contains()` is a pure function of `keyToU64(key)` — it re-derives the
    // same hash, same slots, same fingerprint check for either original key —
    // so inserting the hash a second time would add no information, and both
    // colliding keys still test `true` after only one insertion.
    //
    // Ordering (and therefore the golden vector) is UNCHANGED in the common
    // case: a `Set`-based dedup preserves first-seen order, so when there are
    // no collisions (the overwhelmingly common case) `keyHashes` is identical
    // to `rawHashes` and this is a no-op.
    const seenHashes = new Set<bigint>()
    const dedupedHashes: bigint[] = []
    for (let i = 0; i < rawN; i++) {
      const h = rawHashes[i] as bigint
      if (!seenHashes.has(h)) {
        seenHashes.add(h)
        dedupedHashes.push(h)
      }
    }
    const n = dedupedHashes.length
    const keyHashes = BigUint64Array.from(dedupedHashes)

    const geom = computeGeometry(n)
    const { segmentLength, arrayLength } = geom

    // Construction scratch.
    const t2count = new Uint8Array(arrayLength)
    const t2hash = new BigUint64Array(arrayLength)
    const reverseOrder = new BigUint64Array(n)
    const reverseH = new Uint8Array(n)
    // Stable, integer-typed queue of "alone" slot indices.
    const queue = new Int32Array(arrayLength)

    let seed = 0x66666b6c >>> 0 // "lkff" little — fixed deterministic start
    let stacksize = 0

    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      t2count.fill(0)
      t2hash.fill(0n)
      stacksize = 0

      // Hash every key into its three slots.
      for (let i = 0; i < n; i++) {
        const hash = mix(keyHashes[i] as bigint, seed)
        const [h0, h1, h2] = BinaryFuse16.hashToSlots(hash, geom)
        t2count[h0] = ((t2count[h0] as number) + 1) & 0xff
        t2hash[h0] = (t2hash[h0] as bigint) ^ hash
        t2count[h1] = ((t2count[h1] as number) + 1) & 0xff
        t2hash[h1] = (t2hash[h1] as bigint) ^ hash
        t2count[h2] = ((t2count[h2] as number) + 1) & 0xff
        t2hash[h2] = (t2hash[h2] as bigint) ^ hash
      }

      // Seed the queue with every slot that currently holds exactly one key.
      let qlen = 0
      for (let p = 0; p < arrayLength; p++) {
        if ((t2count[p] as number) === 1) {
          queue[qlen++] = p
        }
      }

      // Peel.
      while (qlen > 0) {
        const p = queue[--qlen] as number
        if ((t2count[p] as number) !== 1) continue // count changed since enqueue
        const hash = t2hash[p] as bigint
        const [h0, h1, h2] = BinaryFuse16.hashToSlots(hash, geom)
        const found = h0 === p ? 0 : h1 === p ? 1 : 2

        reverseOrder[stacksize] = hash
        reverseH[stacksize] = found
        stacksize++

        // Remove this hash from all three of its slots; re-enqueue any that
        // become "alone".
        const slots: [number, number, number] = [h0, h1, h2]
        for (let j = 0; j < ARITY; j++) {
          const q = slots[j] as number
          const c = ((t2count[q] as number) - 1) & 0xff
          t2count[q] = c
          t2hash[q] = (t2hash[q] as bigint) ^ hash
          if (c === 1) queue[qlen++] = q
        }
      }

      if (stacksize === n) break // SUCCESS
      seed = next32(seed) // retry with a fresh 32-bit seed
    }

    if (stacksize !== n) {
      throw new TesseraError('BUILD_FUSE_CONSTRUCTION_FAILED', 'fuse: construction failed to converge')
    }

    // Assign fingerprints in REVERSE peel order. For each peeled hash, the slot
    // it "owns" (reverseH) gets fingerprint16(hash) XOR the fingerprints of the
    // other two slots (which are already assigned by the time we reach it).
    const fingerprints = new Uint16Array(arrayLength) // 0-init
    for (let i = n - 1; i >= 0; i--) {
      const hash = reverseOrder[i] as bigint
      const found = reverseH[i] as number
      const slots = BinaryFuse16.hashToSlots(hash, geom)
      let fp = fingerprint16(hash)
      let slot = -1
      for (let j = 0; j < ARITY; j++) {
        const q = slots[j] as number
        if (j === found) {
          slot = q
        } else {
          fp ^= fingerprints[q] as number
        }
      }
      fingerprints[slot] = fp & 0xffff
    }

    return new BinaryFuse16({
      seed,
      segmentLength: geom.segmentLength,
      segmentLengthMask: geom.segmentLengthMask,
      segmentCount: geom.segmentCount,
      segmentCountLength: geom.segmentCountLength,
      arrayLength,
      fingerprints,
    })
  }

  /** Membership query. False negatives are impossible after a successful build;
   *  false positives occur at ≈ 2^-16. */
  contains(memberKey: string): boolean {
    const hash = mix(keyToU64(memberKey), this.seed)
    const f = fingerprint16(hash)
    const [h0, h1, h2] = BinaryFuse16.hashToSlots(hash, this)
    const stored =
      (this.fingerprints[h0] as number) ^
      (this.fingerprints[h1] as number) ^
      (this.fingerprints[h2] as number)
    return f === stored
  }

  /** Reconstruct a filter from its serialized parts (used by the KFLT codec).
   *  Recomputes the geometry-derived fields from segmentLength/segmentCount. */
  static fromParts(p: {
    seed: number
    segmentLength: number
    segmentCount: number
    fingerprints: Uint16Array
  }): BinaryFuse16 {
    const segmentLength = p.segmentLength
    const segmentCount = p.segmentCount
    const segmentLengthMask = segmentLength - 1
    const segmentCountLength = segmentCount * segmentLength
    const arrayLength = (segmentCount + ARITY - 1) * segmentLength
    return new BinaryFuse16({
      seed: p.seed >>> 0,
      segmentLength,
      segmentLengthMask,
      segmentCount,
      segmentCountLength,
      arrayLength,
      fingerprints: p.fingerprints,
    })
  }
}
