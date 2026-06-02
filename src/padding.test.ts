import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { nextPowerOfTwoBand, deriveDecoys } from './padding.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { serializeFilter } from './codec.js'
import { memberKey } from './member-key.js'

// Deterministic distinct 64-hex pubkeys (same style as filter.test.ts).
const pubkeys = (n: number, tag = 7): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )

const EPOCH = 1_700_000_000
// 64 lowercase hex chars → valid even-length hex seed (`'aa..'` per spec).
const SEED = 'aa'.repeat(32)
const SEED2 = 'bb'.repeat(32)

const HEX64 = /^[0-9a-f]{64}$/

describe('nextPowerOfTwoBand', () => {
  it('rounds up to the smallest power of two >= n', () => {
    expect(nextPowerOfTwoBand(0)).toBe(1)
    expect(nextPowerOfTwoBand(1)).toBe(1)
    expect(nextPowerOfTwoBand(2)).toBe(2)
    expect(nextPowerOfTwoBand(3)).toBe(4)
    expect(nextPowerOfTwoBand(5)).toBe(8)
    expect(nextPowerOfTwoBand(1000)).toBe(1024)
    expect(nextPowerOfTwoBand(1024)).toBe(1024)
    expect(nextPowerOfTwoBand(1025)).toBe(2048)
  })
})

describe('deriveDecoys', () => {
  it('returns `count` distinct 64-hex strings', () => {
    const k = 10
    const decoys = deriveDecoys(SEED, k)
    expect(decoys).toHaveLength(k)
    for (const d of decoys) expect(d).toMatch(HEX64)
    expect(new Set(decoys).size).toBe(k) // all distinct
  })

  it('count 0 yields an empty array', () => {
    expect(deriveDecoys(SEED, 0)).toEqual([])
  })

  it('is deterministic: same (seed, count) ⇒ identical array', () => {
    expect(deriveDecoys(SEED, 7)).toEqual(deriveDecoys(SEED, 7))
  })

  it('is seed-sensitive: different seed ⇒ different decoys', () => {
    expect(deriveDecoys(SEED, 7)).not.toEqual(deriveDecoys(SEED2, 7))
  })

  it('is count-sensitive as a stable prefix: first k of a longer run are a prefix', () => {
    const five = deriveDecoys(SEED, 5)
    const three = deriveDecoys(SEED, 3)
    expect(three).toEqual(five.slice(0, 3))
  })

  it('matches the documented construction sha256(seedBytes || LE32(i))', () => {
    // Hand-compute decoy_0 and decoy_1 to pin the byte construction.
    const seedBytes = Uint8Array.from(
      SEED.match(/../g)!.map((h) => parseInt(h, 16)),
    )
    const expected = (i: number): string => {
      const le = new Uint8Array(4)
      new DataView(le.buffer).setUint32(0, i, true) // LE32
      const msg = new Uint8Array(seedBytes.length + 4)
      msg.set(seedBytes, 0)
      msg.set(le, seedBytes.length)
      return bytesToHex(sha256(msg))
    }
    const decoys = deriveDecoys(SEED, 3)
    expect(decoys[0]).toBe(expected(0))
    expect(decoys[1]).toBe(expected(1))
    expect(decoys[2]).toBe(expected(2))
  })
})

describe('padded build — stable (decoySeedHex provided)', () => {
  it('pads 5 members to the bucket: band=8, padded flag set, all members present', () => {
    const real = pubkeys(5, 21).map((pk) => memberKey(pk))
    const f = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })

    for (const k of real) expect(testMembership(f, k)).toBe(true)
    expect(f._padded).toBe(true)
    expect(f._memberCountBand).toBe(8) // band = TRUE count's bucket (5 → 8)
  })

  it('builds the fuse over the bucket count (8), not the true count (5)', () => {
    // The padded fuse must have the SAME geometry as an honest build over the
    // bucket-many distinct keys — proving the decoys were actually inserted.
    const real = pubkeys(5, 22).map((pk) => memberKey(pk))
    const padded = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })
    // Honest 8-distinct-key build for geometry reference.
    const eight = buildMembershipFilter(pubkeys(8, 99).map((pk) => memberKey(pk)), {
      epoch: EPOCH,
      padToBucket: false,
    })
    expect(padded._fuse.arrayLength).toBe(eight._fuse.arrayLength)
    expect(padded._fuse.segmentLength).toBe(eight._fuse.segmentLength)
    expect(padded._fuse.segmentCount).toBe(eight._fuse.segmentCount)
  })

  it('is byte-stable: rebuild with same inputs+seed ⇒ identical serialized blob', () => {
    const real = pubkeys(5, 23).map((pk) => memberKey(pk))
    const a = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })
    const b = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })
    const ba = serializeFilter(a)
    const bb = serializeFilter(b)
    expect(ba).toEqual(bb)
    // Sanity: this is a real, non-trivial blob (header + fingerprint array).
    expect(ba.length).toBeGreaterThan(128)
  })

  it('padding is observable at a scale where the bucket changes fuse geometry', () => {
    // n=17 → band 32. Honest unpadded(17) and padded(17→32) have DIFFERENT
    // array sizes (probed: 48 vs 96), so the on-wire size is bucket-quantized.
    const real = pubkeys(17, 24).map((pk) => memberKey(pk))
    const padded = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })
    const unpadded = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: false,
    })
    expect(padded._memberCountBand).toBe(32)
    expect(padded._padded).toBe(true)
    expect(unpadded._padded).toBe(false)
    // Padded array is larger than the honest array for this count — the size
    // now reveals only the bucket (32), not 17.
    expect(padded._fuse.arrayLength).toBeGreaterThan(unpadded._fuse.arrayLength)
    for (const k of real) expect(testMembership(padded, k)).toBe(true)
  })
})

describe('padded build — unstable (no decoySeedHex)', () => {
  it('still pads to the bucket, members present, padded flag set', () => {
    const real = pubkeys(5, 25).map((pk) => memberKey(pk))
    const f = buildMembershipFilter(real, { epoch: EPOCH, padToBucket: true })
    for (const k of real) expect(testMembership(f, k)).toBe(true)
    expect(f._padded).toBe(true)
    expect(f._memberCountBand).toBe(8)
  })

  it('does not throw and produces a usable filter without a seed', () => {
    const real = pubkeys(17, 26).map((pk) => memberKey(pk))
    expect(() =>
      buildMembershipFilter(real, { epoch: EPOCH, padToBucket: true }),
    ).not.toThrow()
  })

  it('two unstable builds MAY differ (no equality assertion — just that both are valid)', () => {
    const real = pubkeys(17, 27).map((pk) => memberKey(pk))
    const a = buildMembershipFilter(real, { epoch: EPOCH, padToBucket: true })
    const b = buildMembershipFilter(real, { epoch: EPOCH, padToBucket: true })
    // Both must have every real member; we deliberately do NOT assert blob equality.
    for (const k of real) {
      expect(testMembership(a, k)).toBe(true)
      expect(testMembership(b, k)).toBe(true)
    }
    expect(a._memberCountBand).toBe(32)
    expect(b._memberCountBand).toBe(32)
  })
})

describe('unpadded build (padToBucket:false)', () => {
  it('does not pad, no padded flag, members present', () => {
    const real = pubkeys(5, 28).map((pk) => memberKey(pk))
    const f = buildMembershipFilter(real, { epoch: EPOCH, padToBucket: false })
    for (const k of real) expect(testMembership(f, k)).toBe(true)
    expect(f._padded).toBe(false)
    expect(f._memberCountBand).toBe(8)
  })
})

describe('band reflects TRUE count even when padded', () => {
  it('5 real → band 8; 9 real → band 16 (padded)', () => {
    const five = buildMembershipFilter(
      pubkeys(5, 29).map((pk) => memberKey(pk)),
      { epoch: EPOCH, padToBucket: true, decoySeedHex: SEED },
    )
    expect(five._memberCountBand).toBe(8)

    const nine = buildMembershipFilter(
      pubkeys(9, 30).map((pk) => memberKey(pk)),
      { epoch: EPOCH, padToBucket: true, decoySeedHex: SEED },
    )
    expect(nine._memberCountBand).toBe(16)
  })
})

describe('real members are never excluded by a decoy collision', () => {
  it('builds with decoy-shaped members; every real member still tests true', () => {
    // Construct a member set that INCLUDES the very decoys this seed would
    // generate, forcing the decoy generator to skip-and-advance to keep the set
    // a true set. All real members must survive.
    const wouldBeDecoys = deriveDecoys(SEED, 20) // some of these would collide
    const realPks = pubkeys(3, 31).map((pk) => memberKey(pk))
    const real = [...realPks, ...wouldBeDecoys.slice(0, 3)] // 6 real, 3 decoy-shaped
    const f = buildMembershipFilter(real, {
      epoch: EPOCH,
      padToBucket: true,
      decoySeedHex: SEED,
    })
    for (const k of real) expect(testMembership(f, k)).toBe(true)
    // 6 distinct real → band 8.
    expect(f._memberCountBand).toBe(8)
    expect(f._padded).toBe(true)
  })
})
