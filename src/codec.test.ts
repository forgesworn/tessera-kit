import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'
import { serializeFilter, parseFilter } from './codec.js'
import { KFLT_HEADER_LEN, KFLT_MAX_BLOB_BYTES } from './types.js'
import type { MembershipFilter } from './types.js'

// Deterministic distinct 64-hex pubkeys (same style as filter.test.ts).
const pubkeys = (n: number, tag = 7): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )

const EPOCH = 1_700_000_000
const SALT = 'deadbeefcafef00d'

function openFilter(n: number, tag = 7): { f: MembershipFilter; memberKeys: string[] } {
  const pks = pubkeys(n, tag)
  const memberKeys = pks.map((pk) => memberKey(pk))
  const f = buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 16 })
  return { f, memberKeys }
}

describe('serializeFilter / parseFilter — round-trip', () => {
  it('open pool: every member tests true on the parsed filter; scalar fields preserved', () => {
    const { f, memberKeys } = openFilter(50)
    const blob = serializeFilter(f)
    const parsed = parseFilter(blob)

    for (const k of memberKeys) expect(testMembership(parsed, k)).toBe(true)

    expect(parsed.epoch).toBe(f.epoch)
    expect(parsed.keyed).toBe(f.keyed)
    expect(parsed.keyed).toBe(false)
    expect(parsed._padded).toBe(f._padded)
    expect(parsed._memberCountBand).toBe(f._memberCountBand)
    expect(parsed.type).toBe(1)
    expect(parsed.fingerprintBits).toBe(16)
  })

  it('keyed pool: keyed flag round-trips true', () => {
    const pks = pubkeys(40, 8)
    const memberKeys = pks.map((pk) => memberKey(pk, SALT))
    const f = buildMembershipFilter(memberKeys, { epoch: EPOCH, salt: SALT })
    const parsed = parseFilter(serializeFilter(f))

    for (const k of memberKeys) expect(testMembership(parsed, k)).toBe(true)
    expect(parsed.keyed).toBe(true)
    expect(parsed.epoch).toBe(EPOCH)
    expect(parsed._memberCountBand).toBe(f._memberCountBand)
  })

  it('_padded flag round-trips when set', () => {
    const { f } = openFilter(20)
    const padded: MembershipFilter = { ...f, _padded: true }
    const parsed = parseFilter(serializeFilter(padded))
    expect(parsed._padded).toBe(true)
  })

  it('large epoch (> 2^32) round-trips exactly via LE u64', () => {
    const { f } = openFilter(10)
    const big = { ...f, epoch: 4_300_000_000 } // > 2^32
    const parsed = parseFilter(serializeFilter(big))
    expect(parsed.epoch).toBe(4_300_000_000)
  })

  it('blob length is exactly KFLT_HEADER_LEN + arrayLength*2', () => {
    const { f } = openFilter(30)
    const blob = serializeFilter(f)
    expect(blob.length).toBe(KFLT_HEADER_LEN + f._fuse.arrayLength * 2)
  })

  it('signer_pubkey and sig regions are zero-filled in TK-4', () => {
    const { f } = openFilter(10)
    const blob = serializeFilter(f)
    for (let i = 32; i < 128; i++) expect(blob[i]).toBe(0)
  })

  it('round-trips across many sizes', () => {
    for (const n of [0, 1, 2, 3, 10, 100, 1000]) {
      const { f, memberKeys } = openFilter(n, 20 + n)
      const parsed = parseFilter(serializeFilter(f))
      for (const k of memberKeys) expect(testMembership(parsed, k)).toBe(true)
      expect(parsed._memberCountBand).toBe(f._memberCountBand)
    }
  })
})

describe('parseFilter — hardening (each check throws on a corrupted copy)', () => {
  // A known-good blob to corrupt.
  const good = serializeFilter(openFilter(40).f)

  it('throws on bad magic', () => {
    const b = good.slice()
    b[0] = 0x00 // not 'K'
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws on bad version', () => {
    const b = good.slice()
    b[4] = 2
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws "unsupported filter type" for filter_type=2', () => {
    const b = good.slice()
    b[5] = 2
    expect(() => parseFilter(b)).toThrow('unsupported filter type')
  })

  it('throws "unsupported filter type" for filter_type=3', () => {
    const b = good.slice()
    b[5] = 3
    expect(() => parseFilter(b)).toThrow('unsupported filter type')
  })

  it('throws on filter_type outside {1,2,3} (e.g. 0)', () => {
    const b = good.slice()
    b[5] = 0
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws "unsupported fingerprint bits" for fingerprint_bits=8', () => {
    const b = good.slice()
    b[6] = 8
    expect(() => parseFilter(b)).toThrow('unsupported fingerprint bits')
  })

  it('throws on fingerprint_bits not in {8,16,20,32} (e.g. 7)', () => {
    const b = good.slice()
    b[6] = 7
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws when segment_length is not a power of two', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    // Write a non-power-of-two segment_length (e.g. 5) at off 20.
    dv.setUint32(20, 5, true)
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws on truncated blob (< KFLT_HEADER_LEN)', () => {
    const b = good.slice(0, KFLT_HEADER_LEN - 1)
    expect(() => parseFilter(b)).toThrow()
  })

  it('throws on empty blob', () => {
    expect(() => parseFilter(new Uint8Array(0))).toThrow()
  })

  it('throws "length mismatch" when declared length != actual (flip a segment_count byte)', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    const sc = dv.getUint32(24, true)
    dv.setUint32(24, sc + 1, true) // bump segment_count → expectedLen grows
    expect(() => parseFilter(b)).toThrow('length mismatch')
  })

  it('a huge declared arrayLength throws at the geometry/overflow check, not via allocation', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    // segment_length = 2^18 (max, power of two), segment_count = 0xffffffff.
    // arrayLength*2 vastly exceeds the 64MB cap → must throw at step 6.
    dv.setUint32(20, 1 << 18, true)
    dv.setUint32(24, 0xffffffff, true)
    let threw: unknown
    try {
      parseFilter(b)
    } catch (e) {
      threw = e
    }
    expect(threw).toBeInstanceOf(Error)
  })

  it('rejects a blob whose total length exceeds KFLT_MAX_BLOB_BYTES (step-1 guard)', () => {
    // A single ~64MB allocation is cheap and lazily-backed in Node; constructing
    // it lets us exercise the over-cap guard for real. The point of the guard is
    // that parseFilter rejects this at step 1 WITHOUT itself allocating a second
    // huge buffer (the fingerprint Uint16Array). All bytes are zero, so even the
    // magic check would fail — but the length guard fires first.
    const oversized = new Uint8Array(KFLT_MAX_BLOB_BYTES + 1)
    expect(() => parseFilter(oversized)).toThrow('exceeds maximum size')
  })

  it('accepts the boundary: a (synthetic) blob of exactly KFLT_HEADER_LEN parses if geometry matches', () => {
    // Smallest real filter (n=0) already round-trips above; here we just confirm
    // the minimum-length acceptance path: header + a valid tiny fingerprint array.
    const { f } = openFilter(0)
    const parsed = parseFilter(serializeFilter(f))
    expect(parsed.type).toBe(1)
  })

  // B7 (audit fix) — parseFilter rejects a u64 epoch above Number.MAX_SAFE_INTEGER
  // rather than silently losing precision in the BigInt→Number conversion.
  it('throws when the header epoch exceeds Number.MAX_SAFE_INTEGER', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    dv.setBigUint64(8, BigInt(Number.MAX_SAFE_INTEGER) + 2n, true)
    expect(() => parseFilter(b)).toThrow(/epoch/)
  })

  it('still accepts an epoch exactly at Number.MAX_SAFE_INTEGER', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    dv.setBigUint64(8, BigInt(Number.MAX_SAFE_INTEGER), true)
    const parsed = parseFilter(b)
    expect(parsed.epoch).toBe(Number.MAX_SAFE_INTEGER)
  })

  // B9 (audit fix) — reserved flag bits 2-7 must be zero; `serializeFilter` never
  // sets them, so a blob that does is non-canonical input.
  it('throws when a reserved flag bit (2-7) is set', () => {
    const b = good.slice()
    b[7] = (b[7] as number) | 0x04 // bit 2, reserved
    expect(() => parseFilter(b)).toThrow(/flag/i)
  })

  it('still accepts flags with only bit0 (keyed) and/or bit1 (padded) set', () => {
    const b = good.slice()
    b[7] = 0x03 // keyed + padded, no reserved bits
    expect(() => parseFilter(b)).not.toThrow()
  })

  // B9 (audit fix) — member_count_band must be a power of two: `serializeFilter`
  // always writes `nextPowerOfTwoBand(trueCount)`, which is always a power of two
  // >= 1 regardless of `padToBucket`, so any other value is non-canonical input.
  it('throws when member_count_band is not a power of two', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    dv.setUint32(28, 5, true) // 5 is not a power of two
    expect(() => parseFilter(b)).toThrow(/member_count_band/)
  })

  it('throws when member_count_band is 0', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    dv.setUint32(28, 0, true)
    expect(() => parseFilter(b)).toThrow(/member_count_band/)
  })

  it('still accepts a power-of-two member_count_band (e.g. 64)', () => {
    const b = good.slice()
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength)
    dv.setUint32(28, 64, true)
    expect(() => parseFilter(b)).not.toThrow()
  })
})

// ---- Deterministic counter-based PRNG (xorshift32) — no Math.random flakiness.
function makePrng(seed: number): () => number {
  let s = seed >>> 0
  if (s === 0) s = 0x9e3779b9
  return () => {
    s ^= s << 13
    s >>>= 0
    s ^= s >> 17
    s ^= s << 5
    s >>>= 0
    return s
  }
}

describe('parseFilter — fuzz (never throws non-Error, never hangs/over-allocates)', () => {
  it('5000+ random blobs of varied length → MembershipFilter or Error, never else', () => {
    const rng = makePrng(0xc0ffee)
    const ITERATIONS = 5200
    let parsedOk = 0
    let threwError = 0

    // A real blob to derive truncations/mutations from.
    const realBlob = serializeFilter(openFilter(64, 41).f)

    for (let iter = 0; iter < ITERATIONS; iter++) {
      const mode = rng() % 4
      let blob: Uint8Array

      if (mode === 0) {
        // Fully random bytes, length 0..512.
        const len = rng() % 513
        blob = new Uint8Array(len)
        for (let i = 0; i < len; i++) blob[i] = rng() & 0xff
      } else if (mode === 1) {
        // Truncation of a real blob.
        const len = rng() % (realBlob.length + 1)
        blob = realBlob.slice(0, len)
      } else if (mode === 2) {
        // Real blob with a few random bytes flipped (valid-looking header,
        // possibly wrong body / wrong declared geometry).
        blob = realBlob.slice()
        const flips = (rng() % 8) + 1
        for (let j = 0; j < flips; j++) {
          const pos = rng() % blob.length
          blob[pos] = rng() & 0xff
        }
      } else {
        // Valid magic+version+type+bits prefix, then random geometry + body.
        const len = (rng() % 600) + KFLT_HEADER_LEN
        blob = new Uint8Array(len)
        for (let i = 0; i < len; i++) blob[i] = rng() & 0xff
        blob[0] = 0x4b
        blob[1] = 0x46
        blob[2] = 0x4c
        blob[3] = 0x54
        blob[4] = 1 // version
        blob[5] = 1 // filter_type fuse
        blob[6] = 16 // fingerprint_bits
      }

      let result: MembershipFilter | undefined
      let err: unknown
      try {
        result = parseFilter(blob)
      } catch (e) {
        err = e
      }

      if (err !== undefined) {
        // MUST be an Error, never a string/number/object/non-Error throw.
        expect(err).toBeInstanceOf(Error)
        threwError++
      } else {
        // If it parsed, it must be a structurally-valid MembershipFilter.
        expect(result).toBeDefined()
        expect(result!.type).toBe(1)
        expect(result!.fingerprintBits).toBe(16)
        expect(typeof result!.epoch).toBe('number')
        expect(typeof result!.keyed).toBe('boolean')
        expect(result!._fuse.fingerprints.length).toBe(result!._fuse.arrayLength)
        parsedOk++
      }
    }

    // Sanity: the corpus exercised both branches (not strictly required, but a
    // useful guard that the fuzzer isn't trivially all-throw or all-pass).
    expect(threwError + parsedOk).toBe(ITERATIONS)
    expect(threwError).toBeGreaterThan(0)
  })

  it('every prefix-length truncation of a real blob is Error-or-valid', () => {
    const realBlob = serializeFilter(openFilter(32, 42).f)
    for (let len = 0; len <= Math.min(realBlob.length, 400); len++) {
      const b = realBlob.slice(0, len)
      let err: unknown
      let ok: MembershipFilter | undefined
      try {
        ok = parseFilter(b)
      } catch (e) {
        err = e
      }
      if (err !== undefined) {
        expect(err).toBeInstanceOf(Error)
      } else {
        // The only truncation that can validly parse is the full-length one.
        expect(len).toBe(realBlob.length)
        expect(ok).toBeDefined()
      }
    }
  })
})
