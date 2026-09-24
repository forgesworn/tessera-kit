import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'

// Deterministic distinct 64-hex pubkeys (same style as fuse.test.ts).
const pubkeys = (n: number, tag = 7): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )

const EPOCH = 1_700_000_000
const SALT = 'deadbeefcafef00d'

describe('buildMembershipFilter / testMembership', () => {
  it('open pool: every member tests true, a non-member tests false', () => {
    const pks = pubkeys(20)
    const memberKeys = pks.map((pk) => memberKey(pk))
    const f = buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 16 })

    for (const k of memberKeys) expect(testMembership(f, k)).toBe(true)

    // A pubkey that is NOT in the pool, transformed the same (open) way.
    const nonMember = memberKey(pubkeys(1, 99)[0] as string)
    expect(testMembership(f, nonMember)).toBe(false)

    expect(f.keyed).toBe(false)
    expect(f.epoch).toBe(EPOCH)
    expect(f.type).toBe(1)
    // TK-6 made `padToBucket` default to TRUE, so a build with no padding opt is
    // now padded. (The unpadded shape — `_padded:false` — is covered explicitly
    // in padding.test.ts with `padToBucket:false`.)
    expect(f._padded).toBe(true)
    expect(f.fingerprintBits).toBe(16)
  })

  it('keyed pool: every member tests true, keyed flag set from salt presence', () => {
    const pks = pubkeys(20, 8)
    const memberKeys = pks.map((pk) => memberKey(pk, SALT))
    const f = buildMembershipFilter(memberKeys, { epoch: EPOCH, salt: SALT })

    for (const k of memberKeys) expect(testMembership(f, k)).toBe(true)
    expect(f.keyed).toBe(true)
    expect(f.epoch).toBe(EPOCH)
    expect(f.type).toBe(1)
  })

  it('defaults fingerprintBits to 16 when omitted', () => {
    const memberKeys = pubkeys(5).map((pk) => memberKey(pk))
    const f = buildMembershipFilter(memberKeys, { epoch: EPOCH })
    expect(f.fingerprintBits).toBe(16)
  })

  it('unsupported fingerprintBits throws the documented error', () => {
    const memberKeys = pubkeys(5).map((pk) => memberKey(pk))
    expect(() =>
      buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 8 }),
    ).toThrow('tessera-kit: only fingerprintBits=16 implemented')
    expect(() =>
      buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 20 }),
    ).toThrow('tessera-kit: only fingerprintBits=16 implemented')
    expect(() =>
      buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 32 }),
    ).toThrow('tessera-kit: only fingerprintBits=16 implemented')
  })

  it('duplicate inputs do not break the build; band reflects the DEDUPED count', () => {
    const pks = pubkeys(5, 11)
    const distinct = pks.map((pk) => memberKey(pk))
    // 5 distinct keys, but the array carries repeats (12 entries total).
    const withDupes = [...distinct, ...distinct, distinct[0] as string, distinct[1] as string]
    expect(withDupes.length).toBe(12)

    const f = buildMembershipFilter(withDupes, { epoch: EPOCH })
    for (const k of distinct) expect(testMembership(f, k)).toBe(true)

    // 5 distinct → next power of two ≥ 5 is 8.
    expect(f._memberCountBand).toBe(8)
  })

  it('_memberCountBand is next power of two ≥ true deduped count', () => {
    const exact = pubkeys(8, 12).map((pk) => memberKey(pk)) // 8 distinct → band 8
    expect(buildMembershipFilter(exact, { epoch: EPOCH })._memberCountBand).toBe(8)

    const nine = pubkeys(9, 13).map((pk) => memberKey(pk)) // 9 distinct → band 16
    expect(buildMembershipFilter(nine, { epoch: EPOCH })._memberCountBand).toBe(16)

    const one = pubkeys(1, 14).map((pk) => memberKey(pk)) // 1 distinct → band 1
    expect(buildMembershipFilter(one, { epoch: EPOCH })._memberCountBand).toBe(1)
  })

  it('open vs keyed are different filters: an open-form key need not test true against the keyed filter', () => {
    const pks = pubkeys(20, 15)
    const keyedFilter = buildMembershipFilter(
      pks.map((pk) => memberKey(pk, SALT)),
      { epoch: EPOCH, salt: SALT },
    )
    // The OPEN-form value for each member is a different inserted value than its
    // keyed form, so it must not be (reliably) present. Across 20 members the
    // chance all 20 collide at the ~2^-16 FP rate is astronomically small.
    const openHits = pks.filter((pk) => testMembership(keyedFilter, memberKey(pk))).length
    expect(openHits).toBe(0)
  })
})

// `testMembership` is a PUBLIC boundary. A malformed `valueHex` (odd-length / non-hex) must surface a
// KIT-SHAPED error, not a raw @noble `RangeError` leaking from the fuse hash. Every INTERNAL caller
// passes `memberKey(...)` output (always 64-hex), so the guard is safe; it only rejects callers that
// hand-build a bad value. Case-variant hex is still accepted (lowercased internally).
describe('testMembership — 64-hex input guard (kit-shaped error at the public boundary)', () => {
  const pks = pubkeys(5, 21)
  const f = buildMembershipFilter(
    pks.map((pk) => memberKey(pk)),
    { epoch: EPOCH },
  )

  it('throws a kit-shaped error on an odd-length hex value (not a raw @noble RangeError)', () => {
    expect(() => testMembership(f, 'abc')).toThrow('tessera-kit: testMembership value must be 64 hex chars')
  })

  it('throws a kit-shaped error on a non-hex value', () => {
    expect(() => testMembership(f, 'z'.repeat(64))).toThrow(
      'tessera-kit: testMembership value must be 64 hex chars',
    )
  })

  it('throws a kit-shaped error on a wrong-length (but hex) value', () => {
    expect(() => testMembership(f, 'ab'.repeat(31))).toThrow(
      'tessera-kit: testMembership value must be 64 hex chars',
    )
    expect(() => testMembership(f, 'ab'.repeat(33))).toThrow(
      'tessera-kit: testMembership value must be 64 hex chars',
    )
    expect(() => testMembership(f, '')).toThrow('tessera-kit: testMembership value must be 64 hex chars')
  })

  it('still accepts a valid 64-hex value, case-insensitively', () => {
    const member = memberKey(pks[0] as string) // 64-hex
    expect(testMembership(f, member)).toBe(true)
    // Uppercased variant of the same 64-hex value is still accepted (lowercased internally).
    expect(testMembership(f, member.toUpperCase())).toBe(true)
  })
})

// B3 (audit fix) — buildMembershipFilter validates EVERY input key as 64-hex,
// case-insensitive, and lowercases BEFORE dedup so a case-variant duplicate
// collapses to one entry instead of surviving to break fuse peeling.
describe('buildMembershipFilter — input key validation (B3 audit fix)', () => {
  it('a mixed-case duplicate (same key, different case) builds fine and dedupes to one member', () => {
    const base = pubkeys(4, 51).map((pk) => memberKey(pk))
    const withCaseDupe = [...base, (base[0] as string).toUpperCase()]
    const f = buildMembershipFilter(withCaseDupe, { epoch: EPOCH, padToBucket: false })
    for (const k of base) expect(testMembership(f, k)).toBe(true)
    // 4 distinct keys after dedup (the uppercase variant collapsed onto index 0).
    expect(f._memberCountBand).toBe(4)
  })

  it('throws naming the offending index on a non-hex key', () => {
    const keys = [memberKey(pubkeys(1, 52)[0] as string), 'not-hex-at-all-'.padEnd(64, '0')]
    expect(() => buildMembershipFilter(keys, { epoch: EPOCH })).toThrow(/memberKeysHex\[1\]/)
  })

  it('throws naming the offending index on an odd-length key', () => {
    const keys = [memberKey(pubkeys(1, 53)[0] as string), 'ab'.repeat(31) + 'a'] // 63 chars
    expect(() => buildMembershipFilter(keys, { epoch: EPOCH })).toThrow(/memberKeysHex\[1\]/)
  })

  it('throws naming the offending index on a 66-hex key (too long)', () => {
    const keys = [memberKey(pubkeys(1, 54)[0] as string), 'ab'.repeat(33)] // 66 chars
    expect(() => buildMembershipFilter(keys, { epoch: EPOCH })).toThrow(/memberKeysHex\[1\]/)
  })
})

// B7 (audit fix) — epoch must be a non-negative safe integer at build time (a
// negative epoch previously wrapped to 2^64-1 on the wire via setBigUint64).
describe('buildMembershipFilter — epoch validation (B7 audit fix)', () => {
  const keys = pubkeys(3, 60).map((pk) => memberKey(pk))

  it('rejects a negative epoch', () => {
    expect(() => buildMembershipFilter(keys, { epoch: -1 })).toThrow(/epoch/)
  })

  it('rejects a fractional epoch', () => {
    expect(() => buildMembershipFilter(keys, { epoch: 1.5 })).toThrow(/epoch/)
  })

  it('rejects a non-finite epoch', () => {
    expect(() => buildMembershipFilter(keys, { epoch: Number.NaN })).toThrow(/epoch/)
    expect(() => buildMembershipFilter(keys, { epoch: Infinity })).toThrow(/epoch/)
  })

  it('rejects an epoch above Number.MAX_SAFE_INTEGER', () => {
    expect(() =>
      buildMembershipFilter(keys, { epoch: Number.MAX_SAFE_INTEGER + 2 }),
    ).toThrow(/epoch/)
  })

  it('accepts epoch 0 and a normal epoch', () => {
    expect(() => buildMembershipFilter(keys, { epoch: 0 })).not.toThrow()
    expect(() => buildMembershipFilter(keys, { epoch: EPOCH })).not.toThrow()
  })
})
