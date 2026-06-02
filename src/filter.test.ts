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
    expect(f._padded).toBe(false)
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
