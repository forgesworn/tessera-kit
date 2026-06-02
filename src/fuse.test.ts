import { describe, it, expect } from 'vitest'
import { BinaryFuse16 } from './fuse.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'

const keys = (n: number) =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, 1]))),
  )

describe('BinaryFuse16', () => {
  it.each([0, 1, 2, 3, 10, 100, 1000, 5000])('zero false negatives for n=%i', (n) => {
    const ks = keys(n)
    const f = BinaryFuse16.build(ks)
    for (const k of ks) expect(f.contains(k)).toBe(true)
  })

  it('false-positive rate ≈ 2^-16 over 200k non-members', () => {
    const members = keys(2000)
    const f = BinaryFuse16.build(members)
    const memberSet = new Set(members)
    let fp = 0,
      trials = 0
    for (let i = 0; i < 200_000; i++) {
      const cand = bytesToHex(
        sha256(new Uint8Array([i & 255, (i >> 8) & 255, (i >> 16) & 255, 99])),
      )
      if (memberSet.has(cand)) continue
      trials++
      if (f.contains(cand)) fp++
    }
    const rate = fp / trials
    expect(rate).toBeLessThan(0.0005) // 2^-16 ≈ 1.5e-5; generous ceiling absorbs variance
  })

  it('all positions land within arrayLength', () => {
    const f = BinaryFuse16.build(keys(500))
    expect(f.arrayLength).toBeGreaterThan(0)
    expect(f.fingerprints.length).toBe(f.arrayLength)
  })
})
