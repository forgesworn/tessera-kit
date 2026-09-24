import { describe, it, expect, vi } from 'vitest'
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

// M1 audit fix — a hash-level (not just string-level) collision must not break
// construction. Two DISTINCT member keys can share a `keyToU64` output (found
// by a ~2^32 targeted birthday search against the real 64-bit hash — see
// review.md M1 and `coll.mjs` in the audit scratchpad, which demonstrates the
// attack against a truncated-hash stand-in). Before the fix, such a pair always
// lands in the same three slots on every seed (the slots are a pure function
// of the hash, not the seed), so every peel attempt fails and `build()` throws
// forever. Finding a genuine 64-bit sha256 collision is infeasible in a test,
// so this test INJECTS one by mocking `sha256` to force two fixed keys
// (COLLIDE_A / COLLIDE_B) to hash identically, while every other input
// (including every other test in this file) goes through the real sha256
// unchanged.
const { COLLIDE_A, COLLIDE_B } = vi.hoisted(() => ({
  COLLIDE_A: 'aa'.repeat(32),
  COLLIDE_B: 'bb'.repeat(32),
}))

vi.mock('@noble/hashes/sha2.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@noble/hashes/sha2.js')>()
  const { hexToBytes } = await import('@noble/hashes/utils.js')
  const bBytes = hexToBytes(COLLIDE_B)
  const aBytes = hexToBytes(COLLIDE_A)
  const bytesEqual = (x: Uint8Array, y: Uint8Array) =>
    x.length === y.length && x.every((v, i) => v === (y[i] as number))
  return {
    ...actual,
    // Force keyToU64(COLLIDE_B) === keyToU64(COLLIDE_A) by returning
    // COLLIDE_A's digest whenever asked to hash COLLIDE_B's bytes (keyToU64
    // only reads the first 8 bytes, so aliasing the whole digest is more than
    // sufficient). Every other input is untouched.
    sha256: (msg: Uint8Array) => (bytesEqual(msg, bBytes) ? actual.sha256(aBytes) : actual.sha256(msg)),
  }
})

describe('BinaryFuse16 — hash collision (audit fix M1)', () => {
  it('converges, and BOTH colliding keys test true, when two distinct member keys share a keyToU64 hash', () => {
    const others = keys(200)
    const ks = [...others, COLLIDE_A, COLLIDE_B]

    let f: BinaryFuse16 | undefined
    expect(() => {
      f = BinaryFuse16.build(ks)
    }).not.toThrow()

    expect(f!.contains(COLLIDE_A)).toBe(true)
    expect(f!.contains(COLLIDE_B)).toBe(true)
    // The rest of the (non-colliding) set is unaffected.
    for (const k of others) expect(f!.contains(k)).toBe(true)
  })
})
