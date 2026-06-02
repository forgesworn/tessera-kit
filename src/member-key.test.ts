import { describe, it, expect } from 'vitest'
import { memberKey } from './member-key.js'

const PK = 'a'.repeat(64)
describe('memberKey', () => {
  it('open mode returns the pubkey unchanged (lowercased)', () => {
    expect(memberKey(PK)).toBe(PK)
    expect(memberKey('A'.repeat(64))).toBe('a'.repeat(64))
  })
  it('keyed mode returns sha256(salt || pubkey) as 64-hex, differing from open', () => {
    const k = memberKey(PK, 'deadbeef')
    expect(k).toMatch(/^[0-9a-f]{64}$/)
    expect(k).not.toBe(PK)
  })
  it('keyed is deterministic and salt-sensitive', () => {
    expect(memberKey(PK, 'aa')).toBe(memberKey(PK, 'aa'))
    expect(memberKey(PK, 'aa')).not.toBe(memberKey(PK, 'bb'))
  })
  it('rejects non-hex / wrong-length pubkey', () => {
    expect(() => memberKey('xyz')).toThrow()
    expect(() => memberKey('a'.repeat(63))).toThrow()
  })
})
