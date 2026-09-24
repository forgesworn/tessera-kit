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

  // Follow-up audit fix — an EMPTY salt makes the "keyed" value sha256('' ‖ pk),
  // which anyone can compute from the bare pubkey alone: it provides no
  // speed-bump at all, so it is refused outright (distinct from OMITTING
  // `saltHex`, which is the legitimate open-pool form).
  it('rejects an empty salt', () => {
    expect(() => memberKey(PK, '')).toThrow('memberKey: salt must be non-empty even-length hex')
  })

  it('rejects a non-hex salt', () => {
    expect(() => memberKey(PK, 'zz')).toThrow('memberKey: salt must be non-empty even-length hex')
  })

  it('rejects an odd-length salt', () => {
    expect(() => memberKey(PK, 'abc')).toThrow('memberKey: salt must be non-empty even-length hex')
  })

  it('omitting saltHex entirely (the open-pool form) still works', () => {
    expect(memberKey(PK)).toBe(PK)
  })
})
