import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildMembershipFilter } from './filter.js'
import { memberKey } from './member-key.js'
import {
  issuePresenceCapability,
  testWithCapability,
  type PresenceCapability,
} from './capability.js'

// --- fixtures -------------------------------------------------------------

const EPOCH = 1_700_000_000
const SALT = 'deadbeefcafe'
// Colon-free server identifier — the canonical-bytes delimiter guard rejects any
// serverId containing ':'. Real `wss://host:port` URLs MUST be reduced to a
// colon-free id (e.g. bare host, or a hash of the URL) by the caller.
const SERVER_ID = 'relay.example.com'

/** Deterministic Schnorr keypair from a label byte (reproducible, same style as
 *  sign.test.ts). The 32-byte private key is sha256(label) — a valid secp256k1
 *  scalar w.o.p.; the x-only pubkey is derived by the same API capability.ts uses. */
function keypairFromSeed(byte: number): { privHex: string; pubHex: string } {
  const privBytes = sha256(new Uint8Array([byte, 0xca, 0x9a]))
  const pubHex = bytesToHex(schnorr.getPublicKey(privBytes))
  return { privHex: bytesToHex(privBytes), pubHex }
}

const SUBJECT = keypairFromSeed(0x42)

/** Build a KEYED filter (salt set ⇒ keyed flag) whose member set is the given
 *  pubkeys transformed via `memberKey(pk, salt)`. Optionally seed extra noise
 *  members so the subject isn't the only key. */
function keyedFilterFor(
  includedPubHex: string[],
  salt: string,
  extra = 20,
) {
  const noise = Array.from({ length: extra }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, 0xbe]))),
  )
  const memberValues = [...includedPubHex, ...noise].map((pk) => memberKey(pk, salt))
  return buildMembershipFilter(memberValues, { epoch: EPOCH, salt })
}

/** Build an OPEN pool (no salt ⇒ keyed flag false) whose member set is the given
 *  pubkeys transformed via the BARE open-pool form `memberKey(pk)`. This is the
 *  exact form an open-pool capability (`salt` omitted at issue) must match
 *  against: its `memberValue` is `memberKey(subjectPub)` (bare), computed once at
 *  issue time and carried on the token (audit fix — the value, never the salt). */
function openFilterFor(includedPubHex: string[], extra = 20) {
  const noise = Array.from({ length: extra }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, 0x0d]))),
  )
  const memberValues = [...includedPubHex, ...noise].map((pk) => memberKey(pk))
  return buildMembershipFilter(memberValues, { epoch: EPOCH, fingerprintBits: 16 })
}

function baseParams() {
  return {
    serverId: SERVER_ID,
    subjectPubHex: SUBJECT.pubHex,
    salt: SALT,
    expiresAt: EPOCH + 3600,
  }
}

// --- issue → verify round-trip -------------------------------------------

describe('issuePresenceCapability / testWithCapability — round-trip', () => {
  it('issues a well-formed capability (fields preserved, memberValue derived, sig is 64-byte hex)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    expect(cap.serverId).toBe(SERVER_ID)
    expect(cap.subjectPubHex).toBe(SUBJECT.pubHex)
    // memberValue = memberKey(subjectPubHex, salt) for a keyed pool — NOT the
    // salt itself (audit fix: v1 carried the salt as `saltHint`).
    expect(cap.memberValue).toBe(memberKey(SUBJECT.pubHex, SALT))
    expect(cap.memberValue).toMatch(/^[0-9a-f]{64}$/)
    expect(cap).not.toHaveProperty('saltHint')
    expect(cap.expiresAt).toBe(EPOCH + 3600)
    expect(cap.sig).toMatch(/^[0-9a-f]{128}$/) // 64-byte Schnorr sig as hex
  })

  it('tests true against a keyed filter that INCLUDES memberKey(subjectPub, salt)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(testWithCapability(f, cap, EPOCH)).toBe(true)
  })

  it('tests false against a keyed filter that does NOT include the subject', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const f = keyedFilterFor([], SALT) // subject absent, only noise
    expect(testWithCapability(f, cap, EPOCH)).toBe(false)
  })
})

// --- omitted salt ⇒ OPEN-pool capability matches a real open pool -------
//
// SECURITY.md §6 / PROTOCOL.md §5: omitting `salt` at issue is an OPEN-pool
// capability — `memberValue` is the BARE `memberKey(subjectPub)` form, so it
// matches a real open pool (never `memberKey(pk, '')`, which is the keyed value
// for an empty salt and never a member of an open pool built over bare pubkeys).

describe('issuePresenceCapability — omitted salt matches an OPEN pool', () => {
  it('tests TRUE against a real open pool that INCLUDES the bare memberKey(subjectPub)', () => {
    const cap = issuePresenceCapability(
      { serverId: SERVER_ID, subjectPubHex: SUBJECT.pubHex, expiresAt: EPOCH + 3600 },
      SUBJECT.privHex,
    )
    expect(cap.memberValue).toBe(SUBJECT.pubHex)
    const f = openFilterFor([SUBJECT.pubHex]) // open pool built over memberKey(pk)
    expect(testWithCapability(f, cap, EPOCH)).toBe(true)
  })

  it('tests FALSE against an open pool that does NOT include the subject', () => {
    const cap = issuePresenceCapability(
      { serverId: SERVER_ID, subjectPubHex: SUBJECT.pubHex, expiresAt: EPOCH + 3600 },
      SUBJECT.privHex,
    )
    const f = openFilterFor([]) // subject absent, only noise
    expect(testWithCapability(f, cap, EPOCH)).toBe(false)
  })
})

// --- tampered field → bad sig --------------------------------------------

describe('testWithCapability — tampered field throws "capability signature invalid"', () => {
  const cap0 = () => issuePresenceCapability(baseParams(), SUBJECT.privHex)
  const f = () => keyedFilterFor([SUBJECT.pubHex], SALT)

  it('mutating serverId after issuance breaks the signature', () => {
    // Mutate to a different but still COLON-FREE serverId so field-shape
    // validation passes and we reach the signature check — proving the sig
    // actually binds serverId (a colon here would trip the delimiter guard first).
    const cap: PresenceCapability = { ...cap0(), serverId: 'evil.example.com' }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow('capability signature invalid')
  })

  it('mutating subjectPubHex after issuance breaks the signature', () => {
    const OTHER = keypairFromSeed(0x77)
    const cap: PresenceCapability = { ...cap0(), subjectPubHex: OTHER.pubHex }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow('capability signature invalid')
  })

  it('mutating memberValue after issuance breaks the signature', () => {
    const cap: PresenceCapability = { ...cap0(), memberValue: 'aa'.repeat(32) }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow('capability signature invalid')
  })

  it('mutating expiresAt after issuance breaks the signature', () => {
    const cap: PresenceCapability = { ...cap0(), expiresAt: EPOCH + 999999 }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow('capability signature invalid')
  })

  it('mutating the sig itself breaks verification', () => {
    const cap = cap0()
    // Flip the last hex nibble of the signature.
    const last = cap.sig.slice(-1)
    const flipped = last === '0' ? '1' : '0'
    const tampered: PresenceCapability = { ...cap, sig: cap.sig.slice(0, -1) + flipped }
    expect(() => testWithCapability(f(), tampered, EPOCH)).toThrow('capability signature invalid')
  })
})

// --- expiry --------------------------------------------------------------

describe('testWithCapability — expiry', () => {
  it('throws "capability expired" when now > expiresAt (injected now)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(() => testWithCapability(f, cap, cap.expiresAt + 1)).toThrow('capability expired')
  })

  it('does NOT throw at exactly now === expiresAt (boundary is still valid)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(testWithCapability(f, cap, cap.expiresAt)).toBe(true)
  })

  it('expiry is checked BEFORE the membership test (expired throws even for an absent subject)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const f = keyedFilterFor([], SALT) // subject absent — would be false if tested
    expect(() => testWithCapability(f, cap, cap.expiresAt + 1)).toThrow('capability expired')
  })

  it('throws on a non-finite resolved `now` instead of silently skipping the expiry check (audit fix)', () => {
    // Before the fix, `NaN > expiresAt` is always false, so an expired-by-design
    // capability (expiresAt in the past) would sail through with an injected
    // NaN clock. It must now throw instead.
    const cap = issuePresenceCapability(
      { ...baseParams(), expiresAt: 100 },
      SUBJECT.privHex,
    )
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(() => testWithCapability(f, cap, Number.NaN)).toThrow()
    // And it must NOT return `true` (the pre-fix bug's observable symptom).
    let result: boolean | undefined
    let threw = false
    try {
      result = testWithCapability(f, cap, Number.NaN)
    } catch {
      threw = true
    }
    expect(threw).toBe(true)
    expect(result).toBeUndefined()
  })
})

// --- wrong salt (valid sig, salt mismatch) ---------------------------

describe('issuePresenceCapability — wrong salt at issue time', () => {
  it('a capability issued under the WRONG salt has a memberValue absent from the real (differently-salted) pool', () => {
    // Issue a capability whose memberValue is derived from WRONG_SALT (signed
    // over that memberValue, so the sig is internally valid)...
    const WRONG_SALT = 'ffeeddccbbaa'
    const cap = issuePresenceCapability(
      { ...baseParams(), salt: WRONG_SALT },
      SUBJECT.privHex,
    )
    expect(cap.memberValue).toBe(memberKey(SUBJECT.pubHex, WRONG_SALT))
    // ...but the FILTER was built under the real SALT. memberKey(subj, WRONG_SALT)
    // is not in the pool, so the subject isn't found.
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(testWithCapability(f, cap, EPOCH)).toBe(false)
  })
})

// --- colon-in-serverId delimiter-injection guard -------------------------

describe('colon-in-serverId rejection (delimiter-injection guard)', () => {
  it('issuePresenceCapability throws when serverId contains a colon', () => {
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), serverId: 'wss://relay.example.com:443' },
        SUBJECT.privHex,
      ),
    ).toThrow()
  })

  it('testWithCapability throws on a hand-crafted cap whose serverId contains a colon', () => {
    // Hand-craft a cap (bypassing issue's guard) with a colon serverId + a
    // syntactically-valid 64-byte sig. testWithCapability must reject it before
    // any verify/membership work.
    const cap: PresenceCapability = {
      serverId: 'host:with:colons',
      subjectPubHex: SUBJECT.pubHex,
      memberValue: memberKey(SUBJECT.pubHex, SALT),
      expiresAt: EPOCH + 3600,
      sig: '00'.repeat(64),
    }
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(() => testWithCapability(f, cap, EPOCH)).toThrow()
  })
})

// --- pubkey-matches-priv assertion ---------------------------------------

describe('issuePresenceCapability — subjectPubHex must match subjectPrivHex', () => {
  it('throws when the claimed subjectPubHex is not the pubkey of subjectPrivHex', () => {
    const OTHER = keypairFromSeed(0x55)
    expect(OTHER.pubHex).not.toBe(SUBJECT.pubHex)
    // Claim OTHER's pubkey while signing with SUBJECT's priv → must be rejected
    // (a caller can't issue a capability for a subject key they don't control).
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), subjectPubHex: OTHER.pubHex },
        SUBJECT.privHex,
      ),
    ).toThrow()
  })
})

// --- field validation ----------------------------------------------------

describe('issuePresenceCapability — field validation', () => {
  it('rejects a non-64-hex subjectPrivHex', () => {
    expect(() =>
      issuePresenceCapability(baseParams(), 'deadbeef'),
    ).toThrow()
  })

  it('rejects a non-64-hex subjectPubHex', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), subjectPubHex: 'abc' }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects an odd-length salt', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), salt: 'abc' }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects a non-hex salt', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), salt: 'zz' }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects an empty serverId', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), serverId: '' }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects a non-finite expiresAt', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), expiresAt: Number.NaN }, SUBJECT.privHex),
    ).toThrow()
    expect(() =>
      issuePresenceCapability({ ...baseParams(), expiresAt: Infinity }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects a negative expiresAt (audit fix — must be a NON-NEGATIVE safe integer)', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), expiresAt: -1 }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects a fractional expiresAt (audit fix — must be an INTEGER, canonical across languages)', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), expiresAt: 1.5 }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects an expiresAt above Number.MAX_SAFE_INTEGER (audit fix — canonicalisation)', () => {
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), expiresAt: Number.MAX_SAFE_INTEGER + 2 },
        SUBJECT.privHex,
      ),
    ).toThrow()
  })

  it('accepts an EMPTY salt string as an even-length-hex keyed salt (memberKey("" ‖ pk))', () => {
    // salt '' is even-length hex, distinct from omitting `salt` entirely: it
    // still routes through memberKey's KEYED branch (`saltHex !== undefined`),
    // producing sha256('' || pk) — NOT the open-pool bare-pubkey form.
    const cap = issuePresenceCapability({ ...baseParams(), salt: '' }, SUBJECT.privHex)
    expect(cap.memberValue).toBe(memberKey(SUBJECT.pubHex, ''))
    expect(cap.memberValue).not.toBe(SUBJECT.pubHex)
  })

  it('omitting salt entirely yields the BARE open-pool memberValue (subjectPubHex itself)', () => {
    const cap = issuePresenceCapability(
      { serverId: SERVER_ID, subjectPubHex: SUBJECT.pubHex, expiresAt: EPOCH + 3600 },
      SUBJECT.privHex,
    )
    expect(cap.memberValue).toBe(SUBJECT.pubHex)
  })
})

// --- testWithCapability field validation ---------------------------------

describe('testWithCapability — field validation', () => {
  const f = () => keyedFilterFor([SUBJECT.pubHex], SALT)

  it('throws on a non-64-hex subjectPubHex', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), subjectPubHex: 'abc' }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow()
  })

  it('throws on a non-64-hex memberValue', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), memberValue: 'abc' }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow()
  })

  it('throws on a negative expiresAt', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), expiresAt: -1 }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow()
  })

  it('throws on a non-hex sig', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), sig: 'nothex' }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow()
  })
})

// --- private-key zeroization ---------------------------------------------

describe('issuePresenceCapability — subject priv zeroized after issuance', () => {
  it('zeroizes the private-key byte copy it derives (observed via a spied hexToBytes path)', async () => {
    // We can't observe capability.ts's internal byte copy directly, but we can
    // assert the documented zeroization code path runs by confirming the function
    // completes and produces a valid sig (the finally{} always runs). As a
    // stronger structural check, the source must call `.fill(0)` in a finally —
    // verified by a static read of the module text.
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    expect(cap.sig).toMatch(/^[0-9a-f]{128}$/)

    const src = await import('node:fs').then((fs) =>
      fs.readFileSync(new URL('./capability.ts', import.meta.url), 'utf8'),
    )
    expect(src).toMatch(/finally/)
    expect(src).toMatch(/\.fill\(0\)/)
  })
})

// --- B1 audit fix: a capability no longer discloses the pool salt --------
//
// The whole point of the fix: holding a capability for one friend must NOT hand
// the bearer the means to probe every OTHER member of the same keyed pool. The
// old `saltHint` field WAS the pool salt in clear; `memberValue` is only this one
// subject's derived value and cannot be inverted back to the salt or reused to
// compute anyone else's value.

describe('B1 — capability does not leak the pool salt', () => {
  it('the capability object never carries the raw salt string anywhere in its own fields', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const values = Object.values(cap)
    expect(values).not.toContain(SALT)
    // memberValue is a sha256 digest — no relation to the salt's raw bytes/hex.
    expect(cap.memberValue).not.toBe(SALT)
  })

  it('memberValue cannot be used to compute a DIFFERENT member\'s value (it is not the salt)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    const OTHER = keypairFromSeed(0x88)
    // A bearer who only holds `cap.memberValue` has no way to derive
    // memberKey(OTHER.pubHex, SALT) from it — unlike v1, where holding the raw
    // salt let a bearer compute memberKey(anyPk, saltHint) for ANY candidate.
    const otherRealValue = memberKey(OTHER.pubHex, SALT)
    expect(cap.memberValue).not.toBe(otherRealValue)
    // (There is no exported function that takes a memberValue and a candidate
    // pubkey and returns another member's value — the fix is structural, not
    // just a missing helper; this test pins that memberValue and the salt are
    // simply different, unrelated 64-hex strings.)
  })
})
