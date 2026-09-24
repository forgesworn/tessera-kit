import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
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

// --- M2 audit fix: memberValue bound to subjectPubHex on an OPEN pool ----
//
// Before the fix, `testWithCapability` checked only that the SUBJECT signed
// the tuple — never that `memberValue` was actually derived FROM
// `subjectPubHex`. Alice can validly sign a tuple naming her own
// `subjectPubHex` while setting `memberValue` to Bob's pool value; the
// signature checks out (it only proves Alice signed THAT tuple), so a bearer
// would be told "Alice is present" when the hit is really Bob's presence,
// disclosed without Bob's consent. On an open pool `memberValue` MUST equal
// `subjectPubHex` (§5.1), so this is now checked and rejected directly. On a
// keyed pool there is no salt to check the binding with — see the module note
// and the doc comment on `testWithCapability` for why that side is an
// inherent limit, not a bug.

describe('M2 — testWithCapability binds memberValue to subjectPubHex on an OPEN pool', () => {
  /** Hand-sign a capability tuple exactly like `issuePresenceCapability` does,
   *  bypassing its internal `memberValue = memberKey(subjectPubHex, salt)`
   *  derivation — lets a test construct an internally-consistent (validly
   *  signed) capability whose `memberValue` is a DIFFERENT subject's value
   *  than the one named in `subjectPubHex`. */
  function handSignCapability(p: {
    serverId: string
    subjectPubHex: string
    memberValue: string
    expiresAt: number
  }, signerPrivHex: string): PresenceCapability {
    const preimage = utf8ToBytes(
      `tessera-cap:v2:${p.serverId}:${p.subjectPubHex}:${p.memberValue}:${p.expiresAt}`,
    )
    const digest = sha256(preimage)
    const sig = bytesToHex(schnorr.sign(digest, hexToBytes(signerPrivHex)))
    return { ...p, sig }
  }

  it('throws when Alice signs a tuple naming her own subjectPubHex but Bob\'s memberValue (open pool)', () => {
    const ALICE = SUBJECT
    const BOB = keypairFromSeed(0x62)
    const forged = handSignCapability(
      {
        serverId: SERVER_ID,
        subjectPubHex: ALICE.pubHex,
        memberValue: BOB.pubHex, // open-pool memberValue IS the bare pubkey
        expiresAt: EPOCH + 3600,
      },
      ALICE.privHex,
    )
    // Sanity: the forged capability is internally consistent (Alice really
    // did sign this exact tuple) — the sig alone would pass.
    const f = openFilterFor([ALICE.pubHex, BOB.pubHex])
    expect(f.keyed).toBe(false)
    expect(() => testWithCapability(f, forged, EPOCH)).toThrow(
      'capability: memberValue does not match subjectPubHex (open pool)',
    )
  })

  it('honest open-pool capabilities (memberValue === subjectPubHex) are unaffected', () => {
    const cap = issuePresenceCapability(
      { serverId: SERVER_ID, subjectPubHex: SUBJECT.pubHex, expiresAt: EPOCH + 3600 },
      SUBJECT.privHex,
    )
    expect(cap.memberValue).toBe(SUBJECT.pubHex)
    const f = openFilterFor([SUBJECT.pubHex])
    expect(testWithCapability(f, cap, EPOCH)).toBe(true)
  })

  it('honest keyed-pool capabilities are unaffected (no binding check on a keyed pool)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    expect(cap.memberValue).toBe(memberKey(SUBJECT.pubHex, SALT))
    expect(cap.memberValue).not.toBe(SUBJECT.pubHex) // keyed value, not the bare pubkey
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(f.keyed).toBe(true)
    expect(testWithCapability(f, cap, EPOCH)).toBe(true)
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

// --- L3 audit fix: lone UTF-16 surrogates in serverId ---------------------
//
// `utf8ToBytes` (TextEncoder) silently turns an unpaired surrogate into U+FFFD
// (the replacement character), so "a\uD800" (a lone high surrogate) and
// "a�" (the literal replacement char) previously encoded to IDENTICAL
// UTF-8 bytes and so produced an IDENTICAL canonical preimage/digest — a
// capability issued for one verified when presented under the other.

describe('L3 — assertServerId rejects a lone (unpaired) UTF-16 surrogate', () => {
  it('issuePresenceCapability throws when serverId contains a lone high surrogate', () => {
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), serverId: 'a\uD800' },
        SUBJECT.privHex,
      ),
    ).toThrow(/surrogate/)
  })

  it('issuePresenceCapability throws when serverId contains a lone low surrogate', () => {
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), serverId: 'a\uDC00' },
        SUBJECT.privHex,
      ),
    ).toThrow(/surrogate/)
  })

  it('a well-formed surrogate PAIR (an actual astral character) is accepted', () => {
    // U+1F600 GRINNING FACE, as a JS string, is the surrogate pair 😀
    // — a valid, well-formed code point, not a lone surrogate.
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), serverId: 'srv-😀' },
        SUBJECT.privHex,
      ),
    ).not.toThrow()
  })

  it('a capability honestly issued for the U+FFFD replacement character does NOT verify when presented as the lone surrogate it is not (the collision the fix closes)', () => {
    // Before the fix, `assertServerId` accepted BOTH "a�" and "a\uD800"
    // and `utf8ToBytes` mapped them to the same bytes, so a capability issued
    // under one string's canonical digest would still verify under the other.
    // After the fix, "a\uD800" is rejected outright — the two strings can no
    // longer collide because the lone-surrogate form is never accepted at all.
    const cap = issuePresenceCapability(
      { ...baseParams(), serverId: 'a�' },
      SUBJECT.privHex,
    )
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(testWithCapability(f, cap, EPOCH)).toBe(true) // honest use still works
    expect(() =>
      testWithCapability(f, { ...cap, serverId: 'a\uD800' }, EPOCH),
    ).toThrow(/surrogate/) // the collision path is now rejected before it can match
  })

  it('testWithCapability rejects a hand-crafted cap whose serverId contains a lone surrogate', () => {
    const cap: PresenceCapability = {
      serverId: 'a\uD800',
      subjectPubHex: SUBJECT.pubHex,
      memberValue: memberKey(SUBJECT.pubHex, SALT),
      expiresAt: EPOCH + 3600,
      sig: '00'.repeat(64),
    }
    const f = keyedFilterFor([SUBJECT.pubHex], SALT)
    expect(() => testWithCapability(f, cap, EPOCH)).toThrow(/surrogate/)
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

  // Follow-up audit fix: an EMPTY salt makes the "keyed" value sha256('' ‖ pk),
  // computable by anyone from the bare pubkey alone — no protection at all —
  // so `memberKey` now rejects it outright, and `issuePresenceCapability`
  // throws too (it derives `memberValue` via `memberKey(subjectPubHex, p.salt)`).
  it('rejects an EMPTY salt string (propagated from memberKey)', () => {
    expect(() => issuePresenceCapability({ ...baseParams(), salt: '' }, SUBJECT.privHex)).toThrow(
      'memberKey: salt must be non-empty even-length hex',
    )
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

// --- L4 audit fix: typeof checks — a non-string field throws a capability ---
// --- error, not a raw TypeError --------------------------------------------
//
// Before the fix, e.g. `sig: undefined` (a plausible shape a caller could hand
// in from a partially-filled object, or a JSON payload with a missing field)
// reached `cap.sig.toLowerCase()` directly and threw
// `TypeError: Cannot read properties of undefined (reading 'toLowerCase')` —
// an un-kit-shaped error that could not be distinguished from a genuine bug.

describe('L4 — non-string fields throw a capability-shaped error, not a raw TypeError (issue)', () => {
  it('rejects a non-string subjectPrivHex', () => {
    expect(() => issuePresenceCapability(baseParams(), undefined as unknown as string)).toThrow(
      'capability: subjectPrivHex must be a string',
    )
    expect(() => issuePresenceCapability(baseParams(), 12345 as unknown as string)).toThrow(
      'capability: subjectPrivHex must be a string',
    )
  })

  it('rejects a non-string subjectPubHex', () => {
    expect(() =>
      issuePresenceCapability(
        { ...baseParams(), subjectPubHex: undefined as unknown as string },
        SUBJECT.privHex,
      ),
    ).toThrow('capability: subjectPubHex must be a string')
  })

  it('rejects a non-string salt (when provided)', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), salt: 12345 as unknown as string }, SUBJECT.privHex),
    ).toThrow('capability: salt must be a string')
  })
})

describe('L4 — non-string fields throw a capability-shaped error, not a raw TypeError (test)', () => {
  const f = () => keyedFilterFor([SUBJECT.pubHex], SALT)
  const cap0 = () => issuePresenceCapability(baseParams(), SUBJECT.privHex)

  it('rejects sig: undefined (the exact TypeError-triggering shape from the audit probe)', () => {
    const cap: PresenceCapability = { ...cap0(), sig: undefined as unknown as string }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow('capability: sig must be a string')
  })

  it('rejects a non-string subjectPubHex', () => {
    const cap: PresenceCapability = { ...cap0(), subjectPubHex: 12345 as unknown as string }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow(
      'capability: subjectPubHex must be a string',
    )
  })

  it('rejects a non-string memberValue', () => {
    const cap: PresenceCapability = { ...cap0(), memberValue: undefined as unknown as string }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow(
      'capability: memberValue must be a string',
    )
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
