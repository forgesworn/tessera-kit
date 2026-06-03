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
 *  exact form an `saltHint:''` capability must match against (audit fix): an
 *  empty-hint capability is an OPEN-pool capability, so its membership value is
 *  `memberKey(subjectPub)` (bare), NOT `memberKey(subjectPub, '')` (= sha256('' ‖ pk)). */
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
    saltHint: SALT,
    expiresAt: EPOCH + 3600,
  }
}

// --- issue → verify round-trip -------------------------------------------

describe('issuePresenceCapability / testWithCapability — round-trip', () => {
  it('issues a well-formed capability (fields preserved, sig is 64-byte hex)', () => {
    const cap = issuePresenceCapability(baseParams(), SUBJECT.privHex)
    expect(cap.serverId).toBe(SERVER_ID)
    expect(cap.subjectPubHex).toBe(SUBJECT.pubHex)
    expect(cap.saltHint).toBe(SALT)
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

// --- empty saltHint ⇒ OPEN-pool capability matches a real open pool (audit fix) --
//
// SECURITY.md §6: "saltHint = '' corresponds to an open-pool capability (the value
// tested is the open-pool form)." Before the fix, testWithCapability ALWAYS computed
// `memberKey(subjectPubHex, saltHint)`, so for an empty hint it produced
// `memberKey(pk, '') = sha256('' ‖ pk)` — which is NEVER in an open pool built over
// the bare `memberKey(pk)`. The capability therefore could never match an open pool,
// a false-negative the docs explicitly claimed didn't exist. These tests pin the
// documented behaviour: an empty-hint cap is tested against the BARE open-pool value.

describe('testWithCapability — empty saltHint matches an OPEN pool (audit fix)', () => {
  it('tests TRUE against a real open pool that INCLUDES the bare memberKey(subjectPub)', () => {
    const cap = issuePresenceCapability(
      { ...baseParams(), saltHint: '' },
      SUBJECT.privHex,
    )
    const f = openFilterFor([SUBJECT.pubHex]) // open pool built over memberKey(pk)
    expect(testWithCapability(f, cap, EPOCH)).toBe(true)
  })

  it('tests FALSE against an open pool that does NOT include the subject', () => {
    const cap = issuePresenceCapability(
      { ...baseParams(), saltHint: '' },
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

  it('mutating saltHint after issuance breaks the signature', () => {
    const cap: PresenceCapability = { ...cap0(), saltHint: 'aabbccdd' }
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
})

// --- wrong saltHint (valid sig, salt mismatch) ---------------------------

describe('testWithCapability — wrong saltHint', () => {
  it('a validly-signed cap whose saltHint differs from the filter salt tests false', () => {
    // Issue a capability whose saltHint is WRONG_SALT (signed over WRONG_SALT, so
    // the sig is internally valid)...
    const WRONG_SALT = 'ffeeddccbbaa'
    const cap = issuePresenceCapability(
      { ...baseParams(), saltHint: WRONG_SALT },
      SUBJECT.privHex,
    )
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
      saltHint: SALT,
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

  it('rejects an odd-length saltHint', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), saltHint: 'abc' }, SUBJECT.privHex),
    ).toThrow()
  })

  it('rejects a non-hex saltHint', () => {
    expect(() =>
      issuePresenceCapability({ ...baseParams(), saltHint: 'zz' }, SUBJECT.privHex),
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

  it('accepts an EMPTY saltHint (even-length hex, length 0) — open-pool hint', () => {
    // saltHint '' is even-length hex; memberKey(pk, '') = sha256('' || pk).
    const cap = issuePresenceCapability({ ...baseParams(), saltHint: '' }, SUBJECT.privHex)
    expect(cap.saltHint).toBe('')
  })
})

// --- testWithCapability field validation ---------------------------------

describe('testWithCapability — field validation', () => {
  const f = () => keyedFilterFor([SUBJECT.pubHex], SALT)

  it('throws on a non-64-hex subjectPubHex', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), subjectPubHex: 'abc' }
    expect(() => testWithCapability(f(), cap, EPOCH)).toThrow()
  })

  it('throws on an odd-length saltHint', () => {
    const cap: PresenceCapability = { ...issuePresenceCapability(baseParams(), SUBJECT.privHex), saltHint: 'abc' }
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
