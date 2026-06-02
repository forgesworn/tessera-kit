// Property-level tests for tessera-kit (spec §7.6 accumulation budget, §10.2
// non-enumerability). These complement the per-module unit tests (106 of them):
// the unit tests assert the building blocks behave; these two assert the
// SYSTEM-LEVEL privacy/accuracy properties the spec makes load-bearing claims
// about, and pin the honest framing of those claims in executable form.

import { describe, it, expect } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'
import { serializeFilter } from './codec.js'
import * as tesseraSurface from './index.js'

// ─────────────────────────────────────────────────────────────────────────────
// Part A.1 — Accumulation budget (spec §7.6)
//
// §7.6 corrected math:  E[false hits] = c · S · p
//   where  c = candidate tests per sweep, S = members, p = per-test FPR.
//   At 16-bit fingerprints, p ≈ 2^-16 ≈ 1.5e-5 (false-negative-free; only the
//   false-POSITIVE rate matters for accumulation).
//
//   The spec's headline example is c=100, S=1000:
//     E[false hits] = 100 · 1000 · 1.5e-5 ≈ 1.5 false hits per full sweep.
//   i.e. ≈ one spurious "present" per ~0.7 ecosystem sweeps — which is exactly
//   why a consumer at scale MUST add a confirm-on-connect step (the §6.2
//   key-control challenge): a single bare `testMembership` hit is not proof of
//   presence, it is a CANDIDATE to confirm.
//
// We don't run a 100-sweep ecosystem here; we measure p DIRECTLY at smaller
// scale (a 1000-member filter, ~100,000 random non-member candidate tests) and
// assert the observed false-hit RATE sits near the 16-bit ideal and well under
// the 5e-4 ceiling the spec budget allows. Knowing p, the sweep-level E above is
// just arithmetic — documented, not re-simulated.
// ─────────────────────────────────────────────────────────────────────────────

describe('accumulation budget (spec §7.6) — measured false-positive rate', () => {
  // Keep the ceiling per the task spec. 16-bit ideal p ≈ 1.5e-5; the ceiling is
  // ~33× the ideal, comfortably absorbing sampling noise over ~1e5 trials while
  // still failing loudly if the filter's real FPR were anywhere near 1e-3+.
  const FALSE_HIT_CEILING = 5e-4
  const S = 1000 // members
  const CANDIDATES = 100_000 // non-member probes

  it(`a ${S}-member 16-bit filter false-hits < ${FALSE_HIT_CEILING} over ${CANDIDATES} non-member probes`, () => {
    // Build a 1000-member OPEN pool of distinct random pubkeys. padToBucket:false
    // so the inserted set is EXACTLY the 1000 members — decoys would add extra
    // "true" values and muddy a clean non-member-FPR measurement. (Decoy
    // behaviour is covered in padding.test.ts.)
    const memberPubkeys = new Set<string>()
    while (memberPubkeys.size < S) memberPubkeys.add(bytesToHex(randomBytes(32)))
    const memberKeys = [...memberPubkeys].map((pk) => memberKey(pk))
    const f = buildMembershipFilter(memberKeys, {
      epoch: 1_700_000_000,
      fingerprintBits: 16,
      padToBucket: false,
    })

    // Sanity: zero false negatives (a successful build is exact on members).
    for (const k of memberKeys) expect(testMembership(f, k)).toBe(true)

    // Probe with CANDIDATES random NON-members. Guard against the (astronomically
    // unlikely) case of a probe pubkey colliding a real member: regenerate it so
    // every probe is a genuine non-member and a "true" can only be a false hit.
    const memberKeySet = new Set(memberKeys)
    let falseHits = 0
    for (let i = 0; i < CANDIDATES; i++) {
      let probePk = bytesToHex(randomBytes(32))
      let probe = memberKey(probePk)
      while (memberPubkeys.has(probePk) || memberKeySet.has(probe)) {
        probePk = bytesToHex(randomBytes(32))
        probe = memberKey(probePk)
      }
      if (testMembership(f, probe)) falseHits++
    }

    const rate = falseHits / CANDIDATES
    // The measured false-hit rate must be near the 2^-16 ideal and under the
    // §7.6 budget ceiling. (Do NOT loosen below 5e-4 — that would mask a broken
    // fingerprint.)
    expect(rate).toBeLessThan(FALSE_HIT_CEILING)

    // Document (not assert) the sweep-level consequence: at the OBSERVED rate,
    // a c=100 sweep over S=1000 yields ~ c·S·rate false hits. Even at the worst
    // tolerated rate (5e-4) that is 100·1000·5e-4 = 50, and at the 16-bit ideal
    // (1.5e-5) it is ~1.5 — the spec's headline number. Either way: confirm hits
    // on connect; a bare hit is a candidate, not a proof.
    const impliedSweepFalseHits = 100 * 1000 * rate
    expect(Number.isFinite(impliedSweepFalseHits)).toBe(true)
  })
})

// ─────────────────────────────────────────────────────────────────────────────
// Part A.2 — Non-enumerability sanity (spec §10.2)
//
// HONEST SCOPE (read this before trusting the test name): "non-enumerable" is a
// precise, NARROW claim, not "private."
//   - NON-enumerable  ✅ : given only a published filter/blob, the public API
//     surface gives you NO way to LIST the members. The blob carries 16-bit
//     FINGERPRINTS, not keys; the 2^256 pubkey universe makes reconstruction
//     infeasible (false positives outnumber real members by ~10^72 at 16-bit).
//   - NON-confirmable ❌ : a held SPECIFIC pubkey IS confirmable-present — that
//     is literally what `testMembership` / `testWithCapability` DO. Keyed pools
//     raise the bar from "anyone with a pubkey" to "salt-holders" (a speed-bump,
//     §7.4), NOT to "members only." See SECURITY.md.
//
// This is an ASSERTION/DOCUMENTATION test over the export surface, NOT a crypto
// proof: it asserts the ABSENCE of any enumeration affordance and the SHAPE of
// the parsed filter (fingerprints, no keys). It cannot and does not prove
// reconstruction is hard — that rests on the fingerprint construction, asserted
// statistically by Part A.1 and argued in PROTOCOL.md.
// ─────────────────────────────────────────────────────────────────────────────

describe('non-enumerability sanity (spec §10.2) — no member-listing affordance', () => {
  it('the public `.` export surface exposes no enumeration / member-listing function', () => {
    // The complete, intended public surface of the `.` entry. Anything outside
    // this set is unexpected and would warrant review — but crucially NONE of
    // these returns member keys; the only membership affordance is a per-key
    // boolean TEST (testMembership), which is confirmation, not enumeration.
    const exportNames = Object.keys(tesseraSurface).sort()

    // Enumeration would look like one of these names. Assert every one is absent.
    const enumerationLikeNames = [
      'members',
      'listMembers',
      'getMembers',
      'enumerate',
      'enumerateMembers',
      'extractMembers',
      'recoverMembers',
      'memberKeys',
      'keys',
      'toArray',
      'toList',
      'dump',
      'reconstruct',
    ]
    for (const banned of enumerationLikeNames) {
      expect(exportNames).not.toContain(banned)
    }

    // Belt-and-braces: no exported VALUE is a function whose name advertises
    // enumeration, even if it were re-exported under a different binding.
    for (const [name, value] of Object.entries(tesseraSurface)) {
      if (typeof value === 'function') {
        const fnName = (value as { name?: string }).name ?? name
        expect(/enumerat|listmember|getmember|recovermember|extractmember/i.test(fnName)).toBe(false)
      }
    }
  })

  it('a parsed filter / serialized blob carries fingerprints, not member keys', () => {
    // Build a small known pool, serialize, and confirm the only membership-shaped
    // state reachable from the public types is the opaque fingerprint structure —
    // there is no array of member keys to read back.
    const pubkeys = Array.from({ length: 16 }, () => bytesToHex(randomBytes(32)))
    const memberKeys = pubkeys.map((pk) => memberKey(pk))
    const f = buildMembershipFilter(memberKeys, {
      epoch: 1_700_000_000,
      fingerprintBits: 16,
      padToBucket: false,
    })

    // The MembershipFilter's documented public fields are metadata only
    // (fingerprintBits / keyed / epoch / type). There is NO `members` /
    // `memberKeys` field on the public contract.
    expect('members' in f).toBe(false)
    expect('memberKeys' in f).toBe(false)
    expect('keys' in f).toBe(false)

    // The internal structure (carried, not contracted) is a fingerprint array of
    // 16-bit values — NOT the keys. We can read it here because the test is in
    // the same package, but it is fingerprints: a key cannot be recovered from a
    // 16-bit fingerprint (the 2^256→2^16 map is massively non-injective).
    const internal = (f as unknown as { _fuse: { fingerprints: Uint16Array } })._fuse
    expect(internal.fingerprints).toBeInstanceOf(Uint16Array)
    // Every entry is a 16-bit value; none of them is, or yields, a 64-hex pubkey.
    for (const fp of internal.fingerprints) expect(fp).toBeLessThanOrEqual(0xffff)

    // The serialized blob is bytes: a 128-byte header + a u16 fingerprint array.
    // None of the original 64-hex member keys appears as a contiguous substring
    // of the blob's hex (the keys were hashed into the fingerprint domain, never
    // stored). This is a sanity check on "fingerprints, not keys," not a proof.
    const blob = serializeFilter(f)
    const blobHex = bytesToHex(blob)
    for (const mk of memberKeys) {
      expect(blobHex.includes(mk)).toBe(false)
    }

    // RESIDUAL, stated in-test so nobody mistakes this for non-confirmability:
    // a HELD specific key is still confirmable-present. This is the function, not
    // a leak — `testMembership` returns true for a member you already hold.
    expect(testMembership(f, memberKeys[0] as string)).toBe(true)
  })
})
