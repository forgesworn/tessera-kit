// Reachability matrix for `TesseraErrorCode` (item 3 of the pre-publish
// pass: typed errors) — one assertion per code, proving every code listed in
// `errors.ts` is actually throwable from real (or realistically-forced) input,
// and that the thrown value is always a `TesseraError` (never a bare `Error`)
// carrying exactly that `code`.
//
// Most `PARSE_*` codes are exercised via `vectors/reject.golden.v1.json`
// directly (that file IS the authoritative "which bytes trigger which code"
// contract — see CONFORMANCE.md and `scripts/check-vectors.mjs`'s "reject"
// kind) rather than re-deriving equivalent malformed bytes by hand here.
//
// `PARSE_GEOMETRY_OVERFLOW` has NO test here — see the note above that code's
// test slot below. It is genuinely unreachable given the current field
// widths (`segment_count` is a u32, `segment_length` is capped at 2^18 by an
// earlier check), so `segmentCountLength`/`arrayLength` can never exceed
// `Number.MAX_SAFE_INTEGER`; codec.ts's own comment at that check already
// says as much ("cannot actually overflow... but we assert it anyway").

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { TesseraError } from './errors.js'
import type { TesseraErrorCode } from './errors.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'
import { serializeFilter, parseFilter } from './codec.js'
import { signFilterBlob, verifyFilterBlob, verifyAndParseFilter } from './sign.js'
import { deriveDecoys, nextPowerOfTwoBand } from './padding.js'
import { decodeFilterPublicationContent, buildFilterPublication } from './nostr.js'
import { issuePresenceCapability, testWithCapability } from './capability.js'
import type { PresenceCapability } from './capability.js'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import type { MembershipFilter } from './types.js'
import { BinaryFuse16 } from './fuse.js'

/** Assert `fn` throws a `TesseraError` with EXACTLY `code`. This is the one
 *  shape every reachability case below checks. */
function expectCode(fn: () => unknown, code: TesseraErrorCode): void {
  let caught: unknown
  try {
    fn()
  } catch (e) {
    caught = e
  }
  expect(caught).toBeInstanceOf(TesseraError)
  expect((caught as TesseraError).code).toBe(code)
  expect((caught as TesseraError).name).toBe('TesseraError')
}

const EPOCH = 1_700_000_000
const pubkeys = (n: number, tag = 1): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )
function openFilterBlob(n = 10, tag = 1) {
  const memberKeys = pubkeys(n, tag).map((pk) => memberKey(pk))
  const f = buildMembershipFilter(memberKeys, { epoch: EPOCH })
  return { blob: serializeFilter(f), memberKeys }
}
function keypairFromSeed(byte: number): { privHex: string; pubHex: string } {
  const privBytes = sha256(new Uint8Array([byte, 0xe4, 0x40]))
  const pubHex = bytesToHex(schnorr.getPublicKey(privBytes))
  return { privHex: bytesToHex(privBytes), pubHex }
}
const CTX = 'errors-test-ctx'

// ---------------------------------------------------------------------------
// PARSE_* — driven directly from the frozen reject vectors (the authoritative
// byte->code contract; see CONFORMANCE.md).
// ---------------------------------------------------------------------------

const rejectVectorPath = fileURLToPath(new URL('../vectors/reject.golden.v1.json', import.meta.url))
const rejectVector = JSON.parse(readFileSync(rejectVectorPath, 'utf8')) as {
  cases: { description: string; blobHex: string; expectedErrorCode: TesseraErrorCode }[]
}

describe('TesseraErrorCode reachability — PARSE_* (via vectors/reject.golden.v1.json)', () => {
  for (const c of rejectVector.cases) {
    it(`${c.description} -> ${c.expectedErrorCode}`, () => {
      expectCode(() => parseFilter(hexToBytes(c.blobHex)), c.expectedErrorCode)
    })
  }

  // PARSE_GEOMETRY_OVERFLOW: deliberately NOT tested — see the module note.

  it('PARSE_BLOB_TYPE — blob is not a Uint8Array', () => {
    expectCode(() => parseFilter(null as unknown as Uint8Array), 'PARSE_BLOB_TYPE')
    expectCode(() => parseFilter(42 as unknown as Uint8Array), 'PARSE_BLOB_TYPE')
    expectCode(() => parseFilter({} as unknown as Uint8Array), 'PARSE_BLOB_TYPE')
  })
})

// ---------------------------------------------------------------------------
// CODEC_*
// ---------------------------------------------------------------------------

describe('TesseraErrorCode reachability — CODEC_*', () => {
  it('CODEC_BLOB_TOO_LARGE — serializeFilter refuses an output over KFLT_MAX_BLOB_BYTES', () => {
    const { f } = { f: buildMembershipFilter(pubkeys(5, 2).map((pk) => memberKey(pk)), { epoch: EPOCH }) }
    // Force `arrayLength` (and so the serialized size) past the cap by lying
    // about the fuse's own state via a structurally-shaped stand-in — the
    // cheapest way to reach this branch without actually building tens of
    // millions of members.
    const huge = {
      ...f,
      _fuse: {
        ...f._fuse,
        arrayLength: KFLT_MAX_BLOB_BYTES, // *2 bytes/entry alone exceeds the cap
      },
    }
    expectCode(() => serializeFilter(huge), 'CODEC_BLOB_TOO_LARGE')
  })

  it('CODEC_FILTER_TYPE — f is not a MembershipFilter-shaped object', () => {
    expectCode(() => serializeFilter(null as unknown as MembershipFilter), 'CODEC_FILTER_TYPE')
    expectCode(() => serializeFilter(42 as unknown as MembershipFilter), 'CODEC_FILTER_TYPE')
    expectCode(() => serializeFilter({} as unknown as MembershipFilter), 'CODEC_FILTER_TYPE')
  })
})

// ---------------------------------------------------------------------------
// SIGN_* / VERIFY_*
// ---------------------------------------------------------------------------

describe('TesseraErrorCode reachability — SIGN_*', () => {
  it('SIGN_BLOB_TOO_SHORT', () => {
    const SERVER = keypairFromSeed(1)
    expectCode(() => signFilterBlob(new Uint8Array(10), SERVER.privHex, CTX), 'SIGN_BLOB_TOO_SHORT')
  })

  it('SIGN_CONTEXT_EMPTY', () => {
    const { blob } = openFilterBlob()
    const SERVER = keypairFromSeed(2)
    expectCode(() => signFilterBlob(blob, SERVER.privHex, ''), 'SIGN_CONTEXT_EMPTY')
  })

  it('SIGN_CONTEXT_NOT_WELL_FORMED', () => {
    const { blob } = openFilterBlob(10, 3)
    const SERVER = keypairFromSeed(3)
    expectCode(() => signFilterBlob(blob, SERVER.privHex, 'x\uD800'), 'SIGN_CONTEXT_NOT_WELL_FORMED')
  })

  it('SIGN_CONTEXT_TOO_LONG', () => {
    const { blob } = openFilterBlob(10, 4)
    const SERVER = keypairFromSeed(4)
    expectCode(() => signFilterBlob(blob, SERVER.privHex, 'x'.repeat(1025)), 'SIGN_CONTEXT_TOO_LONG')
  })

  it('SIGN_PRIVATE_KEY_INVALID', () => {
    const { blob } = openFilterBlob(10, 5)
    expectCode(() => signFilterBlob(blob, 'not-hex', CTX), 'SIGN_PRIVATE_KEY_INVALID')
  })

  // Follow-up review fix — a 64-hex private key that is out of range for the
  // secp256k1 scalar field (zero, or >= the curve order) previously escaped
  // as a raw @noble RangeError/Error from `schnorr.getPublicKey`, not a
  // TesseraError. Both boundary values are wrapped now.
  it('SIGN_PRIVATE_KEY_OUT_OF_RANGE — zero scalar', () => {
    const { blob } = openFilterBlob(10, 71)
    expectCode(() => signFilterBlob(blob, '00'.repeat(32), CTX), 'SIGN_PRIVATE_KEY_OUT_OF_RANGE')
  })

  it('SIGN_PRIVATE_KEY_OUT_OF_RANGE — scalar >= curve order', () => {
    const { blob } = openFilterBlob(10, 72)
    expectCode(() => signFilterBlob(blob, 'ff'.repeat(32), CTX), 'SIGN_PRIVATE_KEY_OUT_OF_RANGE')
  })

  // Follow-up review fix — wrong-typed arguments (null/number/object) must
  // raise a TesseraError, never a raw TypeError, at every exported function's
  // entry. See also the blanket sweep at the bottom of this file.
  it('SIGN_BLOB_TYPE — unsignedBlob is not a Uint8Array', () => {
    const SERVER = keypairFromSeed(73)
    expectCode(() => signFilterBlob(null as unknown as Uint8Array, SERVER.privHex, CTX), 'SIGN_BLOB_TYPE')
    expectCode(() => signFilterBlob(42 as unknown as Uint8Array, SERVER.privHex, CTX), 'SIGN_BLOB_TYPE')
  })

  it('SIGN_PRIVATE_KEY_TYPE — signerPrivHex is not a string', () => {
    const { blob } = openFilterBlob(10, 74)
    expectCode(() => signFilterBlob(blob, null as unknown as string, CTX), 'SIGN_PRIVATE_KEY_TYPE')
    expectCode(() => signFilterBlob(blob, 42 as unknown as string, CTX), 'SIGN_PRIVATE_KEY_TYPE')
  })
})

describe('TesseraErrorCode reachability — VERIFY_*', () => {
  it('VERIFY_CONTEXT_EMPTY', () => {
    const { blob } = openFilterBlob(10, 6)
    expectCode(() => verifyFilterBlob(blob, ''), 'VERIFY_CONTEXT_EMPTY')
  })

  it('VERIFY_CONTEXT_NOT_WELL_FORMED', () => {
    const { blob } = openFilterBlob(10, 7)
    expectCode(() => verifyFilterBlob(blob, 'x\uD800'), 'VERIFY_CONTEXT_NOT_WELL_FORMED')
  })

  it('VERIFY_CONTEXT_TOO_LONG', () => {
    const { blob } = openFilterBlob(10, 8)
    expectCode(() => verifyFilterBlob(blob, 'x'.repeat(1025)), 'VERIFY_CONTEXT_TOO_LONG')
  })

  it('VERIFY_PINNED_PUBKEY_INVALID', () => {
    const { blob } = openFilterBlob(10, 9)
    expectCode(
      () => verifyAndParseFilter(blob, { pinnedPubkeyHex: 'nope', context: CTX }),
      'VERIFY_PINNED_PUBKEY_INVALID',
    )
  })

  it('VERIFY_MIN_EPOCH_INVALID', () => {
    const SERVER = keypairFromSeed(10)
    const { blob } = openFilterBlob(10, 10)
    signFilterBlob(blob, SERVER.privHex, CTX)
    expectCode(
      () =>
        verifyAndParseFilter(blob, {
          pinnedPubkeyHex: SERVER.pubHex,
          context: CTX,
          minEpoch: Number.NaN,
        }),
      'VERIFY_MIN_EPOCH_INVALID',
    )
  })

  it('VERIFY_SIGNATURE_OR_SIGNER_MISMATCH — wrong signer', () => {
    const SERVER = keypairFromSeed(11)
    const OTHER = keypairFromSeed(12)
    const { blob } = openFilterBlob(10, 11)
    signFilterBlob(blob, SERVER.privHex, CTX)
    expectCode(
      () => verifyAndParseFilter(blob, { pinnedPubkeyHex: OTHER.pubHex, context: CTX }),
      'VERIFY_SIGNATURE_OR_SIGNER_MISMATCH',
    )
  })

  it('VERIFY_SIGNATURE_OR_SIGNER_MISMATCH — wrong context (SAME code as wrong signer, by design)', () => {
    const SERVER = keypairFromSeed(13)
    const { blob } = openFilterBlob(10, 12)
    signFilterBlob(blob, SERVER.privHex, CTX)
    expectCode(
      () => verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: 'a-different-context' }),
      'VERIFY_SIGNATURE_OR_SIGNER_MISMATCH',
    )
  })

  it('VERIFY_STALE_EPOCH', () => {
    const SERVER = keypairFromSeed(14)
    const { blob } = openFilterBlob(10, 13)
    signFilterBlob(blob, SERVER.privHex, CTX)
    expectCode(
      () =>
        verifyAndParseFilter(blob, {
          pinnedPubkeyHex: SERVER.pubHex,
          context: CTX,
          minEpoch: EPOCH + 1,
        }),
      'VERIFY_STALE_EPOCH',
    )
  })

  it('VERIFY_BLOB_TYPE — blob is not a Uint8Array', () => {
    expectCode(() => verifyFilterBlob(null as unknown as Uint8Array, CTX), 'VERIFY_BLOB_TYPE')
    expectCode(() => verifyFilterBlob(42 as unknown as Uint8Array, CTX), 'VERIFY_BLOB_TYPE')
  })

  it('VERIFY_OPTS_TYPE — opts is not an object', () => {
    const { blob } = openFilterBlob(10, 75)
    expectCode(
      () => verifyAndParseFilter(blob, null as unknown as { pinnedPubkeyHex: string; context: string }),
      'VERIFY_OPTS_TYPE',
    )
    expectCode(
      () => verifyAndParseFilter(blob, 42 as unknown as { pinnedPubkeyHex: string; context: string }),
      'VERIFY_OPTS_TYPE',
    )
  })
})

// ---------------------------------------------------------------------------
// CAPABILITY_*
// ---------------------------------------------------------------------------

describe('TesseraErrorCode reachability — CAPABILITY_*', () => {
  const SUBJECT = keypairFromSeed(20)

  it('CAPABILITY_EXPIRES_AT_INVALID', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: -1 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_EXPIRES_AT_INVALID',
    )
  })

  it('CAPABILITY_SERVER_ID_EMPTY', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: '', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SERVER_ID_EMPTY',
    )
  })

  it('CAPABILITY_SERVER_ID_HAS_COLON', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'a:b', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SERVER_ID_HAS_COLON',
    )
  })

  it('CAPABILITY_SERVER_ID_NOT_WELL_FORMED', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'a\uD800', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SERVER_ID_NOT_WELL_FORMED',
    )
  })

  it('CAPABILITY_SUBJECT_PRIV_HEX_TYPE', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          undefined as unknown as string,
        ),
      'CAPABILITY_SUBJECT_PRIV_HEX_TYPE',
    )
  })

  it('CAPABILITY_SUBJECT_PRIV_HEX_INVALID', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          'not-hex',
        ),
      'CAPABILITY_SUBJECT_PRIV_HEX_INVALID',
    )
  })

  it('CAPABILITY_SUBJECT_PUB_HEX_TYPE — issue side', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: undefined as unknown as string, expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SUBJECT_PUB_HEX_TYPE',
    )
  })

  it('CAPABILITY_SUBJECT_PUB_HEX_INVALID — issue side', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: 'nope', expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SUBJECT_PUB_HEX_INVALID',
    )
  })

  it('CAPABILITY_SALT_TYPE', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          {
            serverId: 'srv',
            subjectPubHex: SUBJECT.pubHex,
            salt: 123 as unknown as string,
            expiresAt: 0,
          },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SALT_TYPE',
    )
  })

  it('CAPABILITY_SUBJECT_KEY_MISMATCH', () => {
    const OTHER = keypairFromSeed(21)
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: OTHER.pubHex, expiresAt: 0 },
          SUBJECT.privHex,
        ),
      'CAPABILITY_SUBJECT_KEY_MISMATCH',
    )
  })

  function validCap(): PresenceCapability {
    return issuePresenceCapability(
      { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 4_000_000_000 },
      SUBJECT.privHex,
    )
  }

  it('CAPABILITY_SUBJECT_PUB_HEX_TYPE — test side', () => {
    const cap = { ...validCap(), subjectPubHex: undefined as unknown as string }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_SUBJECT_PUB_HEX_TYPE')
  })

  it('CAPABILITY_SUBJECT_PUB_HEX_INVALID — test side', () => {
    const cap = { ...validCap(), subjectPubHex: 'nope' }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_SUBJECT_PUB_HEX_INVALID')
  })

  it('CAPABILITY_MEMBER_VALUE_TYPE', () => {
    const cap = { ...validCap(), memberValue: undefined as unknown as string }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_MEMBER_VALUE_TYPE')
  })

  it('CAPABILITY_MEMBER_VALUE_INVALID', () => {
    const cap = { ...validCap(), memberValue: 'nope' }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_MEMBER_VALUE_INVALID')
  })

  it('CAPABILITY_SIG_TYPE', () => {
    const cap = { ...validCap(), sig: undefined as unknown as string }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_SIG_TYPE')
  })

  it('CAPABILITY_SIG_INVALID_SHAPE', () => {
    const cap = { ...validCap(), sig: 'ab' }
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_SIG_INVALID_SHAPE')
  })

  it('CAPABILITY_CLOCK_NOT_FINITE', () => {
    const cap = validCap()
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap, Number.NaN), 'CAPABILITY_CLOCK_NOT_FINITE')
  })

  it('CAPABILITY_EXPIRED', () => {
    const cap = issuePresenceCapability(
      { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 100 },
      SUBJECT.privHex,
    )
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap, 200), 'CAPABILITY_EXPIRED')
  })

  it('CAPABILITY_SIGNATURE_INVALID', () => {
    const cap = { ...validCap(), sig: 'ab'.repeat(64) } // well-shaped, but not a valid sig
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_SIGNATURE_INVALID')
  })

  it('CAPABILITY_MEMBER_VALUE_MISMATCH', () => {
    const OTHER = keypairFromSeed(22)
    // Sign a tuple naming SUBJECT but carrying OTHER's memberValue — only
    // possible by hand-building the cap (issuePresenceCapability itself
    // prevents this at issue time by deriving memberValue from subjectPubHex).
    // We reconstruct it the same way capability.ts's `canonicalDigest` does.
    const preimage = `tessera-cap:v2:srv:${SUBJECT.pubHex}:${OTHER.pubHex}:4000000000`
    const digest = sha256(new TextEncoder().encode(preimage))
    const sig = bytesToHex(schnorr.sign(digest, hexToBytes(SUBJECT.privHex)))
    const cap: PresenceCapability = {
      serverId: 'srv',
      subjectPubHex: SUBJECT.pubHex,
      memberValue: OTHER.pubHex,
      expiresAt: 4_000_000_000,
      sig,
    }
    const filter = buildMembershipFilter([SUBJECT.pubHex, OTHER.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, cap), 'CAPABILITY_MEMBER_VALUE_MISMATCH')
  })

  // Follow-up review fix — a 64-hex subjectPrivHex out of range for the
  // secp256k1 scalar field previously escaped as a raw @noble error.
  it('CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE — zero scalar', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          '00'.repeat(32),
        ),
      'CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE',
    )
  })

  it('CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE — scalar >= curve order', () => {
    expectCode(
      () =>
        issuePresenceCapability(
          { serverId: 'srv', subjectPubHex: SUBJECT.pubHex, expiresAt: 0 },
          'ff'.repeat(32),
        ),
      'CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE',
    )
  })

  // Follow-up review fix — wrong-typed p/f/cap arguments must raise a
  // TesseraError, never a raw TypeError.
  it('CAPABILITY_OPTS_TYPE — issuePresenceCapability(p, ...) with p not an object', () => {
    expectCode(
      () => issuePresenceCapability(null as unknown as { serverId: string; subjectPubHex: string; expiresAt: number }, SUBJECT.privHex),
      'CAPABILITY_OPTS_TYPE',
    )
    expectCode(
      () => issuePresenceCapability(42 as unknown as { serverId: string; subjectPubHex: string; expiresAt: number }, SUBJECT.privHex),
      'CAPABILITY_OPTS_TYPE',
    )
  })

  it('CAPABILITY_FILTER_TYPE — testWithCapability(f, ...) with f not a MembershipFilter', () => {
    const cap = validCap()
    expectCode(() => testWithCapability(null as unknown as MembershipFilter, cap), 'CAPABILITY_FILTER_TYPE')
    expectCode(() => testWithCapability(42 as unknown as MembershipFilter, cap), 'CAPABILITY_FILTER_TYPE')
  })

  it('CAPABILITY_CAP_TYPE — testWithCapability(..., cap) with cap not an object', () => {
    const filter = buildMembershipFilter([SUBJECT.pubHex], { epoch: EPOCH })
    expectCode(() => testWithCapability(filter, null as unknown as PresenceCapability), 'CAPABILITY_CAP_TYPE')
    expectCode(() => testWithCapability(filter, 42 as unknown as PresenceCapability), 'CAPABILITY_CAP_TYPE')
  })
})

// ---------------------------------------------------------------------------
// BUILD_* / TEST_*
// ---------------------------------------------------------------------------

describe('TesseraErrorCode reachability — BUILD_*', () => {
  it('BUILD_DECOY_SEED_HEX_INVALID', () => {
    expectCode(
      () => buildMembershipFilter([memberKey(pubkeys(1, 30)[0] as string)], { epoch: EPOCH, decoySeedHex: 'zz' }),
      'BUILD_DECOY_SEED_HEX_INVALID',
    )
  })

  it('BUILD_DECOY_SEED_HEX_TOO_SHORT', () => {
    expectCode(
      () =>
        buildMembershipFilter([memberKey(pubkeys(1, 31)[0] as string)], {
          epoch: EPOCH,
          decoySeedHex: 'ab',
        }),
      'BUILD_DECOY_SEED_HEX_TOO_SHORT',
    )
  })

  it('BUILD_SALT_INVALID', () => {
    expectCode(
      () =>
        buildMembershipFilter([memberKey(pubkeys(1, 32)[0] as string)], { epoch: EPOCH, salt: '' }),
      'BUILD_SALT_INVALID',
    )
  })

  it('BUILD_FINGERPRINT_BITS_UNSUPPORTED', () => {
    expectCode(
      () =>
        buildMembershipFilter([memberKey(pubkeys(1, 33)[0] as string)], {
          epoch: EPOCH,
          fingerprintBits: 8,
        }),
      'BUILD_FINGERPRINT_BITS_UNSUPPORTED',
    )
  })

  it('BUILD_EPOCH_INVALID', () => {
    expectCode(
      () => buildMembershipFilter([memberKey(pubkeys(1, 34)[0] as string)], { epoch: -1 }),
      'BUILD_EPOCH_INVALID',
    )
  })

  it('BUILD_MEMBER_KEY_INVALID', () => {
    expectCode(() => buildMembershipFilter(['not-hex'], { epoch: EPOCH }), 'BUILD_MEMBER_KEY_INVALID')
  })

  it('BUILD_FUSE_CONSTRUCTION_FAILED', () => {
    // Force every key onto the SAME single slot for every seed attempt by
    // monkey-patching the (TS-private-only, runtime-public) static
    // `hashToSlots` helper — guarantees `t2count` never drops to 1 anywhere,
    // so peeling can never start and every one of the 100 seeded attempts
    // fails. Restored in `finally` so no other test in the suite is affected.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const fuseAny = BinaryFuse16 as any
    const original = fuseAny.hashToSlots
    fuseAny.hashToSlots = () => [0, 0, 0]
    try {
      expectCode(() => BinaryFuse16.build(pubkeys(5, 40)), 'BUILD_FUSE_CONSTRUCTION_FAILED')
    } finally {
      fuseAny.hashToSlots = original
    }
  })

  it('BUILD_MEMBER_KEYS_TYPE — memberKeysHex is not an array', () => {
    expectCode(() => buildMembershipFilter(null as unknown as string[], { epoch: EPOCH }), 'BUILD_MEMBER_KEYS_TYPE')
    expectCode(() => buildMembershipFilter(42 as unknown as string[], { epoch: EPOCH }), 'BUILD_MEMBER_KEYS_TYPE')
  })

  it('BUILD_OPTS_TYPE — opts is not an object', () => {
    const keys = [memberKey(pubkeys(1, 35)[0] as string)]
    expectCode(
      () => buildMembershipFilter(keys, null as unknown as { epoch: number }),
      'BUILD_OPTS_TYPE',
    )
    expectCode(
      () => buildMembershipFilter(keys, 42 as unknown as { epoch: number }),
      'BUILD_OPTS_TYPE',
    )
  })
})

describe('TesseraErrorCode reachability — TEST_*', () => {
  it('TEST_VALUE_INVALID', () => {
    const { blob } = openFilterBlob(10, 50)
    const parsed = parseFilter(blob)
    expectCode(() => testMembership(parsed, 'not-hex'), 'TEST_VALUE_INVALID')
  })

  it('TEST_FILTER_TYPE — f is not a MembershipFilter-shaped object', () => {
    expectCode(() => testMembership(null as unknown as MembershipFilter, 'a'.repeat(64)), 'TEST_FILTER_TYPE')
    expectCode(() => testMembership(42 as unknown as MembershipFilter, 'a'.repeat(64)), 'TEST_FILTER_TYPE')
    expectCode(() => testMembership({} as unknown as MembershipFilter, 'a'.repeat(64)), 'TEST_FILTER_TYPE')
  })
})

// ---------------------------------------------------------------------------
// INPUT_*
// ---------------------------------------------------------------------------

describe('TesseraErrorCode reachability — INPUT_*', () => {
  it('INPUT_PUBKEY_INVALID', () => {
    expectCode(() => memberKey('not-hex'), 'INPUT_PUBKEY_INVALID')
  })

  it('INPUT_SALT_INVALID', () => {
    const pk = pubkeys(1, 60)[0] as string
    expectCode(() => memberKey(pk, ''), 'INPUT_SALT_INVALID')
  })

  it('INPUT_DECOY_SEED_HEX_INVALID', () => {
    expectCode(() => deriveDecoys('', 1), 'INPUT_DECOY_SEED_HEX_INVALID')
  })

  it('INPUT_CONTENT_TYPE', () => {
    expectCode(
      () => decodeFilterPublicationContent(undefined as unknown as string),
      'INPUT_CONTENT_TYPE',
    )
  })

  it('INPUT_MAX_BYTES_INVALID', () => {
    expectCode(() => decodeFilterPublicationContent('', Number.NaN), 'INPUT_MAX_BYTES_INVALID')
  })

  it('INPUT_CONTENT_TOO_LARGE', () => {
    expectCode(
      () => decodeFilterPublicationContent('A'.repeat(1000), 10),
      'INPUT_CONTENT_TOO_LARGE',
    )
  })

  it('INPUT_CONTENT_DECODED_TOO_LARGE', () => {
    // Craft base64 whose ENCODED length passes the pre-check but whose
    // DECODED length exceeds maxBytes — the defence-in-depth post-check.
    // ceil(maxBytes/3)*4 with maxBytes=2 is 4 chars; use a maxBytes where the
    // encoded-length bound is looser than the true 3-byte-per-4-char ratio
    // would suggest is impossible for standard base64 — so instead exploit
    // the rounding: maxBytes=1 -> maxEncodedLen=ceil(1/3)*4=4, and a 4-char
    // base64 string decodes to 3 bytes > 1.
    expectCode(() => decodeFilterPublicationContent('AAAA', 1), 'INPUT_CONTENT_DECODED_TOO_LARGE')
  })

  // Follow-up review fix — malformed (non-alphabet) base64 previously escaped
  // as a raw @scure Error from `base64.decode`. This is hostile relay input
  // (the whole point of this function), so it must be a TesseraError.
  it('INPUT_CONTENT_MALFORMED_BASE64', () => {
    expectCode(() => decodeFilterPublicationContent('!!!!'), 'INPUT_CONTENT_MALFORMED_BASE64')
  })

  // Follow-up review fix — memberKey's pubkeyHex previously called
  // `.toLowerCase()` before any typeof check, so a non-string threw a raw
  // TypeError instead of a TesseraError.
  it('INPUT_PUBKEY_TYPE', () => {
    expectCode(() => memberKey(null as unknown as string), 'INPUT_PUBKEY_TYPE')
    expectCode(() => memberKey(42 as unknown as string), 'INPUT_PUBKEY_TYPE')
  })

  // Follow-up review fix — deriveDecoys' count previously reached
  // `new Array(count)` unguarded: `new Array(NaN)` throws a raw RangeError,
  // and a non-number count silently produced a corrupt (mis-typed) result.
  it('INPUT_DECOY_COUNT_INVALID', () => {
    expectCode(() => deriveDecoys('ab'.repeat(16), Number.NaN), 'INPUT_DECOY_COUNT_INVALID')
    expectCode(() => deriveDecoys('ab'.repeat(16), 'x' as unknown as number), 'INPUT_DECOY_COUNT_INVALID')
    expectCode(() => deriveDecoys('ab'.repeat(16), null as unknown as number), 'INPUT_DECOY_COUNT_INVALID')
  })

  // Follow-up review fix — nextPowerOfTwoBand previously accepted any value
  // silently (a non-number `n` coerces to NaN in the comparison and the loop
  // never runs, returning 1 with no signal that the input was nonsense).
  it('INPUT_BAND_INVALID', () => {
    expectCode(() => nextPowerOfTwoBand(Number.NaN), 'INPUT_BAND_INVALID')
    expectCode(() => nextPowerOfTwoBand('x' as unknown as number), 'INPUT_BAND_INVALID')
    expectCode(() => nextPowerOfTwoBand(null as unknown as number), 'INPUT_BAND_INVALID')
    expectCode(() => nextPowerOfTwoBand(-1), 'INPUT_BAND_INVALID')
  })

  // Follow-up review fix — buildFilterPublication's p (and p.blob) previously
  // reached `base64.encode(p.blob)` unguarded.
  it('INPUT_PUBLICATION_TYPE', () => {
    expectCode(
      () => buildFilterPublication(null as unknown as { kind: number; tags: string[][]; blob: Uint8Array; createdAt: number }),
      'INPUT_PUBLICATION_TYPE',
    )
    expectCode(
      () => buildFilterPublication(42 as unknown as { kind: number; tags: string[][]; blob: Uint8Array; createdAt: number }),
      'INPUT_PUBLICATION_TYPE',
    )
    expectCode(
      () => buildFilterPublication({ kind: 1, tags: [], blob: null as unknown as Uint8Array, createdAt: 0 }),
      'INPUT_PUBLICATION_TYPE',
    )
    expectCode(
      () => buildFilterPublication({ kind: 1, tags: [], blob: 42 as unknown as Uint8Array, createdAt: 0 }),
      'INPUT_PUBLICATION_TYPE',
    )
  })
})

// ---------------------------------------------------------------------------
// Class shape
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Follow-up review fix — blanket sweep: EVERY exported function, called with
// `null` and with a bare number (`42`) in every argument position, must
// EITHER throw a `TesseraError` or return a value — NEVER let a raw
// TypeError/RangeError/@noble/@scure error escape. This is the "nothing but
// a TesseraError escapes a public function" rule, checked mechanically
// across the full `.` / `./capability` / `./nostr` export surface, so a
// future new export is caught by the eslint-style intent of this test even
// before someone remembers to add a dedicated reachability case for it.
// ---------------------------------------------------------------------------

/** Call `fn`, and if it throws, assert the thrown value is a `TesseraError`
 *  (never a bare Error/TypeError/RangeError). A NON-throwing return is also
 *  acceptable — the rule is "nothing but a TesseraError escapes," not "must
 *  throw." */
function assertNeverRawError(label: string, fn: () => unknown): void {
  try {
    fn()
    // No throw — a valid return. Nothing further to assert.
  } catch (e) {
    if (!(e instanceof TesseraError)) {
      throw new Error(
        `${label}: escaped a NON-TesseraError (${e instanceof Error ? e.constructor.name : typeof e}: ${String(e instanceof Error ? e.message : e)})`,
      )
    }
  }
}

describe('every exported function rejects null/number without leaking a raw error', () => {
  const okBlob = openFilterBlob(10, 90).blob
  const okKeypair = keypairFromSeed(90)
  const okCap = issuePresenceCapability(
    { serverId: 'srv', subjectPubHex: okKeypair.pubHex, expiresAt: 4_000_000_000 },
    okKeypair.privHex,
  )
  const okFilter = buildMembershipFilter([okKeypair.pubHex], { epoch: EPOCH })

  const cases: [string, (bad: unknown) => unknown][] = [
    ['memberKey(bad)', (bad) => memberKey(bad as string)],
    ['memberKey(ok, bad)', (bad) => memberKey(okKeypair.pubHex, bad as string)],
    ['buildMembershipFilter(bad, ok)', (bad) => buildMembershipFilter(bad as string[], { epoch: EPOCH })],
    ['buildMembershipFilter(ok, bad)', (bad) => buildMembershipFilter([], bad as { epoch: number })],
    ['testMembership(bad, ok)', (bad) => testMembership(bad as MembershipFilter, 'a'.repeat(64))],
    ['testMembership(ok, bad)', (bad) => testMembership(okFilter, bad as string)],
    ['serializeFilter(bad)', (bad) => serializeFilter(bad as MembershipFilter)],
    ['parseFilter(bad)', (bad) => parseFilter(bad as Uint8Array)],
    ['signFilterBlob(bad, ok, ok)', (bad) => signFilterBlob(bad as Uint8Array, okKeypair.privHex, CTX)],
    ['signFilterBlob(ok, bad, ok)', (bad) => signFilterBlob(okBlob.slice(), bad as string, CTX)],
    ['signFilterBlob(ok, ok, bad)', (bad) => signFilterBlob(okBlob.slice(), okKeypair.privHex, bad as string)],
    ['verifyFilterBlob(bad, ok)', (bad) => verifyFilterBlob(bad as Uint8Array, CTX)],
    ['verifyFilterBlob(ok, bad)', (bad) => verifyFilterBlob(okBlob, bad as string)],
    ['verifyAndParseFilter(bad, ok)', (bad) => verifyAndParseFilter(bad as Uint8Array, { pinnedPubkeyHex: okKeypair.pubHex, context: CTX })],
    ['verifyAndParseFilter(ok, bad)', (bad) => verifyAndParseFilter(okBlob, bad as { pinnedPubkeyHex: string; context: string })],
    ['nextPowerOfTwoBand(bad)', (bad) => nextPowerOfTwoBand(bad as number)],
    ['deriveDecoys(bad, 1)', (bad) => deriveDecoys(bad as string, 1)],
    ['deriveDecoys(ok, bad)', (bad) => deriveDecoys('ab'.repeat(16), bad as number)],
    ['issuePresenceCapability(bad, ok)', (bad) => issuePresenceCapability(bad as { serverId: string; subjectPubHex: string; expiresAt: number }, okKeypair.privHex)],
    ['issuePresenceCapability(ok, bad)', (bad) => issuePresenceCapability({ serverId: 'srv', subjectPubHex: okKeypair.pubHex, expiresAt: 0 }, bad as string)],
    ['testWithCapability(bad, ok)', (bad) => testWithCapability(bad as MembershipFilter, okCap)],
    ['testWithCapability(ok, bad)', (bad) => testWithCapability(okFilter, bad as PresenceCapability)],
    ['buildFilterPublication(bad)', (bad) => buildFilterPublication(bad as { kind: number; tags: string[][]; blob: Uint8Array; createdAt: number })],
    ['decodeFilterPublicationContent(bad)', (bad) => decodeFilterPublicationContent(bad as string)],
  ]

  for (const [label, fn] of cases) {
    it(`${label} — null`, () => {
      assertNeverRawError(`${label} [null]`, () => fn(null))
    })
    it(`${label} — number`, () => {
      assertNeverRawError(`${label} [42]`, () => fn(42))
    })
  }
})

describe('TesseraError class', () => {
  it('is an instanceof Error, has name "TesseraError", and a readonly code', () => {
    const e = new TesseraError('INPUT_PUBKEY_INVALID', 'test message')
    expect(e).toBeInstanceOf(Error)
    expect(e).toBeInstanceOf(TesseraError)
    expect(e.name).toBe('TesseraError')
    expect(e.code).toBe('INPUT_PUBKEY_INVALID')
    expect(e.message).toBe('test message')
  })
})
