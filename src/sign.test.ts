import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'
import { serializeFilter, parseFilter, OFF_FINGERPRINTS } from './codec.js'
import { signFilterBlob, verifyFilterBlob, verifyAndParseFilter, isValidFilterContext } from './sign.js'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import type { MembershipFilter } from './types.js'

// Deterministic distinct 64-hex pubkeys (same style as codec.test.ts).
const pubkeys = (n: number, tag = 7): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )

const EPOCH = 1_700_000_000

// The context every test signs/verifies against unless the test specifically
// exercises context mismatch/validation. Stands in for a deployment's stable
// address — e.g. a kindred d-tag `kindred:members:<ns>:<serverId>` (§4.3/§6).
const CTX = 'test-ctx:example-server'

function openFilter(n: number, tag = 7): { f: MembershipFilter; memberKeys: string[] } {
  const pks = pubkeys(n, tag)
  const memberKeys = pks.map((pk) => memberKey(pk))
  const f = buildMembershipFilter(memberKeys, { epoch: EPOCH, fingerprintBits: 16 })
  return { f, memberKeys }
}

/** Deterministic Schnorr keypair from a label byte (so tests are reproducible).
 *  The 32-byte private key is sha256(label) — a valid secp256k1 scalar w.o.p.;
 *  the x-only pubkey is derived by the same API `sign.ts` uses. */
function keypairFromSeed(byte: number): { privHex: string; pubHex: string } {
  const privBytes = sha256(new Uint8Array([byte, 0x5e, 0xed]))
  const pubHex = bytesToHex(schnorr.getPublicKey(privBytes))
  return { privHex: bytesToHex(privBytes), pubHex }
}

const SERVER = keypairFromSeed(0x11)

function signedBlob(
  n = 50,
  tag = 7,
  context = CTX,
): { blob: Uint8Array; memberKeys: string[] } {
  const { f, memberKeys } = openFilter(n, tag)
  const unsigned = serializeFilter(f)
  const blob = signFilterBlob(unsigned, SERVER.privHex, context)
  return { blob, memberKeys }
}

/** Independent re-implementation of `computeDigest` (sign.ts) using
 *  `node:crypto` instead of `@noble/hashes`, so the digest formula is
 *  hand-checked against a second SHA-256 implementation, not just this
 *  package's own dependency. Mirrors the exact byte layout in PROTOCOL.md
 *  §4.1:
 *    sha256( utf8("tessera-kflt-sig:v1") ‖ 0x00 ‖ u32be(byteLen(ctx)) ‖
 *            utf8(ctx) ‖ blob[0..64) ‖ sha256(blob[128..end)) )
 */
function independentDigest(blob: Uint8Array, context: string): Uint8Array {
  const ctxBytes = Buffer.from(context, 'utf8')
  const lenBytes = Buffer.alloc(4)
  lenBytes.writeUInt32BE(ctxBytes.length, 0)
  const fingerprintHash = createHash('sha256').update(blob.subarray(128)).digest()
  const preimage = Buffer.concat([
    Buffer.from('tessera-kflt-sig:v1', 'utf8'),
    Buffer.from([0x00]),
    lenBytes,
    ctxBytes,
    Buffer.from(blob.subarray(0, 64)),
    fingerprintHash,
  ])
  return new Uint8Array(createHash('sha256').update(preimage).digest())
}

describe('signFilterBlob / verifyFilterBlob — round-trip', () => {
  it('signs an unsigned KFLT blob and verifies valid with the correct signer pubkey and context', () => {
    const { blob } = signedBlob(50)
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob, CTX)
    expect(ok).toBe(true)
    expect(signerPubkeyHex).toBe(SERVER.pubHex)
  })

  it('writes the signer pubkey into [32,64) and a non-zero sig into [64,128)', () => {
    const { blob } = signedBlob(20)
    expect(bytesToHex(blob.subarray(32, 64))).toBe(SERVER.pubHex)
    // sig region must be populated (overwhelmingly non-zero).
    let nonZero = 0
    for (let i = 64; i < 128; i++) if ((blob[i] as number) !== 0) nonZero++
    expect(nonZero).toBeGreaterThan(0)
  })

  it('round-trips across many sizes', () => {
    for (const n of [0, 1, 2, 3, 10, 100, 500]) {
      const { blob } = signedBlob(n, 30 + n)
      const { ok, signerPubkeyHex } = verifyFilterBlob(blob, CTX)
      expect(ok).toBe(true)
      expect(signerPubkeyHex).toBe(SERVER.pubHex)
    }
  })

  it('mutates the buffer in place and returns the same buffer', () => {
    const { f } = openFilter(15)
    const unsigned = serializeFilter(f)
    const returned = signFilterBlob(unsigned, SERVER.privHex, CTX)
    expect(returned).toBe(unsigned) // same reference (in-place mutation, documented)
  })
})

// Signature-context binding (spec §4.1/§4.3) — the digest now folds in a
// caller-supplied `context` string so a blob validly signed for one
// deployment cannot be replayed as another's, even under a reused signing
// key. This is the fix for the "the blob does not name its server" gap.
describe('signFilterBlob / verifyFilterBlob — context binding', () => {
  it('a blob signed for context A does not verify under context B (same key, same bytes otherwise)', () => {
    const { blob } = signedBlob(20, 10, 'server-a')
    expect(verifyFilterBlob(blob, 'server-a').ok).toBe(true)
    expect(verifyFilterBlob(blob, 'server-b').ok).toBe(false)
  })

  it('signFilterBlob requires a non-empty string context', () => {
    const { f } = openFilter(5)
    const unsigned = serializeFilter(f)
    expect(() => signFilterBlob(unsigned, SERVER.privHex, '')).toThrow()
    // @ts-expect-error — deliberately wrong type for the runtime check.
    expect(() => signFilterBlob(serializeFilter(f), SERVER.privHex, undefined)).toThrow()
  })

  it('signFilterBlob rejects a context with an unpaired UTF-16 surrogate', () => {
    const { f } = openFilter(5)
    const unsigned = serializeFilter(f)
    expect(() => signFilterBlob(unsigned, SERVER.privHex, 'a\uD800')).toThrow()
  })

  it('signFilterBlob rejects a context whose UTF-8 encoding exceeds 1024 bytes', () => {
    const { f } = openFilter(5)
    const unsigned = serializeFilter(f)
    const tooLong = 'x'.repeat(1025) // ASCII: 1 char == 1 UTF-8 byte
    expect(() => signFilterBlob(unsigned, SERVER.privHex, tooLong)).toThrow()
    // Exactly 1024 bytes is fine.
    const { f: f2 } = openFilter(5, 999)
    const ok = signFilterBlob(serializeFilter(f2), SERVER.privHex, 'x'.repeat(1024))
    expect(verifyFilterBlob(ok, 'x'.repeat(1024)).ok).toBe(true)
  })

  it('verifyFilterBlob requires a context argument (usage error, not a silent ok:false)', () => {
    const { blob } = signedBlob(10)
    // @ts-expect-error — deliberately wrong type for the runtime check.
    expect(() => verifyFilterBlob(blob, undefined)).toThrow()
    expect(() => verifyFilterBlob(blob, '')).toThrow()
  })

  it('byte-exact, no Unicode normalisation: NFC vs NFD context strings are DIFFERENT contexts', () => {
    const nfc = 'é' // é, precomposed
    const nfd = 'é' // e + combining acute, decomposed
    expect(nfc.normalize('NFC')).not.toBe(nfd) // sanity: distinct JS strings
    const { blob } = signedBlob(10, 55, nfc)
    expect(verifyFilterBlob(blob, nfc).ok).toBe(true)
    expect(verifyFilterBlob(blob, nfd).ok).toBe(false)
  })

  it('the digest matches an independent node:crypto re-implementation of the formula', () => {
    const { blob } = signedBlob(12, 61, CTX)
    // Re-derive the digest independently and confirm the EMBEDDED signature
    // verifies against it — this proves sign.ts's computeDigest computes
    // exactly this formula, hand-checked against a second SHA-256 stack.
    const independent = independentDigest(blob, CTX)
    const ok = schnorr.verify(blob.subarray(64, 128), independent, blob.subarray(32, 64))
    expect(ok).toBe(true)
  })
})

// kenspeckle adoption follow-up — `isValidFilterContext` is exported (from
// sign.ts and the main entry) as the ONE reusable predicate for "is this a
// valid `context` string," so a caller (e.g. kenspeckle deciding whether to
// even attempt a sign/verify call, or validating a config value up front)
// doesn't need to hand-roll the same three rules (non-empty, well-formed
// UTF-16, <=1024 UTF-8 bytes) a second time. `signFilterBlob`/
// `verifyFilterBlob` use this SAME predicate internally (see `assertContext`
// in sign.ts) — it is not a parallel, independently-maintained copy of the
// same rules.
describe('isValidFilterContext', () => {
  it('accepts a normal non-empty ASCII string', () => {
    expect(isValidFilterContext('kindred:members:ns:server')).toBe(true)
  })

  it('rejects non-strings, including null and undefined', () => {
    expect(isValidFilterContext(null)).toBe(false)
    expect(isValidFilterContext(undefined)).toBe(false)
    expect(isValidFilterContext(42)).toBe(false)
    expect(isValidFilterContext(true)).toBe(false)
    expect(isValidFilterContext({})).toBe(false)
    expect(isValidFilterContext([])).toBe(false)
    expect(isValidFilterContext(['a'])).toBe(false)
  })

  it('rejects the empty string', () => {
    expect(isValidFilterContext('')).toBe(false)
  })

  it('rejects a lone (unpaired) UTF-16 surrogate', () => {
    expect(isValidFilterContext('a\uD800')).toBe(false)
    expect(isValidFilterContext('\uDC00b')).toBe(false)
  })

  it('accepts a well-formed surrogate PAIR (a real non-BMP character)', () => {
    expect(isValidFilterContext('a😀b')).toBe(true) // 😀 between two ASCII chars
  })

  // Boundary: exactly 1024 UTF-8 bytes accepted, 1025 rejected.
  it('accepts a context whose UTF-8 encoding is EXACTLY 1024 bytes', () => {
    expect(isValidFilterContext('x'.repeat(1024))).toBe(true) // ASCII: 1 char == 1 byte
  })

  it('rejects a context whose UTF-8 encoding is 1025 bytes (one over)', () => {
    expect(isValidFilterContext('x'.repeat(1025))).toBe(false)
  })

  it('applies the UTF-8 byte bound, not the JS character-length bound (multi-byte chars)', () => {
    // 'é' below is 2 UTF-8 bytes each; 512 of them is exactly 1024 bytes.
    expect(isValidFilterContext('é'.repeat(512))).toBe(true)
    expect(isValidFilterContext('é'.repeat(513))).toBe(false) // 1026 bytes
  })

  // Agreement with sign/verify acceptance — isValidFilterContext must predict
  // EXACTLY whether signFilterBlob/verifyFilterBlob reject `context` with a
  // SIGN_CONTEXT_*/VERIFY_CONTEXT_* code, for the same set of inputs the
  // boundary tests above use, plus a few more.
  const AGREEMENT_INPUTS: unknown[] = [
    'kindred:members:ns:server',
    '',
    'a\uD800',
    '\uDC00b',
    'a😀b',
    'x'.repeat(1024),
    'x'.repeat(1025),
    'é'.repeat(512),
    'é'.repeat(513),
    null,
    undefined,
    42,
    {},
  ]

  it('signFilterBlob throws a SIGN_CONTEXT_* code iff isValidFilterContext is false', () => {
    for (const ctx of AGREEMENT_INPUTS) {
      const { f } = openFilter(3, 200 + AGREEMENT_INPUTS.indexOf(ctx))
      const unsigned = serializeFilter(f)
      const expectedValid = isValidFilterContext(ctx)
      let threwContextCode = false
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        signFilterBlob(unsigned, SERVER.privHex, ctx as any)
      } catch (e) {
        const code = (e as { code?: string }).code
        threwContextCode = typeof code === 'string' && code.startsWith('SIGN_CONTEXT_')
      }
      expect(threwContextCode, `context=${JSON.stringify(ctx)}`).toBe(!expectedValid)
    }
  })

  it('verifyFilterBlob throws a VERIFY_CONTEXT_* code iff isValidFilterContext is false', () => {
    const { blob } = signedBlob(3, 250)
    for (const ctx of AGREEMENT_INPUTS) {
      const expectedValid = isValidFilterContext(ctx)
      let threwContextCode = false
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        verifyFilterBlob(blob, ctx as any)
      } catch (e) {
        const code = (e as { code?: string }).code
        threwContextCode = typeof code === 'string' && code.startsWith('VERIFY_CONTEXT_')
      }
      expect(threwContextCode, `context=${JSON.stringify(ctx)}`).toBe(!expectedValid)
    }
  })
})

describe('signFilterBlob — input validation', () => {
  it('rejects a non-64-hex private key', () => {
    const { f } = openFilter(10)
    const unsigned = serializeFilter(f)
    expect(() => signFilterBlob(unsigned, 'deadbeef', CTX)).toThrow()
    expect(() => signFilterBlob(unsigned, 'z'.repeat(64), CTX)).toThrow()
    expect(() => signFilterBlob(unsigned, SERVER.privHex.slice(0, 63), CTX)).toThrow()
  })

  it('rejects a too-short blob (< 128 bytes)', () => {
    expect(() => signFilterBlob(new Uint8Array(127), SERVER.privHex, CTX)).toThrow()
  })
})

describe('signFilterBlob → end-to-end with parseFilter', () => {
  it('a signed blob still parses and every member tests true (signing does not corrupt fingerprints)', () => {
    const { blob, memberKeys } = signedBlob(80, 41)
    // Verify provenance...
    expect(verifyFilterBlob(blob, CTX).ok).toBe(true)
    // ...and the structure is intact.
    const parsed = parseFilter(blob)
    for (const k of memberKeys) expect(testMembership(parsed, k)).toBe(true)
  })

  it('build → serialize → sign → parse preserves scalar header fields', () => {
    const { f } = openFilter(60)
    const blob = signFilterBlob(serializeFilter(f), SERVER.privHex, CTX)
    const parsed = parseFilter(blob)
    expect(parsed.epoch).toBe(EPOCH)
    expect(parsed.keyed).toBe(false)
    expect(parsed._memberCountBand).toBe(f._memberCountBand)
    expect(parsed.type).toBe(1)
    expect(parsed.fingerprintBits).toBe(16)
  })
})

describe('verifyFilterBlob — tamper detection (flip a byte in each region)', () => {
  it('(a) flipping a byte in the header [0,32) invalidates', () => {
    const { blob } = signedBlob(40)
    blob[8] ^= 0xff // inside epoch field, header region
    expect(verifyFilterBlob(blob, CTX).ok).toBe(false)
  })

  it('(b) flipping a byte in signer_pubkey [32,64) invalidates (verify uses a different key)', () => {
    const { blob } = signedBlob(40)
    blob[40] ^= 0xff // inside signer_pubkey
    const { ok } = verifyFilterBlob(blob, CTX)
    expect(ok).toBe(false)
  })

  it('(c) flipping a byte in the sig [64,128) invalidates', () => {
    const { blob } = signedBlob(40)
    blob[100] ^= 0xff // inside sig
    expect(verifyFilterBlob(blob, CTX).ok).toBe(false)
  })

  it('(d) flipping a byte in the fingerprint array [128,end) invalidates', () => {
    const { blob } = signedBlob(40)
    blob[blob.length - 1] ^= 0xff // last fingerprint byte
    expect(verifyFilterBlob(blob, CTX).ok).toBe(false)
  })

  it('every single-byte flip across the whole blob invalidates (exhaustive over a small blob)', () => {
    const { blob } = signedBlob(8, 55)
    for (let i = 0; i < blob.length; i++) {
      const b = blob.slice()
      b[i] = (b[i] as number) ^ 0xff
      // A flip anywhere — header, signer, sig, or fingerprints — must break it.
      // (signer_pubkey flips change the verifying key, which also yields false.)
      expect(verifyFilterBlob(b, CTX).ok).toBe(false)
    }
  })
})

describe('verifyFilterBlob — wrong key', () => {
  it('a blob signed by A but with signer_pubkey overwritten by B (no re-sign) is invalid', () => {
    const { blob } = signedBlob(30)
    const KEY_B = keypairFromSeed(0x22)
    expect(KEY_B.pubHex).not.toBe(SERVER.pubHex)
    // Overwrite signer_pubkey [32,64) with B's pubkey, leaving A's sig in place.
    blob.set(hexToBytes(KEY_B.pubHex), 32)
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob, CTX)
    expect(signerPubkeyHex).toBe(KEY_B.pubHex) // it reports the embedded (forged) key
    expect(ok).toBe(false) // ...but the sig doesn't verify under it
  })
})

describe('verifyFilterBlob — pinned-key threat model (PROTOCOL.md §4.2)', () => {
  it('an attacker can produce a validly-self-signed blob, but a pinned-key check rejects it', () => {
    // The attacker builds and signs their OWN blob under their OWN key.
    const ATTACKER = keypairFromSeed(0x99)
    const { f } = openFilter(25, 77)
    const forged = signFilterBlob(serializeFilter(f), ATTACKER.privHex, CTX)

    const { signerPubkeyHex, ok } = verifyFilterBlob(forged, CTX)
    // The blob is internally consistent — ok:true...
    expect(ok).toBe(true)
    // ...but the signer is the attacker, NOT the server we pinned.
    expect(signerPubkeyHex).toBe(ATTACKER.pubHex)

    // A consumer MUST compare against the pinned/known server key. ok:true is
    // NOT trust. This pinned-key comparison is what defeats forged-filter doxxing.
    const PINNED_SERVER_PUBKEY = SERVER.pubHex
    const trusted = ok && signerPubkeyHex === PINNED_SERVER_PUBKEY
    expect(trusted).toBe(false) // rejected: attacker's key ≠ pinned key
    expect(signerPubkeyHex).not.toBe(PINNED_SERVER_PUBKEY)
  })

  it('the same check ACCEPTS a blob signed by the pinned key', () => {
    const { blob } = signedBlob(25, 78)
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob, CTX)
    const PINNED_SERVER_PUBKEY = SERVER.pubHex
    expect(ok && signerPubkeyHex === PINNED_SERVER_PUBKEY).toBe(true)
  })
})

describe('verifyFilterBlob — malformed input does not throw', () => {
  it('too-short blob (< 128 bytes) → ok:false, no throw', () => {
    for (const len of [0, 1, 32, 64, 127]) {
      const { ok, signerPubkeyHex } = verifyFilterBlob(new Uint8Array(len), CTX)
      expect(ok).toBe(false)
      expect(signerPubkeyHex).toBe('')
    }
  })

  it('a 128-byte all-zero blob (zero pubkey, zero sig) → ok:false, no throw', () => {
    const { ok } = verifyFilterBlob(new Uint8Array(128), CTX)
    expect(ok).toBe(false)
  })

  it('random 128-byte garbage → ok:false, no throw', () => {
    const b = new Uint8Array(200)
    for (let i = 0; i < b.length; i++) b[i] = (i * 73 + 11) & 0xff
    expect(() => verifyFilterBlob(b, CTX)).not.toThrow()
    expect(verifyFilterBlob(b, CTX).ok).toBe(false)
  })
})

// L1 audit fix — an oversized blob is rejected BEFORE any hashing, not just
// (eventually) by parseFilter. Before the fix, `verifyFilterBlob` SHA-256'd
// the entire `blob[128..end)` region unconditionally — a raw-HTTPS caller who
// handed it a huge hostile blob paid for that hash before any size check ran.
describe('verifyFilterBlob / verifyAndParseFilter — oversized blob rejected before hashing (L1 audit fix)', () => {
  it('verifyFilterBlob returns ok:false, no throw, for a blob over KFLT_MAX_BLOB_BYTES', () => {
    const big = new Uint8Array(KFLT_MAX_BLOB_BYTES + 1)
    // Give it a plausible-looking header (magic + real signer/sig prefix) so
    // that, if the size check were missing, it would proceed to hash and
    // verify rather than failing for some unrelated reason.
    const { blob } = signedBlob(10, 200)
    big.set(blob.subarray(0, OFF_FINGERPRINTS), 0)
    const { ok, signerPubkeyHex } = verifyFilterBlob(big, CTX)
    expect(ok).toBe(false)
    expect(signerPubkeyHex).toBe('')
  })

  it('verifyAndParseFilter throws for an oversized blob (pin check fails before parseFilter is ever reached)', () => {
    const big = new Uint8Array(KFLT_MAX_BLOB_BYTES + 1)
    const { blob } = signedBlob(10, 201)
    big.set(blob.subarray(0, OFF_FINGERPRINTS), 0)
    expect(() =>
      verifyAndParseFilter(big, { pinnedPubkeyHex: SERVER.pubHex, context: CTX }),
    ).toThrow('signature invalid or signer does not match')
  })
})

// B4 (audit fix) — verifyAndParseFilter: the combined pin-verify + parse +
// freshness helper. Makes the mandatory pin check and the (new) minEpoch
// freshness check the only path, closing the "forgot to pin" and "no rollback
// check" gaps left by using verifyFilterBlob/parseFilter separately.
describe('verifyAndParseFilter (B4 audit fix)', () => {
  it('returns the parsed filter when the blob is validly signed by the pinned key and context', () => {
    const { blob, memberKeys } = signedBlob(30, 90)
    const filter = verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: CTX })
    for (const k of memberKeys) expect(testMembership(filter, k)).toBe(true)
    expect(filter.epoch).toBe(EPOCH)
  })

  it('accepts the pinned key case-insensitively', () => {
    const { blob } = signedBlob(10, 91)
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex.toUpperCase(), context: CTX }),
    ).not.toThrow()
  })

  it('throws when the signer does not match the pinned key (cross-server substitution)', () => {
    const { blob } = signedBlob(10, 92)
    const OTHER = keypairFromSeed(0x33)
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: OTHER.pubHex, context: CTX }),
    ).toThrow()
  })

  it('throws when the signature is internally invalid (tampered blob)', () => {
    const { blob } = signedBlob(10, 93)
    blob[100] ^= 0xff // inside the sig region
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: CTX }),
    ).toThrow()
  })

  it('throws on a too-short blob (fails the pin check — ok:false — before parseFilter is ever reached)', () => {
    // A too-short blob fails verifyFilterBlob first (signerPubkeyHex: '', ok:false),
    // so this exercises the PIN-CHECK failure path, not the parse-failure path —
    // see the next test for a blob that passes the pin check and fails at parse.
    expect(() =>
      verifyAndParseFilter(new Uint8Array(10), { pinnedPubkeyHex: SERVER.pubHex, context: CTX }),
    ).toThrow('signature invalid or signer does not match')
  })

  it('throws on a CORRECTLY-SIGNED blob with a reserved flag bit set (passes the pin check, fails at parseFilter)', () => {
    // Set the reserved bit BEFORE signing, so the signature covers it and the
    // blob is internally consistent — verifyFilterBlob/the pin check PASS. The
    // failure must come from parseFilter's structural validation (B9), reached
    // only after the pin check succeeds.
    const { f } = openFilter(12, 96)
    const unsigned = serializeFilter(f)
    unsigned[7] = (unsigned[7] as number) | 0x04 // bit 2, reserved
    const blob = signFilterBlob(unsigned, SERVER.privHex, CTX)
    expect(verifyFilterBlob(blob, CTX).ok).toBe(true) // sanity: pin check would pass
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: CTX }),
    ).toThrow(/reserved flag/i)
  })

  it('throws on a CORRECTLY-SIGNED blob with a non-power-of-two member_count_band (passes the pin check, fails at parseFilter)', () => {
    const { f } = openFilter(12, 97)
    const unsigned = serializeFilter(f)
    new DataView(unsigned.buffer, unsigned.byteOffset, unsigned.byteLength).setUint32(28, 5, true)
    const blob = signFilterBlob(unsigned, SERVER.privHex, CTX)
    expect(verifyFilterBlob(blob, CTX).ok).toBe(true) // sanity: pin check would pass
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: CTX }),
    ).toThrow(/member_count_band/)
  })

  it('accepts a filter whose epoch is >= minEpoch', () => {
    const { blob } = signedBlob(10, 94)
    const filter = verifyAndParseFilter(blob, {
      pinnedPubkeyHex: SERVER.pubHex,
      context: CTX,
      minEpoch: EPOCH,
    })
    expect(filter.epoch).toBe(EPOCH)
  })

  it('throws on a stale/rolled-back filter whose epoch is < minEpoch', () => {
    const { blob } = signedBlob(10, 95)
    expect(() =>
      verifyAndParseFilter(blob, {
        pinnedPubkeyHex: SERVER.pubHex,
        context: CTX,
        minEpoch: EPOCH + 1,
      }),
    ).toThrow(/stale|rollback/)
  })

  // Context mismatch — the security-load-bearing case (spec §4.3): a blob
  // signed for one deployment's context must be rejected when checked against
  // a DIFFERENT context, and the failure must be the SAME generic message as
  // a bad signature/wrong signer — never a distinguishable "context mismatch"
  // error, so a caller can't probe which check failed.
  describe('context binding', () => {
    it('throws the SAME generic message for a wrong context as for a wrong signer', () => {
      const { blob } = signedBlob(10, 110, 'server-a')
      let wrongContextMessage = ''
      let wrongSignerMessage = ''
      try {
        verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: 'server-b' })
      } catch (e) {
        wrongContextMessage = (e as Error).message
      }
      const OTHER = keypairFromSeed(0x44)
      try {
        verifyAndParseFilter(blob, { pinnedPubkeyHex: OTHER.pubHex, context: 'server-a' })
      } catch (e) {
        wrongSignerMessage = (e as Error).message
      }
      expect(wrongContextMessage).not.toBe('')
      expect(wrongContextMessage).toBe(wrongSignerMessage)
    })

    it('verifyAndParseFilter requires a context option', () => {
      const { blob } = signedBlob(10, 111)
      // @ts-expect-error — deliberately omitted for the runtime check.
      expect(() => verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex })).toThrow()
    })
  })

  // Review follow-up — verifyAndParseFilter input validation (opts themselves).
  describe('opts validation', () => {
    it('throws on a non-64-hex pinnedPubkeyHex', () => {
      const { blob } = signedBlob(10, 98)
      expect(() =>
        verifyAndParseFilter(blob, { pinnedPubkeyHex: 'abc', context: CTX }),
      ).toThrow('pinnedPubkeyHex must be 64 hex chars')
    })

    it('throws on a NaN minEpoch instead of silently accepting a stale blob (audit fix)', () => {
      // Before the fix, `filter.epoch < NaN` is always false, so a NaN minEpoch
      // would accept ANY epoch — the same footgun as B5's NaN capability clock.
      const { blob } = signedBlob(10, 99)
      expect(() =>
        verifyAndParseFilter(blob, {
          pinnedPubkeyHex: SERVER.pubHex,
          context: CTX,
          minEpoch: Number.NaN,
        }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })

    it('throws on a negative minEpoch', () => {
      const { blob } = signedBlob(10, 100)
      expect(() =>
        verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, context: CTX, minEpoch: -1 }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })

    it('throws on a fractional minEpoch', () => {
      const { blob } = signedBlob(10, 101)
      expect(() =>
        verifyAndParseFilter(blob, {
          pinnedPubkeyHex: SERVER.pubHex,
          context: CTX,
          minEpoch: 1.5,
        }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })
  })
})
