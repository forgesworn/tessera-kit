import { describe, it, expect } from 'vitest'
import { schnorr } from '@noble/curves/secp256k1.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { buildMembershipFilter, testMembership } from './filter.js'
import { memberKey } from './member-key.js'
import { serializeFilter, parseFilter, OFF_FINGERPRINTS } from './codec.js'
import { signFilterBlob, verifyFilterBlob, verifyAndParseFilter } from './sign.js'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import type { MembershipFilter } from './types.js'

// Deterministic distinct 64-hex pubkeys (same style as codec.test.ts).
const pubkeys = (n: number, tag = 7): string[] =>
  Array.from({ length: n }, (_, i) =>
    bytesToHex(sha256(new Uint8Array([i & 255, (i >> 8) & 255, tag]))),
  )

const EPOCH = 1_700_000_000

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

function signedBlob(n = 50, tag = 7): { blob: Uint8Array; memberKeys: string[] } {
  const { f, memberKeys } = openFilter(n, tag)
  const unsigned = serializeFilter(f)
  const blob = signFilterBlob(unsigned, SERVER.privHex)
  return { blob, memberKeys }
}

describe('signFilterBlob / verifyFilterBlob — round-trip', () => {
  it('signs an unsigned KFLT blob and verifies valid with the correct signer pubkey', () => {
    const { blob } = signedBlob(50)
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
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
      const { ok, signerPubkeyHex } = verifyFilterBlob(blob)
      expect(ok).toBe(true)
      expect(signerPubkeyHex).toBe(SERVER.pubHex)
    }
  })

  it('mutates the buffer in place and returns the same buffer', () => {
    const { f } = openFilter(15)
    const unsigned = serializeFilter(f)
    const returned = signFilterBlob(unsigned, SERVER.privHex)
    expect(returned).toBe(unsigned) // same reference (in-place mutation, documented)
  })
})

describe('signFilterBlob — input validation', () => {
  it('rejects a non-64-hex private key', () => {
    const { f } = openFilter(10)
    const unsigned = serializeFilter(f)
    expect(() => signFilterBlob(unsigned, 'deadbeef')).toThrow()
    expect(() => signFilterBlob(unsigned, 'z'.repeat(64))).toThrow()
    expect(() => signFilterBlob(unsigned, SERVER.privHex.slice(0, 63))).toThrow()
  })

  it('rejects a too-short blob (< 128 bytes)', () => {
    expect(() => signFilterBlob(new Uint8Array(127), SERVER.privHex)).toThrow()
  })
})

describe('signFilterBlob → end-to-end with parseFilter', () => {
  it('a signed blob still parses and every member tests true (signing does not corrupt fingerprints)', () => {
    const { blob, memberKeys } = signedBlob(80, 41)
    // Verify provenance...
    expect(verifyFilterBlob(blob).ok).toBe(true)
    // ...and the structure is intact.
    const parsed = parseFilter(blob)
    for (const k of memberKeys) expect(testMembership(parsed, k)).toBe(true)
  })

  it('build → serialize → sign → parse preserves scalar header fields', () => {
    const { f } = openFilter(60)
    const blob = signFilterBlob(serializeFilter(f), SERVER.privHex)
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
    expect(verifyFilterBlob(blob).ok).toBe(false)
  })

  it('(b) flipping a byte in signer_pubkey [32,64) invalidates (verify uses a different key)', () => {
    const { blob } = signedBlob(40)
    blob[40] ^= 0xff // inside signer_pubkey
    const { ok } = verifyFilterBlob(blob)
    expect(ok).toBe(false)
  })

  it('(c) flipping a byte in the sig [64,128) invalidates', () => {
    const { blob } = signedBlob(40)
    blob[100] ^= 0xff // inside sig
    expect(verifyFilterBlob(blob).ok).toBe(false)
  })

  it('(d) flipping a byte in the fingerprint array [128,end) invalidates', () => {
    const { blob } = signedBlob(40)
    blob[blob.length - 1] ^= 0xff // last fingerprint byte
    expect(verifyFilterBlob(blob).ok).toBe(false)
  })

  it('every single-byte flip across the whole blob invalidates (exhaustive over a small blob)', () => {
    const { blob } = signedBlob(8, 55)
    for (let i = 0; i < blob.length; i++) {
      const b = blob.slice()
      b[i] = (b[i] as number) ^ 0xff
      // A flip anywhere — header, signer, sig, or fingerprints — must break it.
      // (signer_pubkey flips change the verifying key, which also yields false.)
      expect(verifyFilterBlob(b).ok).toBe(false)
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
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
    expect(signerPubkeyHex).toBe(KEY_B.pubHex) // it reports the embedded (forged) key
    expect(ok).toBe(false) // ...but the sig doesn't verify under it
  })
})

describe('verifyFilterBlob — pinned-key threat model (spec §10 invariant 5)', () => {
  it('an attacker can produce a validly-self-signed blob, but a pinned-key check rejects it', () => {
    // The attacker builds and signs their OWN blob under their OWN key.
    const ATTACKER = keypairFromSeed(0x99)
    const { f } = openFilter(25, 77)
    const forged = signFilterBlob(serializeFilter(f), ATTACKER.privHex)

    const { signerPubkeyHex, ok } = verifyFilterBlob(forged)
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
    const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
    const PINNED_SERVER_PUBKEY = SERVER.pubHex
    expect(ok && signerPubkeyHex === PINNED_SERVER_PUBKEY).toBe(true)
  })
})

describe('verifyFilterBlob — malformed input does not throw', () => {
  it('too-short blob (< 128 bytes) → ok:false, no throw', () => {
    for (const len of [0, 1, 32, 64, 127]) {
      const { ok, signerPubkeyHex } = verifyFilterBlob(new Uint8Array(len))
      expect(ok).toBe(false)
      expect(signerPubkeyHex).toBe('')
    }
  })

  it('a 128-byte all-zero blob (zero pubkey, zero sig) → ok:false, no throw', () => {
    const { ok } = verifyFilterBlob(new Uint8Array(128))
    expect(ok).toBe(false)
  })

  it('random 128-byte garbage → ok:false, no throw', () => {
    const b = new Uint8Array(200)
    for (let i = 0; i < b.length; i++) b[i] = (i * 73 + 11) & 0xff
    expect(() => verifyFilterBlob(b)).not.toThrow()
    expect(verifyFilterBlob(b).ok).toBe(false)
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
    const { ok, signerPubkeyHex } = verifyFilterBlob(big)
    expect(ok).toBe(false)
    expect(signerPubkeyHex).toBe('')
  })

  it('verifyAndParseFilter throws for an oversized blob (pin check fails before parseFilter is ever reached)', () => {
    const big = new Uint8Array(KFLT_MAX_BLOB_BYTES + 1)
    const { blob } = signedBlob(10, 201)
    big.set(blob.subarray(0, OFF_FINGERPRINTS), 0)
    expect(() =>
      verifyAndParseFilter(big, { pinnedPubkeyHex: SERVER.pubHex }),
    ).toThrow('signature invalid or signer does not match')
  })
})

// B4 (audit fix) — verifyAndParseFilter: the combined pin-verify + parse +
// freshness helper. Makes the mandatory pin check and the (new) minEpoch
// freshness check the only path, closing the "forgot to pin" and "no rollback
// check" gaps left by using verifyFilterBlob/parseFilter separately.
describe('verifyAndParseFilter (B4 audit fix)', () => {
  it('returns the parsed filter when the blob is validly signed by the pinned key', () => {
    const { blob, memberKeys } = signedBlob(30, 90)
    const filter = verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex })
    for (const k of memberKeys) expect(testMembership(filter, k)).toBe(true)
    expect(filter.epoch).toBe(EPOCH)
  })

  it('accepts the pinned key case-insensitively', () => {
    const { blob } = signedBlob(10, 91)
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex.toUpperCase() }),
    ).not.toThrow()
  })

  it('throws when the signer does not match the pinned key (cross-server substitution)', () => {
    const { blob } = signedBlob(10, 92)
    const OTHER = keypairFromSeed(0x33)
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: OTHER.pubHex }),
    ).toThrow()
  })

  it('throws when the signature is internally invalid (tampered blob)', () => {
    const { blob } = signedBlob(10, 93)
    blob[100] ^= 0xff // inside the sig region
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex }),
    ).toThrow()
  })

  it('throws on a too-short blob (fails the pin check — ok:false — before parseFilter is ever reached)', () => {
    // A too-short blob fails verifyFilterBlob first (signerPubkeyHex: '', ok:false),
    // so this exercises the PIN-CHECK failure path, not the parse-failure path —
    // see the next test for a blob that passes the pin check and fails at parse.
    expect(() =>
      verifyAndParseFilter(new Uint8Array(10), { pinnedPubkeyHex: SERVER.pubHex }),
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
    const blob = signFilterBlob(unsigned, SERVER.privHex)
    expect(verifyFilterBlob(blob).ok).toBe(true) // sanity: pin check would pass
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex }),
    ).toThrow(/reserved flag/i)
  })

  it('throws on a CORRECTLY-SIGNED blob with a non-power-of-two member_count_band (passes the pin check, fails at parseFilter)', () => {
    const { f } = openFilter(12, 97)
    const unsigned = serializeFilter(f)
    new DataView(unsigned.buffer, unsigned.byteOffset, unsigned.byteLength).setUint32(28, 5, true)
    const blob = signFilterBlob(unsigned, SERVER.privHex)
    expect(verifyFilterBlob(blob).ok).toBe(true) // sanity: pin check would pass
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex }),
    ).toThrow(/member_count_band/)
  })

  it('accepts a filter whose epoch is >= minEpoch', () => {
    const { blob } = signedBlob(10, 94)
    const filter = verifyAndParseFilter(blob, {
      pinnedPubkeyHex: SERVER.pubHex,
      minEpoch: EPOCH,
    })
    expect(filter.epoch).toBe(EPOCH)
  })

  it('throws on a stale/rolled-back filter whose epoch is < minEpoch', () => {
    const { blob } = signedBlob(10, 95)
    expect(() =>
      verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, minEpoch: EPOCH + 1 }),
    ).toThrow(/stale|rollback/)
  })

  // Review follow-up — verifyAndParseFilter input validation (opts themselves).
  describe('opts validation', () => {
    it('throws on a non-64-hex pinnedPubkeyHex', () => {
      const { blob } = signedBlob(10, 98)
      expect(() => verifyAndParseFilter(blob, { pinnedPubkeyHex: 'abc' })).toThrow(
        'pinnedPubkeyHex must be 64 hex chars',
      )
    })

    it('throws on a NaN minEpoch instead of silently accepting a stale blob (audit fix)', () => {
      // Before the fix, `filter.epoch < NaN` is always false, so a NaN minEpoch
      // would accept ANY epoch — the same footgun as B5's NaN capability clock.
      const { blob } = signedBlob(10, 99)
      expect(() =>
        verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, minEpoch: Number.NaN }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })

    it('throws on a negative minEpoch', () => {
      const { blob } = signedBlob(10, 100)
      expect(() =>
        verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, minEpoch: -1 }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })

    it('throws on a fractional minEpoch', () => {
      const { blob } = signedBlob(10, 101)
      expect(() =>
        verifyAndParseFilter(blob, { pinnedPubkeyHex: SERVER.pubHex, minEpoch: 1.5 }),
      ).toThrow('minEpoch must be a non-negative safe integer')
    })
  })
})
