// KFLT byte codec — serialize a `MembershipFilter` to / parse it from the
// on-wire `KFLT` blob (spec §7.3, §7.6).
//
// HARDENING (parseFilter): this codec is the trust boundary for hostile input.
// `parseFilter` validates the header EXHAUSTIVELY and recomputes the expected
// blob length from header geometry BEFORE allocating anything sized by an
// attacker-controlled field — a malformed blob can never trigger an unbounded
// allocation or read past its own bounds. Every reachable failure throws an
// `Error` (never a non-Error value), so callers can `try/catch (e instanceof
// Error)` uniformly.
//
// SIGNATURE IS NOT VERIFIED HERE. `parseFilter` deserializes structure only and
// leaves the signer_pubkey (off 32..64) and sig (off 64..128) regions opaque. A
// caller MUST call `verifyFilterBlob` (TK-5) on the raw blob BEFORE trusting any
// membership result from the parsed filter — an unverified blob is just bytes a
// stranger sent you. See `parseFilter`'s doc comment.
//
// SEED WIDTH: the fuse seed is 32-bit by construction (see fuse.ts), so the
// 4-byte `seed` field at off 16 holds it losslessly and the spec's 128-byte
// header is exact. We zero-extend on read via `BinaryFuse16.fromParts`.

import { BinaryFuse16 } from './fuse.js'
import {
  KFLT_HEADER_LEN,
  KFLT_MAX_BLOB_BYTES,
  KFLT_VERSION,
} from './types.js'
import type { MembershipFilter } from './types.js'

// Field offsets (bytes). Matches the authoritative KFLT v1 header layout.
const OFF_MAGIC = 0
const OFF_VERSION = 4
const OFF_FILTER_TYPE = 5
const OFF_FINGERPRINT_BITS = 6
const OFF_FLAGS = 7
const OFF_EPOCH = 8
const OFF_SEED = 16
const OFF_SEGMENT_LENGTH = 20
const OFF_SEGMENT_COUNT = 24
const OFF_MEMBER_COUNT_BAND = 28

// Signing regions, exported so `sign.ts` (TK-5) reuses ONE definition of the
// byte layout rather than re-hardcoding 32/64/128. signer_pubkey is the 32-byte
// x-only key at [32,64); sig is the 64-byte Schnorr signature at [64,128); the
// fingerprint array begins at [128, end).
/** Byte offset of the 32-byte x-only signer pubkey. */
export const OFF_SIGNER_PUBKEY = 32
/** Byte offset of the 64-byte Schnorr signature. */
export const OFF_SIGNATURE = 64
/** Byte offset where the fingerprint array begins (= header length, 128). */
export const OFF_FINGERPRINTS = KFLT_HEADER_LEN // 128

// Magic bytes: "KFLT".
const MAGIC_0 = 0x4b // K
const MAGIC_1 = 0x46 // F
const MAGIC_2 = 0x4c // L
const MAGIC_3 = 0x54 // T

const FLAG_KEYED = 0x01
const FLAG_PADDED = 0x02

// Fuse arity = 3 ⇒ arrayLength = (segment_count + 2) * segment_length.
const ARITY_MINUS_ONE = 2

// Geometry bounds (mirror fuse.ts SEGMENT_LENGTH_CAP = 1 << 18).
const SEGMENT_LENGTH_MIN = 4
const SEGMENT_LENGTH_MAX = 1 << 18 // 262144

/** True iff `n` is a positive power of two. */
function isPowerOfTwo(n: number): boolean {
  return Number.isInteger(n) && n > 0 && (n & (n - 1)) === 0
}

/**
 * Serialize a `MembershipFilter` into a `KFLT` v1 blob.
 *
 * Allocates exactly `128 + arrayLength*2` bytes. The signer_pubkey (off 32..64)
 * and sig (off 64..128) regions are left ZERO — TK-5's signing step fills them
 * in place over the same byte layout.
 */
export function serializeFilter(f: MembershipFilter): Uint8Array {
  const fuse = f._fuse
  const arrayLength = fuse.arrayLength
  const total = KFLT_HEADER_LEN + arrayLength * 2

  const buf = new Uint8Array(total)
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)

  // Magic (raw bytes, not an LE integer).
  buf[OFF_MAGIC] = MAGIC_0
  buf[OFF_MAGIC + 1] = MAGIC_1
  buf[OFF_MAGIC + 2] = MAGIC_2
  buf[OFF_MAGIC + 3] = MAGIC_3

  buf[OFF_VERSION] = KFLT_VERSION
  buf[OFF_FILTER_TYPE] = f.type
  buf[OFF_FINGERPRINT_BITS] = f.fingerprintBits
  buf[OFF_FLAGS] = (f.keyed ? FLAG_KEYED : 0) | (f._padded ? FLAG_PADDED : 0)

  // epoch as LE u64.
  dv.setBigUint64(OFF_EPOCH, BigInt(f.epoch), true)

  // seed (LE u32). Fuse seed is 32-bit; mask defensively.
  dv.setUint32(OFF_SEED, fuse.seed >>> 0, true)
  dv.setUint32(OFF_SEGMENT_LENGTH, fuse.segmentLength >>> 0, true)
  dv.setUint32(OFF_SEGMENT_COUNT, fuse.segmentCount >>> 0, true)
  dv.setUint32(OFF_MEMBER_COUNT_BAND, f._memberCountBand >>> 0, true)

  // signer_pubkey (32..64) + sig (64..128) left zero (Uint8Array is 0-init).

  // Fingerprint array as LE u16 starting at off 128.
  const fps = fuse.fingerprints
  for (let i = 0; i < arrayLength; i++) {
    dv.setUint16(OFF_FINGERPRINTS + i * 2, fps[i] as number, true)
  }

  return buf
}

/**
 * Parse a `KFLT` v1 blob into a `MembershipFilter`. HARDENED against malformed
 * and hostile input: every header field is validated and the expected blob
 * length is recomputed from header geometry BEFORE any allocation sized by an
 * attacker-controlled field. Throws an `Error` on any malformation.
 *
 * SECURITY — THE SIGNATURE IS NOT VERIFIED HERE. This function deserializes the
 * filter STRUCTURE only; it does not authenticate the blob's origin. The caller
 * MUST call `verifyFilterBlob` (TK-5) on the raw blob and confirm the Schnorr
 * signature against an expected signer BEFORE trusting ANY membership result
 * from the returned filter. A parse success means "well-formed bytes," not
 * "trustworthy bytes."
 */
export function parseFilter(blob: Uint8Array): MembershipFilter {
  // 1. Bounds: at least a full header, at most the hard cap.
  if (blob.length < KFLT_HEADER_LEN) {
    throw new Error('KFLT: blob shorter than header')
  }
  if (blob.length > KFLT_MAX_BLOB_BYTES) {
    throw new Error('KFLT: blob exceeds maximum size')
  }

  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength)

  // 2. Magic bytes === "KFLT".
  if (
    blob[OFF_MAGIC] !== MAGIC_0 ||
    blob[OFF_MAGIC + 1] !== MAGIC_1 ||
    blob[OFF_MAGIC + 2] !== MAGIC_2 ||
    blob[OFF_MAGIC + 3] !== MAGIC_3
  ) {
    throw new Error('KFLT: bad magic')
  }

  // 3. Format version.
  const version = blob[OFF_VERSION] as number
  if (version !== KFLT_VERSION) {
    throw new Error('KFLT: unsupported format version')
  }

  // 4. Filter type ∈ {1,2,3}; only fuse (1) implemented.
  const filterType = blob[OFF_FILTER_TYPE] as number
  if (filterType !== 1 && filterType !== 2 && filterType !== 3) {
    throw new Error('KFLT: invalid filter type')
  }
  if (filterType !== 1) {
    throw new Error('unsupported filter type')
  }

  // 5. Fingerprint bits ∈ {8,16,20,32}; only 16 implemented.
  const fingerprintBits = blob[OFF_FINGERPRINT_BITS] as number
  if (
    fingerprintBits !== 8 &&
    fingerprintBits !== 16 &&
    fingerprintBits !== 20 &&
    fingerprintBits !== 32
  ) {
    throw new Error('KFLT: invalid fingerprint bits')
  }
  if (fingerprintBits !== 16) {
    throw new Error('unsupported fingerprint bits')
  }

  // 6. Geometry. Read segment_length / segment_count and validate hard, then
  //    derive arrayLength. All checks happen on plain numbers — no allocation.
  const segmentLength = dv.getUint32(OFF_SEGMENT_LENGTH, true)
  const segmentCount = dv.getUint32(OFF_SEGMENT_COUNT, true)

  if (!isPowerOfTwo(segmentLength)) {
    throw new Error('KFLT: segment_length not a power of two')
  }
  if (segmentLength < SEGMENT_LENGTH_MIN || segmentLength > SEGMENT_LENGTH_MAX) {
    throw new Error('KFLT: segment_length out of range')
  }
  if (segmentCount < 1) {
    throw new Error('KFLT: segment_count must be >= 1')
  }

  // segmentCountLength and arrayLength must be safe integers. segment_count is a
  // u32 (≤ 2^32-1) and segment_length ≤ 2^18, so the products are ≤ ~2^50 < 2^53
  // and cannot actually overflow a JS safe integer — but we assert it anyway so
  // the invariant is explicit and survives any future bound change.
  const segmentCountLength = segmentCount * segmentLength
  const arrayLength = (segmentCount + ARITY_MINUS_ONE) * segmentLength
  if (
    !Number.isSafeInteger(segmentCountLength) ||
    !Number.isSafeInteger(arrayLength)
  ) {
    throw new Error('KFLT: geometry overflow')
  }

  // The fingerprint region alone must fit under the hard cap. Check BEFORE we
  // size any buffer by arrayLength.
  const fingerprintBytes = arrayLength * 2
  if (
    !Number.isSafeInteger(fingerprintBytes) ||
    OFF_FINGERPRINTS + fingerprintBytes > KFLT_MAX_BLOB_BYTES
  ) {
    throw new Error('KFLT: declared array exceeds maximum size')
  }

  // 7. Recompute expected blob length from header geometry; must match exactly.
  //    This is the recompute-before-allocate guard: a blob that lies about its
  //    geometry is rejected here, before the Uint16Array below is allocated.
  const expectedLen = OFF_FINGERPRINTS + fingerprintBytes
  if (expectedLen !== blob.length) {
    throw new Error('KFLT: length mismatch')
  }

  // Header scalars needed for the result. (epoch as LE u64 → Number; seed u32.)
  const epoch = Number(dv.getBigUint64(OFF_EPOCH, true))
  const seed = dv.getUint32(OFF_SEED, true)
  const flags = blob[OFF_FLAGS] as number
  const memberCountBand = dv.getUint32(OFF_MEMBER_COUNT_BAND, true)

  // 8. ONLY NOW allocate and read the fingerprint array (LE u16 × arrayLength).
  const fingerprints = new Uint16Array(arrayLength)
  for (let i = 0; i < arrayLength; i++) {
    fingerprints[i] = dv.getUint16(OFF_FINGERPRINTS + i * 2, true)
  }

  const _fuse = BinaryFuse16.fromParts({
    seed,
    segmentLength,
    segmentCount,
    fingerprints,
  })

  // 9. Assemble the MembershipFilter from header flags + fields.
  return {
    fingerprintBits: 16,
    keyed: (flags & FLAG_KEYED) !== 0,
    epoch,
    type: 1,
    _fuse,
    _memberCountBand: memberCountBand,
    _padded: (flags & FLAG_PADDED) !== 0,
  }
}
