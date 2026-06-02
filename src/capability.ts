// Presence-capability tokens (`./capability` subpath) — spec §7.4.
//
// WHAT THIS SOLVES: a KEYED presence server (one whose member pool is built over
// `memberKey(pk, salt)`) is not openly probeable — you need the salt to compute
// the value to test. That salt is a speed-bump, not a member-privacy boundary
// (SECURITY.md), but it does mean a stranger can't locate an arbitrary friend on
// a keyed server. A `PresenceCapability` lets a CONSENTING subject hand a specific
// bearer a one-time, expiring token that carries (a) the salt hint needed to
// compute the subject's `memberKey`, and (b) the SUBJECT's own Schnorr signature
// over the whole token — so the bearer can test *that one friend's* presence on
// *that one keyed server* without the server going open and without the bearer
// being able to forge a capability for anyone else.
//
// The signature is by the SUBJECT (the person whose presence is being tested),
// NOT the server — it is consent ("you may test MY presence here, until then"),
// not provenance. Provenance of the FILTER itself is a separate concern handled
// by `signFilterBlob` / `verifyFilterBlob` (sign.ts): a consumer should ALSO
// pin-verify the filter's signer before trusting a hit. A capability says
// "this subject consents"; it says nothing about whether the filter is genuine.
//
// ───────────────────────────────────────────────────────────────────────────
// CANONICAL SIGNING BYTES (document verbatim in PROTOCOL.md / consume in TK-8):
//
//   preimage = utf8(`tessera-cap:v1:${serverId}:${subjectPubHex}:${saltHint}:${expiresAt}`)
//   digest   = sha256(preimage)                    // 32 bytes — the Schnorr message
//   sig      = schnorr.sign(digest, subjectPriv)   // 64-byte BIP340 compact sig (hex)
//
// DELIMITER-INJECTION GUARD: the canonical string is colon-delimited. Three of the
// four interpolated fields can never contain a colon — `subjectPubHex` and
// `saltHint` are validated as hex (`[0-9a-f]`, no `:`), and `expiresAt` is a
// finite number (stringifies without `:`). Only `serverId` is free-form, so we
// REJECT any `serverId` containing a colon — on BOTH issue and test. Without this
// guard a crafted `serverId` like "x:DEADBEEF:cafe:0" could shift the field
// boundaries and make one tuple's preimage collide another's (a different
// {subjectPubHex, saltHint, expiresAt} set producing identical bytes). Rejecting
// the colon keeps the simple delimited form unambiguous without escaping. (Note:
// `wss://relay.example.com` is fine; `wss://relay.example.com:443` is rejected —
// callers pass a colon-free server identifier, e.g. host without the port, or a
// hash of the URL. This is documented in PROTOCOL.md.)
// ───────────────────────────────────────────────────────────────────────────
//
// No console output. No new runtime deps — `@noble/curves` + `@noble/hashes`
// only, same as the rest of the kit. The subject private-key byte copy is
// zeroized in a `finally` after signing (mirrors sign.ts).
//
// SEPARATE SUBPATH: this file is the `./capability` entry (package.json export
// `"./capability"`), NOT part of the `.` barrel (`index.ts`). Consumers import it
// as `tessera-kit/capability`.

import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { memberKey } from './member-key.js'
import { testMembership } from './filter.js'
import type { MembershipFilter } from './types.js'

const HEX64 = /^[0-9a-f]{64}$/
const HEX_EVEN = /^[0-9a-f]*$/ // even-length checked separately
const SIG_HEX = /^[0-9a-f]{128}$/ // 64-byte Schnorr sig as hex

export interface PresenceCapability {
  /** Free-form server identifier. MUST NOT contain a colon (delimiter guard). */
  serverId: string
  /** The friend whose presence the bearer may test (x-only pubkey, 64-hex). */
  subjectPubHex: string
  /** Hex; the keyed-pool salt needed to compute `memberKey(subjectPubHex, saltHint)`.
   *  Even-length hex (may be empty for an open-pool hint). */
  saltHint: string
  /** Unix seconds. The capability is valid while `now <= expiresAt`. */
  expiresAt: number
  /** Schnorr (BIP340) signature, hex, by the SUBJECT over the canonical bytes. */
  sig: string
}

/**
 * Build the canonical preimage bytes for a capability tuple. The colon-delimited
 * form `tessera-cap:v1:<serverId>:<subjectPubHex>:<saltHint>:<expiresAt>`. Callers
 * MUST have validated the fields (esp. serverId colon-freeness) before calling.
 */
function canonicalDigest(
  serverId: string,
  subjectPubHex: string,
  saltHint: string,
  expiresAt: number,
): Uint8Array {
  const preimage = utf8ToBytes(
    `tessera-cap:v1:${serverId}:${subjectPubHex}:${saltHint}:${expiresAt}`,
  )
  return sha256(preimage)
}

/** Throw if `serverId` is empty or contains a colon (delimiter-injection guard). */
function assertServerId(serverId: string): void {
  if (typeof serverId !== 'string' || serverId.length === 0) {
    throw new Error('capability: serverId must be a non-empty string')
  }
  if (serverId.includes(':')) {
    throw new Error(
      'capability: serverId must not contain a colon (delimiter-injection guard)',
    )
  }
}

/** Throw if `saltHint` is not even-length lowercase hex. Empty string is allowed. */
function assertSaltHint(saltHint: string): void {
  if (
    typeof saltHint !== 'string' ||
    !HEX_EVEN.test(saltHint) ||
    saltHint.length % 2 !== 0
  ) {
    throw new Error('capability: saltHint must be even-length hex')
  }
}

/**
 * Subject issues a capability letting the bearer test the SUBJECT's presence on a
 * keyed server. Signed by `subjectPrivHex`; the embedded `subjectPubHex` is
 * asserted to be the matching x-only pubkey (see step 2) so a caller cannot mint a
 * capability claiming a subject key they don't control.
 *
 * @param p             serverId (colon-free, non-empty), subjectPubHex (64-hex),
 *                      saltHint (even-length hex, possibly empty), expiresAt
 *                      (finite unix-seconds number).
 * @param subjectPrivHex 64 hex chars — the SUBJECT's secret key.
 * @returns a `PresenceCapability` with the Schnorr `sig` filled in.
 * @throws on any malformed field, a colon in serverId, or a subjectPubHex that is
 *         not the pubkey of subjectPrivHex.
 */
export function issuePresenceCapability(
  p: { serverId: string; subjectPubHex: string; saltHint: string; expiresAt: number },
  subjectPrivHex: string,
): PresenceCapability {
  // 1. Validate every field up front.
  const priv = subjectPrivHex.toLowerCase()
  if (!HEX64.test(priv)) {
    throw new Error('capability: subjectPrivHex must be 64 hex chars')
  }
  const subjectPubHex = p.subjectPubHex.toLowerCase()
  if (!HEX64.test(subjectPubHex)) {
    throw new Error('capability: subjectPubHex must be 64 hex chars')
  }
  assertSaltHint(p.saltHint.toLowerCase())
  assertServerId(p.serverId)
  if (typeof p.expiresAt !== 'number' || !Number.isFinite(p.expiresAt)) {
    throw new Error('capability: expiresAt must be a finite number')
  }
  const saltHint = p.saltHint.toLowerCase()

  const privBytes = hexToBytes(priv)
  try {
    // 2. Assert the claimed subjectPubHex really is this priv's x-only pubkey, so
    //    a caller can't issue a capability for a key they don't hold. (Tested.)
    const derivedPubHex = bytesToHex(schnorr.getPublicKey(privBytes))
    if (derivedPubHex !== subjectPubHex) {
      throw new Error(
        'capability: subjectPubHex does not match subjectPrivHex (cannot issue for a key you do not control)',
      )
    }

    // 3. Sign the canonical digest. BIP340 schnorr signs the 32-byte message
    //    directly (no internal prehash), so digest is the message — same shape as
    //    sign.ts.
    const digest = canonicalDigest(p.serverId, subjectPubHex, saltHint, p.expiresAt)
    const sig = bytesToHex(schnorr.sign(digest, privBytes))

    // 5. Return the capability.
    return {
      serverId: p.serverId,
      subjectPubHex,
      saltHint,
      expiresAt: p.expiresAt,
      sig,
    }
  } finally {
    // 4. Zeroize the private-key copy regardless of success/throw.
    privBytes.fill(0)
  }
}

/**
 * Test the capability's subject against a (keyed) filter. Order of operations is
 * load-bearing: SIGNATURE and EXPIRY are checked BEFORE any membership test, so a
 * malformed/expired/forged capability is rejected up front and never reaches the
 * filter.
 *
 *   1. Validate cap field shapes (hex, even-length salt, colon-free serverId).
 *   2. `now ?? floor(Date.now()/1000)`. If `now > expiresAt` → throw 'capability expired'.
 *   3. Recompute the digest and `schnorr.verify` against `subjectPubHex`.
 *      Invalid (or noble-rejected) → throw 'capability signature invalid'.
 *   4. ONLY THEN compute `memberKey(subjectPubHex, saltHint)` and return
 *      `testMembership(f, value)`.
 *
 * An expired or invalid capability is a USAGE error — we THROW rather than
 * silently returning false, so a caller can't confuse "not present" with "this
 * token is no good." A genuine present/absent answer is the only `boolean` result.
 *
 * @param f   the keyed membership filter (built over `memberKey(pk, salt)` values).
 * @param cap the presence capability to test.
 * @param now injectable unix-seconds clock (defaults to wall clock). Valid while
 *            `now <= expiresAt` (the boundary instant is still valid).
 * @returns whether the subject is present in `f`.
 * @throws 'capability expired' / 'capability signature invalid', or a field-shape
 *         error (incl. colon in serverId).
 */
export function testWithCapability(
  f: MembershipFilter,
  cap: PresenceCapability,
  now?: number,
): boolean {
  // 1. Validate field shapes (mirrors issue; rejects colon serverId on the test
  //    side too — the delimiter guard must hold wherever the canonical string is
  //    recomputed).
  const subjectPubHex = cap.subjectPubHex.toLowerCase()
  if (!HEX64.test(subjectPubHex)) {
    throw new Error('capability: subjectPubHex must be 64 hex chars')
  }
  const saltHint = cap.saltHint.toLowerCase()
  assertSaltHint(saltHint)
  assertServerId(cap.serverId)
  if (typeof cap.expiresAt !== 'number' || !Number.isFinite(cap.expiresAt)) {
    throw new Error('capability: expiresAt must be a finite number')
  }
  const sig = cap.sig.toLowerCase()
  if (!SIG_HEX.test(sig)) {
    throw new Error('capability: sig must be 128 hex chars (64-byte Schnorr sig)')
  }

  // 2. Expiry — checked BEFORE the signature and BEFORE membership. An expired
  //    capability throws (usage error), never a silent false.
  const nowSec = now ?? Math.floor(Date.now() / 1000)
  if (nowSec > cap.expiresAt) {
    throw new Error('capability expired')
  }

  // 3. Signature — recompute the exact canonical digest and verify against the
  //    SUBJECT pubkey. noble may throw on a malformed sig/pubkey; normalize both
  //    "returned false" and "threw" into the single thrown usage error.
  const digest = canonicalDigest(cap.serverId, subjectPubHex, saltHint, cap.expiresAt)
  let sigValid = false
  try {
    sigValid = schnorr.verify(hexToBytes(sig), digest, hexToBytes(subjectPubHex))
  } catch {
    sigValid = false
  }
  if (!sigValid) {
    throw new Error('capability signature invalid')
  }

  // 4. ONLY after sig + expiry pass: compute the keyed memberKey and test it.
  const value = memberKey(subjectPubHex, saltHint)
  return testMembership(f, value)
}
