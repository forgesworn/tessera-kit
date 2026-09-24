// Presence-capability tokens (`./capability` subpath) — spec §7.4.
//
// WHAT THIS SOLVES: a KEYED presence server (one whose member pool is built over
// `memberKey(pk, salt)`) is not openly probeable — you need the salt to compute
// the value to test. That salt is a speed-bump, not a member-privacy boundary
// (SECURITY.md), but it does mean a stranger can't locate an arbitrary friend on
// a keyed server. A `PresenceCapability` lets a CONSENTING subject hand a specific
// bearer a BEARER token that carries (a) the exact 64-hex value the SUBJECT is
// present in the pool as — never the pool salt itself — and (b) the SUBJECT's own
// Schnorr signature over the whole token — so the bearer can test *that one
// friend's* presence on *that one server* without the pool going open to that
// bearer and without the bearer being able to forge a capability for anyone else.
//
// HONEST SCOPE (audit fix — read before using): this is a BEARER token, not a
// one-time token. Nothing in the token or the check binds it to a single use or
// to a single bearer: whoever holds the bytes can call `testWithCapability` as
// many times as they like, and can forward the token to anyone else, until
// `expiresAt`. It reveals ONLY this subject's own pool value (`memberValue`) —
// never the salt, and never any other member's value — so holding one capability
// does NOT grant probing of the rest of the keyed pool (unlike the pre-fix design,
// which carried the salt itself). The subject's signature is CONSENT ("I allow
// testing of MY presence, until then"); it is not bearer-binding — it does not
// name or restrict who may hold or replay the token.
//
// A capability is also NOT bound to a specific filter beyond the free-form
// `serverId` string (see §5.3/PROTOCOL.md "B11" note): `serverId` is whatever the
// issuer and bearer agree it means, and nothing here cross-checks it against a
// filter's signer or contents. A capability issued naming server A's `serverId`
// will test true against ANY filter a bearer chooses to run it against, if that
// filter happens to contain `memberValue` — including a same-salt pool the
// subject never intended to expose. Pin-verify the filter (`sign.ts`) and choose
// `serverId` values that are actually unique per deployment if that distinction
// matters to you.
//
// `expiresAt` ONLY bounds `testWithCapability` — the convenience wrapper in this
// file. It does NOT bound `memberValue` itself: once a bearer has SEEN
// `memberValue` (from a valid, unexpired capability, or leaked any other way),
// nothing stops them calling `testMembership(filter, memberValue)` directly,
// bypassing `testWithCapability` entirely, for as long as `memberValue` remains
// a real value in the pool — i.e. for every future epoch, until the pool's
// keyed salt rotates (which changes `memberKey(pk, salt)` and so changes
// `memberValue` too), or indefinitely for an OPEN pool, where `memberValue` is
// the bare pubkey and never changes at all. Salt rotation is therefore the only
// actual revocation mechanism; `expiresAt` is a courtesy on the wrapper
// function, not a cryptographic bound on how long the disclosed value stays
// testable.
//
// The signature is by the SUBJECT (the person whose presence is being tested),
// NOT the server — it is consent, not provenance. Provenance of the FILTER itself
// is a separate concern handled by `signFilterBlob` / `verifyFilterBlob` (sign.ts):
// a consumer should ALSO pin-verify the filter's signer before trusting a hit. A
// capability says "this subject consents"; it says nothing about whether the
// filter is genuine.
//
// ───────────────────────────────────────────────────────────────────────────
// CANONICAL SIGNING BYTES (document verbatim in PROTOCOL.md / consume in TK-8):
//
//   preimage = utf8(`tessera-cap:v2:${serverId}:${subjectPubHex}:${memberValue}:${expiresAt}`)
//   digest   = sha256(preimage)                    // 32 bytes — the Schnorr message
//   sig      = schnorr.sign(digest, subjectPriv)   // 64-byte BIP340 compact sig (hex)
//
// `memberValue` is `memberKey(subjectPubHex, salt)` for a keyed pool, or
// `subjectPubHex` itself (the open-pool form of `memberKey`) for an open pool.
// The pool `salt` is supplied by the SUBJECT at issue time and is used ONLY to
// compute `memberValue` — it is discarded immediately after and NEVER enters the
// token, the preimage, or the return value (audit fix — v1 carried the salt
// itself as `saltHint`, which handed the bearer the means to probe the whole
// keyed pool, not just this one subject).
//
// DELIMITER-INJECTION GUARD: the canonical string is colon-delimited. Three of the
// four interpolated fields can never contain a colon — `subjectPubHex` and
// `memberValue` are validated as hex (`[0-9a-f]`, no `:`), and `expiresAt` is a
// non-negative safe integer (stringifies without `:`). Only `serverId` is
// free-form, so we REJECT any `serverId` containing a colon — on BOTH issue and
// test. Without this guard a crafted `serverId` like "x:DEADBEEF:cafe:0" could
// shift the field boundaries and make one tuple's preimage collide another's (a
// different {subjectPubHex, memberValue, expiresAt} set producing identical
// bytes). Rejecting the colon keeps the simple delimited form unambiguous without
// escaping. (Note: `wss://relay.example.com` is fine;
// `wss://relay.example.com:443` is rejected — callers pass a colon-free server
// identifier, e.g. host without the port, or a hash of the URL. This is
// documented in PROTOCOL.md.)
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
const SIG_HEX = /^[0-9a-f]{128}$/ // 64-byte Schnorr sig as hex

export interface PresenceCapability {
  /** Free-form server identifier. MUST NOT contain a colon (delimiter guard).
   *  NOT cryptographically bound to any particular filter beyond this string —
   *  see the module note (B11). */
  serverId: string
  /** The friend whose presence the bearer may test (x-only pubkey, 64-hex). */
  subjectPubHex: string
  /** The 64-hex value the SUBJECT is present in the pool as:
   *  `memberKey(subjectPubHex, salt)` for a keyed pool, or `subjectPubHex` itself
   *  for an open pool. Reveals nothing about any OTHER member's value and never
   *  carries the pool salt (audit fix — replaces the v1 `saltHint` field). */
  memberValue: string
  /** Unix seconds, non-negative safe integer. The capability is valid while
   *  `now <= expiresAt`. This is a BEARER credential: anyone holding the token
   *  can test it, any number of times, until this instant — it is not one-time
   *  and not bound to a specific bearer. */
  expiresAt: number
  /** Schnorr (BIP340) signature, hex, by the SUBJECT over the canonical bytes.
   *  This is CONSENT, not bearer-binding: it does not restrict who may hold or
   *  replay the token. */
  sig: string
}

/** Throw if `expiresAt` is not a non-negative safe integer (audit fix — a
 *  fractional or huge value can't be canonically reproduced across languages;
 *  see PROTOCOL.md §5). */
function assertExpiresAt(expiresAt: number, context: string): void {
  if (
    typeof expiresAt !== 'number' ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt < 0
  ) {
    throw new Error(`${context}: expiresAt must be a non-negative safe integer`)
  }
}

/**
 * Build the canonical preimage bytes for a capability tuple. The colon-delimited
 * form `tessera-cap:v2:<serverId>:<subjectPubHex>:<memberValue>:<expiresAt>`.
 * Callers MUST have validated the fields (esp. serverId colon-freeness) before
 * calling.
 */
function canonicalDigest(
  serverId: string,
  subjectPubHex: string,
  memberValue: string,
  expiresAt: number,
): Uint8Array {
  const preimage = utf8ToBytes(
    `tessera-cap:v2:${serverId}:${subjectPubHex}:${memberValue}:${expiresAt}`,
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

/**
 * Subject issues a capability letting the bearer test the SUBJECT's presence on
 * a server. Signed by `subjectPrivHex`; the embedded `subjectPubHex` is asserted
 * to be the matching x-only pubkey (see step 2) so a caller cannot mint a
 * capability claiming a subject key they don't control.
 *
 * `p.salt`, if the pool is keyed, is used ONLY to compute `memberValue` — it is
 * never stored on the returned capability and never enters the signed bytes
 * (audit fix; see the module note). Omit it for an open pool.
 *
 * @param p             serverId (colon-free, non-empty), subjectPubHex (64-hex),
 *                      salt (optional; even-length hex, the KEYED pool's salt —
 *                      omit for an open pool), expiresAt (non-negative safe
 *                      integer unix-seconds).
 * @param subjectPrivHex 64 hex chars — the SUBJECT's secret key.
 * @returns a `PresenceCapability` with `memberValue` and the Schnorr `sig` filled
 *          in. The salt itself is discarded — only `memberKey(subjectPubHex,
 *          salt)` survives.
 * @throws on any malformed field, a colon in serverId, or a subjectPubHex that is
 *         not the pubkey of subjectPrivHex.
 */
export function issuePresenceCapability(
  p: { serverId: string; subjectPubHex: string; salt?: string; expiresAt: number },
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
  assertServerId(p.serverId)
  assertExpiresAt(p.expiresAt, 'capability')
  // `memberKey` itself validates `salt` (even-length hex) when it is defined —
  // no need to duplicate that check here. `salt === undefined` ⇒ open pool ⇒
  // `memberKey` returns `subjectPubHex` verbatim.
  const memberValue = memberKey(subjectPubHex, p.salt)

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
    const digest = canonicalDigest(p.serverId, subjectPubHex, memberValue, p.expiresAt)
    const sig = bytesToHex(schnorr.sign(digest, privBytes))

    // 5. Return the capability. Note: `p.salt` does NOT appear anywhere below —
    //    only its derived `memberValue` survives.
    return {
      serverId: p.serverId,
      subjectPubHex,
      memberValue,
      expiresAt: p.expiresAt,
      sig,
    }
  } finally {
    // 4. Zeroize the private-key copy regardless of success/throw.
    privBytes.fill(0)
  }
}

/**
 * Test the capability's subject against a filter. Order of operations is
 * load-bearing: EXPIRY and SIGNATURE are checked BEFORE any membership test, so a
 * malformed/expired/forged capability is rejected up front and never reaches the
 * filter.
 *
 *   1. Validate cap field shapes (hex, colon-free serverId, safe-integer expiresAt).
 *   2. `now ?? floor(Date.now()/1000)`. Throw if that resolved clock value is not
 *      `Number.isFinite` (audit fix — a `NaN` clock previously skipped the expiry
 *      check entirely, since `NaN > x` is always `false`). Then, if
 *      `now > expiresAt` → throw 'capability expired'.
 *   3. Recompute the digest and `schnorr.verify` against `subjectPubHex`.
 *      Invalid (or noble-rejected) → throw 'capability signature invalid'.
 *   4. ONLY THEN test `cap.memberValue` directly against the filter — the bearer
 *      never re-derives anything from a salt; the capability already carries the
 *      exact value to test.
 *
 * An expired or invalid capability is a USAGE error — we THROW rather than
 * silently returning false, so a caller can't confuse "not present" with "this
 * token is no good." A genuine present/absent answer is the only `boolean` result.
 *
 * REMEMBER (see the module note): this check does not — and cannot — enforce
 * single use. A capability that passes here is a valid BEARER credential; it
 * will pass again for anyone else holding the same bytes, until `expiresAt`.
 *
 * @param f   the membership filter to test the subject's `memberValue` against.
 * @param cap the presence capability to test.
 * @param now injectable unix-seconds clock (defaults to wall clock). Valid while
 *            `now <= expiresAt` (the boundary instant is still valid). Must
 *            resolve to a finite number.
 * @returns whether the subject is present in `f`.
 * @throws 'capability expired' / 'capability signature invalid', or a field-shape
 *         error (incl. colon in serverId, or a non-finite resolved clock).
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
  const memberValue = cap.memberValue.toLowerCase()
  if (!HEX64.test(memberValue)) {
    throw new Error('capability: memberValue must be 64 hex chars')
  }
  assertServerId(cap.serverId)
  assertExpiresAt(cap.expiresAt, 'capability')
  const sig = cap.sig.toLowerCase()
  if (!SIG_HEX.test(sig)) {
    throw new Error('capability: sig must be 128 hex chars (64-byte Schnorr sig)')
  }

  // 2. Resolve the clock, THEN check expiry — checked BEFORE the signature and
  //    BEFORE membership. A non-finite resolved `now` (e.g. an injected `NaN`)
  //    throws up front rather than silently passing `NaN > expiresAt` (always
  //    `false`), which would have skipped the expiry check entirely (audit fix).
  const nowSec = now ?? Math.floor(Date.now() / 1000)
  if (!Number.isFinite(nowSec)) {
    throw new Error('capability: now must resolve to a finite number')
  }
  if (nowSec > cap.expiresAt) {
    throw new Error('capability expired')
  }

  // 3. Signature — recompute the exact canonical digest and verify against the
  //    SUBJECT pubkey. noble may throw on a malformed sig/pubkey; normalize both
  //    "returned false" and "threw" into the single thrown usage error.
  const digest = canonicalDigest(cap.serverId, subjectPubHex, memberValue, cap.expiresAt)
  let sigValid = false
  try {
    sigValid = schnorr.verify(hexToBytes(sig), digest, hexToBytes(subjectPubHex))
  } catch {
    sigValid = false
  }
  if (!sigValid) {
    throw new Error('capability signature invalid')
  }

  // 4. ONLY after sig + expiry pass: test the carried memberValue directly. There
  //    is no salt to re-derive anything from — the capability already IS the
  //    value to test (audit fix; see the module note on why the salt itself is
  //    never carried).
  return testMembership(f, memberValue)
}
