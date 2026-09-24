import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js'
import { TesseraError } from './errors.js'

const HEX64 = /^[0-9a-f]{64}$/
const NONEMPTY_HEX = /^[0-9a-f]+$/

/**
 * True iff `s` is a non-empty, even-length, hex string (case-insensitive).
 * This is the ONE definition of "what a salt must look like," shared by
 * `memberKey` (below) and `buildMembershipFilter`'s `opts.salt` validation
 * (`filter.ts`) — so the two never drift apart into two independently
 * maintained copies of the same rule (follow-up audit fix).
 */
export function isValidSaltHex(s: string): boolean {
  return typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && NONEMPTY_HEX.test(s.toLowerCase())
}

/** The value to insert/test: pubkey (open) or sha256(salt || pubkey) (keyed).
 *
 * `saltHex`, when supplied, MUST be non-empty even-length hex (follow-up
 * audit fix). An EMPTY salt is rejected, not merely accepted-as-distinct: a
 * keyed pool built with `salt: ''` inserts `sha256('' ‖ pk)`, which ANYONE
 * can compute from the bare pubkey alone (no out-of-band salt needed) — it
 * provides no speed-bump at all, so it is not a meaningful "keyed" value and
 * is refused outright, the same as omitting `salt` would be meaningfully
 * different from passing one that grants no protection. To build an OPEN
 * pool, omit `saltHex` entirely — do not pass `''`. */
export function memberKey(pubkeyHex: string, saltHex?: string): string {
  // Follow-up review fix — `.toLowerCase()` on a non-string previously threw
  // a raw TypeError before the HEX64 shape check ever ran.
  if (typeof pubkeyHex !== 'string') {
    throw new TesseraError('INPUT_PUBKEY_TYPE', 'memberKey: pubkeyHex must be a string')
  }
  const pk = pubkeyHex.toLowerCase()
  if (!HEX64.test(pk)) {
    throw new TesseraError('INPUT_PUBKEY_INVALID', 'memberKey: pubkey must be 64 lowercase hex chars')
  }
  if (saltHex === undefined) return pk
  if (!isValidSaltHex(saltHex)) {
    throw new TesseraError('INPUT_SALT_INVALID', 'memberKey: salt must be non-empty even-length hex')
  }
  const salt = saltHex.toLowerCase()
  return bytesToHex(sha256(concatBytes(hexToBytes(salt), hexToBytes(pk))))
}
