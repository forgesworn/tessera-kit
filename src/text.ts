// Shared UTF-16 well-formedness check — INTERNAL module, not part of the public
// API (no subpath export; imported directly by sibling files in src/).
//
// WHY THIS EXISTS: `TextEncoder` (used everywhere in this kit via `utf8ToBytes`)
// silently replaces an UNPAIRED ("lone") UTF-16 surrogate with U+FFFD (the
// replacement character) instead of throwing. That means two DIFFERENT JS
// strings — e.g. `"a\uD800"` (a lone high surrogate) and `"a�"` (the
// literal replacement character) — can encode to IDENTICAL UTF-8 bytes. Any
// place in this kit that signs or verifies a caller-supplied string (a
// capability `serverId`, a signing `context`) needs to reject that collision
// at the STRING boundary, before encoding, or two distinct inputs could
// produce the identical signed preimage.
//
// `capability.ts`'s `assertServerId` (L3 audit fix) was the first fix for
// this; `sign.ts`'s `context` argument (signature-context binding) needs the
// exact same check. Rather than maintain two copies of the same regex, both
// import this ONE definition.
//
// `String.prototype.isWellFormed` (ES2024) would do this natively, but this
// kit's `engines` field does not (yet) make that guarantee load-bearing for
// every consumer's runtime, so a regex check is used instead of depending on
// it (matches the reasoning in the original L3 audit-fix comment).

/** Matches a lone (unpaired) UTF-16 surrogate: a high surrogate not followed
 *  by a low surrogate, or a low surrogate not preceded by a high surrogate. */
export const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

/** True iff `s` contains at least one unpaired UTF-16 surrogate (i.e. `s` is
 *  NOT well-formed UTF-16 — `utf8ToBytes(s)` would silently lossy-encode it). */
export function hasLoneSurrogate(s: string): boolean {
  return LONE_SURROGATE.test(s)
}
