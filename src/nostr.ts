// Generic filter-publication builder (`./nostr` subpath) — spec §6 (server publication shape)
//
// WHAT THIS SOLVES: the "a server needs only tessera-kit to publish a filter"
// promise was, until now, doc-only — PROTOCOL.md §6 hand-copied a markdown table
// of the Nostr event shape that a publisher had to re-implement by eye, with no
// shared mechanics. This module is the reusable, RELATIONSHIP-AGNOSTIC core of
// that publication: it base64-encodes the raw KFLT blob into the event content and
// assembles a minimal Nostr `EventTemplate` from a kind + tags the CALLER supplies.
//
// DELIBERATELY KNOWS NOTHING ABOUT KINDRED. tessera-kit must not learn kindred's
// addressing conventions (kind `30444`, the `kindred:members:<ns>:<serverId>`
// d-tag, the `#n` namespace tag) — `kindred` names the CONVENTION, not a
// package; the code that implements it is `kenspeckle`. Those conventions
// stay in `kenspeckle`, which will DELEGATE to this builder by passing its
// own kind + tags. Keeping this layer ignorant of the relationship
// vocabulary is what lets a tessera-kit-only server publish AND lets
// kenspeckle reuse the same bytes without a circular concept dependency.
//
// SEPARATE SUBPATH: this file is the `./nostr` entry (package.json export
// `"./nostr"`), NOT part of the `.` barrel (`index.ts`). The core `.` / `./capability`
// entries stay @noble-only; ONLY this optional subpath pulls in `@scure/base` for
// base64. Consumers import it as `@forgesworn/tessera-kit/nostr`.
//
// STRUCTURAL Nostr type — no `nostr-tools` runtime dependency. `EventTemplate` is
// the unsigned-event shape (kind/tags/content/created_at); the caller signs it with
// their own Nostr key (standard NIP-01), which is SEPARATE from the in-blob Schnorr
// provenance signature (`signFilterBlob`). No console output.

import { base64 } from '@scure/base'
import { KFLT_MAX_BLOB_BYTES } from './types.js'
import { TesseraError } from './errors.js'

// Re-exported here (not just from the `.` barrel) — every error
// `decodeFilterPublicationContent` throws (the `INPUT_*` codes below)
// originates in THIS file, and a consumer who only imports
// `@forgesworn/tessera-kit/nostr` shouldn't need a second import from `.`
// just to get `instanceof TesseraError` / the `TesseraErrorCode` type.
export { TesseraError } from './errors.js'
export type { TesseraErrorCode } from './errors.js'

/**
 * Minimal Nostr event-template type (structural — no `nostr-tools` runtime dep).
 * This is the UNSIGNED event shape; the caller adds `pubkey`/`id`/`sig` when they
 * sign it with their own Nostr key.
 */
export interface EventTemplate {
  kind: number
  tags: string[][]
  content: string
  created_at: number
}

/** Default (and absolute ceiling on) decoded blob size: the actual
 *  `KFLT_MAX_BLOB_BYTES` constant (64 MiB, spec §3), imported rather than
 *  re-declared so the two can never drift apart. `decodeFilterPublicationContent`
 *  rejects content whose decoded length would exceed the (clamped) cap BEFORE
 *  handing the bytes on, so a hostile oversized event can't drive an unbounded
 *  allocation downstream. */
const DEFAULT_MAX_BYTES = KFLT_MAX_BLOB_BYTES

/**
 * Generic filter-publication builder: base64-encodes the raw KFLT `blob` into the
 * event `content` and assembles the `EventTemplate`. RELATIONSHIP-AGNOSTIC — the
 * CALLER supplies the `kind` and `tags` (e.g. kindred supplies kind `30444` plus
 * its `["d", "kindred:members:…"]` / `["n", …]` tags). tessera-kit adds no tags
 * and assumes no addressing convention.
 *
 * @param p.kind      the Nostr event kind (caller-chosen).
 * @param p.tags      the event tags (caller-chosen; passed through verbatim).
 * @param p.blob      the raw KFLT blob to carry (base64-encoded into `content`).
 * @param p.createdAt the event `created_at` (unix seconds; caller-chosen).
 * @returns `{ kind, tags, content: base64(blob), created_at }`.
 */
export function buildFilterPublication(p: {
  kind: number
  tags: string[][]
  blob: Uint8Array
  createdAt: number
}): EventTemplate {
  // Type guards (follow-up review fix) — a non-object `p` (null, a number)
  // previously reached `p.kind`/`p.blob` and threw a raw TypeError; a `p.blob`
  // that isn't a Uint8Array previously reached `base64.encode(p.blob)` and
  // threw a raw @scure error.
  if (p === null || typeof p !== 'object') {
    throw new TesseraError('INPUT_PUBLICATION_TYPE', 'buildFilterPublication: p must be an object')
  }
  if (!(p.blob instanceof Uint8Array)) {
    throw new TesseraError('INPUT_PUBLICATION_TYPE', 'buildFilterPublication: p.blob must be a Uint8Array')
  }
  return {
    kind: p.kind,
    tags: p.tags,
    content: base64.encode(p.blob),
    created_at: p.createdAt,
  }
}

/**
 * Inverse helper consumers can use to decode a publication's `content` back to the
 * raw blob bytes. Applies a sane length cap BEFORE decoding: base64 expands ~4/3,
 * so a `content` string longer than `ceil(maxBytes/3)*4` could only decode to more
 * than `maxBytes` and is rejected up front — the recompute-before-allocate posture
 * the rest of the kit uses against hostile input.
 *
 * @param content the base64 event content produced by `buildFilterPublication`.
 * @param maxBytes max permitted DECODED length (defaults to `KFLT_MAX_BLOB_BYTES`,
 *                 64 MiB). MUST be a non-negative safe integer; a caller-supplied
 *                 value above `KFLT_MAX_BLOB_BYTES` is silently CLAMPED to it
 *                 (audit fix — a hostile/careless `NaN` or negative `maxBytes`
 *                 previously disabled the size cap entirely: the pre-check
 *                 `content.length > maxEncodedLen` is vacuously false for
 *                 `NaN`/negative bounds).
 * @returns the decoded blob bytes.
 * @throws if `maxBytes` is not a non-negative safe integer, if the base64 string
 *         is too long for the (clamped) `maxBytes`, if it is malformed base64, or
 *         if the decoded length somehow still exceeds the (clamped) `maxBytes`.
 */
export function decodeFilterPublicationContent(
  content: string,
  maxBytes: number = DEFAULT_MAX_BYTES,
): Uint8Array {
  if (typeof content !== 'string') {
    throw new TesseraError(
      'INPUT_CONTENT_TYPE',
      'decodeFilterPublicationContent: content must be a string',
    )
  }
  // `maxBytes` must itself be well-formed BEFORE it's used to bound anything —
  // a NaN/negative/non-integer value must never silently disable the cap below
  // (audit fix; see the doc comment above).
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new TesseraError(
      'INPUT_MAX_BYTES_INVALID',
      'decodeFilterPublicationContent: maxBytes must be a non-negative safe integer',
    )
  }
  // Clamp to the hard KFLT ceiling regardless of what the caller passed — no
  // caller-supplied value can raise the cap above the format's own maximum.
  const clampedMaxBytes = Math.min(maxBytes, KFLT_MAX_BLOB_BYTES)

  // Upper-bound the decoded size from the ENCODED length before decoding. Standard
  // base64 encodes 3 bytes -> 4 chars (with '=' padding), so the maximum decodable
  // byte count is ceil(clampedMaxBytes / 3) * 4 characters. Reject anything longer
  // so a hostile event can't force a large allocation in `base64.decode`.
  const maxEncodedLen = Math.ceil(clampedMaxBytes / 3) * 4
  if (content.length > maxEncodedLen) {
    throw new TesseraError(
      'INPUT_CONTENT_TOO_LARGE',
      `decodeFilterPublicationContent: content exceeds max decoded size (${clampedMaxBytes} bytes)`,
    )
  }

  // Follow-up review fix — malformed (non-alphabet) base64 previously escaped
  // as a raw @scure Error. `content` is hostile relay input by design (this
  // function's whole job is decoding untrusted event content), so a decode
  // failure must be a TesseraError, not a leaked dependency error.
  let bytes: Uint8Array
  try {
    bytes = base64.decode(content)
  } catch {
    throw new TesseraError(
      'INPUT_CONTENT_MALFORMED_BASE64',
      'decodeFilterPublicationContent: content is not valid base64',
    )
  }
  // Defence in depth: the length pre-check is an upper bound; assert the actual
  // decoded length too (covers any padding/edge slack).
  if (bytes.length > clampedMaxBytes) {
    throw new TesseraError(
      'INPUT_CONTENT_DECODED_TOO_LARGE',
      `decodeFilterPublicationContent: decoded ${bytes.length} bytes exceeds max ${clampedMaxBytes}`,
    )
  }
  return bytes
}
