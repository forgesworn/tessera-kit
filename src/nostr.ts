// Generic filter-publication builder (`./nostr` subpath) — spec §15 Q5.
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
// d-tag, the `#n` namespace tag). Those stay in `kindred`, which will DELEGATE to
// this builder by passing its own kind + tags. Keeping this layer ignorant of the
// relationship vocabulary is what lets a tessera-kit-only server publish AND lets
// kindred reuse the same bytes without a circular concept dependency.
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

/** Hard cap on decoded blob size, mirroring `KFLT_MAX_BLOB_BYTES` (64 MiB, spec
 *  §7.3). `decodeFilterPublicationContent` rejects content whose decoded length
 *  would exceed this BEFORE handing the bytes on, so a hostile oversized event
 *  can't drive an unbounded allocation downstream. */
const DEFAULT_MAX_BYTES = 64 * 1024 * 1024

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
 * @param maxBytes max permitted DECODED length (defaults to 64 MiB, the KFLT cap).
 * @returns the decoded blob bytes.
 * @throws if the base64 string is too long for `maxBytes`, if it is malformed
 *         base64, or if the decoded length somehow still exceeds `maxBytes`.
 */
export function decodeFilterPublicationContent(
  content: string,
  maxBytes: number = DEFAULT_MAX_BYTES,
): Uint8Array {
  if (typeof content !== 'string') {
    throw new Error('decodeFilterPublicationContent: content must be a string')
  }
  // Upper-bound the decoded size from the ENCODED length before decoding. Standard
  // base64 encodes 3 bytes -> 4 chars (with '=' padding), so the maximum decodable
  // byte count is ceil(maxBytes / 3) * 4 characters. Reject anything longer so a
  // hostile event can't force a large allocation in `base64.decode`.
  const maxEncodedLen = Math.ceil(maxBytes / 3) * 4
  if (content.length > maxEncodedLen) {
    throw new Error(
      `decodeFilterPublicationContent: content exceeds max decoded size (${maxBytes} bytes)`,
    )
  }

  const bytes = base64.decode(content) // throws on malformed base64
  // Defence in depth: the length pre-check is an upper bound; assert the actual
  // decoded length too (covers any padding/edge slack).
  if (bytes.length > maxBytes) {
    throw new Error(
      `decodeFilterPublicationContent: decoded ${bytes.length} bytes exceeds max ${maxBytes}`,
    )
  }
  return bytes
}
