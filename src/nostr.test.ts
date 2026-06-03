import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'
import {
  buildFilterPublication,
  decodeFilterPublicationContent,
  type EventTemplate,
} from './nostr.js'

// A deterministic pseudo-blob: not a real KFLT blob (this module is byte-agnostic —
// it carries whatever bytes the caller hands it), just a stable Uint8Array to
// round-trip. Covers 0x00 and 0xff so base64 edge bytes are exercised.
function fakeBlob(n: number): Uint8Array {
  const b = new Uint8Array(n)
  for (let i = 0; i < n; i++) b[i] = (i * 131 + 7) & 0xff
  return b
}

describe('buildFilterPublication', () => {
  it('base64-encodes the blob into content and carries kind/tags/created_at verbatim', () => {
    const blob = fakeBlob(200)
    const tags = [
      ['d', 'kindred:members:demo:relay.example.com'],
      ['n', 'demo'],
      ['epoch', '1700000000'],
    ]
    const tpl: EventTemplate = buildFilterPublication({
      kind: 30444,
      tags,
      blob,
      createdAt: 1_700_000_123,
    })

    expect(tpl.kind).toBe(30444)
    expect(tpl.tags).toEqual(tags)
    expect(tpl.tags).toBe(tags) // passed through verbatim (same reference)
    expect(tpl.created_at).toBe(1_700_000_123)
    expect(tpl.content).toBe(base64.encode(blob))
  })

  it('is relationship-agnostic — any caller-chosen kind and empty tags are honoured', () => {
    const tpl = buildFilterPublication({
      kind: 12345,
      tags: [],
      blob: fakeBlob(16),
      createdAt: 42,
    })
    expect(tpl.kind).toBe(12345)
    expect(tpl.tags).toEqual([])
    expect(tpl.created_at).toBe(42)
  })
})

describe('decodeFilterPublicationContent — round-trip', () => {
  it('decodes content produced by buildFilterPublication back to identical bytes', () => {
    for (const n of [0, 1, 2, 3, 31, 128, 200, 1024]) {
      const blob = fakeBlob(n)
      const tpl = buildFilterPublication({
        kind: 30444,
        tags: [],
        blob,
        createdAt: 1,
      })
      const decoded = decodeFilterPublicationContent(tpl.content)
      expect(Array.from(decoded)).toEqual(Array.from(blob))
    }
  })
})

describe('decodeFilterPublicationContent — oversized content rejected by the cap', () => {
  it('rejects content longer than the encoded bound for a small maxBytes', () => {
    // Build a 300-byte blob (content ~400 base64 chars), then decode with a tiny
    // 100-byte cap — the encoded string is far longer than ceil(100/3)*4, so it is
    // rejected BEFORE decoding.
    const tpl = buildFilterPublication({
      kind: 1,
      tags: [],
      blob: fakeBlob(300),
      createdAt: 1,
    })
    expect(() => decodeFilterPublicationContent(tpl.content, 100)).toThrow()
  })

  it('accepts content exactly at the cap boundary', () => {
    const blob = fakeBlob(48)
    const tpl = buildFilterPublication({ kind: 1, tags: [], blob, createdAt: 1 })
    // maxBytes = 48 ⇒ the 48-byte blob is exactly at the limit and must decode.
    const decoded = decodeFilterPublicationContent(tpl.content, 48)
    expect(Array.from(decoded)).toEqual(Array.from(blob))
  })

  it('the default cap is the 64 MiB KFLT max (a normal-sized blob decodes fine)', () => {
    const blob = fakeBlob(4096)
    const tpl = buildFilterPublication({ kind: 1, tags: [], blob, createdAt: 1 })
    expect(() => decodeFilterPublicationContent(tpl.content)).not.toThrow()
  })

  it('throws on malformed base64 content', () => {
    expect(() => decodeFilterPublicationContent('not valid base64 @@@@')).toThrow()
  })
})
