// NARROWED (item 4, pre-publish pass): the exported TYPES now say exactly
// what the code accepts — `1` (fuse) and `16` (bits) — instead of advertising
// wire values the code has always rejected at runtime (`filter.ts`'s
// `BUILD_FINGERPRINT_BITS_UNSUPPORTED`, `codec.ts`'s
// `PARSE_UNSUPPORTED_FILTER_TYPE` / `PARSE_UNSUPPORTED_FINGERPRINT_BITS`).
// Before this change, `FilterType = 1 | 2 | 3` and
// `FingerprintBits = 8 | 16 | 20 | 32` type-checked a caller's
// `fingerprintBits: 8` as valid, even though `buildMembershipFilter` would
// always throw at runtime for it — a type lying about what the API accepts.
//
// The WIRE format still RESERVES `2`/`3` (xor/cuckoo) and `8`/`20`/`32` bits
// for forward-compat — see PROTOCOL.md §3's header table, which documents
// them as "reserved" — and `parseFilter` still explicitly rejects each one
// with its own `TesseraErrorCode` (`PARSE_INVALID_FILTER_TYPE` /
// `PARSE_UNSUPPORTED_FILTER_TYPE`, `PARSE_INVALID_FINGERPRINT_BITS` /
// `PARSE_UNSUPPORTED_FINGERPRINT_BITS` — PROTOCOL.md §9). Narrowing these
// EXPORTED types changes nothing about that runtime behaviour; it only stops
// the TYPE SYSTEM from advertising values the implementation has never
// accepted. A future format_version bump that actually implements one of the
// reserved values would widen these types again, as a deliberate, documented
// change — not silently, the way the pre-narrowing types implied it already
// worked.
export type FilterType = 1                     // 1=fuse (only filter type implemented; 2=xor, 3=cuckoo reserved on the wire — PROTOCOL.md §3)
export type FingerprintBits = 16               // only 16-bit fingerprints implemented; 8/20/32 reserved on the wire — PROTOCOL.md §3

export const KFLT_MAGIC = 0x4b464c54          // "KFLT" big-endian
export const KFLT_VERSION = 1
export const KFLT_HEADER_LEN = 128
export const KFLT_MAX_BLOB_BYTES = 64 * 1024 * 1024   // 64 MB hard cap (spec §3)

export interface MembershipFilter {
  readonly fingerprintBits: FingerprintBits
  readonly keyed: boolean
  readonly epoch: number
  readonly type: FilterType
  // opaque internal fingerprint structure — see fuse.ts. Carried but not part of the documented contract.
  readonly _fuse: import('./fuse.js').BinaryFuse16
  readonly _memberCountBand: number
  readonly _padded: boolean
}

export interface FilterBuildOptions {
  fingerprintBits?: FingerprintBits            // default 16
  salt?: string                                // hex; presence ⇒ keyed=true. When
                                                // given, MUST be non-empty
                                                // even-length hex (audit fix, L4) —
                                                // its bytes are never used, only
                                                // its presence, but the shape is
                                                // still validated so `keyed` can't
                                                // be set by an accidental empty or
                                                // malformed value (filter.ts).
  padToBucket?: boolean                        // default true
  /** Even-length hex seed, MUST be at least 16 bytes (32 hex chars), for
   *  STABLE-PER-EPOCH decoy padding (spec §2.8). When set, `buildMembershipFilter`
   *  derives a fresh effective seed from `(decoySeedHex, epoch)` before padding
   *  (see `filter.ts`'s `deriveEpochDecoySeedHex`): a REBUILD of the SAME epoch
   *  with the SAME seed is byte-identical, but each NEW epoch gets a fresh decoy
   *  set. This is what defeats cross-epoch churn-diffing — a FIXED decoy set
   *  reused across epochs does not (see `padding.ts`'s module note: fuse slots
   *  are XOR-shared, so a stable-forever decoy set makes the array diff exactly
   *  0 slots when nothing changed and ~3 when one member swapped). When OMITTED,
   *  padding still happens but with CSPRNG-random decoys, unstable even within an
   *  epoch. Throws if the seed is malformed or shorter than 16 bytes. */
  decoySeedHex?: string
  epoch: number                                // unix seconds, REQUIRED
}
