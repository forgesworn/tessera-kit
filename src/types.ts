export type FilterType = 1 | 2 | 3            // 1=fuse, 2=xor, 3=cuckoo (only 1 implemented)
export type FingerprintBits = 8 | 16 | 20 | 32

export const KFLT_MAGIC = 0x4b464c54          // "KFLT" big-endian
export const KFLT_VERSION = 1
export const KFLT_HEADER_LEN = 128
export const KFLT_MAX_BLOB_BYTES = 64 * 1024 * 1024   // 64 MB hard cap (spec §7.3)

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
   *  STABLE-PER-EPOCH decoy padding (spec §7.5). When set, `buildMembershipFilter`
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
