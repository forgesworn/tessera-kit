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
  // TK-2 will replace `unknown` with import('./fuse.js').BinaryFuse16 once that module exists.
  readonly _fuse: unknown
  readonly _memberCountBand: number
  readonly _padded: boolean
}

export interface FilterBuildOptions {
  fingerprintBits?: FingerprintBits            // default 16
  salt?: string                                // hex; presence ⇒ keyed=true
  padToBucket?: boolean                        // default true
  epoch: number                                // unix seconds, REQUIRED
}
