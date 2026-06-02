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
  salt?: string                                // hex; presence ⇒ keyed=true
  padToBucket?: boolean                        // default true
  /** Even-length hex seed for STABLE decoy padding (spec §7.5). When set, the
   *  decoys added to reach the size bucket are deterministic across rebuilds, so
   *  version-diffing can't track real churn. When OMITTED, padding still happens
   *  but with CSPRNG-random decoys — an attacker can then track churn by diffing
   *  array contents across epochs (the documented "unstable" case). Additive in
   *  TK-6; pre-TK-6 callers that don't pass it get the unstable-but-padded path. */
  decoySeedHex?: string
  epoch: number                                // unix seconds, REQUIRED
}
