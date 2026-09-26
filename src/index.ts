export * from './types.js'
export * from './member-key.js'
export { buildMembershipFilter, testMembership, testMany, describeFilter } from './filter.js'
export { serializeFilter, parseFilter } from './codec.js'
export { signFilterBlob, verifyFilterBlob, verifyAndParseFilter, isValidFilterContext } from './sign.js'
export { nextPowerOfTwoBand, deriveDecoys } from './padding.js'
// Typed error contract (PROTOCOL.md's error-codes table) — every throw
// reachable from this entry (and from `./capability` / `./nostr`, which
// re-export the same class from their own files) is a `TesseraError` with a
// stable `code`. See errors.ts for the full code table and the security rule
// on why signature/signer/context failures share ONE code.
export { TesseraError } from './errors.js'
export type { TesseraErrorCode } from './errors.js'
