// Typed error contract (`TesseraError` / `TesseraErrorCode`) — every `throw`
// reachable from this kit's public API throws a `TesseraError`, never a bare
// `Error`, so a consumer (or a `reject.golden.*.json` vector checker) can
// branch on a STABLE `code` instead of pattern-matching a message string.
//
// WHY THIS EXISTS: before this module, every failure was a plain `new
// Error(message)`. That is fine for a human reading a stack trace, but a
// program that wants to react differently to "blob truncated" vs "bad magic"
// vs "wrong signer" had nothing to switch on but the message text — and this
// kit's message text was never designed or frozen as an API surface (see
// PROTOCOL.md's error-codes table, the actual stable contract now). Freezing
// message strings as the API would also make normal wording improvements a
// breaking change forever; freezing `code` instead lets messages stay free
// to improve while `code` stays put.
//
// MESSAGES ARE UNCHANGED. Every `TesseraError` thrown by this kit carries the
// EXACT SAME `message` text it always did (see the historical `throw new
// Error(...)` call this replaces, at each call site) — this pass adds `code`
// and `name`, it does not rewrite prose. Existing tests/consumers that match
// on message substrings keep working; NEW code should match on `code`.
//
// GROUPED BY PREFIX. `TesseraErrorCode` is one flat string-literal union,
// SCREAMING_SNAKE, grouped by the prefix before the first underscore:
//   PARSE_*       — `parseFilter`'s hostile-input trust boundary (codec.ts)
//   CODEC_*       — `serializeFilter`'s own output-size guard (codec.ts)
//   SIGN_*        — `signFilterBlob` (sign.ts)
//   VERIFY_*      — `verifyFilterBlob` / `verifyAndParseFilter` (sign.ts)
//   CAPABILITY_*  — `issuePresenceCapability` / `testWithCapability` (capability.ts)
//   BUILD_*       — `buildMembershipFilter`, and `BinaryFuse16.build`'s
//                   construction failure (fuse.ts), since it is only ever
//                   reachable THROUGH the build pipeline
//   TEST_*        — `testMembership` (filter.ts) — not "BUILD_" because it
//                   validates a QUERY value, not anything about building
//   INPUT_*        — small, standalone utility-function input validation not
//                   owned by one of the verbs above: `memberKey`
//                   (member-key.ts), `nextPowerOfTwoBand` / `deriveDecoys`
//                   (padding.ts), `buildFilterPublication` /
//                   `decodeFilterPublicationContent` (nostr.ts)
//
// TYPE GUARDS (follow-up review fix). Every exported function also validates
// its OWN argument TYPES (not just shape/range) at entry — e.g. a `blob`
// argument that isn't a `Uint8Array`, an `opts`/`p`/`cap` argument that isn't
// an object, a `count`/`n` argument that isn't a finite number. Before this
// fix, several of these escaped as a raw `TypeError` (property access on
// `null`), `RangeError` (`new Array(NaN)`), or a raw `@noble`/`@scure` error
// (an out-of-range secp256k1 scalar, malformed base64) — never a
// `TesseraError`. The rule this closes: **nothing but a `TesseraError`
// escapes a public function** — checked mechanically in errors.test.ts's
// "every exported function rejects null/number" sweep, in addition to the
// per-code reachability case for each new `*_TYPE` / `*_OUT_OF_RANGE` /
// `*_MALFORMED_*` code below.
//
// SECURITY RULE — ONE CODE FOR "SIGNATURE INVALID / WRONG SIGNER / WRONG
// CONTEXT". `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` is deliberately the ONLY
// code `verifyAndParseFilter` throws for a bad signature, a signer that
// doesn't match the pinned key, OR a `context` that doesn't match what was
// signed (spec §4.1/§4.3) — these are NOT split into distinguishable codes,
// the same way they are not split into distinguishable MESSAGES (see
// sign.ts's doc comments). A `code`-based checker gets exactly as much
// information as a message-based one did: "this blob is not trustworthy,"
// nothing about WHY, so probing `code` cannot leak which check failed either.
//
// STABILITY. This table is documented as a stable contract in PROTOCOL.md §9
// (linked from here) — a future removal or renaming of a `TesseraErrorCode`
// value, OR a change to what an EXISTING code means, is a breaking change,
// the same as removing or repurposing an exported function would be, and
// will not happen within a major version. Adding a NEW code for a NEW
// failure mode is NOT breaking and MAY happen in a MINOR release — this pass
// itself added three (`TEST_VALUES_TYPE`, `VERIFY_STRICTLY_NEWER_THAN_INVALID`,
// `VERIFY_EPOCH_NOT_NEWER`) without bumping a major version, because they are
// new failure modes from new, additive functionality, not a change to any
// existing code's meaning.
//
// CONSEQUENCE FOR CONSUMERS (PROTOCOL.md §9 states this too): do NOT write an
// exhaustive `switch (code) { case 'A': ...; case 'B': ... }` with no
// `default`, and do NOT write a `Record<TesseraErrorCode, X>` object literal
// — TypeScript accepts either against TODAY's union, but a future MINOR
// release that adds one more code (which this contract explicitly permits)
// silently falls through an exhaustiveness-less `switch` at runtime, or fails
// to type-check a `Record` literal that must cover every member. Always
// include a `default` / trailing `else` that handles "a code I don't
// specifically recognise" as its own case.
//
// EXPORTED FROM: the main entry (`.`) and from each subpath whose errors
// originate there (`./capability`, `./nostr`) — see those files' re-exports.

/**
 * Every error code this kit can throw, grouped by prefix (see the module
 * note above for what each prefix means). SCREAMING_SNAKE_CASE, one literal
 * per distinct throw site's MEANING — two call sites that throw the exact
 * same message for the exact same reason (e.g. `capability.ts`'s
 * `subjectPubHex` shape checks, shared by issue and test) share ONE code.
 *
 * STABILITY (see the module note above for the full policy): an existing
 * member's meaning is fixed for the life of a major version; new members MAY
 * be added in a minor release. Consumers should not treat this union as
 * exhaustive-and-closed — code that switches on `TesseraErrorCode` should
 * always have a `default`/`else` fallback for a code it does not recognise.
 */
export type TesseraErrorCode =
  // --- PARSE_* — codec.ts, parseFilter (the hostile-input trust boundary) ---
  | 'PARSE_BLOB_TOO_SHORT'
  | 'PARSE_BLOB_TOO_LARGE'
  | 'PARSE_BAD_MAGIC'
  | 'PARSE_UNSUPPORTED_VERSION'
  | 'PARSE_INVALID_FILTER_TYPE'
  | 'PARSE_UNSUPPORTED_FILTER_TYPE'
  | 'PARSE_INVALID_FINGERPRINT_BITS'
  | 'PARSE_UNSUPPORTED_FINGERPRINT_BITS'
  | 'PARSE_SEGMENT_LENGTH_NOT_POWER_OF_TWO'
  | 'PARSE_SEGMENT_LENGTH_OUT_OF_RANGE'
  | 'PARSE_SEGMENT_COUNT_INVALID'
  | 'PARSE_GEOMETRY_OVERFLOW'
  | 'PARSE_ARRAY_TOO_LARGE'
  | 'PARSE_LENGTH_MISMATCH'
  | 'PARSE_EPOCH_OVERFLOW'
  | 'PARSE_RESERVED_FLAGS_SET'
  | 'PARSE_MEMBER_COUNT_BAND_INVALID'
  | 'PARSE_BLOB_TYPE'
  // --- CODEC_* — codec.ts, serializeFilter ---
  | 'CODEC_BLOB_TOO_LARGE'
  | 'CODEC_FILTER_TYPE'
  // --- SIGN_* — sign.ts, signFilterBlob ---
  | 'SIGN_BLOB_TOO_SHORT'
  | 'SIGN_CONTEXT_EMPTY'
  | 'SIGN_CONTEXT_NOT_WELL_FORMED'
  | 'SIGN_CONTEXT_TOO_LONG'
  | 'SIGN_PRIVATE_KEY_INVALID'
  | 'SIGN_PRIVATE_KEY_OUT_OF_RANGE'
  | 'SIGN_BLOB_TYPE'
  | 'SIGN_PRIVATE_KEY_TYPE'
  // --- VERIFY_* — sign.ts, verifyFilterBlob / verifyAndParseFilter ---
  | 'VERIFY_CONTEXT_EMPTY'
  | 'VERIFY_CONTEXT_NOT_WELL_FORMED'
  | 'VERIFY_CONTEXT_TOO_LONG'
  | 'VERIFY_PINNED_PUBKEY_INVALID'
  | 'VERIFY_MIN_EPOCH_INVALID'
  // The ONE opaque code for a bad signature / wrong signer / wrong context —
  // see the SECURITY RULE in the module note. Never split this.
  | 'VERIFY_SIGNATURE_OR_SIGNER_MISMATCH'
  | 'VERIFY_STALE_EPOCH'
  | 'VERIFY_BLOB_TYPE'
  | 'VERIFY_OPTS_TYPE'
  // `opts.strictlyNewerThan` (additive, opt-in) — same validation SHAPE as
  // `minEpoch` above (own code, non-negative safe integer), and its own
  // distinct failure code for "not strictly newer," mirroring the
  // `VERIFY_MIN_EPOCH_INVALID` / `VERIFY_STALE_EPOCH` pair. Closes the
  // same-epoch-replay gap `minEpoch`'s `<` (not `<=`) comparison leaves open,
  // for a caller who opts in — see sign.ts's doc comment and PROTOCOL.md §4.3.
  | 'VERIFY_STRICTLY_NEWER_THAN_INVALID'
  | 'VERIFY_EPOCH_NOT_NEWER'
  // --- CAPABILITY_* — capability.ts ---
  | 'CAPABILITY_EXPIRES_AT_INVALID'
  | 'CAPABILITY_SERVER_ID_EMPTY'
  | 'CAPABILITY_SERVER_ID_HAS_COLON'
  | 'CAPABILITY_SERVER_ID_NOT_WELL_FORMED'
  | 'CAPABILITY_SUBJECT_PRIV_HEX_TYPE'
  | 'CAPABILITY_SUBJECT_PRIV_HEX_INVALID'
  | 'CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE'
  | 'CAPABILITY_SUBJECT_PUB_HEX_TYPE'
  | 'CAPABILITY_SUBJECT_PUB_HEX_INVALID'
  | 'CAPABILITY_SALT_TYPE'
  | 'CAPABILITY_SUBJECT_KEY_MISMATCH'
  | 'CAPABILITY_MEMBER_VALUE_TYPE'
  | 'CAPABILITY_MEMBER_VALUE_INVALID'
  | 'CAPABILITY_SIG_TYPE'
  | 'CAPABILITY_SIG_INVALID_SHAPE'
  | 'CAPABILITY_CLOCK_NOT_FINITE'
  | 'CAPABILITY_EXPIRED'
  | 'CAPABILITY_SIGNATURE_INVALID'
  | 'CAPABILITY_MEMBER_VALUE_MISMATCH'
  | 'CAPABILITY_OPTS_TYPE'
  | 'CAPABILITY_FILTER_TYPE'
  | 'CAPABILITY_CAP_TYPE'
  // --- BUILD_* — filter.ts (buildMembershipFilter) and fuse.ts (its construction) ---
  | 'BUILD_DECOY_SEED_HEX_INVALID'
  | 'BUILD_DECOY_SEED_HEX_TOO_SHORT'
  | 'BUILD_SALT_INVALID'
  | 'BUILD_FINGERPRINT_BITS_UNSUPPORTED'
  | 'BUILD_EPOCH_INVALID'
  | 'BUILD_MEMBER_KEY_INVALID'
  | 'BUILD_FUSE_CONSTRUCTION_FAILED'
  | 'BUILD_MEMBER_KEYS_TYPE'
  | 'BUILD_OPTS_TYPE'
  // --- TEST_* — filter.ts (testMembership, describeFilter, testMany) ---
  | 'TEST_VALUE_INVALID'
  | 'TEST_FILTER_TYPE'
  // `testMany`'s own non-array-values check (additive) — `TEST_VALUE_INVALID`
  // (a bad ELEMENT) and `TEST_FILTER_TYPE` (a bad `f`) are reused as-is, since
  // they mean exactly what they already mean; this is the one genuinely new
  // failure mode `testMany` introduces (filter.ts).
  | 'TEST_VALUES_TYPE'
  // --- INPUT_* — standalone utility-function validation (member-key.ts, padding.ts, nostr.ts) ---
  | 'INPUT_PUBKEY_INVALID'
  | 'INPUT_PUBKEY_TYPE'
  | 'INPUT_SALT_INVALID'
  | 'INPUT_DECOY_SEED_HEX_INVALID'
  | 'INPUT_DECOY_COUNT_INVALID'
  | 'INPUT_BAND_INVALID'
  | 'INPUT_CONTENT_TYPE'
  | 'INPUT_MAX_BYTES_INVALID'
  | 'INPUT_CONTENT_TOO_LARGE'
  | 'INPUT_CONTENT_DECODED_TOO_LARGE'
  | 'INPUT_CONTENT_MALFORMED_BASE64'
  | 'INPUT_PUBLICATION_TYPE'

/**
 * Every error this kit throws is a `TesseraError` — never a bare `Error`.
 * `code` is the stable contract (see the module note); `message` is
 * unchanged from before this class existed and MAY improve wording over
 * time (only `code` is the frozen part).
 *
 * `instanceof TesseraError` works normally (ES2022 target; `class ... extends
 * Error` needs no `Object.setPrototypeOf` workaround at this target/module
 * setting). `error.name === 'TesseraError'` for any code that logs
 * `error.toString()` / `error.stack` without special-casing this class.
 */
export class TesseraError extends Error {
  readonly code: TesseraErrorCode

  constructor(code: TesseraErrorCode, message: string) {
    super(message)
    this.name = 'TesseraError'
    this.code = code
    // V8 (Node, Chrome) only; a no-op elsewhere. Keeps this constructor frame
    // out of the stack trace, same as the built-in Error class does for
    // `new Error(...)` itself. `captureStackTrace` isn't in the standard
    // `ErrorConstructor` type, hence the narrow, explicit cast rather than
    // widening this function's types or reaching for `any`.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type -- narrow, local cast only
    const errorCtor = Error as unknown as {
      captureStackTrace?: (target: object, constructorOpt: Function) => void
    }
    if (typeof errorCtor.captureStackTrace === 'function') {
      errorCtor.captureStackTrace(this, TesseraError)
    }
  }
}
