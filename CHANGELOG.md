# Changelog

All notable changes to `@forgesworn/tessera-kit` are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Purely additive since 0.2.0 — no existing exported function, type, error
code, wire format, vector, or default behaviour changes. Existing tests and
vectors pass unmodified.

### Added

- `describeFilter(f)` (`.`) — a plain, readonly public view of a
  `MembershipFilter`'s metadata (`fingerprintBits`, `filterType`, `keyed`,
  `padded`, `epoch`, `memberCountBand`, `segmentLength`, `segmentCount`,
  `arrayLength`, `byteLength`, `theoreticalFalsePositiveRate`), and the
  `FilterDescription` type. Reveals nothing beyond what the serialized `KFLT`
  header already discloses (PROTOCOL.md §10).
- `testMany(f, valuesHex)` (`.`) — test many values against a filter in one
  call, with the exact same validation and semantics as calling
  `testMembership` on each value (PROTOCOL.md §10).
- `verifyAndParseFilter`'s `opts.strictlyNewerThan` — an opt-in, stricter
  sibling of `minEpoch` that rejects a parsed filter whose `epoch` is not
  *strictly* greater than the given value, closing the same-epoch-replay gap
  `minEpoch`'s non-strict `<` comparison leaves open for a caller who opts in
  (PROTOCOL.md §4.3). `minEpoch`'s own behaviour is unchanged.
- New `TesseraErrorCode` values: `TEST_VALUES_TYPE` (`testMany`'s
  non-array `valuesHex`), `VERIFY_STRICTLY_NEWER_THAN_INVALID` and
  `VERIFY_EPOCH_NOT_NEWER` (`opts.strictlyNewerThan`'s validation and
  freshness-check failures).
- PROTOCOL.md §10 ("Introspection & bulk-test helpers") and §11 ("Evolution /
  versioning") — new sections; `CONFORMANCE.md` links §11.
- Dev tooling: `fast-check` property tests (build→serialize→parse round-trip
  and byte-identical re-serialization over random member sets sized 0–2000;
  `testMany` vs. the equivalent `testMembership` loop) and a structure-aware
  fast-check fuzz test for `parseFilter` that mutates individual header
  fields (boundary + random values), fingerprint bytes, and geometry-driven
  resizes, asserting every failure is a `TesseraError`; `@vitest/coverage-v8`
  and a `test:coverage` script (reporting only, no CI-failing thresholds); a
  `bench` script (`scripts/bench.mjs`, not run in CI or `npm test`) timing
  build/test/testMany/parse/sign/verify at 1k/100k/1M members.
- PROTOCOL.md corrections from an independent review of this pass: §11's
  "how a verifier rejects an unknown version" now distinguishes `parseFilter`
  (rejects at `PARSE_UNSUPPORTED_VERSION`, after bounds/magic) from
  `verifyAndParseFilter` (rejects almost all such blobs earlier, at
  `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH`, since `verifyFilterBlob` never
  inspects `format_version`); §4.3 now states plainly that this kit does not
  enforce "one content per epoch," and gives usage guidance for
  `strictlyNewerThan` (an ordinary re-fetch of the current epoch throws
  `VERIFY_EPOCH_NOT_NEWER` — treat that as "no update," or use `minEpoch`
  for re-fetches instead); §9 and the `TesseraErrorCode` JSDoc now state the
  minor-vs-major stability policy explicitly (existing codes are fixed within
  a major version, new codes may be added in a minor one — don't write an
  exhaustive `switch`/`Record` over the union without a fallback).
- CI now runs the test matrix on Node 22 and 24 (was 22 only).

## [0.2.0] — 2026-09-25

A post-audit hardening pass over 0.1.0, a second review pass that closed gaps
the first missed, and a third pre-publish pass (below) that closes the
remaining gaps found before first release. Several fixes are **breaking** —
0.1.0 was never published, so this is the first shape consumers actually
build against.

**Summary.** This release binds the signed-blob digest to a caller-supplied
`context`, closing cross-server/namespace filter substitution
cryptographically (previously only distinct signing keys defended against
it) — `isValidFilterContext(ctx)` is now exported (from `.` and `sign.ts`) as
the one reusable predicate for "is this a valid `context`," used internally
by `signFilterBlob`/`verifyFilterBlob` themselves. Every thrown error is now
a `TesseraError` with a stable `code`. `FilterType`/`FingerprintBits` are
narrowed to the values actually implemented (`1`/`16`); the wire format still
reserves the rest. Conformance vectors now cover realistic/boundary sizes
(see `CONFORMANCE.md`), and docs are consistent on kindred (the convention)
vs. kenspeckle (the code).

**Breaking, this round:**
- `signFilterBlob`/`verifyFilterBlob`/`verifyAndParseFilter` require `context`
  — the digest formula changed; old signed blobs won't verify.
- Every throw is a `TesseraError`, not a bare `Error` (messages unchanged).
- `FilterType`/`FingerprintBits` narrowed to `1`/`16` (reserved values stay
  documented + rejected at runtime; only the exported TYPE changed).

### Third pass — pre-publish hardening

#### Breaking

- **Signature-context binding (§4.1/§4.3).** The signed digest is now
  `sha256("tessera-kflt-sig:v1" ‖ 0x00 ‖ u32be(byteLen(ctx)) ‖ utf8(ctx) ‖
  blob[0..64) ‖ sha256(blob[128..end)))` — a fixed domain tag and a
  length-prefixed, caller-supplied `context` string, byte-exact with no
  Unicode normalisation (reusing the lone-surrogate check `capability.ts`'s
  `serverId` already used, now shared via `src/text.ts`). `context` is
  REQUIRED, non-empty, well-formed UTF-16, and ≤1024 UTF-8 bytes.
  **Why:** before this fix, `pinnedPubkeyHex` alone was the only binding a
  verifier had; reusing one signing key across servers/namespaces let a
  relay/MITM substitute one deployment's validly-signed blob for another's,
  invisibly. `context` (the verifier's own stable, out-of-band-known
  deployment address — e.g. a kindred d-tag
  `kindred:members:<namespace>:<serverId>`) closes this cryptographically.
  **A wrong context fails with the exact same generic error as a wrong
  signer** (`VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` / "signature invalid or
  signer does not match") — never a distinguishable message or code.
  A distinct signing key per server is now defence in depth, not the only
  mitigation. **Migrate:** pass `context` everywhere these three functions
  are called; re-sign every stored blob.
- **`FilterType` narrowed to `1`; `FingerprintBits` narrowed to `16`.** These
  exported types previously advertised `1|2|3` and `8|16|20|32` — values the
  code has always rejected at runtime. The wire format still reserves those
  values (PROTOCOL.md §3), and `parseFilter` still rejects them with their
  own `TesseraErrorCode`s; only the TYPE, not the runtime behaviour, changed.
  **Migrate:** if you constructed a `FilterBuildOptions`/`MembershipFilter`
  object with a non-implemented value under `as` a cast, TypeScript will now
  catch it at compile time.

#### Added

- **`TesseraError` / `TesseraErrorCode`** (`src/errors.ts`, exported from `.`,
  `./capability`, and `./nostr`) — every `throw` reachable from this kit is
  now a `TesseraError` with a readonly, stable `code` (SCREAMING_SNAKE,
  grouped by prefix: `PARSE_*`, `CODEC_*`, `SIGN_*`, `VERIFY_*`,
  `CAPABILITY_*`, `BUILD_*`, `TEST_*`, `INPUT_*` — documented as a stable
  contract in PROTOCOL.md §9). Messages are UNCHANGED. Security rule:
  `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` is the one opaque code for a bad
  signature, wrong signer, or wrong context — never split further.
  `vectors/reject.golden.v1.json` and `keyed-member-key.golden.v1.json` now
  assert on `expectedErrorCode`, not a message substring.
- **Conformance vectors at realistic sizes** (`CONFORMANCE.md` is new):
  `kflt-sizes.golden.v1.json` (n=0,1,2,3,9,100,1000 — degenerate-n guard
  input and the two smallest segment-length transitions, full blob hex),
  `kflt-retry-seed.golden.v1.json` (n=829, the smallest input found needing a
  seed retry to converge), `kflt-large-10000.golden.v1.json` and
  `kflt-large-100000.golden.v1.json` (geometry + blob-hash + ≥20
  present/absent samples, members regenerated from a documented deterministic
  rule rather than stored inline). `signed-blob.golden.v1.json` regenerated
  with `context` and a must-reject wrong-context case.
- **PROTOCOL.md §9** — the error-codes table (stable contract).
- **`isValidFilterContext(ctx: unknown): boolean`** (`sign.ts`, exported from
  `.`) — kenspeckle-adoption follow-up: the one reusable predicate for "is
  this a valid signing `context`" (non-empty string, well-formed UTF-16,
  ≤1024 UTF-8 bytes), so a caller can validate a `context` value up front
  without hand-rolling the same three rules. `signFilterBlob` and
  `verifyFilterBlob` use this SAME function internally — it is the single
  source of truth, not a parallel copy of the rules their own error codes
  already encode.

#### Docs

- **The kindred `namespace` MUST NOT contain a colon** (`serverId` may) —
  kenspeckle-adoption follow-up, PROTOCOL.md §4.3/§6. Without this rule, two
  different `(namespace, serverId)` pairs can produce the byte-identical
  `kindred:members:<namespace>:<serverId>` string by shifting where the
  `d`-tag's first colon after the prefix falls (e.g. `("a", "b:c")` and
  `("a:b", "c")` both give `...a:b:c`), which lets a relay serve one
  deployment's blob as another's when the context strings collide.
- **When to call `verifyFilterBlob` directly vs. `verifyAndParseFilter`**
  (PROTOCOL.md §4.3, and both functions' JSDoc) — kenspeckle-adoption
  follow-up: use `verifyAndParseFilter` when you hold a fixed pinned key;
  call `verifyFilterBlob(blob, context)` yourself, check the returned
  `signerPubkeyHex` against a key authenticated some other way (e.g. the
  Nostr event author, as kenspeckle's `requireAuthorIsSigner` does), and only
  then `parseFilter`, when the trusted key isn't a static pin.
- **kindred vs. kenspeckle, said consistently.** `kindred` is the wire
  protocol/addressing convention name (the d-tag, the kind); `kenspeckle` is
  the code that implements it (`@forgesworn/kenspeckle`). README, llms.txt,
  PROTOCOL.md, and SECURITY.md no longer conflate the two (e.g. PROTOCOL.md
  §6 was "zero `kindred` dependency" — you can't depend on a naming
  convention; it's now "zero `kenspeckle` dependency"). llms.txt's quick
  start now uses `verifyAndParseFilter` (with `context`), matching its own
  "recommended" API guidance instead of the two-call hand-rolled path.
- **Every `§`-section cross-reference fixed.** Several source comments and
  `properties.test.ts` cited PROTOCOL.md sections that never existed (`§7.3`,
  `§7.4`, `§7.5`, `§7.6`, `§10`, `§10.2`, `§6.2`, `§12.2`, `§15`) — likely
  left over from a section renumbering. Every one now points at the section
  that actually documents the claim (mostly §1, §2.8, §3, §4.2, §5, §6, §7.2,
  or SECURITY.md's own numbered sections where the claim lives there
  instead). `properties.test.ts` also no longer says "S = members" for the
  accumulation formula's `S` — it's a SERVER count (§7.2), a stale comment
  the PROTOCOL.md fix in the prior pass didn't propagate to this test file.

### Second review pass

#### Breaking

- **`testWithCapability` now rejects an OPEN-pool capability whose
  `memberValue` does not equal `subjectPubHex` (M2).** Previously, a validly
  signed capability naming subject A's `subjectPubHex` but a DIFFERENT
  subject B's `memberValue` would test B's presence and report it as if it
  were A's — the subject's signature proved only "A signed this tuple," never
  that `memberValue` was actually derived from A's own pubkey. On an open
  pool `memberValue` MUST equal `subjectPubHex` by construction (PROTOCOL.md
  §5.1), so this is now checked and a mismatch throws `'capability:
  memberValue does not match subjectPubHex (open pool)'`. **This check cannot
  be, and is not, applied to a keyed pool** — the bearer has no salt to
  recompute the binding with, so the subject's signature remains the only
  assertion available there (PROTOCOL.md §5.4b). **Migrate:** an honestly
  issued capability (`issuePresenceCapability`'s own output, unmodified) is
  unaffected; only a hand-crafted or tampered open-pool capability with a
  mismatched `memberValue` newly throws.
- **`buildMembershipFilter`'s `opts.salt`, when supplied, must be non-empty
  even-length hex.** Previously `salt: ''` or `salt: 'zz'` both silently set
  the on-wire `keyed` flag despite not being anything that could plausibly
  serve as a salt. **Migrate:** pass a real (even-length hex) salt, or omit
  `salt` entirely for an open pool.
- **`memberKey`'s `saltHex` (and everything built on it) now REJECTS an empty
  salt, not just a malformed one.** `memberKey(pk, '')` previously returned
  `sha256('' ‖ pk)` as a valid "keyed" value distinct from the open form
  `pk` — true bytewise, but meaningless as a boundary: `sha256('' ‖ pk)` is
  computable by **anyone** who holds the bare pubkey, with no out-of-band
  salt needed, so an empty salt provides none of the speed-bump a keyed pool
  exists for. `memberKey(pk, '')` now throws `'memberKey: salt must be
  non-empty even-length hex'`. This propagates to
  `issuePresenceCapability({ salt: '' })` (`./capability`), which derives
  `memberValue` via `memberKey` and so now throws for the same reason — an
  issuer can no longer mint a "keyed" capability that gives away nothing an
  unkeyed one wouldn't. `buildMembershipFilter`'s `opts.salt` check above
  now defers to the SAME shape rule (`isValidSaltHex`, `member-key.ts`)
  rather than a second, independently-maintained copy of it. **Migrate:**
  never pass `salt: ''` / `saltHex: ''` anywhere in this kit — omit the
  option entirely for an open pool.

#### Fixed

- **Fuse construction could be permanently blocked by two member keys that
  hash to the same 64-bit value (M1).** `BinaryFuse16.build` de-duplicated
  member-key STRINGS only (`buildMembershipFilter`'s own dedup); two DISTINCT
  keys colliding on the internal `keyToU64` hash landed in the same three
  slots on every seed, so peeling never converged and `build()` threw `'fuse:
  construction failed to converge'` on every call for as long as both keys
  remained — an availability bug reachable by anyone able to find such a
  collision (a ~2^32 targeted search, not a brute force of the full 2^64
  space). Construction now also de-duplicates by 64-bit HASH VALUE before
  peeling, matching the Lemire reference C's `binary_fuse_sort_and_remove_dup`
  pre-processing step. Dropping a hash-duplicate changes nothing observable —
  both colliding keys still test `true`. The existing frozen golden vector
  (`vectors/kflt.golden.v1.json`, no collisions) is byte-identical.
- **An oversized blob was hashed before its size was checked (L1).**
  `verifyFilterBlob` unconditionally SHA-256'd the entire fingerprint region
  before any size cap ran; a raw-HTTPS caller (not gated by `parseFilter`,
  whose own cap only applied downstream) paid real CPU (~870 ms measured for a
  200 MB blob) hashing a hostile oversized blob before it was ever rejected.
  `verifyFilterBlob` (and so `verifyAndParseFilter`, which calls it first) now
  rejects `blob.length > KFLT_MAX_BLOB_BYTES` up front, alongside the existing
  too-short check — before any hashing.
- **`serverId` accepted an unpaired UTF-16 surrogate, colliding with the
  literal replacement character (L3).** `utf8ToBytes` (`TextEncoder`) silently
  maps a lone surrogate to U+FFFD, so e.g. `"a\uD800"` and `"a�"`
  previously produced IDENTICAL UTF-8 bytes and so an identical canonical
  preimage — a capability issued for one string verified when presented under
  the other. `serverId` is now validated to be well-formed UTF-16 (no lone
  surrogates) on both issue and test. PROTOCOL.md §5.3 now also documents that
  `serverId` is compared BYTE-EXACTLY after UTF-8 encoding with NO Unicode
  normalisation, and recommends restricting `serverId` to printable ASCII.
- **Several public functions leaked a raw, un-kit-shaped error on malformed
  input (L4):** `deriveDecoys` now rejects an empty or malformed
  (non-hex/odd-length) `decoySeedHex` instead of silently producing
  public/predictable decoys or letting `@noble/hashes` throw a raw
  `RangeError` — note this is a behaviour change even for `count <= 0`:
  `deriveDecoys('', 0)` previously returned `[]` (the `count <= 0` short
  circuit ran BEFORE the seed was ever touched), and now throws, since the
  seed is validated first regardless of `count`; `issuePresenceCapability` / `testWithCapability` now
  `typeof`-check every string field before use, so e.g. a hand-built
  capability with `sig: undefined` throws a `capability:`-prefixed error
  instead of a raw `TypeError`; `serializeFilter` now throws if its output
  would exceed `KFLT_MAX_BLOB_BYTES`, checked before allocating, instead of
  producing a blob `parseFilter`/`verifyFilterBlob` would reject anyway.

#### Added

- **Five new frozen vector files** under `vectors/` (v1 naming, alongside
  `kflt.golden.v1.json`): `decoy-seed.golden.v1.json` (the per-epoch decoy-seed
  derivation formula + `deriveDecoys` output), `decoy-padding.golden.v1.json`
  (the same derivation wired end-to-end through `buildMembershipFilter`),
  `keyed-member-key.golden.v1.json` (`memberKey`, keyed and open forms),
  `capability.golden.v1.json` (the capability canonical preimage/digest and a
  FIXED, already-valid signature that must re-verify — BIP340 verification is
  fully deterministic even though signing itself uses random aux data, so this
  corrects the previous claim in `check-vectors.mjs` that "signatures cannot
  be frozen"), `signed-blob.golden.v1.json` (a fully signed KFLT blob that
  must verify against a pinned pubkey), and `reject.golden.v1.json` (must-reject
  `parseFilter` cases: truncated, bad magic, bad version, invalid
  type/fingerprint-bits, bad geometry, oversized declared length, length
  mismatch, epoch overflow, reserved flags, non-power-of-two band). All were
  independently hand-checked against `node:crypto` (not just this package's
  own `@noble/hashes` dependency) at generation time.
  `scripts/check-vectors.mjs` now dispatches by a `kind` field and checks all
  six vector kinds; the original "filter" check now ALSO `parseFilter`s the
  frozen bytes directly and re-checks membership against the PARSED filter,
  not only the rebuilt one.

#### Docs

- Fixed the dependency count: README/llms.txt/SECURITY.md said "two runtime
  deps"; it is three (`@noble/curves`, `@noble/hashes`, `@scure/base` — the
  last one pulled in only by the optional `./nostr` subpath).
- Documented the `./nostr` subpath (`buildFilterPublication` /
  `decodeFilterPublicationContent`) in README.md and llms.txt — it was
  exported but undocumented.
- Fixed PROTOCOL.md §7.2's accumulation formula wording: `S` is a SERVER
  COUNT (the number of filters probed), not a member count — "`S`-member
  servers" read as if the per-test FPR scaled with a filter's member count,
  which it does not (§7.1).
- PROTOCOL.md now documents: the M1 hash-level dedup (§2.5), the M2
  memberValue/subjectPubHex binding and its keyed-pool limit (§5.4b), the L1
  reject-before-hash size cap (§4.2), the L3 byte-exact/no-normalisation
  `serverId` encoding (§5.3), and the L4 input-validation additions
  (`opts.salt`, §1; `deriveDecoys`, §2.8; `serializeFilter`'s size cap, §3).

### First audit pass

#### Breaking

- **Capability `saltHint` → `memberValue`.** `PresenceCapability.saltHint` (the
  raw keyed-pool salt, carried in clear) is replaced by `memberValue`: the
  64-hex value the subject is present in the pool as
  (`memberKey(subjectPubHex, salt)` for a keyed pool, or `subjectPubHex` itself
  for an open pool). `issuePresenceCapability(p, subjectPrivHex)` now takes
  `p.salt?: string` (optional; the keyed pool's salt, omit for an open pool)
  instead of `p.saltHint: string` — the salt is used only to derive
  `memberValue` and never appears on the returned token.
  **Migrate:** replace `saltHint: mySalt` with `salt: mySalt` at issue time (or
  omit `salt` entirely for an open pool instead of passing `saltHint: ''`); read
  `cap.memberValue` instead of `cap.saltHint` off an issued capability.
- **Capability canonical preimage bumped `tessera-cap:v1:` → `tessera-cap:v2:`.**
  The signed tuple is now `{serverId, subjectPubHex, memberValue, expiresAt}`
  instead of `{serverId, subjectPubHex, saltHint, expiresAt}`. A v1-signed
  capability will not verify against v2 `testWithCapability`, and vice versa.
  **Migrate:** re-issue any stored/cached capabilities.
- **Member keys must be exactly 64 hex chars.** `buildMembershipFilter` now
  validates every input against `/^[0-9a-f]{64}$/i` and throws, naming the
  offending index, on anything else (non-hex, odd-length, 66-hex, …). Previously
  any string was accepted, which could silently break fuse-peel convergence on
  a case-variant duplicate or build an untestable non-64-hex member.
  **Migrate:** ensure every value passed to `buildMembershipFilter` is
  `memberKey()` output (or otherwise exactly 64 hex chars) before calling.
- **`epoch` must be a non-negative safe integer.** `buildMembershipFilter`
  throws on a negative, fractional, non-finite, or too-large `epoch` (a
  negative epoch previously wrapped to `2^64-1` on the wire).
  `parseFilter` mirrors this on read: a blob whose header `epoch` exceeds
  `Number.MAX_SAFE_INTEGER` now throws instead of silently losing precision.
- **`expiresAt` must be a non-negative safe integer** in both
  `issuePresenceCapability` and `testWithCapability` (previously "any finite
  number," which allowed a fractional value or one that can't be canonically
  reproduced across a non-JS verifier, e.g. `1e21`).
- **`decoySeedHex` must be even-length hex of at least 16 bytes (32 hex
  chars).** `buildMembershipFilter` throws otherwise; previously an empty or
  odd-length seed was accepted (producing public/predictable decoys, or leaking
  a raw `RangeError`).
- **Decoys are now re-keyed per epoch.** When `decoySeedHex` is supplied,
  `buildMembershipFilter` derives the seed actually passed to the decoy
  generator from `sha256("tessera-decoy:v1:" ‖ decoySeedHex ‖ epoch)` instead of
  using `decoySeedHex` directly. A rebuild of the **same** epoch with the same
  inputs is still byte-identical, but the serialized blob for a given
  `(memberKeysHex, decoySeedHex)` pair now differs from what 0.1.0 produced,
  and differs across epochs where 0.1.0 would have produced the same decoys
  every time. **Migrate:** do not assume decoy bytes are stable across epochs
  (they no longer are, by design — see `### Security` below); a frozen
  golden-vector fixture using a fixed `decoySeedHex` across epochs will change.
- **`parseFilter` now rejects reserved flag bits (2-7) and a non-power-of-two
  `member_count_band`.** Both are values `serializeFilter` never emits, so a
  blob setting either is non-canonical and now throws instead of parsing.
- **`decodeFilterPublicationContent`'s `maxBytes` is validated and clamped.** A
  non-safe-integer or negative `maxBytes` now throws (it previously disabled
  the size cap entirely); any value above `KFLT_MAX_BLOB_BYTES` is silently
  clamped down to it.

#### Added

- **`verifyAndParseFilter(blob, { pinnedPubkeyHex, minEpoch? })`** (`sign.ts`,
  exported from `.`) — the recommended combined path: pin-verifies the signer
  (case-insensitive), parses, and (if `minEpoch` is given) rejects a filter
  whose signed `epoch` is older than `minEpoch` (stale/rollback). Closes the
  "forgot to pin" and "no freshness check" gaps left by using
  `verifyFilterBlob` / `parseFilter` separately.

#### Fixed

- `testWithCapability` now throws if the resolved `now` clock value is not
  `Number.isFinite` — an injected `NaN` previously made `NaN > expiresAt`
  evaluate to `false`, silently skipping the expiry check.

#### Security

- **B1 (HIGH): a capability no longer discloses the pool salt.** The old
  `saltHint` field carried the keyed pool's salt in clear, so holding any one
  subject's capability handed the bearer everything needed to compute
  `memberKey(anyPk, saltHint)` for **any** candidate — equivalent to
  salt-holder access to the whole pool, not consent to test one person.
  `memberValue` confines a bearer to testing only the subject named on the
  token. Docs no longer describe the token as "one-time" (it is a bearer
  token; nothing enforces single use) and now state plainly that it is not
  bound to a specific filter beyond the `serverId` string. Docs also now state
  plainly that `expiresAt` bounds only the `testWithCapability` wrapper, not
  `memberValue` itself: a bearer who has already seen `memberValue` can call
  `testMembership(filter, memberValue)` directly, past `expiresAt`, for every
  epoch until the pool's salt rotates — or indefinitely for an open pool, where
  `memberValue` never changes. Salt rotation is the only actual revocation.
- **B2 (MEDIUM): stable decoys enabled cross-epoch churn-diffing, which is the
  opposite of the documented claim.** Fuse fingerprint slots are XOR-shared, so
  a decoy set reused byte-for-byte across epochs diffs 0 slots when nothing
  changed and ~3 slots when exactly one member swapped — a real activity
  leak. Decoys are now re-keyed per epoch (see `### Breaking`), which keeps a
  same-epoch rebuild byte-identical while denying an attacker a stable
  baseline to diff across epochs.
- **B3 (MEDIUM): unvalidated member keys could break construction or admit
  untestable members.** See `### Breaking`.
- **B4 (MEDIUM): no combined verify+parse+freshness helper, and no guidance to
  use the blob's signed epoch over a Nostr tag.** See `### Added`; PROTOCOL.md
  §4.3/§6 now spell out the rollback and cross-server-substitution risks.
  `verifyAndParseFilter` also validates its own options: `pinnedPubkeyHex` must
  be 64 hex chars, and a given `minEpoch` must be a non-negative safe integer —
  a `NaN` `minEpoch` previously made `filter.epoch < minEpoch` always `false`,
  silently accepting a stale blob (the same `NaN`-clock footgun as B5).
- **B5 (LOW): a `NaN` clock skipped capability expiry.** See `### Fixed`.
- **B6 (LOW): a `NaN`/negative `maxBytes` disabled the Nostr content size cap.**
  See `### Breaking`.
- **B7 (LOW): a negative/oversized epoch could corrupt on-wire freshness
  comparisons.** See `### Breaking`.
- **B8 (LOW): `expiresAt`'s JS-number stringification wasn't cross-language
  canonical.** See `### Breaking`.
- **B9 (LOW): `parseFilter` accepted non-canonical reserved flags / bands.**
  See `### Breaking`.
- **B10 (LOW): an empty/short/odd-length `decoySeedHex` produced predictable
  decoys or leaked a raw error.** See `### Breaking`.

## [0.1.0] — Never published

**This version never shipped to npm.** It was superseded by the audit and
review passes folded into 0.2.0 (above) before any release; it is kept here
only as a historical record of the initial design, not as an installable
version — there is no `v0.1.0` git tag and there never will be one.

Planned first release: a privacy-preserving **membership-presence filter**. A
community server publishes one signed, immutable `KFLT` blob per epoch; a client
that already holds a friend's pubkey can test that one key against the blob
**locally**, with no enumeration affordance and no online query API.

### Added

- **Membership filter core** — `buildMembershipFilter` / `testMembership` over a
  clean-room TypeScript port of the Binary Fuse 16 filter (Graf & Lemire 2022).
  No false negatives; false positives ≈ 2⁻¹⁶.
- **`memberKey(pubkeyHex, saltHex?)`** — the value to insert/test: the pubkey
  itself (OPEN pool) or `sha256(salt ‖ pubkey)` (KEYED pool).
- **KFLT byte codec** — `serializeFilter` / `parseFilter`. `parseFilter` is the
  hostile-input trust boundary: it validates magic/version/geometry and
  recomputes the blob length from the header **before** allocating.
- **Schnorr provenance** — `signFilterBlob` (in place, BIP340) and
  `verifyFilterBlob` → `{ signerPubkeyHex, ok }`. `ok: true` is self-consistency,
  **not** trust; consumers MUST pin-compare `signerPubkeyHex` to a known server
  key before trusting any hit.
- **Size-bucket padding** — `nextPowerOfTwoBand` / `deriveDecoys`, with a stable
  decoy pool (`decoySeedHex`) that defeats cross-epoch churn-diffing.
- **Presence capabilities** (`@forgesworn/tessera-kit/capability`) —
  `issuePresenceCapability` / `testWithCapability`: a subject-signed, expiring
  consent token to be located on a keyed server without the server going open.
- **Generic Nostr publication helper** (`@forgesworn/tessera-kit/nostr`) — a
  zero-relationship-knowledge kind-30444 event builder for serving a filter blob.
- **Frozen golden vector** (`vectors/kflt.golden.v1.json`) + strict checker
  (`npm run vectors:check`): the cross-implementation / future-Rust-port contract
  for the KFLT byte layout. The vector is the UNSIGNED `serializeFilter` output
  (Schnorr signatures are non-deterministic and cannot be frozen) and pins
  padding to `padToBucket: false` for byte reproducibility.
- CI (push/PR), tag-triggered release, dependabot + auto-merge workflows.

### Notes

- **Scoped package name.** This package publishes as **`@forgesworn/tessera-kit`**.
- **Publish order.** `@forgesworn/tessera-kit` MUST be on npm **before**
  `@forgesworn/kenspeckle` — `kenspeckle` (the code implementing the
  `kindred` wire convention) depends on it. This note used the package's
  working-title name `kindred` at the time it was written; it was renamed to
  `kenspeckle` before any publish, and `kindred` now names only the wire
  protocol/addressing convention, not a package (see PROTOCOL.md §6).
- **Relationship-agnostic by design.** tessera-kit knows nothing about
  relationships, personas, or Nostr **kinds** — *kinds are kenspeckle's
  concern*. This package only builds, tests, signs, serializes, and parses
  membership filters; the discovery/relationship layer lives in
  `@forgesworn/kenspeckle`.

[0.2.0]: https://github.com/forgesworn/tessera-kit/releases/tag/v0.2.0

<!-- No [0.1.0] link — that version was never published and no v0.1.0 tag
     exists or ever will; see the note under "## [0.1.0] — Never published"
     above. Do not add a link reference for it. -->
