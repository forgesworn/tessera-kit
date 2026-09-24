# Changelog

All notable changes to `@forgesworn/tessera-kit` are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A second audit pass over 0.2.0, closing gaps the first pass missed. Three
items are marked **Breaking** — they change what previously-accepted input now
throws on, or what result a previously-accepted call now returns.

### Breaking

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

### Fixed

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

### Added

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

### Docs

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

## [0.2.0] — Unreleased

A post-audit hardening pass over 0.1.0. Several fixes are **breaking** —
0.1.0 was never published, so this is the first shape consumers actually build
against.

### Breaking

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

### Added

- **`verifyAndParseFilter(blob, { pinnedPubkeyHex, minEpoch? })`** (`sign.ts`,
  exported from `.`) — the recommended combined path: pin-verifies the signer
  (case-insensitive), parses, and (if `minEpoch` is given) rejects a filter
  whose signed `epoch` is older than `minEpoch` (stale/rollback). Closes the
  "forgot to pin" and "no freshness check" gaps left by using
  `verifyFilterBlob` / `parseFilter` separately.

### Fixed

- `testWithCapability` now throws if the resolved `now` clock value is not
  `Number.isFinite` — an injected `NaN` previously made `NaN > expiresAt`
  evaluate to `false`, silently skipping the expiry check.

### Security

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

## [0.1.0] — Unreleased

First public release: a privacy-preserving **membership-presence filter**. A
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
  `@forgesworn/kindred` — `kindred` depends on it.
- **Relationship-agnostic by design.** tessera-kit knows nothing about
  relationships, personas, or Nostr **kinds** — *kinds are `kindred`'s concern*.
  This package only builds, tests, signs, serializes, and parses membership
  filters; the discovery/relationship layer lives in `@forgesworn/kindred`.

[0.2.0]: https://github.com/forgesworn/tessera-kit/releases/tag/v0.2.0
[0.1.0]: https://github.com/forgesworn/tessera-kit/releases/tag/v0.1.0
