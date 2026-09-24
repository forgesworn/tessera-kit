# Changelog

All notable changes to `@forgesworn/tessera-kit` are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
