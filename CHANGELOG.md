# Changelog

All notable changes to `@forgesworn/tessera-kit` are documented here. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/forgesworn/tessera-kit/releases/tag/v0.1.0
