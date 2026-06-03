# Contributing to tessera-kit

## Setup

```bash
git clone https://github.com/forgesworn/tessera-kit.git
cd tessera-kit
npm install
```

## Commands

| Command | Purpose |
|---------|---------|
| `npm test` | Run all tests (vitest) |
| `npm run test:watch` | Watch mode |
| `npm run build` | Compile TypeScript to dist/ |
| `npm run typecheck` | Type-check without emitting |
| `npm run vectors:check` | Verify the frozen KFLT golden vector(s) against the built code |

## Project Structure

```
src/
  member-key.ts   — memberKey(): open (pubkey) vs keyed (sha256(salt ‖ pubkey)) values
  fuse.ts         — Binary Fuse 16 filter (clean-room port; filter-only, knows no relationships)
  filter.ts       — buildMembershipFilter / testMembership (public surface)
  padding.ts      — size-bucket padding + stable decoy pool
  codec.ts        — KFLT byte codec: serializeFilter / parseFilter (hostile-input trust boundary)
  sign.ts         — Schnorr (BIP340) signFilterBlob / verifyFilterBlob
  capability.ts   — presence-capability tokens (./capability subpath)
  nostr.ts        — generic kind-30444 publication helper (./nostr subpath)
  types.ts        — shared types + KFLT_* constants
  index.ts        — barrel re-export
```

Two subpath exports sit alongside the main entry: `@forgesworn/tessera-kit/capability`
and `@forgesworn/tessera-kit/nostr`.

## Conventions

- **British English** — colour, behaviour, serialise, licence
- **Minimal runtime deps** — `@noble/curves`, `@noble/hashes`, `@scure/base` only. No others.
- **ESM-only** — `"type": "module"` in package.json
- **TDD** — write a failing test first, then implement
- **Input validation** — public APIs validate inputs; `parseFilter` is hardened
  against hostile/malformed blobs (recompute length before allocating, throw an
  `Error` on any malformation)
- **No `console.*` in library code** — `src/` is silent; the `scripts/` checkers may log
- **Relationship-agnostic** — this package knows nothing about relationships,
  personas, or Nostr *kinds*. That layer lives in `@forgesworn/kindred`.

## Frozen golden vectors

`vectors/kflt.golden.v1.json` is the cross-implementation / future-Rust-port
**contract** for the KFLT byte layout. `npm run vectors:check` rebuilds the filter
from the vector's inputs, asserts the serialised blob hex is **byte-identical**,
and asserts the declared membership results hold. It runs in CI and gates releases.

If you intentionally change the KFLT byte layout, regenerate the vector against
the new code and add a `CHANGELOG.md` note — a silent change breaks every other
implementation of this codec. The vector is the **UNSIGNED** `serializeFilter`
output (Schnorr signatures are non-deterministic and are covered by `sign.test.ts`,
not the vector), and pins padding (`padToBucket: false`) for byte reproducibility.

## Testing

Tests live alongside source files as `*.test.ts` (unit, fuzz, and property-based).

```bash
# Run all tests
npm test

# Run a specific test file
npx vitest run src/codec.test.ts

# Watch mode
npm run test:watch
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-change`
3. Write tests for your changes
4. Ensure all tests pass: `npm test`
5. Ensure types check: `npm run typecheck`
6. Ensure the golden vector still holds: `npm run vectors:check`
7. Commit with a conventional message (see below)
8. Open a pull request against `main`

## Commit Messages

This project uses conventional-commit prefixes:

| Prefix | Version bump | Example |
|--------|-------------|---------|
| `feat:` | Minor (0.x.0) | `feat: add cuckoo filter type` |
| `fix:` | Patch (0.0.x) | `fix: reject zero-length salt in memberKey` |
| `docs:` | None | `docs: clarify pin-verify requirement` |
| `chore:` | None | `chore: update dev dependencies` |
| `refactor:` | None | `refactor: extract digest construction` |
