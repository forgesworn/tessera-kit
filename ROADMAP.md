# tessera-kit roadmap

tessera-kit is the presence layer for kindred: a signed, non-enumerable filter
that lets a client answer "is this person here?" locally, without the server
publishing its member list. This roadmap is about doing that one job well. It
is not a relationships library (that's kenspeckle) and not a transport.

## Where it sits

- **Consumers:** kenspeckle (the kindred implementation, `^0.2.1` from npm) and
  signet-app (via kenspeckle, plus a direct git pin at `7ffded7`).
  `signet-plans/tools/signet-public-candidate/export.py` vendors the local
  checkout. bothy-node plans a `KenFilter` command (Phase 3, not built).
- **Spec and conformance:** [PROTOCOL.md](./PROTOCOL.md),
  [CONFORMANCE.md](./CONFORMANCE.md), golden vectors in [`vectors/`](./vectors).
  A Rust/WASM port is planned (SECURITY.md) but not started.

## Shipped

| Item | Version |
|------|---------|
| Binary Fuse 16 build/test, KFLT wire format v1, decoy padding | 0.2.0 |
| Context-bound filter signatures (`tessera-kflt-sig:v1`), `isValidFilterContext` | 0.2.0 |
| `TesseraError` with stable codes (PROTOCOL.md §9, sync-tested) | 0.2.0 |
| Presence capabilities, open-pool binding, input validation throughout | 0.2.0 |
| Conformance vectors n = 0 to 100k, must-reject vectors, CONFORMANCE.md | 0.2.0 |
| `describeFilter`, `testMany`, opt-in `strictlyNewerThan` | 0.2.1 |
| Structure-aware `parseFilter` fuzz, property tests, coverage, bench | 0.2.1 |
| Published to npm with provenance | 0.2.0 (2026-09-25), 0.2.1 (2026-09-26) |

## Open

Each item says why it is not done yet. **Blocked on** names what has to happen
first; if it's empty, the item can be picked up directly. Versioning while on
0.x: additive changes ship as a patch (0.2.x); anything breaking is 0.3.0 and
needs kenspeckle and signet-app to move in step.

### Next up (safe, additive)

| Item | Size | Why | Blocked on |
|------|------|-----|------------|
| Release the doc fixes in `c5b8000` (0.x versioning rule, `testMany` scope, `describeFilter` unauthenticated) | S | PROTOCOL.md ships in the npm package; npm still has the older wording | — (release as 0.2.2 with the next change) |
| Size warning in `buildFilterPublication` (configurable byte limit, new error or warning code) plus a PROTOCOL.md note on bytes per member | S | ~2.3 bytes/member means one event overflows common 64 KB relay limits at ~28k members. Not a problem at current scale; this makes it loud instead of a silent relay reject | — |
| CI on Bun, Deno and a browser; consider JSR | S–M | Code is pure TS, so it should pass, but it's unproven | Bun/Deno not installed on the dev machine where this was last worked on |

### Needs a design decision first

| Item | Size | Why | Blocked on |
|------|------|-----|------------|
| Filters larger than one relay event: Blossom (hash-addressed) pointer or chunking, plus a NIP for kind 30444 | M–L | Only matters around ~28k members per server; deliberately deferred 2026-09-26 as "not an issue at our scale" | Choosing Blossom vs chunking, agreed with kenspeckle |
| Version tag on the Nostr filter event | S | Lets a future KFLT v2 roll out cleanly | kindred convention change, agreed with kenspeckle; a breaking 0.3.0 |
| Binary Fuse 32 (32-bit fingerprints) | M | FPR from ~1/65k to ~1/4 billion at twice the size. Wire value is reserved; types are narrowed to 16 | Deciding it's needed; new wire format and 0.3.0 |
| One-call Nostr verify helper (event sig, decode, context, pin, per-server epoch tracking) | M | kenspeckle already does this itself; only worth it if a second consumer verifies filters directly | A second consumer existing |
| Connect-time presence challenge | M | Confirms presence live rather than trusting the filter alone | Design |
| NIP-44-encrypted capability delivery and a per-epoch salt-rotation helper | M | Salt rotation is the only real revocation today | Design |
| Multi-server sweep helper with a false-positive budget | M | Checking one person across many servers compounds FPR | Design |

### Outside this repo

| Item | Where |
|------|-------|
| Move signet-app's tessera-kit pin from `git#7ffded7` to `^0.2.1` when it next bumps kenspeckle | signet-app |
| Remove leftover npm dist-tag `seed` (`npm dist-tag rm @forgesworn/tessera-kit seed`) | npm org owner |

## For an agent picking this up

1. Read this file, then PROTOCOL.md §9 (error-code contract) and §11 (versioning).
2. Pick from **Next up** unless told otherwise. Anything under **Needs a design
   decision** needs a human decision first — raise it, don't implement it.
3. Acceptance for any change: `npm test`, `npm run typecheck`,
   `npm run build && npm run vectors:check`. New error codes must be added to
   the `TesseraErrorCode` union, the PROTOCOL.md §9 table and `errors.test.ts`
   (`protocol-sync.test.ts` enforces the first two).
4. Existing vectors in `vectors/` must never change in an additive release.
5. When an item ships, move it to **Shipped** with its version.
