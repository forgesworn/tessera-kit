# tessera-kit

**Privacy-preserving membership-presence filter — build, sign, and serialize a non-enumerable Binary Fuse filter so a client can answer "is this person here?" locally, without the server ever exposing a member list or a query API.**

[![npm](https://img.shields.io/npm/v/%40forgesworn%2Ftessera-kit)](https://www.npmjs.com/package/@forgesworn/tessera-kit)
[![licence](https://img.shields.io/npm/l/%40forgesworn%2Ftessera-kit)](https://github.com/forgesworn/tessera-kit/blob/main/LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-native-blue)
![ESM only](https://img.shields.io/badge/module-ESM--only-informational)

## The problem

A community server (a game, an app, a venue) wants to let a member answer "is my
friend here?" *without* publishing its member list and *without* running a
who's-here lookup API (which would log "who's interested" and centralise the
social graph). A server-side query endpoint is the exact observability the design
is trying to avoid.

tessera-kit lets the server publish **one signed, immutable blob per epoch**. A
member who already holds a friend's pubkey can test that one key against the blob
**locally**. There is no enumeration affordance and no online query: the blob
carries 16-bit *fingerprints*, not keys.

> **Honest scope (read [SECURITY.md](./SECURITY.md)):** non-enumerable is **not**
> non-confirmable. A held *specific* pubkey is always confirmable-present — that
> is the function. Keyed pools are a **speed-bump, not a member-privacy boundary**.
> A forged filter is a doxxing primitive, so a consumer **MUST** `verifyFilterBlob`
> against a **pinned** server key before trusting any hit.

## Install

```bash
npm i @forgesworn/tessera-kit
```

ESM-only, Node ≥ 22. Three runtime deps: `@noble/curves`, `@noble/hashes`, and
`@scure/base` (pulled in only by the optional `./nostr` subpath, for base64 —
the core `.` and `./capability` entries stay `@noble`-only).

## Quick start

### Server — build, sign, publish the bytes

```typescript
import {
  memberKey,
  buildMembershipFilter,
  serializeFilter,
  signFilterBlob,
} from '@forgesworn/tessera-kit'

const epoch = Math.floor(Date.now() / 1000)

// (a) OPEN pool — opt-in-public members (public figures), discoverable by anyone
//     holding their pubkey. memberKey(pk) inserts the pubkey itself.
const openValues = openMemberPubkeys.map((pk) => memberKey(pk))
const openFilter = buildMembershipFilter(openValues, { epoch })

// (b) KEYED pool — everyone else. memberKey(pk, salt) inserts H(salt ‖ pk), so a
//     stranger needs the out-of-band salt to compute the value to test. (This is
//     a speed-bump, not a boundary — see SECURITY.md.) Passing `salt` only sets
//     the on-wire `keyed` flag; the caller does the salting via memberKey.
const salt = serverKeyedSaltHex // distributed out-of-band; NEVER in the blob
const keyedValues = keyedMemberPubkeys.map((pk) => memberKey(pk, salt))
const keyedFilter = buildMembershipFilter(keyedValues, { epoch, salt })

// Serialize to the KFLT blob, then sign it in place with the SERVER key, BOUND
// to this deployment's `context` — the stable address a verifier already knows
// out-of-band (e.g. a kindred d-tag `kindred:members:<ns>:<serverId>`; see
// PROTOCOL.md §4.1/§4.3). The signature binds provenance AND this context: a
// tampered or attacker-authored blob is detectable, and a blob signed for one
// deployment cannot be replayed as another's, even under a reused signing key.
//
// ⚠️ `namespace` MUST NOT contain a colon (`serverId` may) — the d-tag is
// parsed by splitting on the FIRST colon after "kindred:members:", so a
// colon in `namespace` lets two different (namespace, serverId) pairs
// collide on the same context string. See PROTOCOL.md §4.3/§6.
const context = `kindred:members:${namespace}:${serverId}`
const blob = serializeFilter(openFilter)
signFilterBlob(blob, serverPrivHex, context) // mutates `blob`: writes signer pubkey + sig

// Publish `blob` however you like — HTTPS, or a Nostr kind-30444 event
// (see PROTOCOL.md "Server publication shape" for the zero-dependency tag layout).
```

### Client — parse, **verify against a pinned key + context**, check freshness, then test

```typescript
import { verifyAndParseFilter, testMembership, memberKey } from '@forgesworn/tessera-kit'

// One call does the mandatory work: pin-verify the signer AND context, parse,
// and (if you pass minEpoch) reject a stale/rolled-back blob. `context` MUST be
// the SAME stable deployment address the server signed with (see above) — track
// the highest epoch you've accepted per (pinnedPubkeyHex, context) and pass it
// back in next time.
//
// ⚠️ Build `context` from the (namespace, serverId) YOU chose to fetch —
// `namespace`/`serverId` here are values the client already had BEFORE
// fetching anything (that's how it picked which event to ask for). NEVER
// read the `d`-tag (or any other tag) off the event you just received and
// use THAT to build `context` — a relay/MITM controls every tag on the
// event it serves you, so trusting a tag-derived context lets it swap in a
// different server's validly-signed blob and have your own code "confirm"
// the substitution for it. See PROTOCOL.md §4.3/§6.
const filter = verifyAndParseFilter(blob, {
  pinnedPubkeyHex: PINNED_SERVER_PUBKEY,
  context: `kindred:members:${namespace}:${serverId}`,
  minEpoch: lastSeenEpoch, // optional; omit on first fetch
})
// filter.epoch is the blob's own SIGNED epoch — use THIS for freshness, never a
// Nostr ["epoch"] tag on a wrapping event (that tag is signed only by the
// publisher key and is never cross-checked against the blob; see PROTOCOL.md §4.3/§6).

// Now a local membership test. Transform the query the SAME way the pool was
// built: memberKey(friendPk) for an open pool, memberKey(friendPk, salt) keyed.
const present = testMembership(filter, memberKey(friendPubkey))
// `present === true` is a CANDIDATE, not a proof — at ecosystem scale ~1.5 false
// hits accumulate per full sweep at 16-bit (PROTOCOL.md §7.2). Confirm on connect
// (a key-control challenge) before acting on a hit.
```

> A `KFLT` blob does not name the server/namespace it belongs to in its header
> — the signed `context` string is what binds it. A blob signed for one
> deployment's `context` cannot verify under another's, even if the two
> deployments share a signing key — using a **distinct signing key per
> server/namespace** is still good practice (defence in depth), but it is no
> longer the only thing standing between you and cross-server substitution.

(`parseFilter` / `verifyFilterBlob` are still exported separately if you need
them independently — `verifyAndParseFilter` is the recommended combined path.)

### Locating a consenting friend on a server — capability tokens

A friend can hand you an expiring **bearer** token to test **their** presence on
a server without a keyed pool going open to you and without you being able to
forge a token for anyone else. The token is signed by the **subject** (consent),
not the server (provenance) — still pin-verify the filter.

> **Honest scope:** this is a bearer token, not a one-time token — anyone who
> holds it can test it, any number of times, and can forward it to anyone else,
> until `expiresAt`. What it DOES guarantee: it reveals only **this subject's**
> own pool value, never the pool salt — holding one friend's capability grants
> no ability to probe any other member. It is also not bound to a specific
> filter beyond the free-form `serverId` string. **`expiresAt` only bounds the
> `testWithCapability` check** — a bearer who has already seen the subject's pool
> value can test it directly, every epoch, until the pool's salt rotates (or
> indefinitely, for an open pool). Salt rotation is the real revocation. See
> SECURITY.md §6 / PROTOCOL.md §5.

```typescript
import { issuePresenceCapability, testWithCapability } from '@forgesworn/tessera-kit/capability'

// Subject (the friend) issues a capability for a colon-free serverId. `salt` is
// the KEYED pool's salt — pass it for a keyed server, omit it for an open one.
// The salt itself never ends up on the returned capability; only the subject's
// own derived `memberValue` does.
const cap = issuePresenceCapability(
  { serverId: 'play.example.com', subjectPubHex, salt, expiresAt },
  subjectPrivHex,
)

// Bearer tests it. Expiry + signature are checked BEFORE the membership test;
// an expired/forged capability THROWS (it is not a silent `false`).
const friendPresent = testWithCapability(keyedFilter, cap)
```

## API

### `.` (main entry)

| Export | Purpose |
|--------|---------|
| `memberKey(pubkeyHex, saltHex?)` | The value to insert/test: the pubkey (open) or `sha256(salt ‖ pubkey)` (keyed). |
| `buildMembershipFilter(valuesHex, opts)` | Build a Binary Fuse 16 filter over already-`memberKey`-transformed values. `opts.epoch` required; `fingerprintBits` defaults to 16; `padToBucket` defaults to true; `salt` presence sets the keyed flag; `decoySeedHex` for decoys that are stable within an epoch but re-keyed per epoch (defeats cross-epoch diffing — see SECURITY.md §4). |
| `testMembership(filter, valueHex)` | Local membership test. No false negatives; false positives ≈ 2⁻¹⁶. |
| `testMany(filter, valuesHex)` | Test many values in one call — the exact same validation/semantics as calling `testMembership` on each value, in order. |
| `describeFilter(filter)` | Public, read-only view of a filter's metadata (`fingerprintBits`, `filterType`, `keyed`, `padded`, `epoch`, `memberCountBand`, `segmentLength`, `segmentCount`, `arrayLength`, `byteLength`, `theoreticalFalsePositiveRate`) — reveals nothing beyond the serialized header. |
| `serializeFilter(filter)` | Encode to the `KFLT` blob (signer/sig regions left zero). |
| `parseFilter(blob)` | Hardened decode — validates magic/version/geometry and recomputes length **before** allocating. Self-consistency only; **not** provenance. |
| `signFilterBlob(blob, signerPrivHex, context)` | Sign the blob **in place** (writes signer pubkey + Schnorr sig), binding `context` (a required, non-empty string — the deployment's stable address) into the signed digest. Zeroizes the priv byte copy. |
| `verifyFilterBlob(blob, context)` | `{ signerPubkeyHex, ok }`. Never throws on hostile **blob** input (throws on a malformed `context`, a caller config error). `context` must match what was signed or `ok` is `false`, indistinguishable from a bad signature. **Compare `signerPubkeyHex` to a pinned key before trusting a hit.** |
| `verifyAndParseFilter(blob, { pinnedPubkeyHex, context, minEpoch?, strictlyNewerThan? })` | The recommended combined path: pin-verifies, parses, and (if `minEpoch` given) rejects a stale/rolled-back filter. `strictlyNewerThan` (optional, additive) rejects a filter whose `epoch` is not *strictly* newer — closes the same-epoch-replay gap `minEpoch` alone leaves open, for callers who opt in. Throws on any failure. |
| `nextPowerOfTwoBand(n)` | Size-bucket function (the `member_count_band`). |
| `deriveDecoys(decoySeedHex, count)` | Deterministic decoy keys for a given `(decoySeedHex, count)`. `buildMembershipFilter` calls this with an epoch-derived seed, not the caller's raw `decoySeedHex` — see SECURITY.md §4. |

Types: `MembershipFilter`, `FilterBuildOptions`, `FilterDescription`, `FilterType`, `FingerprintBits`, and the `KFLT_*` constants.

### `./capability`

| Export | Purpose |
|--------|---------|
| `issuePresenceCapability(p, subjectPrivHex)` | Subject mints a **bearer** consent token to be located. `p.salt` (optional; a keyed pool's salt, omit for open) is used only to derive `memberValue` and is never stored on the returned token. Asserts the embedded `subjectPubHex` matches the signing key. |
| `testWithCapability(filter, cap, now?)` | Verify the token (expiry + sig first, in that order) then test `cap.memberValue` directly. Throws on expired/forged/malformed. |
| Type: `PresenceCapability` | `{ serverId, subjectPubHex, memberValue, expiresAt, sig }`. `serverId` **must be colon-free** and is not cryptographically bound to any filter. `memberValue` is the subject's own 64-hex pool value — never the pool salt. |

### `./nostr`

Optional, relationship-agnostic Nostr publication helpers (spec §6). This is
the **only** subpath that pulls in `@scure/base` (for base64) — the core `.`
and `./capability` entries stay `@noble`-only. A server that only needs to
*publish* a filter can depend on tessera-kit alone via this subpath — no
`kenspeckle` import required.

```typescript
import { buildFilterPublication, decodeFilterPublicationContent } from '@forgesworn/tessera-kit/nostr'

// Server: assemble the unsigned Nostr event template around a signed KFLT blob.
// tessera-kit does NOT know kindred's addressing convention (the protocol
// naming — see PROTOCOL.md §6) — YOU supply kind/tags.
const event = buildFilterPublication({ kind: 30444, tags: [['d', 'my:d:tag']], blob, createdAt })
// event.content is base64(blob); sign `event` with your own Nostr key (NIP-01) — separate
// from the in-blob Schnorr provenance signature (signFilterBlob).

// Client: decode an event's content back to the raw blob, capped at KFLT_MAX_BLOB_BYTES
// (or a smaller caller-supplied cap) BEFORE decoding, so a hostile oversized event can't
// force a large allocation.
const blobBytes = decodeFilterPublicationContent(event.content)
```

| Export | Purpose |
|--------|---------|
| `buildFilterPublication({ kind, tags, blob, createdAt })` | Base64-encodes `blob` into `content` and assembles `{ kind, tags, content, created_at }`. Relationship-agnostic — the caller supplies `kind`/`tags`. |
| `decodeFilterPublicationContent(content, maxBytes?)` | Inverse: decodes `content` back to raw blob bytes. Length-capped (defaults to, and is clamped to, `KFLT_MAX_BLOB_BYTES`) **before** decoding. |
| Type: `EventTemplate` | `{ kind, tags, content, created_at }` — the unsigned Nostr event shape (structural; no `nostr-tools` runtime dep). |

The exact byte layouts (KFLT header, signing digest, capability canonical bytes,
and the Nostr publication tag shape) are in **[PROTOCOL.md](./PROTOCOL.md)**.

## Security

tessera-kit makes **narrow, honest** privacy claims. Before you build on it, read
**[SECURITY.md](./SECURITY.md)** — the short version:

- **Non-enumerable ≠ non-confirmable.** A held specific key is always confirmable-present.
- **Keyed = speed-bump, not a boundary.** It does not confine probing to current members and does not survive a salt leak. Real member privacy = per-context personas + not joining open servers.
- **Pin-verify (key AND context) is mandatory.** Always check `signerPubkeyHex` against a known server key, and check against your deployment's own `context`, before trusting a hit — a forged filter is a doxxing primitive, and `context` is what stops one signed blob being replayed as a different deployment's.
- **`member_count_band` leaks a coarse power-of-two count by design;** padding hides only the fine count.
- **Salt rotation defeats array-diffing by non-holders** but a party holding candidate key X can still track X across epochs by re-testing.
- **A capability is a bearer token, not a one-time token,** and reveals only its subject's own pool value, never the pool salt. `expiresAt` bounds only the `testWithCapability` check, not the disclosed value — salt rotation is the actual revocation.

## Toolkit

tessera-kit is the membership-presence brick of the **Forgesworn / Signet**
ecosystem. It is consumed by **`kenspeckle`** (the relationships + discovery
primitive that implements the **kindred** wire protocol/convention —
`kindred` is the addressing convention's name, `kenspeckle` is the code):
`kenspeckle/discovery` is a thin layer over `parseFilter` / `testMembership` /
`memberKey` that adds persona-scoping and signed Nostr publications following
the kindred convention. A server that only needs to *publish* a filter can
depend on tessera-kit alone and emit the kind-30444 event directly
(PROTOCOL.md).

Siblings: [`spoken-token`](https://github.com/forgesworn/spoken-token) (spoken
verification words), [`geohash-kit`](https://github.com/forgesworn/geohash-kit)
(location), [`nsec-tree`](https://github.com/forgesworn/nsec-tree) (hierarchical
key derivation).

## Licence

MIT.
