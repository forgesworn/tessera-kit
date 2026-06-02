# tessera-kit

**Privacy-preserving membership-presence filter — build, sign, and serialize a non-enumerable Binary Fuse filter so a client can answer "is this person here?" locally, without the server ever exposing a member list or a query API.**

[![npm](https://img.shields.io/npm/v/tessera-kit)](https://www.npmjs.com/package/tessera-kit)
[![licence](https://img.shields.io/npm/l/tessera-kit)](https://github.com/forgesworn/tessera-kit/blob/main/LICENSE)
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
npm i tessera-kit
```

ESM-only, Node ≥ 22. Two runtime deps: `@noble/curves`, `@noble/hashes`.

## Quick start

### Server — build, sign, publish the bytes

```typescript
import {
  memberKey,
  buildMembershipFilter,
  serializeFilter,
  signFilterBlob,
} from 'tessera-kit'

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

// Serialize to the KFLT blob, then sign it in place with the SERVER key. The
// signature binds provenance: a tampered or attacker-authored blob is detectable.
const blob = serializeFilter(openFilter)
signFilterBlob(blob, serverPrivHex) // mutates `blob`: writes signer pubkey + sig

// Publish `blob` however you like — HTTPS, or a Nostr kind-30444 event
// (see PROTOCOL.md "Server publication shape" for the zero-dependency tag layout).
```

### Client — parse, **verify against a pinned key**, then test

```typescript
import { parseFilter, verifyFilterBlob, testMembership, memberKey } from 'tessera-kit'

// `parseFilter` validates the blob is SELF-CONSISTENT bytes. It does NOT
// authenticate origin — never trust a hit on parse alone.
const filter = parseFilter(blob)

// Provenance gate. `valid:true` means only "internally-consistent sig by
// signerPubkeyHex." Trust comes from the PINNED-key comparison, not from `valid`.
const { signerPubkeyHex, valid } = verifyFilterBlob(blob)
if (!valid || signerPubkeyHex !== PINNED_SERVER_PUBKEY) {
  throw new Error('untrusted filter — refuse to test')
}

// Now a local membership test. Transform the query the SAME way the pool was
// built: memberKey(friendPk) for an open pool, memberKey(friendPk, salt) keyed.
const present = testMembership(filter, memberKey(friendPubkey))
// `present === true` is a CANDIDATE, not a proof — at ecosystem scale ~1.5 false
// hits accumulate per full sweep at 16-bit (PROTOCOL.md §FPR). Confirm on connect
// (a key-control challenge) before acting on a hit.
```

### Locating a consenting friend on a *keyed* server — capability tokens

A friend can hand you a one-time, expiring token to test **their** presence on a
keyed server without the server going open and without you being able to forge a
token for anyone else. The token is signed by the **subject** (consent), not the
server (provenance) — still pin-verify the filter.

```typescript
import { issuePresenceCapability, testWithCapability } from 'tessera-kit/capability'

// Subject (the friend) issues a capability for a colon-free serverId.
const cap = issuePresenceCapability(
  { serverId: 'play.example.com', subjectPubHex, saltHint: salt, expiresAt },
  subjectPrivHex,
)

// Bearer tests it. Signature + expiry are checked BEFORE the membership test;
// an expired/forged capability THROWS (it is not a silent `false`).
const friendPresent = testWithCapability(keyedFilter, cap)
```

## API

### `.` (main entry)

| Export | Purpose |
|--------|---------|
| `memberKey(pubkeyHex, saltHex?)` | The value to insert/test: the pubkey (open) or `sha256(salt ‖ pubkey)` (keyed). |
| `buildMembershipFilter(valuesHex, opts)` | Build a Binary Fuse 16 filter over already-`memberKey`-transformed values. `opts.epoch` required; `fingerprintBits` defaults to 16; `padToBucket` defaults to true; `salt` presence sets the keyed flag; `decoySeedHex` for stable padding. |
| `testMembership(filter, valueHex)` | Local membership test. No false negatives; false positives ≈ 2⁻¹⁶. |
| `serializeFilter(filter)` | Encode to the `KFLT` blob (signer/sig regions left zero). |
| `parseFilter(blob)` | Hardened decode — validates magic/version/geometry and recomputes length **before** allocating. Self-consistency only; **not** provenance. |
| `signFilterBlob(blob, signerPrivHex)` | Sign the blob **in place** (writes signer pubkey + Schnorr sig). Zeroizes the priv byte copy. |
| `verifyFilterBlob(blob)` | `{ signerPubkeyHex, valid }`. Never throws on hostile input. **Compare `signerPubkeyHex` to a pinned key before trusting a hit.** |
| `nextPowerOfTwoBand(n)` | Size-bucket function (the `member_count_band`). |
| `deriveDecoys(decoySeedHex, count)` | Deterministic decoy keys for stable padding. |

Types: `MembershipFilter`, `FilterBuildOptions`, `FilterType`, `FingerprintBits`, and the `KFLT_*` constants.

### `./capability`

| Export | Purpose |
|--------|---------|
| `issuePresenceCapability(p, subjectPrivHex)` | Subject mints a consent token to be located on a keyed server. Asserts the embedded `subjectPubHex` matches the signing key. |
| `testWithCapability(filter, cap, now?)` | Verify the token (sig + expiry first) then test the subject. Throws on expired/forged. |
| Type: `PresenceCapability` | `{ serverId, subjectPubHex, saltHint, expiresAt, sig }`. `serverId` **must be colon-free**. |

The exact byte layouts (KFLT header, signing digest, capability canonical bytes,
and the Nostr publication tag shape) are in **[PROTOCOL.md](./PROTOCOL.md)**.

## Security

tessera-kit makes **narrow, honest** privacy claims. Before you build on it, read
**[SECURITY.md](./SECURITY.md)** — the short version:

- **Non-enumerable ≠ non-confirmable.** A held specific key is always confirmable-present.
- **Keyed = speed-bump, not a boundary.** It does not confine probing to current members and does not survive a salt leak. Real member privacy = per-context personas + not joining open servers.
- **Pin-verify is mandatory.** Always check `signerPubkeyHex` against a known server key before trusting a hit — a forged filter is a doxxing primitive.
- **`member_count_band` leaks a coarse power-of-two count by design;** padding hides only the fine count.
- **Salt rotation defeats array-diffing by non-holders** but a party holding candidate key X can still track X across epochs by re-testing.

## Toolkit

tessera-kit is the membership-presence brick of the **Forgesworn / Signet**
ecosystem. It is consumed by **`kindred`** (the relationships + discovery
primitive): `kindred/discovery` is a thin layer over `parseFilter` /
`testMembership` / `memberKey` that adds persona-scoping and signed Nostr
publications. A server that only needs to *publish* a filter can depend on
tessera-kit alone and emit the kind-30444 event directly (PROTOCOL.md).

Siblings: [`spoken-token`](https://github.com/forgesworn/spoken-token) (spoken
verification words), [`geohash-kit`](https://github.com/forgesworn/geohash-kit)
(location), [`nsec-tree`](https://github.com/forgesworn/nsec-tree) (hierarchical
key derivation).

## Licence

MIT.
