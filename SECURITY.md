# Security Policy

tessera-kit makes **narrow, precise** privacy claims and refuses the broad ones.
This document is the honest posture (spec §7.4, §10). Read it before building on
the library — several intuitive-sounding guarantees are **deliberately not
made**, and treating the kit as if they were would create a doxxing primitive.

## The privacy posture, stated honestly

### 1. Keyed-salt is a speed-bump, not a member-privacy boundary

A **keyed** pool inserts `memberKey(pk, salt) = sha256(salt ‖ pk)` instead of the
bare pubkey, so a stranger needs the out-of-band salt to compute the value to
test. What this actually buys, stated precisely:

- It **restricts probing** from "anyone holding a pubkey" to "anyone who was
  admitted once (and thus learned the salt), or who was handed the salt by
  someone admitted."
- It does **not confine probing to current members.** Anyone who ever held the
  salt can keep probing arbitrary candidate keys after they leave.
- It does **not survive a salt leak.** One disclosure reopens the pool to
  everyone who receives the leaked salt.

Real member privacy comes from **per-context personas** (a different key per
server, via `nsec-tree`) **and not joining open servers** — not from keying. Keying
raises the cost of casual third-party probing; it is not a confidentiality
boundary, and this library does not present it as one.

### 2. Non-enumerable is **not** non-confirmable

Given only a published filter, there is no affordance to **list** members: the
blob carries 16-bit *fingerprints*, not keys, and the public API exposes no
enumeration function (asserted in `src/properties.test.ts`). Reconstructing the
member set from fingerprints is infeasible — at 16 bits, false positives
outnumber real members by a vast margin over the 2²⁵⁶ pubkey universe.

**But a held *specific* pubkey is always confirmable-present.** That is exactly
what `testMembership` / `testWithCapability` do. Non-enumerability says "you can't
get the list"; it does **not** say "you can't confirm a key you already hold."
Keyed pools raise the bar on *who can confirm* to salt-holders (§1) — a
speed-bump, not a boundary. Do not read "non-enumerable" as "private."

### 3. Pin-verify the filter before trusting any hit — **mandatory**

A `KFLT` blob is just bytes a stranger served you. A **forged** filter is a
doxxing primitive: an attacker who makes you trust an arbitrary membership set can
make `testMembership` report a friend as "present" on a server they never joined
(or hide a real member). Therefore:

- Consumers **MUST** call `verifyFilterBlob(blob)` and compare the returned
  `signerPubkeyHex` against a **pinned / out-of-band-known** server key **before**
  trusting any membership result.
- `verifyFilterBlob` returning `valid: true` means **only** "this blob carries an
  internally-consistent BIP340 Schnorr signature by `signerPubkeyHex`." It is
  **not** trust. Anyone can mint a validly self-signed blob under their own key;
  the **pinned-key comparison**, not `valid` alone, is what defeats forged-filter
  doxxing.

```
const { signerPubkeyHex, valid } = verifyFilterBlob(blob)
if (!valid || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
```

### 4. The count band leaks a coarse count by design; padding hides only the fine count

Size-bucket padding rounds the *inserted-key* count up to a power-of-two bucket by
adding decoys, so the serialized array size reveals only the coarse bucket.
However:

- `member_count_band` (header offset 28) records the **true** count's
  power-of-two bucket and **leaks that coarse count by design**. Padding hides the
  *fine* count, never the bucket.
- Without a **stable** `decoySeedHex`, padding decoys are CSPRNG-random and
  **churn across epochs**. An attacker who collects two epochs' blobs can diff the
  fingerprint arrays: entries that persist are decoys, entries that change are
  real members joining/leaving. **Pass a stable `decoySeedHex`** (a per-server
  secret) to make the decoys byte-identical across rebuilds and defeat this
  version-diffing. The unstable path is allowed but is a documented trade-off the
  caller opts into by omitting the seed.

### 5. Salt rotation defeats array-diffing by non-holders — with a stated residual

Rotating the keyed salt per epoch defeats **structural array-diffing by
non-holders** (a party without the salt can't correlate fingerprints across
epochs). **Residual, stated honestly:** a party who **holds a candidate key X** can
still track X's join/leave across epochs by **re-testing** X each epoch (computing
`memberKey(X, salt_epoch)` and querying). Salt rotation does **not** stop targeted
presence-tracking of a specific held key.

### 6. Capability tokens are subject consent, not filter provenance

A `PresenceCapability` is signed by the **subject** — it means "you may test MY
presence here, until `expiresAt`." It says **nothing** about whether the filter is
genuine. A consumer holding a valid capability **must still** pin-verify the
filter (§3) before trusting the hit. Consent and provenance are orthogonal; the
kit keeps them in separate signatures.

`saltHint = ''` in a capability corresponds to an **open-pool** capability (the
value tested is `memberKey(subjectPubHex, '')`), noted so an empty hint is not
mistaken for a malformed token.

### 7. Keyed mode trades third-party probing for server-side pull-auth logging

Obtaining a keyed salt generally requires an authenticated pull from the server,
which logs "who asked" — the very server-side observability that avoiding a
who's-here query API was meant to prevent. **Keyed mode protects members from
*third parties* (to the degree in §1), not from the server.** Stated explicitly.

### 8. Zeroization honesty

Private-key **byte copies** created internally for signing are wiped with
`.fill(0)` in a `finally` (in `signFilterBlob` and `issuePresenceCapability`).
**However:** a private key passed in as a JavaScript **string** is immutable and
**cannot be zeroized** — it persists in memory until garbage-collected, and the
library has no way to wipe it. Callers who need stronger secret hygiene should
minimise the lifetime of key strings. A future Rust/WASM port should take secrets
as **bytes** so they can be wiped deterministically.

## What is genuinely removed (the honest upside)

The **central-graph-ownership** harm — one party owning and monetising the whole
social graph — is removed: no party holds the edges, discovery is local, there are
no shadow profiles, and there is no who's-here query API to log interest. Open
pools still create an **opt-in, un-consented-by-others** cross-server presence
locator for the members *included in them*, and an aggregator plus a reused pubkey
can reconstruct venue-presence for those members. So the residual harm is
**reduced and opt-out-able**, defeated in practice by per-context personas — **not
eliminated**. We do not claim otherwise.

---

## Reporting a vulnerability

If you discover a security vulnerability in tessera-kit, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Email **thecryptodonkey@proton.me** with a description of the vulnerability,
   steps to reproduce, and any relevant proof-of-concept code.
3. You will receive an acknowledgement within 48 hours.
4. A fix will be developed privately and released as a patch version. You will be
   credited in the release notes unless you prefer otherwise.

## Scope

tessera-kit is a pure-computation library with two runtime dependencies
(`@noble/curves`, `@noble/hashes`) and no network or filesystem access. In scope:

- **Input-validation bypass / unbounded allocation** in `parseFilter` — a
  malformed `KFLT` blob that reads past its bounds or triggers an allocation
  sized by an attacker-controlled field (the recompute-before-allocate guard is
  the primary defence; report any way around it).
- **Signature / provenance weaknesses** — any way to make `verifyFilterBlob`
  accept a blob whose fingerprints, header, or signer pubkey were tampered, or to
  forge a `PresenceCapability` for a subject key you do not control.
- **Delimiter-injection** in the capability canonical bytes (the colon-free
  `serverId` guard) — any tuple collision that bypasses it.
- **Fingerprint weaknesses** — a construction or query bug that materially raises
  the false-positive rate above the ≈ 2⁻¹⁶ design point, or introduces false
  negatives.

Out of scope (by design, documented above):

- Confirming presence of a **held specific key** (§2) — that is the function.
- Probing a keyed pool by a **salt-holder** (§1) — keying is a speed-bump.
- The **coarse `member_count_band`** leak (§4) — leaks by design.
- **Targeted re-testing of a held key across epochs** despite salt rotation (§5).
- Inability to zeroize a key passed as a **string** (§8) — a JS-runtime limitation.
