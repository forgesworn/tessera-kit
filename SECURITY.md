# Security Policy

tessera-kit makes **narrow, precise** privacy claims and refuses the broad ones.
This document is the honest posture (PROTOCOL.md §4 provenance signature, §5
capability tokens). Read it before building on
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

### 3. Pin-verify the filter — key AND context — before trusting any hit — **mandatory**

A `KFLT` blob is just bytes a stranger served you. A **forged** filter is a
doxxing primitive: an attacker who makes you trust an arbitrary membership set can
make `testMembership` report a friend as "present" on a server they never joined
(or hide a real member). Therefore:

- Consumers **MUST** call `verifyFilterBlob(blob, context)` — or, preferably,
  `verifyAndParseFilter` — and compare the returned `signerPubkeyHex` against a
  **pinned / out-of-band-known** server key **before** trusting any membership
  result. `context` MUST be the verifier's own stable, out-of-band-known
  deployment address (PROTOCOL.md §4.1/§4.3) — e.g. a kindred d-tag
  `kindred:members:<namespace>:<serverId>`.
- `verifyFilterBlob` returning `ok: true` means **only** "this blob carries an
  internally-consistent BIP340 Schnorr signature by `signerPubkeyHex`, over
  THIS `context`." It is **not** trust. Anyone can mint a validly self-signed
  blob under their own key for any context; the **pinned-key AND context
  comparison**, not `ok` alone, is what defeats forged-filter doxxing —
  including **cross-server/namespace substitution**: because `context` is
  folded into the signed digest itself, a blob signed for one deployment can
  never verify under a different deployment's context, even if the two
  deployments share a signing key. A distinct signing key per server/namespace
  is still good practice (defence in depth), but it is no longer the only
  thing standing between you and that substitution.

```
const { signerPubkeyHex, ok } = verifyFilterBlob(blob, context)
if (!ok || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
```

### 4. The count band leaks a coarse count by design; padding hides only the fine count — and a FIXED decoy set is itself diffable

Size-bucket padding rounds the *inserted-key* count up to a power-of-two bucket by
adding decoys, so the serialized array size reveals only the coarse bucket.
However:

- `member_count_band` (header offset 28) records the **true** count's
  power-of-two bucket and **leaks that coarse count by design**. Padding hides the
  *fine* count, never the bucket.
- **A stable decoy set reused across epochs does not hide churn — it enables
  diffing it precisely.** Fuse fingerprint slots are XOR-shared across every
  inserted key (member and decoy alike); no slot "belongs" to one key. Measured
  on a 700-member pool at bucket 1024: a **fixed** decoy set diffs **0**
  fingerprint slots between two epochs with no membership change, and only
  **~3** slots when exactly one member swapped (≥2 swaps: ~1000 differ). A
  non-salt-holder diffing two published blobs therefore learns, with high
  confidence, *whether membership changed at all* and *whether it was exactly
  one swap* — an activity-leak with no per-slot attribution needed. Earlier
  guidance recommending a fixed `decoySeedHex` as the safer default was
  **backwards**; it is now corrected below.
- What actually defeats this: `buildMembershipFilter` now derives the decoy seed
  actually used from **`(decoySeedHex, epoch)`** (see PROTOCOL.md §2.8) —
  rebuilding the SAME epoch with the SAME `decoySeedHex` still reproduces a
  byte-identical blob, but each NEW epoch gets a fresh, uncorrelated decoy set.
  Pass a `decoySeedHex` (now automatically epoch-rekeyed) for this behaviour, or
  omit it for CSPRNG-random decoys (unstable even within an epoch). Either
  choice defeats cross-epoch diffing; a decoy set that is stable **forever**
  (the pre-fix behaviour) does not.
- **Degenerate case:** when the true member count already equals the bucket
  size (`n == band`), padding adds **zero** decoys regardless of mode — the
  fingerprint array then diffs *exactly* across epochs, because there is
  nothing else in the mix to obscure it.

### 5. Salt rotation defeats array-diffing by non-holders — with a stated residual

Rotating the keyed salt per epoch defeats **structural array-diffing by
non-holders** (a party without the salt can't correlate fingerprints across
epochs). **Residual, stated honestly:** a party who **holds a candidate key X** can
still track X's join/leave across epochs by **re-testing** X each epoch (computing
`memberKey(X, salt_epoch)` and querying). Salt rotation does **not** stop targeted
presence-tracking of a specific held key.

### 6. Capability tokens are subject consent, not filter provenance — and are BEARER tokens, not one-time tokens

A `PresenceCapability` is signed by the **subject** — it means "you may test MY
presence here, until `expiresAt`." It says **nothing** about whether the filter is
genuine. A consumer holding a valid capability **must still** pin-verify the
filter (§3) before trusting the hit. Consent and provenance are orthogonal; the
kit keeps them in separate signatures.

**Stated plainly, because earlier docs implied otherwise: this is a bearer
token, reusable by anyone holding it, any number of times, until `expiresAt` —
it is not one-time, and nothing in the token or the check binds it to a single
use or a single bearer.** The subject's signature is *consent* ("I allow
testing of my presence, until then"); it is **not** bearer-binding — it does
not name or restrict who may hold or forward the token.

What the token DOES narrowly guarantee: it reveals **only the subject's own
pool value** (`memberValue` — `memberKey(subjectPubHex, salt)` for a keyed pool,
or `subjectPubHex` itself for an open pool), computed once at issue time from a
salt the subject supplies and immediately discards. It **never** carries the
pool salt itself. This is an audit fix: the pre-fix design carried the raw salt
as a `saltHint` field, which meant holding **any one** subject's capability
handed the bearer everything needed to compute `memberKey(anyPk, saltHint)` for
**any** candidate — i.e. holding one friend's cap was equivalent to holding
salt-holder access to the *entire* keyed pool (§1), not consent to test one
person. `memberValue` confines the bearer to the one subject named on the token.

**A capability is also not bound to a specific filter beyond the free-form
`serverId` string.** Nothing cross-checks `serverId` against a filter's signer
or contents — a capability naming server A's `serverId` will test true against
ANY filter a bearer runs it against, if that filter happens to contain
`memberValue`. Pin-verify the filter regardless, and use actually-unique
`serverId` values per deployment if that distinction matters (PROTOCOL.md §5.3).

**`expiresAt` only bounds `testWithCapability` — it does NOT bound `memberValue`
itself.** Once a bearer has SEEN `memberValue` (from a valid capability, or
leaked any other way), nothing stops them calling
`testMembership(filter, memberValue)` directly, skipping `testWithCapability`
and its expiry check entirely, for as long as `memberValue` remains a real
value in the pool: that is every future epoch, until the pool's keyed salt
rotates (rotation changes `memberKey(pk, salt)`, and so changes `memberValue`
too) — or **indefinitely** for an open pool, where `memberValue` is the bare
subject pubkey and never changes. **Salt rotation is the only actual
revocation mechanism.** `expiresAt` is a courtesy bound on the convenience
wrapper, not a cryptographic limit on how long a disclosed `memberValue` stays
testable.

Omitting `salt` at issue is an **open-pool** capability: `memberValue` is the
**bare open-pool form** `memberKey(subjectPubHex)` (the pubkey itself). Passing
`salt: ''` explicitly is **rejected** (follow-up audit fix): `sha256('' ‖ pk)`
is computable by anyone who holds the bare pubkey, so an empty salt gives no
protection at all and is no longer accepted as a "keyed" value —
`memberKey(pk, '')` throws, and so does `issuePresenceCapability({ salt: ''
})`. To build (or issue a capability for) an open pool, omit `salt` entirely;
never pass `''` in its place.

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

tessera-kit is a pure-computation library with three runtime dependencies
(`@noble/curves`, `@noble/hashes`, and `@scure/base` — the latter pulled in
only by the optional `./nostr` subpath, for base64; the core `.` and
`./capability` entries stay `@noble`-only) and no network or filesystem
access. In scope:

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
