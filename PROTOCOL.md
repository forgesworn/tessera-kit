tessera-kit Protocol — KFLT membership-presence filter
======================================================

Non-enumerable, signed, immutable membership-presence filters.

`v1` `KFLT format_version = 1`

## Abstract

This document specifies, for a clean-room re-implementer, the on-wire `KFLT`
filter format, the Binary Fuse 16 construction (including the **exact** seed
scheme so a blob can be reconstructed/verified bit-identically), the Schnorr
provenance signature, the presence-capability canonical bytes, the zero-`kindred`
Nostr publication shape, and the false-positive / accumulation math. It is the
authoritative byte-level reference; `README.md` is the usage guide and
`SECURITY.md` is the honest privacy posture.

## Notation

| Symbol | Meaning |
|--------|---------|
| `sha256(b)` | SHA-256 of byte string `b` (32-byte output) |
| `schnorr.sign(m32, sk)` | BIP340 Schnorr signature of the 32-byte message `m32` (no internal prehash) → 64-byte compact sig |
| `schnorr.verify(sig, m32, pk)` | BIP340 verification, `pk` = 32-byte x-only |
| `utf8(s)` | UTF-8 encoding of string `s` |
| `‖` | byte concatenation |
| `LE16/LE32` | unsigned little-endian 16/32-bit integer |
| `LE64` | unsigned little-endian 64-bit integer |
| `blob[a..b)` | byte slice, inclusive `a`, exclusive `b` |

All multi-byte header scalars are **little-endian**. The magic and the
fingerprint/pubkey/sig regions are raw byte fields (not integers).

---

## 1. `memberKey` — the value that goes into the filter

The filter is built over, and tested with, the output of `memberKey`, **never**
raw pubkeys directly (the caller decides open vs keyed):

```
memberKey(pubkeyHex)            = pubkeyHex                                  (open pool)
memberKey(pubkeyHex, saltHex)   = hex( sha256( bytes(saltHex) ‖ bytes(pubkeyHex) ) )   (keyed pool)
```

- `pubkeyHex` MUST be 64 lowercase hex chars (validated).
- `saltHex` MUST be **non-empty**, even-length hex (follow-up audit fix — see
  below). Passing `saltHex` at all routes into the keyed branch; **omit it
  entirely** for the open-pool form.
- The salt is **never** placed in the blob. It is distributed out-of-band. The
  blob's `keyed` flag only signals "test values were salted."

**`saltHex` MUST be non-empty (follow-up audit fix).** An earlier revision of
this document (and of `memberKey` itself) allowed `saltHex: ''`, producing
`sha256('' ‖ pk)` as "a keyed value, distinct from the open value `pk`." That
was true bytewise but not meaningfully: `sha256('' ‖ pk)` is computable by
**anyone** who holds the bare pubkey — no out-of-band salt is needed — so it
provides NONE of the speed-bump a keyed pool exists for. `memberKey` now
**rejects** an empty `saltHex` outright (`'memberKey: salt must be non-empty
even-length hex'`), the same as a non-hex or odd-length one. This propagates
everywhere `memberKey`'s keyed branch is reachable: `issuePresenceCapability({
salt: '' })` (`./capability`, §5) now throws too, via its own
`memberKey(subjectPubHex, p.salt)` call — an issuer can no longer mint a
"keyed" capability whose `memberValue` gives away nothing an unkeyed one
wouldn't. **To build an open pool, omit `saltHex`/`salt` entirely — never pass
`''`.**

**`buildMembershipFilter`'s `opts.salt` is validated too, by the SAME rule
(audit fix, L4).** `buildMembershipFilter` never uses `opts.salt`'s bytes for
anything (§2's construction module note) — it only tests `opts.salt !==
undefined` to set the on-wire `keyed` flag (the caller is expected to have
already salted the member-key values it hands in, via `memberKey(pk, salt)`,
before calling `buildMembershipFilter`). Before the fix, an unvalidated
`opts.salt: ''` or `opts.salt: 'zz'` both silently set `keyed: true`
regardless of whether anything resembling a real salt was passed. `opts.salt`,
when supplied, is now required to be **non-empty, even-length hex** — the
kit's ONE definition of what a salt looks like (`isValidSaltHex`,
`member-key.ts`), shared by `memberKey` and this check rather than
independently duplicated — so the `keyed` flag can no longer be set from a
value that could not plausibly BE a salt.

---

## 2. Binary Fuse 16 construction

A clean-room TypeScript port of Graf & Lemire (2022), *Binary Fuse Filters: Fast
and Smaller Than Xor Filters* (reference C: `binaryfusefilter.h`,
`binary_fuse16_t`). Arity = 3, 16-bit fingerprints.

### 2.1 Key hashing

Each member-key hex string `k` is reduced to a uniform 64-bit value:

```
keyToU64(k) = big-endian first 8 bytes of sha256(bytes(k))      ∈ [0, 2^64)
```

### 2.2 Mix (per-attempt hash) — and the seed scheme

The construction mixes each key's 64-bit value with the current **32-bit** seed.
**The seed is 32-bit by design** so the on-wire header is exactly 128 bytes (the
`seed` field is 4 bytes, §3). Inside `mix` the 32-bit seed is **zero-extended to
64 bits** before being added:

```
mix(k64, seed32):
    h = (k64 + (seed32 zero-extended to 64 bits)) mod 2^64
    h ^= h >> 33
    h = (h * 0xff51afd7ed558ccd) mod 2^64
    h ^= h >> 33
    h = (h * 0xc4ceb9fe1a85ec53) mod 2^64
    h ^= h >> 33
    return h                                                      (a murmur64 finalizer)
```

Fingerprint of a mixed hash:

```
fingerprint16(h) = (h ^ (h >> 32)) & 0xffff
```

**Seed schedule (load-bearing for reconstruction).** Construction starts from a
fixed deterministic seed and advances it by a 32-bit Weyl (golden-ratio) step on
each peeling retry:

```
seed_0      = 0x66666b6c                          (fixed start)
next32(s)   = (s + 0x9e3779b9) mod 2^32           (Weyl step per retry)
```

The seed that achieves a successful peel is the one written to the header. In
practice 1–3 attempts converge; `MAX_ATTEMPTS = 100`. A 2^32 seed space is far
more than enough. A verifier/reconstructor uses the header's `seed` value
verbatim (zero-extended in `mix`) — it does not re-run the schedule.

### 2.3 Slot indices

For a mixed hash `h`, with geometry (`segmentCountLength`, `segmentLength`,
`segmentLengthMask = segmentLength − 1`):

```
h0 = floor( (h * segmentCountLength) / 2^64 )          ∈ [0, segmentCountLength)
h1 = h0 + segmentLength;   h1 ^= (h >> 18) & segmentLengthMask
h2 = h1 + segmentLength;   h2 ^=  h        & segmentLengthMask
```

### 2.4 Geometry from member count `n` (arity = 3)

```
segmentLength = (n == 0) ? 4 : 1 << floor( log(n)/log(3.33) + 2.25 )
              clamped to [4, 2^18]        (2^18 = 262144 = SEGMENT_LENGTH_CAP)

sizeFactor    = (n <= 1) ? 0 : max(1.125, 0.875 + 0.25*log(1e6)/log(n))
capacity      = (n <= 1) ? 0 : round(n * sizeFactor)

initSegmentCount = floor((capacity + segmentLength - 1)/segmentLength) - (ARITY-1)
arrayLength      = (initSegmentCount + ARITY-1) * segmentLength
segmentCount     = max(1, floor((arrayLength + segmentLength - 1)/segmentLength) - (ARITY-1))
arrayLength      = (segmentCount + ARITY-1) * segmentLength      // ARITY = 3

// degenerate-n guard (n = 0,1,2,3): ensure arrayLength >= segmentLength * ARITY,
// recomputing segmentCount/arrayLength if smaller.

segmentCountLength = segmentCount * segmentLength
```

So `arrayLength = (segmentCount + 2) * segmentLength` and the fingerprint array
holds `arrayLength` 16-bit entries.

### 2.5 Peel + fingerprint assignment

Standard XOR/fuse peeling: hash all keys into their three slots (counting +
XOR-accumulating the hash per slot); repeatedly remove keys from slots that hold
exactly one; record the peel order. If all `n` keys peel, assign fingerprints in
**reverse** peel order — each peeled key's owned slot gets
`fingerprint16(hash) XOR (fingerprints of its other two slots)`. If a seed fails
to peel all keys, advance the seed (`next32`) and retry.

**Duplicate keys break peeling — de-duplication happens at TWO levels (M1,
audit fix).** `buildMembershipFilter` de-duplicates member-key STRINGS first
(§1). That alone is not enough: two DISTINCT key strings can still collide on
`keyToU64` (§2.1) — the 64-bit hash is sha256-derived, so a collision is
~2^-64 by chance, but findable by a targeted birthday search over ~2^32
attempts (feasible; see review notes). A colliding pair lands in the SAME
three slots on EVERY seed (the slots are a pure function of the hash, not the
seed — §2.2/§2.3), so their slot counts never drop below 2 and peeling never
converges — before this fix, `build()` threw `'fuse: construction failed to
converge'` on every call once such a pair existed in the input, for as long as
both keys remained (an availability bug: any attacker who can register two
colliding keys — e.g. two pubkeys on an OPEN pool, where the member key is the
pubkey itself — blocks every future publication for that pool). `build()`
therefore ALSO de-duplicates by 64-bit HASH VALUE, computed once
(seed-independent, §2.1) before the seed/peel loop: the Lemire reference C
does this same de-duplication on the raw keys before `populate()`
(`binary_fuse_sort_and_remove_dup`); this port previously did not. Dropping a
hash-duplicate is SAFE and changes nothing observable — `contains()` (§2.6) is
a pure function of `keyToU64(key)`, so both colliding keys still test `true`
after only one insertion of their shared hash. Geometry (§2.4) and the
peeled/inserted count `n` are computed from the DEDUPED hash count, not the
raw input length; when there are no hash collisions (the overwhelmingly common
case) this is a no-op and the resulting blob is unchanged.

### 2.6 Query

```
contains(value):
    h      = mix(keyToU64(value), seed)
    f      = fingerprint16(h)
    [h0,h1,h2] = slots(h)
    return f == (fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2])
```

False negatives are impossible after a successful build. False positives occur at
≈ 2⁻¹⁶ (§7).

### 2.7 Practical maximum

The geometry is valid while `segmentCountLength < 2^31`, i.e. the slot index
space fits a signed 32-bit integer. With `segmentLength` capped at 2^18 this
corresponds to **many millions of members** — far above the 64 MB blob cap (§3)
and any realistic deployment. Beyond that bound the 32-bit index space is
exceeded; the cap and the recompute-before-allocate guard reject it long before
it is reached in practice.

### 2.8 Decoy padding — per-epoch seed derivation (audit fix, B2)

When `padToBucket` is on (default) and the caller supplies `decoySeedHex`,
`buildMembershipFilter` does **not** pass that seed to the decoy generator
(`padding.ts`'s `deriveDecoys` / `padMembersToBucket`) directly. It first derives
a per-epoch **effective** seed:

```
effectiveSeedHex = hex( sha256( utf8("tessera-decoy:v1:") ‖ bytes(decoySeedHex) ‖ u64be(epoch) ) )
```

`u64be` is big-endian here (distinct from the little-endian on-wire `epoch`
field, §3) — this is an internal derivation input, not a wire value. The
derived `effectiveSeedHex` is what actually reaches `padMembersToBucket`.

**Why:** fuse fingerprint slots are XOR-shared across every inserted key
(member and decoy alike) — no slot belongs to one key. A `decoySeedHex` reused
byte-for-byte across epochs therefore does not hide churn the way a per-key
model would suggest: measured on a 700-member pool at bucket 1024, a FIXED
decoy set diffs **0** fingerprint slots between two epochs with no membership
change and only **~3** slots when exactly one member swapped (≥2 swaps: ~1000).
A non-salt-holder diffing two published blobs can read "did membership change,
and was it exactly one swap" straight off the diff magnitude, with no per-slot
attribution needed. Rekeying the seed by `(decoySeedHex, epoch)` keeps a
REBUILD of the SAME epoch byte-identical (needed for the golden-vector contract
and for caching) while making every NEW epoch's decoy set uncorrelated with the
last — which is what actually defeats the diffing attack. `deriveDecoys` /
`padMembersToBucket` are otherwise unchanged; only the seed handed to them
changed.

**Degenerate case:** when the true member count already equals the bucket size
(`n == band`), zero decoys are added regardless of mode — the fingerprint array
then diffs *exactly* across epochs, because there is nothing else in the mix.

`decoySeedHex`, when supplied, MUST be even-length hex of **at least 16 bytes**
(32 hex chars); a shorter, odd-length, or non-hex seed throws rather than
producing public/predictable decoys or a raw `RangeError` (audit fix, B10).

**`deriveDecoys` itself also validates its `decoySeedHex` argument (audit fix,
L4).** `deriveDecoys` is a public export (the `.` barrel and `padding.ts`),
reachable directly by a caller who bypasses `buildMembershipFilter` entirely —
so it cannot rely on `assertDecoySeedHex` above (a `filter.ts`-local check).
It requires `decoySeedHex` to be **non-empty, well-formed, even-length hex**
(an empty seed is a distinct bug from B10's "too short": `hexToBytes('')` was
previously silently accepted, producing PUBLIC, PREDICTABLE decoys with no
`RangeError` to catch). This is a weaker requirement than
`buildMembershipFilter`'s own >=16-byte minimum above — that minimum is
specific to the build path and is not re-imposed on `deriveDecoys` itself.

---

## 3. `KFLT` blob byte format (v1)

Fixed **128-byte header** followed by the fingerprint array. Total length is
exactly `128 + arrayLength * 2`.

| Offset | Len | Field | Encoding |
|-------:|----:|-------|----------|
| `0`  | 4 | `magic` = `"KFLT"` (`0x4B 0x46 0x4C 0x54`) | raw bytes |
| `4`  | 1 | `format_version` = `1` | u8 |
| `5`  | 1 | `filter_type` (`1`=fuse, `2`=xor, `3`=cuckoo) — only `1` emitted/accepted | u8 |
| `6`  | 1 | `fingerprint_bits` (`8/16/20/32`) — only `16` emitted/accepted | u8 |
| `7`  | 1 | `flags`: bit0 `keyed`, bit1 `padded` | u8 |
| `8`  | 8 | `epoch` (unix seconds) | LE64 |
| `16` | 4 | `seed` — the 32-bit fuse seed | LE32 |
| `20` | 4 | `segment_length` | LE32 |
| `24` | 4 | `segment_count` | LE32 |
| `28` | 4 | `member_count_band` (power-of-two bucket of the **true** count) | LE32 |
| `32` | 32 | `signer_pubkey` (x-only, BIP340) | raw bytes |
| `64` | 64 | `sig` — Schnorr signature (§4) | raw bytes |
| `128`| `arrayLength*2` | `fingerprint_array` — `arrayLength` entries | LE16 each |

Notes:

- The **32-bit seed at offset 16** is the resolution of the seed-width question:
  a 4-byte field keeps the header at exactly 128 bytes and holds the 32-bit
  construction seed losslessly. On read it is zero-extended to 64 bits in `mix`.
- `serializeFilter` leaves `signer_pubkey` (`[32,64)`) and `sig` (`[64,128)`)
  **zero**; `signFilterBlob` fills them in place over the same layout.
- The salt is **not** in the blob (§1). `flags.keyed` only signals the values
  were salted.
- `epoch` (offset 8) is a non-negative safe integer on write and read — see §3.2.
- **`serializeFilter` enforces the `KFLT_MAX_BLOB_BYTES` cap on its OWN output
  too (audit fix, L4)** — checked BEFORE allocating the output buffer. Without
  it, a filter whose true member count pushed `arrayLength` high enough (e.g.
  a true count above ~2^24 with default padding) could produce a blob that
  `parseFilter` (§3.1 step 1) and `verifyFilterBlob` (§4.2) would both reject
  anyway; `serializeFilter` now fails loudly at the source instead of handing
  back bytes no consumer can use.

### 3.1 `parseFilter` hardening (the trust boundary)

`parseFilter` is the hostile-input boundary. In order, it:

1. rejects `blob.length < 128` and `blob.length > 64 MiB` (`KFLT_MAX_BLOB_BYTES`);
2. checks the 4 magic bytes;
3. checks `format_version == 1`;
4. checks `filter_type ∈ {1,2,3}` then requires `== 1`;
5. checks `fingerprint_bits ∈ {8,16,20,32}` then requires `== 16`;
6. reads `segment_length` / `segment_count`, requires `segment_length` a power of
   two in `[4, 2^18]` and `segment_count ≥ 1`, derives
   `arrayLength = (segment_count + 2) * segment_length`, asserts the products are
   safe integers, and checks `128 + arrayLength*2 ≤ 64 MiB`;
7. **recomputes the expected blob length** `128 + arrayLength*2` and requires it
   to equal `blob.length` **before allocating** the fingerprint array;
8. reads `epoch` as a `u64` and requires it `≤ Number.MAX_SAFE_INTEGER` (a larger
   value would lose precision in the lossy `BigInt→Number` conversion — rejected
   rather than silently truncated; §5.5);
9. requires `flags & 0xFC == 0` — reserved bits 2-7 must be zero (`serializeFilter`
   never sets them; a blob that does is non-canonical, not merely forward-compat);
10. requires `member_count_band` to be a power of two (`serializeFilter` always
    writes `nextPowerOfTwoBand(trueCount)`, which is a power of two ≥ 1
    regardless of `padToBucket` — see `padding.ts` — so anything else is
    non-canonical);
11. only then allocates the `Uint16Array` and reads the fingerprints.

Every reachable failure throws an `Error`. A parse SUCCESS means **"well-formed,
self-consistent bytes," not "trustworthy bytes."** `parseFilter` validates a
self-consistent geometry but does **not** prove it is a geometry the builder
would emit; trust comes from `verifyFilterBlob` against a **pinned key** (§4),
**not** from parse.

### 3.2 `epoch` range (build and parse)

`buildMembershipFilter` requires `opts.epoch` to be a **non-negative safe
integer** — a negative value would wrap to `2^64-1` under the LE64 `setBigUint64`
write (§3), silently corrupting every later freshness comparison. `parseFilter`
mirrors this on read: it accepts `epoch` up to `Number.MAX_SAFE_INTEGER` and
rejects anything larger (§3.1 step 8) rather than returning a value that has
already lost precision by being forced through `Number`.

---

## 4. Provenance signature (Schnorr / BIP340)

The blob is signed so an HTTPS- or relay-served blob carries provenance and
tamper-evidence. A forged filter is a doxxing primitive (`SECURITY.md`), so the
signature is what lets a consumer refuse an attacker-authored membership set.

### 4.1 Signed-message construction

Identical on sign and verify — the only place the preimage is built:

```
preimage = blob[0..64)  ‖  sha256( blob[128..end) )
digest   = sha256(preimage)                            // 32 bytes, the Schnorr message
sig      = schnorr.sign(digest, signerPriv)            // 64-byte compact BIP340 sig → blob[64..128)
```

- `blob[0..64)` is the header fields (`[0,32)`) **plus the `signer_pubkey`**
  (`[32,64)`). Including the pubkey **binds the signer's identity** into the
  signature: swapping in a different pubkey changes the digest, so a forged-key
  swap cannot produce a self-consistent blob.
- The 64-byte `sig` region `[64,128)` is **excluded** from the preimage (a
  signature cannot cover itself). It naturally falls outside the `[0,64)` slice.
- `blob[128..end)` (the fingerprint array) is folded in via `sha256`, so any
  fingerprint tamper invalidates the signature.

`signFilterBlob` derives the x-only pubkey from the private key, writes it to
`[32,64)` **before** digesting, signs, writes the sig to `[64,128)`, and zeroizes
the private-key byte copy in a `finally`.

### 4.2 Verification is consistency, not trust

`verifyFilterBlob(blob) → { signerPubkeyHex, ok }`:

- reads `signer_pubkey` from `[32,64)` and `sig` from `[64,128)`, recomputes the
  digest (§4.1), returns `ok = schnorr.verify(sig, digest, signer_pubkey)`;
- never throws on hostile input: a `< 128`-byte OR a `> 64 MiB`
  (`KFLT_MAX_BLOB_BYTES`) blob returns `{ signerPubkeyHex: '', ok: false }`; a
  malformed sig/pubkey yields `ok:false`.

**L1 audit fix — the size cap is checked BEFORE any hashing.** `computeDigest`
(§4.1) SHA-256s the entire `blob[128..end)` fingerprint region unconditionally.
Before the fix, a raw-HTTPS caller who called `verifyFilterBlob` directly (not
gated by `parseFilter`, whose own `KFLT_MAX_BLOB_BYTES` check only runs later,
in `verifyAndParseFilter`, and only AFTER `verifyFilterBlob` had already done
the hashing/verify work) paid the full hashing cost for an oversized hostile
blob — measured at ~870 ms for a 200 MB blob — before it was ever rejected.
`verifyFilterBlob` now rejects `blob.length > KFLT_MAX_BLOB_BYTES` up front,
alongside the existing too-short check, so an oversized blob is turned away
before any hashing happens. This also protects `verifyAndParseFilter` (§4.3),
which calls `verifyFilterBlob` first.

> **`ok:true` is NOT trust.** It means only "this blob carries an
> internally-consistent BIP340 signature by `signerPubkeyHex`." Anyone can mint a
> validly self-signed blob under their **own** key. The consumer **MUST** compare
> `signerPubkeyHex` against a **pinned / out-of-band-known** server key before
> trusting any membership result:
>
> ```
> const { signerPubkeyHex, ok } = verifyFilterBlob(blob)
> if (!ok || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
> ```

### 4.3 `verifyAndParseFilter` — the combined pin + parse + freshness helper

`verifyAndParseFilter(blob, { pinnedPubkeyHex, minEpoch? }) → MembershipFilter`
(`sign.ts`) makes the mandatory pin comparison (§4.2) and an optional freshness
check the only path: it calls `verifyFilterBlob`, throws unless `ok` **and** the
signer matches `pinnedPubkeyHex` (case-insensitive), then `parseFilter`s, then
throws if `minEpoch` is given and the parsed `epoch < minEpoch`.

**Freshness — use the blob's SIGNED `epoch`, never a Nostr `["epoch"]` tag.** A
tag on a wrapping Nostr event is signed only by the event's Nostr publisher key,
never by the pinned blob-signing key, and this kit never cross-checks a tag
against the blob's own signed `epoch`. Relying on the tag for rollback
protection lets a relay or MITM replay an old, validly-signed blob under a
freshly-tagged event. Track the highest `epoch` you've accepted per pinned key
and pass it back in as `minEpoch` on the next check (§6 restates this for the
Nostr publication path specifically).

**Cross-server/namespace substitution — the blob does not name its server.**
Nothing in the 128-byte header (§3) identifies which server or namespace a
filter belongs to; `pinnedPubkeyHex` is the ONLY binding a consumer has. If one
signing key is reused across several servers or namespaces, a relay or MITM can
serve server A's validly-signed blob in place of server B's, and both the pin
check and the `minEpoch` check will pass — the substitution is invisible at this
layer. **Use a distinct signing key per server/namespace** if that distinction
matters to your deployment; `verifyAndParseFilter` cannot detect this on its own.

---

## 5. Presence-capability canonical bytes (`./capability`)

A `PresenceCapability` is **subject consent** to be located on a server. It is
signed by the **subject** (the person whose presence may be tested), **not** the
server — it is *not* filter provenance. Pin-verify the filter regardless.

**Honest scope — read before using (§5.6 restates this for `SECURITY.md`).** A
`PresenceCapability` is a **bearer token**, not a one-time token. Nothing in the
token or the check binds it to a single use or a single holder: anyone in
possession of the bytes can call `testWithCapability` any number of times, and
can forward the token to anyone else, until `expiresAt`. What the token DOES
guarantee is narrower than "one-time": it reveals **only this subject's own pool
value** (`memberValue`, §5.1) — never the pool salt, and never any other
member's value. The subject's signature is **consent** ("I allow testing of MY
presence, until then"); it is **not** bearer-binding — it does not name or
restrict who may hold or replay the token. A capability is also **not bound to
a specific filter** beyond the free-form `serverId` string (§5.3) — see the
`serverId` note there for the substitution consequence (informally "B11").
`expiresAt` bounds only the `testWithCapability` wrapper, not the disclosed
`memberValue` itself — see §5.4a for what that means in practice.

### 5.1 Token shape

```
PresenceCapability = { serverId, subjectPubHex, memberValue, expiresAt, sig }
```

`memberValue` is the 64-hex value the subject is present in the pool **as**:

```
memberValue = memberKey(subjectPubHex, salt)     (keyed pool — salt supplied by the subject at issue time)
memberValue = subjectPubHex                      (open pool — salt omitted at issue time)
```

The pool `salt`, if any, is supplied to `issuePresenceCapability` **only** to
compute `memberValue`; it is discarded immediately after and **never** appears
on the returned token, in the preimage, or anywhere reachable from it (this
replaces the v1 `saltHint` field, which carried the raw salt — see §5.5, the B1
audit fix). Holding a capability therefore lets a bearer test **only this one
subject's** value; it grants no ability to compute or probe any other member's
value, unlike v1.

### 5.2 Canonical signing bytes

```
preimage = utf8( "tessera-cap:v2:" + serverId + ":" + subjectPubHex + ":" + memberValue + ":" + expiresAt )
digest   = sha256(preimage)                            // 32 bytes, the Schnorr message
sig      = hex( schnorr.sign(digest, subjectPriv) )    // 64-byte BIP340 compact sig, hex
```

(Bumped `v1` → `v2` because the tuple's fields changed — §5.5.)

- `subjectPubHex`: 64 lowercase hex (x-only). `issuePresenceCapability` asserts it
  equals the signing key's pubkey — you cannot issue for a key you don't control.
- `memberValue`: 64 lowercase hex, derived as in §5.1. Validated as 64-hex on
  both issue and test.
- `expiresAt`: **non-negative safe integer** (unix seconds). Valid while
  `now ≤ expiresAt` (the boundary instant is still valid). A fractional, negative,
  or too-large value can't be canonically reproduced across a JS/Rust/Go
  verifier pair, so it is rejected rather than accepted and mis-stringified.
- `sig`: 128 hex chars.

### 5.3 **`serverId` MUST be colon-free** (delimiter-injection guard)

The canonical string is colon-delimited. Three of the four interpolated fields
can never contain a colon (`subjectPubHex`/`memberValue` are hex; `expiresAt`
stringifies without `:`). Only `serverId` is free-form, so a `serverId`
containing a colon is **rejected on both issue and test**. Without this guard a
crafted `serverId` like `x:DEADBEEF:cafe:0` could shift field boundaries and make
two distinct tuples produce identical preimage bytes.

> **Practical consequence:** a `wss://host:port` URL has colons and **will be
> rejected**. Callers pass a **bare host** (`play.example.com`) or a **hash of
> the URL** as the `serverId`.

> **`serverId` is not cryptographically bound to any particular filter** — it is
> whatever string the issuer and bearer agree it means, and nothing here
> cross-checks it against a filter's signer or contents. A capability naming
> server A's `serverId` will test true against **any** filter a bearer chooses to
> run it against, if that filter happens to contain `memberValue` — including a
> same-salt pool the subject never intended to expose. Pin-verify the filter
> (§4) and choose actually-unique `serverId` values per deployment if that
> distinction matters.

**`serverId` encoding — byte-exact, NO Unicode normalisation (L3, audit fix).**
The canonical preimage (§5.2) embeds `serverId` via `utf8(serverId)`
(`TextEncoder`). This encoding is **byte-exact**: it does **not** apply any
Unicode normalisation (no NFC/NFD/NFKC/NFKD), so two strings that are
canonically equivalent but not byte-identical (e.g. a precomposed vs.
decomposed accented character) produce **different** preimages and therefore
different signatures — a cross-language re-implementer MUST match this exactly
(no normalisation step) or signatures will not interoperate. Separately,
`TextEncoder` silently replaces an **unpaired UTF-16 surrogate** with U+FFFD
(the replacement character) rather than throwing, which means two DIFFERENT
JS strings — e.g. `"a\uD800"` (a lone high surrogate) and `"a�"` (the
literal replacement character) — previously encoded to IDENTICAL UTF-8 bytes,
so a capability issued for one verified when presented as the other. `serverId`
is therefore now validated to be **well-formed UTF-16** (no lone surrogates) on
both issue and test, rejecting the collision at the input boundary instead of
downstream at the byte level. **Recommendation: restrict `serverId` to
printable ASCII** — it sidesteps both the normalisation question and any
further Unicode edge cases entirely, and is sufficient for the intended use
(a bare host or a hex hash, §5.3 above).

### 5.4 Test order (load-bearing)

`testWithCapability(filter, cap, now?)` checks, in order: (1) field shapes,
including that the resolved clock value (`now ?? floor(Date.now()/1000)`) is
`Number.isFinite` — a non-finite value throws rather than silently skipping the
next check (§5.5); (2) **expiry** (`now > expiresAt` → throw
`'capability expired'`); (3) **signature** (`schnorr.verify` against
`subjectPubHex`, else throw `'capability signature invalid'`); (4) **only
then** the membership test — `testMembership(filter, cap.memberValue)` directly;
there is no salt to re-derive anything from at test time. An expired/forged
capability **throws** (a usage error) rather than returning a silent `false`, so
a caller can never confuse "not present" with "this token is no good."

### 5.4a `expiresAt` only bounds the wrapper — it is not revocation of `memberValue`

`expiresAt` gates `testWithCapability` (§5.4) — the convenience wrapper in this
file — and nothing else. It does **not** bound `memberValue` itself. A bearer
who has SEEN `memberValue` (from a validly-issued, unexpired capability, or
disclosed any other way) can call `testMembership(filter, memberValue)`
**directly**, bypassing `testWithCapability` and its expiry check entirely, for
as long as `memberValue` remains a real value in the pool:

- **Keyed pool:** that is every future epoch, until the pool's `salt` rotates —
  rotation changes `memberKey(subjectPubHex, salt)`, and so changes
  `memberValue` too, which is what actually revokes access.
- **Open pool:** `memberValue` is the bare `subjectPubHex` and **never**
  changes, so there is no rotation event at all — disclosure is effectively
  permanent for that subject on that pool.

**Salt rotation is the only real revocation mechanism.** `expiresAt` is a
courtesy bound on the wrapper function's behaviour, not a cryptographic limit
on how long a disclosed `memberValue` stays testable against the underlying
filter.

### 5.4b `memberValue` is bound to `subjectPubHex` on an OPEN pool only — an inherent limit on a keyed one (M2, audit fix)

The subject's signature (§5.2) proves "the subject named by `subjectPubHex`
signed this exact `{serverId, subjectPubHex, memberValue, expiresAt}` tuple."
It does **not**, by itself, prove that `memberValue` is actually *derived
from* `subjectPubHex` — nothing stops a signer from naming their own
`subjectPubHex` while setting `memberValue` to a **different** subject's pool
value (e.g. Alice signs `{subjectPubHex: alice, memberValue: bob}`); the
signature still verifies, because it only proves Alice signed that tuple, not
that the tuple's `memberValue` belongs to her. Without a check, a bearer would
be told "Alice is present" when the hit is really Bob's presence — disclosed
without Bob's consent.

`testWithCapability` therefore checks the binding directly, but **only when
it can**:

- **Open pool (`!filter.keyed`):** `memberValue` MUST equal `subjectPubHex`
  (case-insensitive) — that is the open-pool form of `memberKey` (§1), the
  only legitimate open-pool `memberValue`. `testWithCapability` rejects a
  mismatch with `'capability: memberValue does not match subjectPubHex (open
  pool)'`, checked AFTER expiry and signature (§5.4) and BEFORE the membership
  test.
- **Keyed pool (`filter.keyed`):** `memberValue = memberKey(subjectPubHex,
  salt)`, and the bearer — by the design of a keyed pool — never holds
  `salt`. There is therefore **no way** for `testWithCapability` to recompute
  `memberKey(subjectPubHex, salt)` and check it against `memberValue`; nothing
  in this check's possession can perform that binding. **This is an inherent
  limit of the keyed-pool design, not a gap a future patch to this function
  can close from the bearer's side.** On a keyed pool, the subject's signature
  is the ONLY assertion available that `memberValue` is theirs, and a consumer
  must trust it as such — the same trust boundary as `memberValue` itself
  (§5.1): a subject who signs a bad tuple is misusing their OWN signing key,
  which is a different threat model from a bearer forging one.

### 5.5 Audit fixes (v1 → v2)

- **The salt is no longer carried (B1, HIGH).** v1's `saltHint` field WAS the
  keyed pool's salt in clear: holding any one subject's capability handed the
  bearer everything needed to compute `memberKey(anyPk, saltHint)` for **any**
  candidate, defeating the keyed pool for that bearer entirely (and for anyone
  they forwarded the token to). `memberValue` (§5.1) replaces it: it is only
  this one subject's derived value and cannot be inverted back to the salt or
  reused for any other subject.
- **"One-time" language is removed.** The token was never actually one-time —
  nothing enforced single use — and the docs now say so plainly (§ intro above).
- **`expiresAt` is a non-negative safe integer**, not merely "a finite number"
  (§5.2) — closes a cross-language canonicalisation gap (`1e21` stringified as
  `"1e+21"` in JS, `1.5` was accepted).
- **`testWithCapability` throws on a non-finite resolved clock** (§5.4) — before
  the fix, an injected `now = NaN` made `NaN > expiresAt` evaluate to `false`,
  silently skipping the expiry check and letting an already-expired capability
  pass.
- **`memberValue` is bound to `subjectPubHex` on an OPEN pool (M2)** (§5.4b) —
  before the fix, `testWithCapability` never checked that an open-pool
  `memberValue` actually equalled `subjectPubHex`, so a validly-signed tuple
  naming one subject's pubkey while carrying a DIFFERENT subject's
  `memberValue` would test that other subject's presence and report it under
  the wrong name. Not fixable on a keyed pool — see §5.4b for why.
- **Every field is `typeof`-checked before use** (both `issuePresenceCapability`
  and `testWithCapability`) — before the fix, a non-string field (e.g. a
  hand-built capability with `sig: undefined`) reached a `.toLowerCase()` call
  directly and threw a raw `TypeError` instead of a `capability:`-prefixed
  kit error.

### 5.6 See also

`SECURITY.md` §6 restates the bearer-token / consent-not-provenance framing for
the honest-privacy-posture reader; the `serverId`-is-not-filter-bound note above
is sometimes referenced informally as "B11" in issue tracking, and the
`memberValue`/`subjectPubHex` binding note (§5.4b) as "M2".

---

## 6. Server publication shape (zero `kindred` dependency)

A server that only needs to *publish* a filter can depend on **tessera-kit alone**
— no `kindred` import required. The reusable mechanics live in the optional
**`./nostr`** subpath (import `@forgesworn/tessera-kit/nostr`):

```
buildFilterPublication({ kind, tags, blob, createdAt }) → EventTemplate
  // = { kind, tags, content: base64(blob), created_at: createdAt }
decodeFilterPublicationContent(content, maxBytes?) → Uint8Array   // inverse, with a length cap
```

`buildFilterPublication` is **relationship-agnostic**: it base64-encodes the blob
into `content` and assembles the `EventTemplate`, but the **caller supplies the
`kind` and `tags`**. tessera-kit deliberately does **not** know kindred's
addressing convention (the `30444` kind, the `kindred:members:` d-tag, the `#n`
namespace tag) — `kindred/discovery` delegates to this builder, passing those
values in. The `./nostr` subpath is the only one that pulls in `@scure/base` (for
base64); the core `.` / `./capability` entries stay `@noble`-only.

**Example — the addressable event `kindred` emits (kind `30444`):** the
caller-supplied `kind` + `tags` that reproduce kindred's publication are:

| Tag / field | Value |
|-------------|-------|
| `kind` | `30444` |
| `["d", …]` | `"kindred:members:<namespace>:<serverId>"` — `namespace` = the game/app (the aggregator unit), `serverId` = the instance |
| `["n", "<namespace>"]` | indexable namespace tag, so an aggregator can `#n`-filter across many `serverId`s |
| `["epoch", "<n>"]` | the filter epoch (unix seconds), for HUMAN/INDEX convenience only |
| `["keyed", "0" \| "1"]` | whether the pool is keyed |
| `content` | **base64 of the raw `KFLT` blob** (produced by `buildFilterPublication`) |

**Freshness — do NOT trust the `["epoch"]` tag for rollback protection.** The tag
is signed only by the Nostr publisher key (standard NIP-01), never by the
pinned blob-signing key (§4), and this kit never cross-checks it against the
blob's own SIGNED `epoch` (KFLT header offset 8, §3). A relay or a malicious
publisher can attach any tag value to any event, including a fresh tag on a
replayed, older blob. Consumers **MUST** decode `content`, call
`verifyAndParseFilter(blob, { pinnedPubkeyHex, minEpoch })` (§4.3), and use the
returned `filter.epoch` — the blob's own signed epoch — for the
`epoch ≤ last-seen` freshness check per `(namespace, serverId)`, never the tag.

The event itself is signed by the publisher's Nostr key (standard NIP-01); that
is **separate** from the in-blob Schnorr provenance signature (§4). A consumer
verifies **both**: the event signature (transport integrity) **and**
`verifyFilterBlob` (or, preferably, `verifyAndParseFilter`) against the pinned
server key (filter provenance). The
`30444` kind is the dedicated addressable kind for filter publications (it
supersedes the `30078` placeholder used during early design — `30078` is
signet-app's contact-sync kind and is reused here only as a historical note, not
the recommended value).

---

## 7. False-positive rate and accumulation budget (§7.6)

### 7.1 Per-test FPR

At 16-bit fingerprints, the per-test false-positive probability is

```
p ≈ 2^-16 ≈ 1.5e-5
```

(false negatives are impossible after a successful build). `src/properties.test.ts`
measures this empirically: a 1000-member filter probed with ~100,000 random
non-members false-hits at a rate `< 5e-4` (near the 1.5e-5 ideal).

### 7.2 Accumulation across a sweep

For a consumer testing `c` candidate keys against `S` **servers** (i.e. `S`
separate filters probed in the sweep — `S` is a SERVER COUNT, not a member
count; the per-test FPR `p` above is independent of how many members are in
any one filter), the expected number of false "present" hits across the whole
sweep is

```
E[false hits] = c · S · p
```

(doc fix: earlier revisions of this document described `S` as "`S`-member
servers," which reads as if `p` scaled with a filter's member count — it does
not, §7.1 — or as if `S` were itself a member count. `S` is the number of
servers/filters the `c` candidates are each tested against.)

The headline example (`c = 100`, `S = 1000`):

| FPR | per-test `p` | `E[false hits]` per full sweep |
|-----|-------------:|-------------------------------:|
| 1% (naïve Bloom) | `1e-2` | **1000** (unusable) |
| **16-bit** | `1.5e-5` | **≈ 1.5** (one per ~0.7 sweeps) |
| 20-bit | `1e-6` | ≈ 0.1 |

Design rule: choose `p ≤ F / (c·S)` for a tolerated sweep budget `F`. At
ecosystem scale, **a bare `testMembership` hit is a CANDIDATE, not a proof** — the
consumer adds a **confirm-on-connect** step (a key-control challenge) before
acting on a hit. 20-bit fingerprints (`p ≈ 1e-6`) tighten the budget for large
`c·S`; the `KFLT` format reserves `fingerprint_bits ∈ {8,16,20,32}` for this,
though only 16 is implemented in v1.

---

## 8. Constants summary

| Constant | Value |
|----------|-------|
| `KFLT_MAGIC` | `"KFLT"` (`0x4B464C54` big-endian) |
| `KFLT_VERSION` | `1` |
| `KFLT_HEADER_LEN` | `128` |
| `KFLT_MAX_BLOB_BYTES` | `64 * 1024 * 1024` (64 MiB) |
| fuse `ARITY` | `3` |
| fuse `MAX_ATTEMPTS` | `100` |
| `SEGMENT_LENGTH_CAP` | `1 << 18` (262144) |
| seed start | `0x66666b6c` |
| seed Weyl step | `0x9e3779b9` |
| capability prefix | `"tessera-cap:v2:"` |
| decoy epoch-rekey prefix | `"tessera-decoy:v1:"` |
| publication kind | `30444` |
