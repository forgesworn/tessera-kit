tessera-kit Protocol — KFLT membership-presence filter
======================================================

Non-enumerable, signed, immutable membership-presence filters.

`v1` `KFLT format_version = 1`

## Abstract

This document specifies, for a clean-room re-implementer, the on-wire `KFLT`
filter format, the Binary Fuse 16 construction (including the **exact** seed
scheme so a blob can be reconstructed/verified bit-identically), the Schnorr
provenance signature, the presence-capability canonical bytes, the
zero-`kenspeckle` Nostr publication shape (§6), and the false-positive /
accumulation math. It is the
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
| `5`  | 1 | `filter_type` (`1`=fuse, `2`=xor RESERVED, `3`=cuckoo RESERVED) — only `1` emitted/accepted | u8 |
| `6`  | 1 | `fingerprint_bits` (`16` implemented; `8`/`20`/`32` RESERVED) — only `16` emitted/accepted | u8 |
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

- **`FilterType`/`FingerprintBits` (the exported TypeScript types) are narrowed
  to exactly `1` and `16`** (item 4, pre-publish pass) — they say what the
  implementation actually accepts, not the full reserved wire range. `2`/`3`
  and `8`/`20`/`32` remain RESERVED at the byte-format level (so a future
  `format_version` can implement one without a header-layout change) and
  `parseFilter` still explicitly rejects each one at runtime, with its own
  `TesseraErrorCode` (§9): `PARSE_INVALID_FILTER_TYPE` /
  `PARSE_UNSUPPORTED_FILTER_TYPE` for `filter_type`,
  `PARSE_INVALID_FINGERPRINT_BITS` / `PARSE_UNSUPPORTED_FINGERPRINT_BITS` for
  `fingerprint_bits`. Narrowing the TYPES changed nothing about this runtime
  behaviour — it only stopped the type system advertising values the
  implementation has never accepted.
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

## 4. Provenance signature (Schnorr / BIP340), bound to a deployment context

The blob is signed so an HTTPS- or relay-served blob carries provenance and
tamper-evidence. A forged filter is a doxxing primitive (`SECURITY.md`), so the
signature is what lets a consumer refuse an attacker-authored membership set.
The signed digest also binds a caller-supplied **`context`** string — see §4.3
for why, and what to pass.

### 4.1 Signed-message construction

Identical on sign and verify — the only place the digest is built:

```
digest = sha256( utf8("tessera-kflt-sig:v1")  ‖  0x00  ‖  u32be(byteLen(ctx))  ‖
                  utf8(ctx)  ‖  blob[0..64)  ‖  sha256( blob[128..end) ) )
sig    = schnorr.sign(digest, signerPriv)            // 64-byte compact BIP340 sig → blob[64..128)
```

- `"tessera-kflt-sig:v1"` is a fixed **domain-separation tag** — without it, a
  signature over this digest could in principle collide with a signature
  intended for a different protocol that also happens to sign
  `sha256(prefix ‖ context ‖ ...)`-shaped messages under the same key.
  `KFLT_VERSION` (the on-wire header field, §3) stays `1` — this tag versions
  the SIGNED DIGEST construction, not the byte layout, and the two are
  independent.
- `0x00` separates the fixed tag from the length-prefixed `ctx` that follows.
  `u32be(byteLen(ctx))` is the big-endian 4-byte length, in UTF-8 bytes, of
  `ctx` — together with the `0x00` separator this makes the
  tag+len+context+header concatenation **unambiguous**: no `ctx` value can be
  crafted to shift field boundaries and make two different `(ctx, blob)` pairs
  hash identically (the same delimiter-injection reasoning as §5.3's
  colon-free `serverId` guard, solved here with an explicit length prefix
  instead of a forbidden character).
- `ctx` is `utf8(context)` — **byte-exact, no Unicode normalisation** (same
  policy as §5.3's `serverId`): two canonically-equivalent but byte-different
  strings (e.g. NFC vs NFD) are DIFFERENT contexts and sign/verify differently.
  A cross-language re-implementer MUST NOT normalise `context`.
- `blob[0..64)` is the header fields (`[0,32)`) **plus the `signer_pubkey`**
  (`[32,64)`). Including the pubkey **binds the signer's identity** into the
  signature: swapping in a different pubkey changes the digest, so a forged-key
  swap cannot produce a self-consistent blob.
- The 64-byte `sig` region `[64,128)` is **excluded** from the digest input (a
  signature cannot cover itself). It naturally falls outside the `[0,64)` slice.
- `blob[128..end)` (the fingerprint array) is folded in via `sha256`, so any
  fingerprint tamper invalidates the signature.

`context` (spec §4.3) MUST be a non-empty string, well-formed UTF-16 (no lone
UTF-16 surrogate — the same check §5.3 requires of `serverId`, sharing one
implementation, `src/text.ts`), and its UTF-8 encoding MUST be at most 1024
bytes. This is a caller-configuration value, not attacker-controlled blob
data, so a malformed `context` is a **usage error** (throws its own distinct
message) — a WRONG-but-well-formed `context` is a different case, handled at
§4.3.

`signFilterBlob(unsignedBlob, signerPrivHex, context)` validates `context`,
derives the x-only pubkey from the private key, writes it to `[32,64)`
**before** digesting, signs, writes the sig to `[64,128)`, and zeroizes
the private-key byte copy in a `finally`.

### 4.2 Verification is consistency, not trust

`verifyFilterBlob(blob, context) → { signerPubkeyHex, ok }`:

- reads `signer_pubkey` from `[32,64)` and `sig` from `[64,128)`, recomputes the
  digest (§4.1) bound to `context`, returns
  `ok = schnorr.verify(sig, digest, signer_pubkey)`;
- never throws on hostile **blob** input: a `< 128`-byte OR a `> 64 MiB`
  (`KFLT_MAX_BLOB_BYTES`) blob returns `{ signerPubkeyHex: '', ok: false }`; a
  malformed sig/pubkey yields `ok:false`;
- DOES throw if `context` itself is malformed (§4.1) — that is a caller
  configuration bug, not hostile blob data, so it is validated the same way
  `pinnedPubkeyHex`/`minEpoch` are in `verifyAndParseFilter` (§4.3);
- a `context` that is well-formed but simply **wrong** (a different
  deployment's context, or the empty-vs-nonempty case aside) is NOT
  distinguished from a bad signature — it folds into the digest before
  verification runs, so it fails exactly the way a tampered signature would:
  `ok: false`, nothing more specific.

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
> const { signerPubkeyHex, ok } = verifyFilterBlob(blob, context)
> if (!ok || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
> ```

### 4.3 `verifyAndParseFilter` — the combined pin + context + parse + freshness helper

`verifyAndParseFilter(blob, { pinnedPubkeyHex, context, minEpoch? }) →
MembershipFilter` (`sign.ts`) makes the mandatory pin comparison (§4.2), the
mandatory context binding, and an optional freshness check the only path: it
calls `verifyFilterBlob(blob, context)`, throws unless `ok` **and** the signer
matches `pinnedPubkeyHex` (case-insensitive), then `parseFilter`s, then throws
if `minEpoch` is given and the parsed `epoch < minEpoch`.

**Which function to call — it depends on how the signer key is known.**

- **You have a PINNED signer key** (you already know, out-of-band, exactly
  which `signerPubkeyHex` you trust for this `context`): call
  `verifyAndParseFilter(blob, { pinnedPubkeyHex, context, minEpoch? })`. This
  is the recommended path for the common case and does the pin comparison
  for you — there is no way to forget it.
- **The signer key is authenticated some OTHER way** (not a static pin) —
  for example, kenspeckle's `requireAuthorIsSigner` check, which derives the
  trusted key from the outer Nostr event's author (`pubkey`) rather than a
  fixed constant, so "the pinned key" is only known AFTER the event arrives,
  not in advance: call `verifyFilterBlob(blob, context)` directly, compare
  the returned `signerPubkeyHex` against whatever your own mechanism
  determined the trusted key to be, and only THEN call `parseFilter(blob)`
  once that comparison passes. Do not call `verifyAndParseFilter` in this
  case — it requires a `pinnedPubkeyHex` you'd have to already have picked
  before knowing the answer.

Either path performs the exact same three checks (signature, signer, and
context); the difference is only WHERE the trusted `signerPubkeyHex` comes
from and who is responsible for comparing it.

**Freshness — use the blob's SIGNED `epoch`, never a Nostr `["epoch"]` tag.** A
tag on a wrapping Nostr event is signed only by the event's Nostr publisher key,
never by the pinned blob-signing key, and this kit never cross-checks a tag
against the blob's own signed `epoch`. Relying on the tag for rollback
protection lets a relay or MITM replay an old, validly-signed blob under a
freshly-tagged event. Track the highest `epoch` you've accepted per
`(pinnedPubkeyHex, context)` and pass it back in as `minEpoch` on the next check
(§6 restates this for the Nostr publication path specifically).

**`minEpoch` is non-strict — a limitation, closeable with `strictlyNewerThan`
(additive, post-0.2.0).** `minEpoch`'s comparison is `epoch < minEpoch`
(§9's `VERIFY_STALE_EPOCH`), which is deliberately **not** `<=`: a parsed
`epoch` EQUAL to `minEpoch` always passes. That is correct for "reject
anything OLDER than the last one I saw," but it means a blob re-served for an
epoch you've already accepted is not itself flagged.

> ⚠️ **This kit does NOT enforce "one content per epoch."** Nothing in
> `buildMembershipFilter`, `signFilterBlob`, or `parseFilter`/`verifyFilterBlob`
> stops a signer from producing and signing TWO DIFFERENT blobs that both
> carry the SAME `epoch` — for example, correcting a mistake and re-signing
> the corrected membership set under the epoch it meant to publish the first
> time, rather than bumping to a new one. `epoch` is a freshness/rollback
> marker the SIGNER chooses to set, not a hash or sequence number the kit
> derives from, or binds to, the blob's actual content. **`minEpoch` alone
> cannot detect this** — two same-epoch blobs both pass `epoch < minEpoch`
> identically, regardless of whether their fingerprint arrays differ.
> Detecting a same-epoch content change is out of scope for this kit's epoch
> mechanism; if that distinction matters to a deployment, compare the parsed
> filter's own bytes/hash out of band, or have the signer bump `epoch` on
> every real change instead.

Some deployments want a DIFFERENT, narrower guarantee than the above: "this
MUST be a genuinely newer epoch than the last one I accepted" (not "the
content might have silently changed under the same epoch" — see the warning
above, which `strictlyNewerThan` does NOT address either).
`verifyAndParseFilter`'s optional `opts.strictlyNewerThan` provides that
narrower guarantee for a caller who opts in — the parsed `epoch` MUST be
**strictly greater** than `strictlyNewerThan`, or this throws
`VERIFY_EPOCH_NOT_NEWER`. It is validated the same way as `minEpoch`
(non-negative safe integer; a malformed value throws
`VERIFY_STRICTLY_NEWER_THAN_INVALID`), checked at the same point (after the
signature/signer/context check, alongside `minEpoch`'s own staleness check),
and is entirely independent of `minEpoch` — passing both is fine, and
`minEpoch`'s own behaviour (including the non-strict `<` comparison) is
completely unchanged by `strictlyNewerThan`'s mere presence. Omit it and
nothing changes from 0.2.0's behaviour.

> ⚠️ **Passing `strictlyNewerThan` = the last epoch you accepted makes an
> ORDINARY re-fetch of the CURRENT, unchanged epoch throw
> `VERIFY_EPOCH_NOT_NEWER`.** This is not a bug — it is exactly what "strictly
> newer" means — but it is easy to misuse: a consumer that re-polls the same
> filter on a schedule, and passes its last-accepted epoch as
> `strictlyNewerThan` on every poll (the same value it would correctly pass as
> `minEpoch`), will throw on EVERY poll where nothing changed, not just on a
> genuine rollback. **`strictlyNewerThan` answers "is there a newer epoch than
> the one I already have," not "is this blob still valid" — those are
> different questions, and re-fetching the current epoch is normal, expected
> behaviour, not an error condition.** Recommended usage:
>
> - **For an ordinary re-fetch/poll of a filter you already hold** (the
>   common case), use `minEpoch`, not `strictlyNewerThan` — `minEpoch` accepts
>   "still the same epoch I already have" exactly as intended, and only
>   rejects a genuine rollback to something OLDER.
> - **If you use `strictlyNewerThan` anyway** (e.g. because you specifically
>   want to detect "nothing new since my last check" as a distinct outcome
>   from "here is fresh data"), catch `VERIFY_EPOCH_NOT_NEWER` and treat it as
>   "no update since last time," not as a trust/validity failure — do NOT
>   treat it the same way you'd treat `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` or
>   a parse failure. The blob you re-fetched may be perfectly valid; it is
>   simply not newer than what you already had.

**Cross-server/namespace substitution — closed cryptographically by `context`.**
Nothing in the 128-byte header (§3) identifies which server or namespace a
filter belongs to. Before the `context` binding existed, `pinnedPubkeyHex` was
the ONLY defence a consumer had: if one signing key was reused across several
servers or namespaces, a relay or MITM could serve server A's validly-signed
blob in place of server B's, and both the pin check and the `minEpoch` check
would pass — the substitution was invisible at that layer. `context` (§4.1)
closes this: it is folded into the SIGNED DIGEST itself, so a blob signed for
server A's context can never verify under server B's context, **even if both
servers share the exact same signing key**. `opts.context` MUST be the
verifier's own stable, out-of-band-known deployment address — the same string
you'd already need to know in order to go fetch this filter in the first
place, so a MITM/relay cannot simply relabel a different blob and have it
pass. **Recommendation: a deployment's `context` should be the stable address
the verifier already knows independently of the blob** — for the kindred
convention (§6), that is the `d`-tag value itself,
`kindred:members:<namespace>:<serverId>`. A consumer not using that convention
should use its own equivalent stable, out-of-band-known identifier.

> ⚠️ **For the kindred convention: `namespace` MUST NOT contain a colon
> (`:`); `serverId` MAY.** `kindred:members:<namespace>:<serverId>` is a
> colon-delimited string, and the convention's own parser (and a human
> reading a `d`-tag) resolves it by splitting on the FIRST `:` AFTER the
> fixed `kindred:members:` prefix — everything before that split is
> `namespace`, everything after (including any further colons) is
> `serverId`. If `namespace` itself were allowed to contain a colon, two
> DIFFERENT `(namespace, serverId)` pairs could produce the IDENTICAL
> `context` string by shifting where the split falls: `("a", "b:c")` and
> `("a:b", "c")` both concatenate to `kindred:members:a:b:c`. Since `context`
> equality is the entire cross-server binding at the digest layer (§4.1) —
> two different deployments that happen to produce the same `context` string
> are, as far as `verifyFilterBlob` is concerned, indistinguishable — a relay
> could then serve namespace `"a:b"` / server `"c"`'s validly-signed blob to
> a verifier that actually asked for namespace `"a"` / server `"b:c"` (or
> vice versa), and the context check would pass, because both parties
> resolve to the byte-identical `context` string. This is exactly the same
> shape as the delimiter-injection guard on `PresenceCapability.serverId`
> (§5.3) — and, like that guard, matters most when the OTHER binding that
> would normally catch it is weak or absent: kenspeckle's `d`-tag-driven
> discovery is the primary place a consumer picks `(namespace, serverId)`
> without an independent cross-check, and its `requireAuthorIsSigner` option
> (binding the outer Nostr event's author key to the in-blob signer) can be
> turned off for an aggregator that intentionally republishes under its own
> key — with that check off, an ambiguous `namespace` is the only thing
> stopping the swap above. **`serverId` has no equivalent restriction**: it is
> the LAST segment, so it may contain colons (e.g. a hash, or a
> `host:port`-shaped value) without creating any ambiguity — only a colon in
> `namespace`, which lands BEFORE the split point, is unsafe.

> ⚠️ **`context` MUST be built from the address the verifier CHOSE to
> request — NEVER taken from the served event's own tags (e.g. its `d`-tag).**
> This is the single most important rule for using `context` correctly, so it
> is repeated here and in §6: a verifier already knows which
> `(namespace, serverId)` — or equivalent identifier — it is asking about,
> because that is how it picked which event to fetch in the first place
> (discovery/subscription happens BEFORE the event arrives). Construct
> `context` from THAT known-in-advance value. If instead you read the `d`-tag
> (or any other tag) OFF the event you just received and pass THAT as
> `context`, the check degenerates to "does this blob's context match a label
> the event carries on itself" — which is ALWAYS true for any validly-signed
> blob, no matter which deployment it was actually signed for, because a
> relay or MITM controls the tags on whatever event it serves you. It could
> swap in server A's validly-signed blob under an event whose `d`-tag says
> "server B," and a verifier that trusts the tag would recompute `context`
> from the ATTACKER-CONTROLLED label and accept it — exactly the substitution
> `context` binding exists to prevent. `context` is only a defence when it
> comes from something the MITM does not control: the verifier's own prior
> knowledge of what it asked for, not anything shipped inside the answer.

**A wrong context fails with the SAME generic error as a wrong signer or a
tampered signature.** `verifyAndParseFilter` deliberately does not distinguish
"signature invalid," "signer doesn't match `pinnedPubkeyHex`," and "context
doesn't match" in its thrown message — all three throw
`'verifyAndParseFilter: signature invalid or signer does not match the pinned
key'` — so a caller (or an attacker probing error messages) cannot learn which
check failed. A malformed `context` (empty, not well-formed UTF-16, or over
1024 UTF-8 bytes — §4.1) is a distinct, separately-worded usage error, the same
as a malformed `pinnedPubkeyHex`.

**Distinct signing keys per server/namespace are now DEFENCE IN DEPTH, not the
only mitigation.** With `context` binding in place, reusing one signing key
across deployments no longer permits the substitution attack described above —
`context` alone defeats it. Using a distinct key per server/namespace still
adds a second, independent layer (e.g. it limits the blast radius of a single
leaked private key to one deployment), and remains good practice, but it is no
longer load-bearing for the substitution defence.

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

## 6. Server publication shape (zero `kenspeckle` dependency)

**Terminology:** `kindred` is the WIRE PROTOCOL / addressing CONVENTION name
(the `30444` kind, the `kindred:members:<namespace>:<serverId>` d-tag, the
`#n` namespace tag) — it is not itself a package. `kenspeckle` is the CODE
that implements that convention (`@forgesworn/kenspeckle`, the relationships +
discovery primitive that consumes tessera-kit). The two are kept distinct
throughout this document.

A server that only needs to *publish* a filter can depend on **tessera-kit alone**
— no `kenspeckle` import required. The reusable mechanics live in the optional
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
namespace tag) — `kenspeckle/discovery` delegates to this builder, passing those
values in. The `./nostr` subpath is the only one that pulls in `@scure/base` (for
base64); the core `.` / `./capability` entries stay `@noble`-only.

**Example — the addressable event a kenspeckle-based server emits, following
the kindred convention (kind `30444`):** the caller-supplied `kind` + `tags`
that reproduce that publication are:

| Tag / field | Value |
|-------------|-------|
| `kind` | `30444` |
| `["d", …]` | `"kindred:members:<namespace>:<serverId>"` — `namespace` = the game/app (the aggregator unit), `serverId` = the instance |
| `["n", "<namespace>"]` | indexable namespace tag, so an aggregator can `#n`-filter across many `serverId`s |
| `["epoch", "<n>"]` | the filter epoch (unix seconds), for HUMAN/INDEX convenience only |
| `["keyed", "0" \| "1"]` | whether the pool is keyed |
| `content` | **base64 of the raw `KFLT` blob** (produced by `buildFilterPublication`) |

> ⚠️ **`namespace` MUST NOT contain a colon (`:`); `serverId` MAY.** The
> `d`-tag is parsed by splitting on the FIRST `:` after the fixed
> `kindred:members:` prefix; everything before that split is `namespace`,
> everything after (including further colons) is `serverId`. Without this
> rule, two different `(namespace, serverId)` pairs can produce the
> byte-identical `d`-tag/context string by shifting the split point — e.g.
> `("a", "b:c")` and `("a:b", "c")` both give `kindred:members:a:b:c` — which
> lets a relay serve one deployment's blob as if it were the other's, since
> the signed-digest `context` check (§4.1/§4.3) only ever compares strings.
> See §4.3 for the full reasoning and the `requireAuthorIsSigner` caveat.

**Freshness — do NOT trust the `["epoch"]` tag for rollback protection.** The tag
is signed only by the Nostr publisher key (standard NIP-01), never by the
pinned blob-signing key (§4), and this kit never cross-checks it against the
blob's own SIGNED `epoch` (KFLT header offset 8, §3). A relay or a malicious
publisher can attach any tag value to any event, including a fresh tag on a
replayed, older blob. Consumers **MUST** decode `content`, call
`verifyAndParseFilter(blob, { pinnedPubkeyHex, context, minEpoch })` (§4.3), and use the
returned `filter.epoch` — the blob's own signed epoch — for the
`epoch ≤ last-seen` freshness check per `(namespace, serverId)`, never the tag.

> ⚠️ **Build `context` from the `(namespace, serverId)` you chose to fetch —
> NEVER from the `d`-tag (or any other tag) on the event you just received.**
> The whole point of the kindred addressing convention is that a client
> already knows the `(namespace, serverId)` pair it wants BEFORE fetching
> anything — that is how it constructs the subscription filter to find the
> right addressable event in the first place. Pass `context =
> "kindred:members:<namespace>:<serverId>"` built from THAT known-in-advance
> pair. Do not instead read the event's own `["d", …]` tag and use it to build
> `context` — a relay or malicious publisher controls every tag on the event
> it serves you, so an attacker could serve server A's validly-signed blob
> under an event tagged as server B's `d`-tag, and a verifier that trusts the
> tag would happily recompute a "matching" `context` from the attacker's own
> label and accept the substitution — precisely what `context` binding (§4.3)
> exists to prevent. See §4.3 for the full reasoning.

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

## 7. False-positive rate and accumulation budget

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
| signing-digest domain tag | `"tessera-kflt-sig:v1"` |
| `context` max UTF-8 bytes | `1024` |
| publication kind | `30444` |

---

## 9. Error codes (`TesseraErrorCode`) — stable contract

Every error this kit throws is a `TesseraError` (`src/errors.ts`, exported
from `.`, `./capability`, and `./nostr`): `class TesseraError extends Error`
with a readonly `code: TesseraErrorCode` and `name === 'TesseraError'`. The
`code` values below are a **stable contract** — like an exported function
name, removing or renaming one is a breaking change; adding a new code for a
new failure mode is not. `message` text is NOT part of this contract and may
be reworded at any time; only `code` should be matched programmatically.
`vectors/reject.golden.v1.json` (and `keyed-member-key.golden.v1.json`'s
`rejectCases`) freeze the exact `code` each listed malformed input must
throw — see `CONFORMANCE.md`.

**Precisely what "stable" promises, stated as a version policy (additive,
post-0.2.0 clarification):**

- **An EXISTING code never changes MEANING, and never disappears, within a
  major version.** `PARSE_BAD_MAGIC` means "bad magic bytes" for the entire
  `1.x` line (whatever `1.x` turns out to mean for this package's own
  versioning); it is never repurposed for a different failure, and it is
  never removed without a major version bump.
- **NEW codes MAY be added in a MINOR release.** This pass itself is the
  example: `TEST_VALUES_TYPE`, `VERIFY_STRICTLY_NEWER_THAN_INVALID`, and
  `VERIFY_EPOCH_NOT_NEWER` (§10, §4.3) are new codes, added without bumping
  a major version, because they are new FAILURE MODES from new, additive
  functionality (`testMany`, `strictlyNewerThan`) — no existing code's
  meaning changed.
- **Consequence for consumers: do NOT write an exhaustive `switch` over
  `TesseraErrorCode` with no `default`, and do NOT write a
  `Record<TesseraErrorCode, ...>` that TypeScript would only accept if every
  current code has an entry.** Either pattern compiles cleanly against
  today's union but breaks (a `switch` silently falls through with no case
  matched; a `Record` literal fails to type-check) the moment a future MINOR
  release adds one more code — which this contract explicitly allows it to
  do. Write a `switch` with a `default` (or an `if/else if` chain with a
  trailing `else`) that handles "a code I don't specifically recognise" as
  its own case, and treat an unrecognised code the same conservative way you
  would treat any other reject: not proof of anything, no special handling
  attempted.

Codes are grouped by the prefix before the first underscore:

| Prefix | Owner | Meaning |
|---|---|---|
| `PARSE_*` | `parseFilter` (§3.1) | The hostile-input trust boundary for a raw `KFLT` blob. |
| `CODEC_*` | `serializeFilter` (§3) | The codec's own output-size guard. |
| `SIGN_*` | `signFilterBlob` (§4.1) | Signing-side input validation. |
| `VERIFY_*` | `verifyFilterBlob` / `verifyAndParseFilter` (§4.2/§4.3) | Verify-side input validation, AND the single opaque trust-failure code (see below). |
| `CAPABILITY_*` | `issuePresenceCapability` / `testWithCapability` (§5) | Capability issue/test validation and trust failures. |
| `BUILD_*` | `buildMembershipFilter` (§2), and `BinaryFuse16.build`'s construction failure (only reachable through the build pipeline) | Filter-construction input validation and (pathological) non-convergence. |
| `TEST_*` | `testMembership` | Query-value validation — distinct from `BUILD_*` because it validates a lookup, not anything about building. |
| `INPUT_*` | `memberKey` (§1), `deriveDecoys` (§2.8), `decodeFilterPublicationContent` (§6) | Small, standalone utility-function input validation not owned by one of the verbs above. |

**Security rule — `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` is deliberately the
ONLY code for "signature invalid," "signer doesn't match the pinned key," OR
"context doesn't match what was signed."** These are never split into
distinguishable codes, the same way §4.3 requires they never be split into
distinguishable messages — a `code`-based checker must learn exactly as
little about WHY a blob was rejected as a message-based one did.

| Code | Thrown when |
|---|---|
| `PARSE_BLOB_TOO_SHORT` | blob shorter than the 128-byte header |
| `PARSE_BLOB_TOO_LARGE` | blob longer than `KFLT_MAX_BLOB_BYTES` |
| `PARSE_BAD_MAGIC` | the 4 magic bytes are not `"KFLT"` |
| `PARSE_UNSUPPORTED_VERSION` | `format_version !== 1` |
| `PARSE_INVALID_FILTER_TYPE` | `filter_type` outside the reserved set `{1,2,3}` |
| `PARSE_UNSUPPORTED_FILTER_TYPE` | `filter_type` is a reserved-but-unimplemented value (`2`, `3`) |
| `PARSE_INVALID_FINGERPRINT_BITS` | `fingerprint_bits` outside the reserved set `{8,16,20,32}` |
| `PARSE_UNSUPPORTED_FINGERPRINT_BITS` | `fingerprint_bits` is a reserved-but-unimplemented value (`8`, `20`, `32`) |
| `PARSE_SEGMENT_LENGTH_NOT_POWER_OF_TWO` | `segment_length` is not a power of two |
| `PARSE_SEGMENT_LENGTH_OUT_OF_RANGE` | `segment_length` outside `[4, 2^18]` |
| `PARSE_SEGMENT_COUNT_INVALID` | `segment_count < 1` |
| `PARSE_GEOMETRY_OVERFLOW` | `segmentCountLength`/`arrayLength` would not be a safe integer — defensive; unreachable given the current u32/2^18 field-width bounds (see `codec.ts`'s comment at this check) |
| `PARSE_ARRAY_TOO_LARGE` | the declared fingerprint array alone would exceed `KFLT_MAX_BLOB_BYTES` |
| `PARSE_LENGTH_MISMATCH` | the geometry-recomputed expected length doesn't equal the actual blob length |
| `PARSE_EPOCH_OVERFLOW` | header `epoch` exceeds `Number.MAX_SAFE_INTEGER` |
| `PARSE_RESERVED_FLAGS_SET` | a reserved `flags` bit (2-7) is set |
| `PARSE_MEMBER_COUNT_BAND_INVALID` | `member_count_band` is not a power of two |
| `PARSE_BLOB_TYPE` | `parseFilter`'s `blob` is not a `Uint8Array` |
| `CODEC_BLOB_TOO_LARGE` | `serializeFilter`'s own output would exceed `KFLT_MAX_BLOB_BYTES` |
| `CODEC_FILTER_TYPE` | `serializeFilter`'s `f` is not a `MembershipFilter`-shaped object |
| `SIGN_BLOB_TOO_SHORT` | `signFilterBlob`'s input blob is shorter than 128 bytes |
| `SIGN_CONTEXT_EMPTY` | `signFilterBlob`'s `context` is empty or not a string |
| `SIGN_CONTEXT_NOT_WELL_FORMED` | `signFilterBlob`'s `context` contains a lone UTF-16 surrogate |
| `SIGN_CONTEXT_TOO_LONG` | `signFilterBlob`'s `context` UTF-8-encodes to over 1024 bytes |
| `SIGN_PRIVATE_KEY_INVALID` | `signerPrivHex` is not 64 hex chars |
| `SIGN_PRIVATE_KEY_OUT_OF_RANGE` | `signerPrivHex` is 64 hex chars but not a valid secp256k1 scalar (zero or >= curve order) |
| `SIGN_BLOB_TYPE` | `signFilterBlob`'s `unsignedBlob` is not a `Uint8Array` |
| `SIGN_PRIVATE_KEY_TYPE` | `signFilterBlob`'s `signerPrivHex` is not a string |
| `VERIFY_CONTEXT_EMPTY` | `verifyFilterBlob`'s `context` is empty or not a string |
| `VERIFY_CONTEXT_NOT_WELL_FORMED` | `verifyFilterBlob`'s `context` contains a lone UTF-16 surrogate |
| `VERIFY_CONTEXT_TOO_LONG` | `verifyFilterBlob`'s `context` UTF-8-encodes to over 1024 bytes |
| `VERIFY_PINNED_PUBKEY_INVALID` | `verifyAndParseFilter`'s `pinnedPubkeyHex` is not 64 hex chars |
| `VERIFY_MIN_EPOCH_INVALID` | `verifyAndParseFilter`'s `minEpoch` is given but not a non-negative safe integer |
| `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` | the signature is invalid, OR the signer doesn't match `pinnedPubkeyHex`, OR `context` doesn't match what was signed — see the security rule above |
| `VERIFY_STALE_EPOCH` | the parsed filter's `epoch` is older than `minEpoch` |
| `VERIFY_BLOB_TYPE` | `verifyFilterBlob`'s `blob` is not a `Uint8Array` (a caller TYPE bug, distinct from the "never throws on hostile content" guarantee — §4.2) |
| `VERIFY_OPTS_TYPE` | `verifyAndParseFilter`'s `opts` is not an object |
| `VERIFY_STRICTLY_NEWER_THAN_INVALID` | `verifyAndParseFilter`'s `strictlyNewerThan` is given but not a non-negative safe integer (additive, §4.3) |
| `VERIFY_EPOCH_NOT_NEWER` | `strictlyNewerThan` is given and the parsed filter's `epoch` is not strictly greater than it — closes the same-epoch-replay gap `minEpoch` alone leaves open, for a caller who opts in (additive, §4.3) |
| `CAPABILITY_EXPIRES_AT_INVALID` | `expiresAt` is not a non-negative safe integer (issue or test) |
| `CAPABILITY_SERVER_ID_EMPTY` | `serverId` is empty or not a string |
| `CAPABILITY_SERVER_ID_HAS_COLON` | `serverId` contains a colon (delimiter-injection guard) |
| `CAPABILITY_SERVER_ID_NOT_WELL_FORMED` | `serverId` contains a lone UTF-16 surrogate |
| `CAPABILITY_SUBJECT_PRIV_HEX_TYPE` | `issuePresenceCapability`'s `subjectPrivHex` is not a string |
| `CAPABILITY_SUBJECT_PRIV_HEX_INVALID` | `subjectPrivHex` is not 64 hex chars |
| `CAPABILITY_SUBJECT_PRIV_HEX_OUT_OF_RANGE` | `subjectPrivHex` is 64 hex chars but not a valid secp256k1 scalar (zero or >= curve order) |
| `CAPABILITY_SUBJECT_PUB_HEX_TYPE` | `subjectPubHex` is not a string (issue or test) |
| `CAPABILITY_SUBJECT_PUB_HEX_INVALID` | `subjectPubHex` is not 64 hex chars (issue or test) |
| `CAPABILITY_SALT_TYPE` | `issuePresenceCapability`'s `salt` is given but not a string |
| `CAPABILITY_SUBJECT_KEY_MISMATCH` | claimed `subjectPubHex` doesn't match the key that signed it |
| `CAPABILITY_MEMBER_VALUE_TYPE` | `testWithCapability`'s `cap.memberValue` is not a string |
| `CAPABILITY_MEMBER_VALUE_INVALID` | `cap.memberValue` is not 64 hex chars |
| `CAPABILITY_SIG_TYPE` | `cap.sig` is not a string |
| `CAPABILITY_SIG_INVALID_SHAPE` | `cap.sig` is not 128 hex chars |
| `CAPABILITY_CLOCK_NOT_FINITE` | the resolved `now` clock value is not `Number.isFinite` |
| `CAPABILITY_EXPIRED` | `now > cap.expiresAt` |
| `CAPABILITY_SIGNATURE_INVALID` | the subject's Schnorr signature over the canonical tuple doesn't verify |
| `CAPABILITY_MEMBER_VALUE_MISMATCH` | on an open pool, `memberValue !== subjectPubHex` (§5.4b) |
| `CAPABILITY_OPTS_TYPE` | `issuePresenceCapability`'s `p` is not an object |
| `CAPABILITY_FILTER_TYPE` | `testWithCapability`'s `f` is not a `MembershipFilter`-shaped object |
| `CAPABILITY_CAP_TYPE` | `testWithCapability`'s `cap` is not an object |
| `BUILD_DECOY_SEED_HEX_INVALID` | `opts.decoySeedHex` is malformed (not even-length hex) |
| `BUILD_DECOY_SEED_HEX_TOO_SHORT` | `opts.decoySeedHex` is shorter than 16 bytes |
| `BUILD_SALT_INVALID` | `opts.salt` is given but not non-empty even-length hex |
| `BUILD_FINGERPRINT_BITS_UNSUPPORTED` | `opts.fingerprintBits` is anything other than `16` |
| `BUILD_EPOCH_INVALID` | `opts.epoch` is not a non-negative safe integer |
| `BUILD_MEMBER_KEY_INVALID` | a `memberKeysHex` entry is not 64 hex chars (message names the index) |
| `BUILD_FUSE_CONSTRUCTION_FAILED` | Binary Fuse 16 peeling failed to converge within `MAX_ATTEMPTS` (pathological input; see CONFORMANCE.md) |
| `BUILD_MEMBER_KEYS_TYPE` | `buildMembershipFilter`'s `memberKeysHex` is not an array |
| `BUILD_OPTS_TYPE` | `buildMembershipFilter`'s `opts` is not an object |
| `TEST_VALUE_INVALID` | `testMembership`'s query value is not 64 hex chars — also thrown by `testMany` (§10) for the same reason, on any one element |
| `TEST_FILTER_TYPE` | `testMembership`'s `f` is not a `MembershipFilter`-shaped object — also thrown by `testMany` and `describeFilter` (§10) for the same reason |
| `TEST_VALUES_TYPE` | `testMany`'s `valuesHex` is not an array (additive, §10) |
| `INPUT_PUBKEY_INVALID` | `memberKey`'s `pubkeyHex` is not 64 lowercase hex chars |
| `INPUT_PUBKEY_TYPE` | `memberKey`'s `pubkeyHex` is not a string |
| `INPUT_SALT_INVALID` | `memberKey`'s `saltHex` is given but not non-empty even-length hex |
| `INPUT_BAND_INVALID` | `nextPowerOfTwoBand`'s `n` is not a non-negative finite number |
| `INPUT_DECOY_SEED_HEX_INVALID` | `deriveDecoys`'s `decoySeedHex` is empty or malformed |
| `INPUT_DECOY_COUNT_INVALID` | `deriveDecoys`'s `count` is not a safe integer |
| `INPUT_CONTENT_TYPE` | `decodeFilterPublicationContent`'s `content` is not a string |
| `INPUT_MAX_BYTES_INVALID` | `decodeFilterPublicationContent`'s `maxBytes` is not a non-negative safe integer |
| `INPUT_CONTENT_TOO_LARGE` | the base64 `content`'s length alone proves it would decode over the cap |
| `INPUT_CONTENT_MALFORMED_BASE64` | `content` is not valid base64 |
| `INPUT_CONTENT_DECODED_TOO_LARGE` | the actually-decoded length exceeds the cap (defence in depth beyond the length pre-check) |
| `INPUT_PUBLICATION_TYPE` | `buildFilterPublication`'s `p` is not an object, or `p.blob` is not a `Uint8Array` |

---

## 10. Introspection & bulk-test helpers (`describeFilter`, `testMany`)

Additive, post-0.2.0 conveniences. Neither changes the wire format, an
existing function's behaviour, or an existing error code; both are read-only
views over an already-built/parsed `MembershipFilter`.

### 10.1 `describeFilter(f) → FilterDescription`

`MembershipFilter` (§ "1. `memberKey`" onward) carries its band/padded/fuse
state on underscored fields (`_fuse`, `_memberCountBand`, `_padded`) that are
explicitly NOT part of the documented public contract (`types.ts`'s comment
on `MembershipFilter`). `describeFilter` is the documented, public way to read
that same information, as a plain readonly object:

```
FilterDescription = {
  fingerprintBits, filterType, keyed, padded, epoch, memberCountBand,
  segmentLength, segmentCount, arrayLength, byteLength,
  theoreticalFalsePositiveRate,
}
```

Every field is either a header field the serialized `KFLT` blob already
discloses to anyone holding it (§3's table: `fingerprint_bits`, `filter_type`,
`flags.keyed`/`flags.padded`, `epoch`, `member_count_band`, `segment_length`,
`segment_count`), or a pure arithmetic function of those fields that any
holder could already compute themselves:

- `arrayLength = (segmentCount + 2) * segmentLength` (§3's `ARITY_MINUS_ONE`
  formula, the same one `codec.ts` uses on both serialize and parse).
- `byteLength = 128 + arrayLength * 2` (`KFLT_HEADER_LEN` plus the fingerprint
  array — `serializeFilter`'s own output-size formula).
- `theoreticalFalsePositiveRate = 2 ** -fingerprintBits` (§7.1's `p`).

**`describeFilter` reveals nothing beyond the serialized header.** It
deliberately does NOT expose the fuse `seed` or the raw `fingerprints` array —
those are on-wire too, but carry no documented public meaning beyond "opaque
construction/query state," so they are left off this contract to keep it
small and stable. `memberCountBand` is the coarse, TRUE-count power-of-two
bucket (§2.8) — it "leaks by design"; `describeFilter` changes nothing about
that, it only makes reading it a documented operation instead of a
`f._memberCountBand` reach-around.

Throws `TEST_FILTER_TYPE` (§9) if `f` is not a `MembershipFilter`-shaped
object — the SAME code `testMembership`/`testMany` throw for the same
reason.

### 10.2 `testMany(f, valuesHex) → boolean[]`

Tests every value in `valuesHex` against `f`, in order, with the EXACT same
semantics and validation `testMembership(f, v)` applies to a single value:

- `f` is validated identically and throws the same `TEST_FILTER_TYPE` for a
  non-`MembershipFilter`.
- each element of `valuesHex` is validated identically (64 lowercase-or-mixed
  hex chars) and throws the same `TEST_VALUE_INVALID` for a malformed one.
- `testMany` introduces exactly one NEW failure mode: `valuesHex` itself not
  being an array, which throws `TEST_VALUES_TYPE` (§9) — `testMembership` has
  no equivalent case to reuse a code from, since it takes one scalar value,
  not a container.

`testMany(f, values)` is equivalent to `values.map(v => testMembership(f,
v))` for every input, valid or invalid (same results, same thrown code on the
same first bad element) — it validates `f` once rather than once per element
and calls the underlying fuse query directly, which is faster than the
equivalent `.map` loop for a large `valuesHex` but is not a different
algorithm: each value is still hashed and queried independently (§2.6).

---

## 11. Evolution / versioning

This section is additive documentation (post-0.2.0): it states, in one place,
what each of this format's version-like knobs actually covers, and what a
future breaking change would look like. It does not change any current
behaviour — every claim below matches what `parseFilter`/`signFilterBlob`/
`verifyFilterBlob` actually do today (§3.1, §4.1).

**`KFLT_VERSION` (the on-wire `format_version` byte, offset 4, §3) covers the
128-byte header LAYOUT and the fingerprint-array encoding** — field order,
widths, and the LE16 fingerprint-array format. It is `1` today and `1` is the
ONLY value `parseFilter` accepts (step 3, §3.1): any other value throws
`PARSE_UNSUPPORTED_VERSION` (§9), unconditionally, before any other header
field is even read. `KFLT_VERSION` does NOT cover the signed-digest
construction (see the domain tag, below) or the capability/Nostr-publication
byte shapes (§5, §6) — those version independently, on their own tags/fields.

**Reserved `filter_type` and `fingerprint_bits` values are a forward-compat
budget already reserved by `format_version = 1`, not a future version bump.**
§3's header table reserves `filter_type ∈ {2, 3}` (xor, cuckoo) and
`fingerprint_bits ∈ {8, 20, 32}` inside the CURRENT header layout — a
"reserved" value is a placeholder for a construction the current byte layout
already has room for (item 10 of the pre-publish gap survey discusses
implementing one, e.g. Binary Fuse 32, without needing a new
`format_version`). `parseFilter` rejects every reserved-but-unimplemented
value explicitly and by name today: `PARSE_INVALID_FILTER_TYPE` /
`PARSE_UNSUPPORTED_FILTER_TYPE` for `filter_type`,
`PARSE_INVALID_FINGERPRINT_BITS` / `PARSE_UNSUPPORTED_FINGERPRINT_BITS` for
`fingerprint_bits` (§9). Implementing one of these later widens the exported
`FilterType`/`FingerprintBits` TypeScript types again (see the note at §3) —
a deliberate, additive change to what the types advertise, not a
`format_version` bump, since the byte LAYOUT does not need to change to fill
an already-reserved slot.

**The signing-digest domain tag versions independently of `KFLT_VERSION`.**
`"tessera-kflt-sig:v1"` (§4.1, the fixed prefix folded into the signed
digest) has its own `:v1` suffix, separate from `KFLT_VERSION`'s `1`. A future
change to the DIGEST CONSTRUCTION ONLY — for example, folding in an additional
field, or changing the length-prefix encoding — would bump this tag to
`:v2` while `KFLT_VERSION` stays `1`, exactly as the `context`-binding change
that introduced `:v1` itself did (it changed the digest formula, not the
128-byte header — see sign.ts's module note). Conversely, a `KFLT_VERSION`
bump that only changed unrelated header fields would leave the signing tag at
`:v1`. The two axes are deliberately independent, so each can change without
forcing a change to the other.

**Error codes (`TesseraErrorCode`, §9) are a stable contract, versioned by
addition only.** §9 already states this; restated here for completeness
alongside the other version-like surfaces this section covers: removing or
renaming a code is a breaking change, exactly like removing an exported
function would be; adding a new code for a new failure mode (as this very
pass did — `VERIFY_STRICTLY_NEWER_THAN_INVALID`, `VERIFY_EPOCH_NOT_NEWER`,
`TEST_VALUES_TYPE`, §10) is not.

**What a future v2 would actually change, and how a verifier rejects an
unknown version today.** A hypothetical `format_version = 2` would be free to
change anything about the header layout `format_version = 1` fixes: field
widths/order/count, the 128-byte header length itself, or how the fingerprint
array is encoded. It could NOT retroactively change how a `format_version =
1` blob is interpreted — old blobs must keep parsing exactly as they do today,
for as long as `parseFilter` supports them.

**Correction — this depends on WHICH function rejects it (`parseFilter` vs.
`verifyAndParseFilter`); an earlier draft of this paragraph glossed over the
difference and stated the claim too strongly.**

- **Called through `parseFilter` directly**, `format_version` IS what rejects
  an unknown version — but only after two prior checks (§3.1 steps 1-2): the
  blob-length bounds check (`PARSE_BLOB_TOO_SHORT`/`PARSE_BLOB_TOO_LARGE`)
  and the magic-bytes check (`PARSE_BAD_MAGIC`) both run BEFORE the
  `format_version` byte is even read. A too-short/too-long or bad-magic blob
  never reaches the version check at all, regardless of what its
  `format_version` byte says. Only once a blob is in-bounds and has the
  correct magic does `parseFilter` read `format_version` and throw
  `PARSE_UNSUPPORTED_VERSION` (§3.1 step 3, §9) for anything other than `1`.
- **Called through `verifyAndParseFilter` (§4.3, the RECOMMENDED path)** — the
  one most consumers actually use — an unknown-version blob is rejected
  EARLIER and DIFFERENTLY: `verifyAndParseFilter` calls `verifyFilterBlob`
  FIRST, and `verifyFilterBlob` (§4.1/§4.2) never inspects `format_version`
  at all. It unconditionally treats `blob[0..64)` as "header fields +
  signer_pubkey" and `blob[128..end)` as "the fingerprint region" — the exact
  v1 offsets — and computes the v1 digest over them regardless of what the
  version byte says. A blob at a genuinely different format version almost
  certainly does NOT carry a signature that verifies against that v1-shaped
  digest (a v2 signer would have signed a v2-shaped digest, or a
  differently-laid-out header, or both) — so `ok` comes back `false`, and
  `verifyAndParseFilter` throws `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH`
  (§4.2/§4.3, §9) BEFORE `parseFilter` is ever called. `PARSE_UNSUPPORTED_VERSION`
  is reachable through this path only in the narrow case where the
  differently-versioned blob HAPPENS to carry a validly-verifying v1-shaped
  signature under the pinned key for the given `context` anyway — which a
  genuine v2 blob, signed by a v2-aware signer using v2's own digest
  construction, essentially never will.
- **The practical upshot:** most consumers, using `verifyAndParseFilter`,
  will observe an unknown-version blob rejected as
  `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH`, not `PARSE_UNSUPPORTED_VERSION` —
  the SAME opaque code a bad signature or wrong signer produces (by design,
  §9's security rule). Only a caller using `parseFilter` directly (bypassing
  verification) sees the version-specific code.

**What a future v2 VERIFIER would need to do, given the above.** A v2-aware
implementation that must support BOTH `format_version = 1` and `= 2` blobs
cannot simply keep today's `verifyFilterBlob` (fixed v1 offsets, fixed v1
digest tag) and layer a v2 `parseFilter` on top of it — that combination
would reject every genuine v2 blob at the signature step, exactly as
described above, never reaching a version-aware code path at all. It would
instead need to inspect `format_version` FIRST — before choosing which
digest construction and which header-offset assumptions to verify with — and
dispatch to the v1 or v2 verify logic accordingly, only THEN parsing with the
matching version's `parseFilter` logic. Read the byte, decide the
construction, THEN verify; never assume one fixed construction and hope a
different version's blob happens to fail informatively.

**A v2-supporting `parseFilter` alone (independent of the above) MUST keep
throwing `PARSE_UNSUPPORTED_VERSION` for anything it does not explicitly
support** — checked right after the bounds and magic checks (§3.1 steps 1-3),
before any OTHER header field is trusted, exactly as today. This kit
implements `format_version = 1` only, so today "unknown version" means
"anything other than `1`," full stop; a future implementation that adds
`format_version = 2` support would widen that check to `version !== 1 &&
version !== 2`, but the PRINCIPLE — reject anything not explicitly
recognised, right after bounds/magic and before any other field — does not
change. A dual-publish migration window (`format_version = 1` and `= 2`
blobs served side by side) is a deployment strategy, not something this
format needs to encode on the wire beyond the `format_version` byte itself
already distinguishing them.
