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
- `saltHex` MUST be even-length hex (may be empty; empty salt ⇒ keyed value =
  `sha256("" ‖ pk)`, still distinct from the open value `pk`).
- The salt is **never** placed in the blob. It is distributed out-of-band. The
  blob's `keyed` flag only signals "test values were salted."

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
to peel all keys, advance the seed (`next32`) and retry. Callers MUST pass
**distinct** keys (duplicates break peeling — `buildMembershipFilter`
de-duplicates first).

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
8. only then allocates the `Uint16Array` and reads the fingerprints.

Every reachable failure throws an `Error`. A parse SUCCESS means **"well-formed,
self-consistent bytes," not "trustworthy bytes."** `parseFilter` validates a
self-consistent geometry but does **not** prove it is a geometry the builder
would emit; trust comes from `verifyFilterBlob` against a **pinned key** (§4),
**not** from parse.

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

`verifyFilterBlob(blob) → { signerPubkeyHex, valid }`:

- reads `signer_pubkey` from `[32,64)` and `sig` from `[64,128)`, recomputes the
  digest (§4.1), returns `valid = schnorr.verify(sig, digest, signer_pubkey)`;
- never throws on hostile input: a `< 128`-byte blob returns
  `{ signerPubkeyHex: '', valid: false }`; a malformed sig/pubkey yields
  `valid:false`.

> **`valid:true` is NOT trust.** It means only "this blob carries an
> internally-consistent BIP340 signature by `signerPubkeyHex`." Anyone can mint a
> validly self-signed blob under their **own** key. The consumer **MUST** compare
> `signerPubkeyHex` against a **pinned / out-of-band-known** server key before
> trusting any membership result:
>
> ```
> const { signerPubkeyHex, valid } = verifyFilterBlob(blob)
> if (!valid || signerPubkeyHex !== PINNED_SERVER_PUBKEY) reject()
> ```

---

## 5. Presence-capability canonical bytes (`./capability`)

A `PresenceCapability` is **subject consent** to be located on a keyed server. It
is signed by the **subject** (the person whose presence may be tested), **not**
the server — it is *not* filter provenance. Pin-verify the filter regardless.

### 5.1 Token shape

```
PresenceCapability = { serverId, subjectPubHex, saltHint, expiresAt, sig }
```

### 5.2 Canonical signing bytes

```
preimage = utf8( "tessera-cap:v1:" + serverId + ":" + subjectPubHex + ":" + saltHint + ":" + expiresAt )
digest   = sha256(preimage)                            // 32 bytes, the Schnorr message
sig      = hex( schnorr.sign(digest, subjectPriv) )    // 64-byte BIP340 compact sig, hex
```

- `subjectPubHex`: 64 lowercase hex (x-only). `issuePresenceCapability` asserts it
  equals the signing key's pubkey — you cannot issue for a key you don't control.
- `saltHint`: even-length lowercase hex; **may be empty**. `saltHint = ''`
  corresponds to an **open-pool** capability, i.e. the value tested is
  `memberKey(subjectPubHex, '')` (noted in `SECURITY.md`).
- `expiresAt`: finite number (unix seconds). Valid while `now ≤ expiresAt` (the
  boundary instant is still valid).
- `sig`: 128 hex chars.

### 5.3 **`serverId` MUST be colon-free** (delimiter-injection guard)

The canonical string is colon-delimited. Three of the four interpolated fields
can never contain a colon (`subjectPubHex`/`saltHint` are hex; `expiresAt`
stringifies without `:`). Only `serverId` is free-form, so a `serverId`
containing a colon is **rejected on both issue and test**. Without this guard a
crafted `serverId` like `x:DEADBEEF:cafe:0` could shift field boundaries and make
two distinct tuples produce identical preimage bytes.

> **Practical consequence:** a `wss://host:port` URL has colons and **will be
> rejected**. Callers pass a **bare host** (`play.example.com`) or a **hash of
> the URL** as the `serverId`.

### 5.4 Test order (load-bearing)

`testWithCapability(filter, cap, now?)` checks, in order: (1) field shapes; (2)
**expiry** (`now > expiresAt` → throw `'capability expired'`); (3) **signature**
(`schnorr.verify` against `subjectPubHex`, else throw
`'capability signature invalid'`); (4) **only then**
`testMembership(filter, memberKey(subjectPubHex, saltHint))`. An expired/forged
capability **throws** (a usage error) rather than returning a silent `false`, so
a caller can never confuse "not present" with "this token is no good."

---

## 6. Server publication shape (zero `kindred` dependency)

A server that only needs to *publish* a filter can depend on **tessera-kit alone**
and emit the Nostr event directly — no `kindred` import required. This mirrors
`kindred/discovery`'s `buildFilterPublication`, documented here so a
tessera-kit-only server can produce the identical event.

**Addressable event, `kind 30444`:**

| Tag / field | Value |
|-------------|-------|
| `kind` | `30444` |
| `["d", …]` | `"kindred:members:<namespace>:<serverId>"` — `namespace` = the game/app (the aggregator unit), `serverId` = the instance |
| `["n", "<namespace>"]` | indexable namespace tag, so an aggregator can `#n`-filter across many `serverId`s |
| `["epoch", "<n>"]` | the filter epoch (unix seconds) — consumers reject `epoch ≤ last-seen` for a `(namespace, serverId)` |
| `["keyed", "0" \| "1"]` | whether the pool is keyed |
| `content` | **base64 of the raw `KFLT` blob** |

The event itself is signed by the publisher's Nostr key (standard NIP-01); that
is **separate** from the in-blob Schnorr provenance signature (§4). A consumer
verifies **both**: the event signature (transport integrity) **and**
`verifyFilterBlob` against the pinned server key (filter provenance). The
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

For a consumer testing `c` candidate keys against `S`-member servers across a
sweep, the expected number of false "present" hits is

```
E[false hits] = c · S · p
```

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
| capability prefix | `"tessera-cap:v1:"` |
| publication kind | `30444` |
