// Frozen golden-vector checker for @forgesworn/tessera-kit.
//
// This is the cross-implementation / future-Rust-port CONTRACT for the KFLT
// codec, the decoy-seed derivation, memberKey, the capability canonical
// bytes, the signed-blob format, and parseFilter's hostile-input rejection.
// Every `vectors/*.golden.*.json` file is dispatched by its `kind` field
// (absent ⇒ the original "filter" shape, for backward compatibility with
// `kflt.golden.v1.json`, predating the `kind` field):
//
//   (no `kind`, i.e. "filter")  — rebuilds + serializes from `memberKeysHex` +
//                                 `opts` using the REAL built code in dist/
//                                 and asserts the result equals the frozen
//                                 `serializedBlobHex` byte-for-byte; ALSO
//                                 `parseFilter`s the frozen bytes directly
//                                 (not just the rebuilt filter) and checks
//                                 `membership.present`/`membership.absent`
//                                 against the PARSED filter too — closing the
//                                 review gap where only the rebuilt filter was
//                                 ever tested, never the parse direction.
//   "decoy-seed"                — re-derives `effectiveSeedHex` (the
//                                 documented per-epoch decoy-seed formula,
//                                 PROTOCOL.md §2.8) and `decoysHex`
//                                 (`deriveDecoys`) and compares byte-for-byte.
//   "keyed-member-key"          — re-derives `memberKey(pubkeyHex, saltHex)`
//                                 (keyed and open forms) and compares.
//   "capability"                — checks `subjectPrivHexDemoOnly` actually
//                                 derives `subjectPubHex`; re-derives the
//                                 canonical preimage/digest; and re-VERIFIES
//                                 the frozen `sig` (via `testWithCapability`
//                                 against a filter built from the vector's own
//                                 member set) — BIP340 verification is fully
//                                 deterministic even though signing itself
//                                 used random aux data.
//   "signed-blob"                — checks `signerPrivHexDemoOnly` actually
//                                 derives `pinnedPubkeyHex`; pin-verifies +
//                                 context-verifies + parses the frozen signed
//                                 blob (`verifyAndParseFilter`, with
//                                 `context`); checks the parsed `epoch` equals
//                                 the vector's frozen `epoch` and
//                                 `membership.present`/`absent`; re-derives the
//                                 signing digest (now bound to `context`,
//                                 PROTOCOL.md §4.1) and compares; and asserts
//                                 the SAME blob+sig is REJECTED when checked
//                                 against `mustRejectContext` (a different,
//                                 well-formed context) — the context-binding
//                                 must-reject case (spec §4.1/§4.3).
//   "reject"                     — asserts `parseFilter` THROWS on every
//                                 listed malformed blob, WITH the case's
//                                 `expectedErrorCode` (item 3: typed errors —
//                                 the PRIMARY, strict assertion; the thrown
//                                 error's `code` must equal it exactly).
//                                 `expectedErrorSubstring` is kept only as
//                                 human-readable documentation and is no
//                                 longer checked.
//   "filter-set"                 — like "filter", but one file holds an array
//                                 of `cases`, each with the same shape as a
//                                 "filter" vector plus an optional `geometry`
//                                 object ({segmentLength, segmentCount,
//                                 arrayLength, seed, attempts}); every case is
//                                 rebuilt/serialized/parsed/membership-checked
//                                 exactly as "filter" does, and `geometry` (if
//                                 present) is cross-checked against the
//                                 rebuilt filter's actual fields — `attempts`
//                                 (how many seeded peel attempts the REAL
//                                 `attemptsFor` re-derivation needed to reach
//                                 the frozen `seed` from `seed_0`, PROTOCOL.md
//                                 §2.2) is computed here, not read off the
//                                 filter object (construction doesn't expose
//                                 an attempt counter).
//   "filter-large"                — for realistic-to-ecosystem-scale n (e.g.
//                                 10,000 / 100,000) where a full member list
//                                 or full blob hex would bloat the vector file
//                                 by hundreds of KB to several MB. Regenerates
//                                 `memberCount` members via the DOCUMENTED
//                                 rule (`memberGenerationRule`, matching
//                                 CONFORMANCE.md — currently
//                                 `member_i = hex(sha256("tessera-vec:" + i))`),
//                                 rebuilds, serializes, checks `geometry`,
//                                 hashes the rebuilt blob and compares to
//                                 `blobSha256Hex`, and checks every
//                                 `samplePresent`/`sampleAbsent` entry (>=20
//                                 each) against the rebuilt filter.
//   "context-validation"         — review follow-up: covers the
//                                 SIGN_CONTEXT_*/VERIFY_CONTEXT_* codes
//                                 (`reject.golden.v1.json` only covers
//                                 `parseFilter`'s `PARSE_*` codes) plus the
//                                 context-mismatch security case. Each of
//                                 `cases[]` has a `side`: "sign" re-signs
//                                 `unsignedBlobHex` under `context` and
//                                 expects `signFilterBlob` to throw
//                                 `expectedErrorCode`; "accept" signs +
//                                 verifies a full round-trip under `context`
//                                 and expects NO throw (covers the exactly-
//                                 1024-UTF-8-byte boundary); "verify" calls
//                                 `verifyFilterBlob(signedBlobHex, context)`
//                                 and expects `expectedErrorCode`;
//                                 "verify-mismatch" calls
//                                 `verifyAndParseFilter(signedBlobHex, {
//                                 pinnedPubkeyHex, context})` with a
//                                 DIFFERENT well-formed `context` and expects
//                                 the single opaque
//                                 `VERIFY_SIGNATURE_OR_SIGNER_MISMATCH` code
//                                 (spec §4.3 security rule).
//
// Determinism precondition for a frozen "filter"/"filter-set"/"filter-large"
// vector: `opts` MUST pin
// padding to a reproducible value — either `padToBucket: false` (no decoys)
// or a fixed `decoySeedHex` (stable decoys). Random-decoy padding is not
// reproducible and is rejected below so a non-reproducible vector can never
// silently pass.
//
// Exits non-zero on ANY mismatch or malformation (strict — this gates releases).

import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'

import {
  buildMembershipFilter,
  serializeFilter,
  testMembership,
  parseFilter,
  memberKey,
  deriveDecoys,
  verifyAndParseFilter,
  signFilterBlob,
  verifyFilterBlob,
} from '../dist/index.js'
import { testWithCapability } from '../dist/capability.js'
import { schnorr } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const rootDir = path.resolve(__dirname, '..')
const vectorsDir = path.join(rootDir, 'vectors')

const files = readdirSync(vectorsDir)
  .filter((name) => name.endsWith('.json') && name !== 'schema.json')
  .sort()

if (files.length === 0) {
  console.error('[vectors] No vector files found in vectors/')
  process.exit(1)
}

const failures = []
let assertionCount = 0

/** Big-endian 8-byte encoding of a non-negative safe-integer — mirrors
 *  filter.ts's `u64be` (used only by the decoy-seed derivation, distinct
 *  from the on-wire little-endian `epoch` field). */
function u64be(n) {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false)
  return b
}

/** Big-endian Weyl seed schedule (PROTOCOL.md §2.2), reimplemented here ONLY
 *  to compute how many attempts a frozen `seed` represents — the filter
 *  object exposes the WINNING seed, not an attempt counter. Declared above
 *  the main per-file loop (not just above its first use) so top-level
 *  execution order can never hit a temporal-dead-zone reference. */
const FUSE_SEED0 = 0x66666b6c
function fuseNext32(s) {
  return (s + 0x9e3779b9) >>> 0
}
function attemptsFor(seed) {
  let s = FUSE_SEED0
  let attempts = 1
  while (s !== seed && attempts < 200) {
    s = fuseNext32(s)
    attempts++
  }
  return attempts
}

for (const fileName of files) {
  const fullPath = path.join(vectorsDir, fileName)
  let vector
  try {
    vector = JSON.parse(readFileSync(fullPath, 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    continue
  }
  if (!vector || typeof vector !== 'object' || Array.isArray(vector)) {
    failures.push({ fileName, message: 'Vector file must be a JSON object' })
    continue
  }

  const kind = vector.kind ?? 'filter'
  const before = failures.length

  switch (kind) {
    case 'filter':
      checkFilterVector(fileName, vector)
      break
    case 'decoy-seed':
      checkDecoySeedVector(fileName, vector)
      break
    case 'keyed-member-key':
      checkKeyedMemberKeyVector(fileName, vector)
      break
    case 'capability':
      checkCapabilityVector(fileName, vector)
      break
    case 'signed-blob':
      checkSignedBlobVector(fileName, vector)
      break
    case 'reject':
      checkRejectVector(fileName, vector)
      break
    case 'filter-set':
      checkFilterSetVector(fileName, vector)
      break
    case 'filter-large':
      checkFilterLargeVector(fileName, vector)
      break
    case 'context-validation':
      checkContextValidationVector(fileName, vector)
      break
    default:
      failures.push({ fileName, message: `Unknown vector "kind": ${JSON.stringify(kind)}` })
  }

  if (failures.length === before) {
    // No failure recorded for this file — at least one assertion must have run.
    // (Each check* function increments assertionCount itself.)
  }
}

if (failures.length > 0) {
  console.error('[vectors] Frozen golden-vector check FAILED.')
  for (const failure of failures) {
    console.error(`- ${failure.fileName}: ${failure.message}`)
  }
  console.error(
    '[vectors] If this change is intentional, regenerate the golden vector against ' +
      'the new code and add a CHANGELOG note — a silent change to the KFLT byte ' +
      'layout (or any other frozen contract here) breaks every other implementation.',
  )
  process.exit(1)
}

console.log(`[vectors] OK (${files.length} file(s), ${assertionCount} assertions).`)

// ---------------------------------------------------------------------------
// "filter" (original / default) vectors
// ---------------------------------------------------------------------------

function checkFilterVector(fileName, vector) {
  const shapeError = validateFilterShape(vector)
  if (shapeError) {
    failures.push({ fileName, message: shapeError })
    return
  }

  // Determinism guard: a frozen vector MUST pin padding.
  const opts = vector.opts
  const padToBucket = opts.padToBucket ?? true
  if (padToBucket && opts.decoySeedHex === undefined) {
    failures.push({
      fileName,
      message:
        'Non-reproducible vector: padToBucket is on with no decoySeedHex (random decoys). ' +
        'Freeze with padToBucket:false OR a fixed decoySeedHex.',
    })
    return
  }

  // 1+2. Rebuild from the frozen inputs and assert byte-exact serialization.
  let actualHex
  try {
    const filter = buildMembershipFilter(vector.memberKeysHex, opts)
    actualHex = bytesToHex(serializeFilter(filter))
  } catch (error) {
    failures.push({ fileName, message: `build/serialize threw: ${String(error)}` })
    return
  }

  assertionCount++
  if (actualHex !== vector.serializedBlobHex) {
    failures.push({
      fileName,
      message:
        'serializedBlobHex MISMATCH (KFLT byte layout drifted).\n' +
        `  expected (${vector.serializedBlobHex.length / 2} bytes): ${vector.serializedBlobHex}\n` +
        `  actual   (${actualHex.length / 2} bytes): ${actualHex}`,
    })
    // Continue to membership checks anyway — more signal is better on a failure.
  }

  // 3. Membership checks against a REBUILT filter.
  let filterForMembership
  try {
    filterForMembership = buildMembershipFilter(vector.memberKeysHex, opts)
  } catch (error) {
    failures.push({ fileName, message: `rebuild for membership threw: ${String(error)}` })
    return
  }
  checkMembership(fileName, 'rebuilt', filterForMembership, vector.membership)

  // 4. Membership checks against the PARSED frozen bytes directly (audit fix:
  //    the parse direction was previously never exercised against frozen
  //    bytes — only the rebuild-and-serialize direction was).
  let parsed
  try {
    parsed = parseFilter(hexToBytes(vector.serializedBlobHex))
  } catch (error) {
    failures.push({ fileName, message: `parseFilter(serializedBlobHex) threw: ${String(error)}` })
    return
  }
  checkMembership(fileName, 'parsed', parsed, vector.membership)

  // 5. Optional `geometry` cross-check (conformance-vector extension — not
  //    present on the original kflt.golden.v1.json). Present on vectors added
  //    to cover realistic/boundary sizes, so a divergent port can localize a
  //    mismatch to geometry vs. peel/fingerprint assignment.
  if (vector.geometry !== undefined) {
    checkGeometry(fileName, filterForMembership, vector.geometry)
  }
}

/** Cross-check a vector's frozen `geometry` object against a rebuilt filter's
 *  actual fields (segmentLength/segmentCount/arrayLength/seed are read off
 *  `filter._fuse`; `attempts` is re-derived from `seed` via the seed schedule
 *  above, since it isn't otherwise exposed). */
function checkGeometry(fileName, filter, geometry) {
  const fuse = filter._fuse
  const expected = {
    segmentLength: fuse.segmentLength,
    segmentCount: fuse.segmentCount,
    arrayLength: fuse.arrayLength,
    seed: fuse.seed,
    attempts: attemptsFor(fuse.seed),
  }
  for (const key of Object.keys(expected)) {
    if (geometry[key] === undefined) continue // field is optional per-vector
    assertionCount++
    if (geometry[key] !== expected[key]) {
      failures.push({
        fileName,
        message: `geometry.${key} MISMATCH: expected ${expected[key]}, vector says ${geometry[key]}`,
      })
    }
  }
}

function checkMembership(fileName, label, filter, membership) {
  for (const key of membership.present) {
    assertionCount++
    if (testMembership(filter, key) !== true) {
      failures.push({
        fileName,
        message: `membership.present FAILED on the ${label} filter: "${key}" tested false (expected present).`,
      })
    }
  }
  for (const key of membership.absent) {
    assertionCount++
    if (testMembership(filter, key) !== false) {
      failures.push({
        fileName,
        message: `membership.absent FAILED on the ${label} filter: "${key}" tested true (expected absent).`,
      })
    }
  }
}

function validateFilterShape(vector) {
  if (typeof vector.description !== 'string' || vector.description.length === 0) {
    return 'Missing or invalid "description"'
  }
  if (!isHexStringArray(vector.memberKeysHex)) {
    return '"memberKeysHex" must be an array of hex strings (may be empty — n=0 is a valid case)'
  }
  if (!vector.opts || typeof vector.opts !== 'object' || Array.isArray(vector.opts)) {
    return 'Missing or invalid "opts" object'
  }
  if (typeof vector.opts.epoch !== 'number') {
    return '"opts.epoch" must be a number'
  }
  if (typeof vector.serializedBlobHex !== 'string' || !/^[0-9a-f]*$/.test(vector.serializedBlobHex)) {
    return '"serializedBlobHex" must be a lowercase hex string'
  }
  if (vector.serializedBlobHex.length % 2 !== 0) {
    return '"serializedBlobHex" must be even-length hex'
  }
  const m = vector.membership
  if (!m || typeof m !== 'object' || Array.isArray(m)) {
    return 'Missing or invalid "membership" object'
  }
  if (!isHexStringArray(m.present)) {
    return '"membership.present" must be an array of hex strings'
  }
  if (!isHexStringArray(m.absent)) {
    return '"membership.absent" must be an array of hex strings'
  }
  return null
}

function isHexStringArray(value) {
  return (
    Array.isArray(value) &&
    value.every((s) => typeof s === 'string' && /^[0-9a-f]+$/.test(s) && s.length % 2 === 0)
  )
}

// ---------------------------------------------------------------------------
// "filter-set" vectors — an array of "filter"-shaped cases in one file, each
// optionally carrying a `geometry` cross-check. Used for the realistic/
// boundary-size conformance vectors (n=0,1,2,3,9,100,1000).
// ---------------------------------------------------------------------------

function checkFilterSetVector(fileName, vector) {
  if (typeof vector.description !== 'string' || vector.description.length === 0) {
    failures.push({ fileName, message: 'Missing or invalid "description"' })
    return
  }
  if (!Array.isArray(vector.cases) || vector.cases.length === 0) {
    failures.push({ fileName, message: '"cases" must be a non-empty array' })
    return
  }
  for (const c of vector.cases) {
    const shapeError = validateFilterShape(c)
    if (shapeError) {
      failures.push({ fileName, message: `case ${JSON.stringify(c.description)}: ${shapeError}` })
      continue
    }
    const opts = c.opts
    const padToBucket = opts.padToBucket ?? true
    if (padToBucket && opts.decoySeedHex === undefined) {
      failures.push({
        fileName,
        message: `case ${JSON.stringify(c.description)}: non-reproducible (padToBucket on, no decoySeedHex)`,
      })
      continue
    }

    let filter
    let actualHex
    try {
      filter = buildMembershipFilter(c.memberKeysHex, opts)
      actualHex = bytesToHex(serializeFilter(filter))
    } catch (error) {
      failures.push({ fileName, message: `case ${JSON.stringify(c.description)}: build/serialize threw: ${String(error)}` })
      continue
    }

    assertionCount++
    if (actualHex !== c.serializedBlobHex) {
      failures.push({
        fileName,
        message:
          `case ${JSON.stringify(c.description)}: serializedBlobHex MISMATCH.\n` +
          `  expected (${c.serializedBlobHex.length / 2} bytes): ${c.serializedBlobHex}\n` +
          `  actual   (${actualHex.length / 2} bytes): ${actualHex}`,
      })
    }

    checkMembership(fileName, `case ${JSON.stringify(c.description)} (rebuilt)`, filter, c.membership)

    let parsed
    try {
      parsed = parseFilter(hexToBytes(c.serializedBlobHex))
    } catch (error) {
      failures.push({ fileName, message: `case ${JSON.stringify(c.description)}: parseFilter threw: ${String(error)}` })
      continue
    }
    checkMembership(fileName, `case ${JSON.stringify(c.description)} (parsed)`, parsed, c.membership)

    if (c.geometry !== undefined) {
      checkGeometry(fileName, filter, c.geometry)
    }
  }
}

// ---------------------------------------------------------------------------
// "filter-large" vectors — realistic-to-ecosystem-scale n. Members are
// regenerated from the documented rule (NOT stored inline); only geometry,
// a blob hash, and sample present/absent sets are checked.
// ---------------------------------------------------------------------------

/** The ONE documented member-generation rule for conformance vectors (see
 *  CONFORMANCE.md): member_i = hex(sha256(utf8("tessera-vec:" + i))). A port
 *  MUST reproduce this exact rule to regenerate the member list for a
 *  "filter-large" vector (and MAY use it to independently regenerate the
 *  "filter"/"filter-set" vectors' `memberKeysHex`, though those store the
 *  list inline so regeneration isn't required for them). */
function vecMember(i) {
  return bytesToHex(sha256(utf8ToBytes('tessera-vec:' + i)))
}

function checkFilterLargeVector(fileName, vector) {
  if (typeof vector.description !== 'string' || vector.description.length === 0) {
    failures.push({ fileName, message: 'Missing or invalid "description"' })
    return
  }
  if (!Number.isSafeInteger(vector.memberCount) || vector.memberCount < 0) {
    failures.push({ fileName, message: '"memberCount" must be a non-negative safe integer' })
    return
  }
  if (!vector.opts || typeof vector.opts !== 'object' || typeof vector.opts.epoch !== 'number') {
    failures.push({ fileName, message: 'Missing or invalid "opts" object (opts.epoch required)' })
    return
  }
  const padToBucket = vector.opts.padToBucket ?? true
  if (padToBucket && vector.opts.decoySeedHex === undefined) {
    failures.push({
      fileName,
      message: 'Non-reproducible vector: padToBucket is on with no decoySeedHex.',
    })
    return
  }
  if (typeof vector.blobSha256Hex !== 'string' || !/^[0-9a-f]{64}$/.test(vector.blobSha256Hex)) {
    failures.push({ fileName, message: '"blobSha256Hex" must be a 64-hex sha256 digest' })
    return
  }
  if (!isHexStringArray(vector.samplePresent) || vector.samplePresent.length < 20) {
    failures.push({ fileName, message: '"samplePresent" must have at least 20 hex entries' })
    return
  }
  if (!isHexStringArray(vector.sampleAbsent) || vector.sampleAbsent.length < 20) {
    failures.push({ fileName, message: '"sampleAbsent" must have at least 20 hex entries' })
    return
  }

  // Regenerate the member list from the documented rule — NOT read from the
  // vector file (that's the whole point of "filter-large": avoid storing a
  // multi-hundred-KB-to-multi-MB member list for a large n).
  assertionCount++
  const members = Array.from({ length: vector.memberCount }, (_, i) => vecMember(i))
  let filter
  let blob
  try {
    filter = buildMembershipFilter(members, vector.opts)
    blob = serializeFilter(filter)
  } catch (error) {
    failures.push({ fileName, message: `build/serialize threw: ${String(error)}` })
    return
  }

  if (vector.geometry !== undefined) {
    checkGeometry(fileName, filter, vector.geometry)
  }

  assertionCount++
  const actualBlobSha256Hex = bytesToHex(sha256(blob))
  if (actualBlobSha256Hex !== vector.blobSha256Hex) {
    failures.push({
      fileName,
      message: `blobSha256Hex MISMATCH: expected ${vector.blobSha256Hex}, got ${actualBlobSha256Hex}`,
    })
  }
  if (typeof vector.blobLengthBytes === 'number') {
    assertionCount++
    if (blob.length !== vector.blobLengthBytes) {
      failures.push({
        fileName,
        message: `blobLengthBytes MISMATCH: expected ${vector.blobLengthBytes}, got ${blob.length}`,
      })
    }
  }

  checkMembership(fileName, 'filter-large sample', filter, {
    present: vector.samplePresent,
    absent: vector.sampleAbsent,
  })
}

// ---------------------------------------------------------------------------
// "decoy-seed" vectors — deriveEpochDecoySeedHex formula + deriveDecoys
// ---------------------------------------------------------------------------

function checkDecoySeedVector(fileName, vector) {
  if (typeof vector.decoySeedHex !== 'string' || typeof vector.effectiveSeedHex !== 'string') {
    failures.push({ fileName, message: 'decoySeedHex / effectiveSeedHex must be hex strings' })
    return
  }
  if (typeof vector.epoch !== 'number' || typeof vector.decoyCount !== 'number') {
    failures.push({ fileName, message: 'epoch / decoyCount must be numbers' })
    return
  }
  if (!isHexStringArray(vector.decoysHex)) {
    failures.push({ fileName, message: '"decoysHex" must be an array of hex strings' })
    return
  }

  // Re-derive effectiveSeedHex from the documented formula (PROTOCOL.md §2.8):
  //   effectiveSeedHex = sha256(utf8("tessera-decoy:v1:") || bytes(decoySeedHex) || u64be(epoch))
  assertionCount++
  const preimage = concatBytes(
    utf8ToBytes('tessera-decoy:v1:'),
    hexToBytes(vector.decoySeedHex.toLowerCase()),
    u64be(vector.epoch),
  )
  const actualEffectiveSeedHex = bytesToHex(sha256(preimage))
  if (actualEffectiveSeedHex !== vector.effectiveSeedHex) {
    failures.push({
      fileName,
      message: `effectiveSeedHex MISMATCH: expected ${vector.effectiveSeedHex}, got ${actualEffectiveSeedHex}`,
    })
  }

  // Re-derive decoysHex via the REAL built deriveDecoys.
  assertionCount++
  let actualDecoysHex
  try {
    actualDecoysHex = deriveDecoys(vector.effectiveSeedHex, vector.decoyCount)
  } catch (error) {
    failures.push({ fileName, message: `deriveDecoys threw: ${String(error)}` })
    return
  }
  if (JSON.stringify(actualDecoysHex) !== JSON.stringify(vector.decoysHex)) {
    failures.push({
      fileName,
      message: `decoysHex MISMATCH:\n  expected: ${JSON.stringify(vector.decoysHex)}\n  actual:   ${JSON.stringify(actualDecoysHex)}`,
    })
  }
}

// ---------------------------------------------------------------------------
// "keyed-member-key" vectors — memberKey(pubkeyHex, saltHex)
// ---------------------------------------------------------------------------

function checkKeyedMemberKeyVector(fileName, vector) {
  if (!Array.isArray(vector.keyedCases) || vector.keyedCases.length === 0) {
    failures.push({ fileName, message: '"keyedCases" must be a non-empty array' })
    return
  }
  for (const c of vector.keyedCases) {
    assertionCount++
    let actual
    try {
      actual = memberKey(c.pubkeyHex, c.saltHex)
    } catch (error) {
      failures.push({ fileName, message: `memberKey threw for case ${JSON.stringify(c)}: ${String(error)}` })
      continue
    }
    if (actual !== c.memberValueHex) {
      failures.push({
        fileName,
        message: `keyedCases memberValueHex MISMATCH for pubkeyHex=${c.pubkeyHex} saltHex=${c.saltHex}: expected ${c.memberValueHex}, got ${actual}`,
      })
    }
  }

  if (!vector.openCase || typeof vector.openCase.pubkeyHex !== 'string') {
    failures.push({ fileName, message: '"openCase" must be present' })
    return
  }
  assertionCount++
  const actualOpen = memberKey(vector.openCase.pubkeyHex)
  if (actualOpen !== vector.openCase.memberValueHex) {
    failures.push({
      fileName,
      message: `openCase memberValueHex MISMATCH: expected ${vector.openCase.memberValueHex}, got ${actualOpen}`,
    })
  }

  // Follow-up audit fix: an EMPTY salt is now a MUST-REJECT case (it gives no
  // protection — sha256('' || pk) is computable by anyone holding the bare
  // pubkey), not an accepted "distinct keyed value."
  if (!Array.isArray(vector.rejectCases) || vector.rejectCases.length === 0) {
    failures.push({ fileName, message: '"rejectCases" must be a non-empty array' })
    return
  }
  for (const c of vector.rejectCases) {
    assertionCount++
    if (typeof c.expectedErrorCode !== 'string') {
      failures.push({
        fileName,
        message: `rejectCases case "${c.description}" is missing "expectedErrorCode" (item 3: reject vectors assert on code, not message substrings)`,
      })
      continue
    }
    let threw = false
    let code
    let message = ''
    try {
      memberKey(c.pubkeyHex, c.saltHex)
    } catch (error) {
      threw = true
      code = error && error.code
      message = String(error && error.message)
    }
    if (!threw) {
      failures.push({
        fileName,
        message: `rejectCases case "${c.description}" did NOT throw (expected memberKey to reject it)`,
      })
      continue
    }
    if (code !== c.expectedErrorCode) {
      failures.push({
        fileName,
        message: `rejectCases case "${c.description}" threw code ${JSON.stringify(code)}, expected ${JSON.stringify(c.expectedErrorCode)} (message was: ${message})`,
      })
    }
  }
}

// ---------------------------------------------------------------------------
// "capability" vectors — canonical preimage/digest + a fixed valid sig
// ---------------------------------------------------------------------------

function checkCapabilityVector(fileName, vector) {
  for (const field of [
    'serverId',
    'subjectPubHex',
    'memberValue',
    'preimageHex',
    'digestHex',
    'sig',
    'subjectPrivHexDemoOnly',
  ]) {
    if (typeof vector[field] !== 'string') {
      failures.push({ fileName, message: `"${field}" must be a string` })
      return
    }
  }
  if (typeof vector.expiresAt !== 'number') {
    failures.push({ fileName, message: '"expiresAt" must be a number' })
    return
  }
  if (!isHexStringArray(vector.filterMemberKeysHex) || !vector.filterOpts) {
    failures.push({ fileName, message: '"filterMemberKeysHex" / "filterOpts" missing or malformed' })
    return
  }

  // The frozen demo private key must actually derive the frozen subjectPubHex
  // — otherwise the vector's sig would verify under a DIFFERENT key than the
  // one it claims to demonstrate, silently.
  assertionCount++
  const actualSubjectPubHex = bytesToHex(schnorr.getPublicKey(hexToBytes(vector.subjectPrivHexDemoOnly)))
  if (actualSubjectPubHex !== vector.subjectPubHex) {
    failures.push({
      fileName,
      message: `subjectPrivHexDemoOnly does not derive subjectPubHex: expected ${vector.subjectPubHex}, got ${actualSubjectPubHex}`,
    })
  }

  // Re-derive the canonical preimage + digest independently.
  assertionCount++
  const preimageStr = `tessera-cap:v2:${vector.serverId}:${vector.subjectPubHex}:${vector.memberValue}:${vector.expiresAt}`
  const actualPreimageHex = bytesToHex(utf8ToBytes(preimageStr))
  if (actualPreimageHex !== vector.preimageHex) {
    failures.push({
      fileName,
      message: `preimageHex MISMATCH: expected ${vector.preimageHex}, got ${actualPreimageHex}`,
    })
  }

  assertionCount++
  const actualDigestHex = bytesToHex(sha256(utf8ToBytes(preimageStr)))
  if (actualDigestHex !== vector.digestHex) {
    failures.push({
      fileName,
      message: `digestHex MISMATCH: expected ${vector.digestHex}, got ${actualDigestHex}`,
    })
  }

  // Re-verify the FROZEN sig — deterministic regardless of the (random) aux
  // data used when it was originally produced. Build the vector's own filter
  // and confirm testWithCapability accepts it.
  assertionCount++
  try {
    const filter = buildMembershipFilter(vector.filterMemberKeysHex, vector.filterOpts)
    const cap = {
      serverId: vector.serverId,
      subjectPubHex: vector.subjectPubHex,
      memberValue: vector.memberValue,
      expiresAt: vector.expiresAt,
      sig: vector.sig,
    }
    const result = testWithCapability(filter, cap, vector.expiresAt)
    if (result !== true) {
      failures.push({ fileName, message: `testWithCapability returned ${result}, expected true` })
    }
  } catch (error) {
    failures.push({ fileName, message: `testWithCapability threw: ${String(error)}` })
  }
}

// ---------------------------------------------------------------------------
// "signed-blob" vectors — a signed blob that must verify against a pinned key
// ---------------------------------------------------------------------------

function checkSignedBlobVector(fileName, vector) {
  if (typeof vector.pinnedPubkeyHex !== 'string' || typeof vector.blobHex !== 'string') {
    failures.push({ fileName, message: '"pinnedPubkeyHex" / "blobHex" must be hex strings' })
    return
  }
  if (typeof vector.context !== 'string' || typeof vector.mustRejectContext !== 'string') {
    failures.push({ fileName, message: '"context" / "mustRejectContext" must be strings' })
    return
  }
  if (typeof vector.epoch !== 'number') {
    failures.push({ fileName, message: '"epoch" must be a number' })
    return
  }
  if (typeof vector.digestHexIndependent !== 'string') {
    failures.push({ fileName, message: '"digestHexIndependent" must be a string' })
    return
  }
  if (typeof vector.signerPrivHexDemoOnly !== 'string') {
    failures.push({ fileName, message: '"signerPrivHexDemoOnly" must be a string' })
    return
  }
  const m = vector.membership
  if (!m || !isHexStringArray(m.present) || !isHexStringArray(m.absent)) {
    failures.push({ fileName, message: '"membership" must have present/absent hex-string arrays' })
    return
  }

  // The frozen demo private key must actually derive the frozen pinnedPubkeyHex
  // — otherwise the blob's signature would verify under a DIFFERENT key than
  // the one this vector claims to demonstrate, silently.
  assertionCount++
  const actualSignerPubHex = bytesToHex(schnorr.getPublicKey(hexToBytes(vector.signerPrivHexDemoOnly)))
  if (actualSignerPubHex !== vector.pinnedPubkeyHex) {
    failures.push({
      fileName,
      message: `signerPrivHexDemoOnly does not derive pinnedPubkeyHex: expected ${vector.pinnedPubkeyHex}, got ${actualSignerPubHex}`,
    })
  }

  const blobBytes = hexToBytes(vector.blobHex)

  assertionCount++
  let filter
  try {
    filter = verifyAndParseFilter(blobBytes, {
      pinnedPubkeyHex: vector.pinnedPubkeyHex,
      context: vector.context,
    })
  } catch (error) {
    failures.push({ fileName, message: `verifyAndParseFilter threw: ${String(error)}` })
    return
  }
  checkMembership(fileName, 'signed-blob', filter, m)

  // The parsed filter's SIGNED epoch must match the vector's frozen epoch.
  assertionCount++
  if (filter.epoch !== vector.epoch) {
    failures.push({
      fileName,
      message: `filter.epoch MISMATCH: expected ${vector.epoch}, got ${filter.epoch}`,
    })
  }

  // Re-derive the signing digest with node:crypto — NOT @noble/hashes (which
  // is used everywhere else in this file, including this package's own
  // sign.ts implementation) — so this actually IS the independent,
  // hand-checked-against-a-second-SHA-256-stack computation the vector's
  // `description` claims ("hand-checked via node:crypto"). Using @noble here
  // would only prove @noble agrees with itself. Mirrors sign.ts's
  // computeDigest, bound to `context` (PROTOCOL.md §4.1):
  //   sha256("tessera-kflt-sig:v1" || 0x00 || u32be(byteLen(ctx)) || utf8(ctx)
  //          || blob[0..64) || sha256(blob[128..end)))
  assertionCount++
  const ctxBytesNode = Buffer.from(vector.context, 'utf8')
  const lenBytesNode = Buffer.alloc(4)
  lenBytesNode.writeUInt32BE(ctxBytesNode.length, 0)
  const headNode = Buffer.from(blobBytes.subarray(0, 64))
  const fingerprintHashNode = createHash('sha256').update(blobBytes.subarray(128)).digest()
  const preimageNode = Buffer.concat([
    Buffer.from('tessera-kflt-sig:v1', 'utf8'),
    Buffer.from([0x00]),
    lenBytesNode,
    ctxBytesNode,
    headNode,
    fingerprintHashNode,
  ])
  const digest = createHash('sha256').update(preimageNode).digest('hex')
  if (digest !== vector.digestHexIndependent) {
    failures.push({
      fileName,
      message: `digestHexIndependent MISMATCH: expected ${vector.digestHexIndependent}, got ${digest}`,
    })
  }

  // Context-binding must-reject case: the SAME blob+sig, checked against a
  // DIFFERENT (but well-formed) context, MUST be rejected — this is the
  // cryptographic fix for cross-deployment substitution (spec §4.1/§4.3).
  assertionCount++
  try {
    verifyAndParseFilter(blobBytes, {
      pinnedPubkeyHex: vector.pinnedPubkeyHex,
      context: vector.mustRejectContext,
    })
    failures.push({
      fileName,
      message: `verifyAndParseFilter ACCEPTED the blob under mustRejectContext ${JSON.stringify(vector.mustRejectContext)} — context binding is broken`,
    })
  } catch {
    // Expected — a different context must fail.
  }
}

// ---------------------------------------------------------------------------
// "context-validation" vectors — SIGN_CONTEXT_*/VERIFY_CONTEXT_* codes and
// the context-mismatch security case (review follow-up; see the header note).
// ---------------------------------------------------------------------------

function checkContextValidationVector(fileName, vector) {
  for (const field of ['unsignedBlobHex', 'signedBlobHex', 'signerPrivHexDemoOnly', 'pinnedPubkeyHex', 'validContext']) {
    if (typeof vector[field] !== 'string') {
      failures.push({ fileName, message: `"${field}" must be a string` })
      return
    }
  }
  if (!Array.isArray(vector.cases) || vector.cases.length === 0) {
    failures.push({ fileName, message: '"cases" must be a non-empty array' })
    return
  }

  // The frozen demo private key must actually derive the frozen
  // pinnedPubkeyHex — same cross-check pattern as "signed-blob".
  assertionCount++
  const actualPub = bytesToHex(schnorr.getPublicKey(hexToBytes(vector.signerPrivHexDemoOnly)))
  if (actualPub !== vector.pinnedPubkeyHex) {
    failures.push({
      fileName,
      message: `signerPrivHexDemoOnly does not derive pinnedPubkeyHex: expected ${vector.pinnedPubkeyHex}, got ${actualPub}`,
    })
  }

  for (const c of vector.cases) {
    if (typeof c.side !== 'string' || typeof c.context !== 'string') {
      failures.push({ fileName, message: `case "${c.description}" missing "side"/"context"` })
      continue
    }

    if (c.side === 'sign') {
      assertionCount++
      if (typeof c.expectedErrorCode !== 'string') {
        failures.push({ fileName, message: `case "${c.description}" (side "sign") missing "expectedErrorCode"` })
        continue
      }
      let code
      try {
        signFilterBlob(hexToBytes(vector.unsignedBlobHex), vector.signerPrivHexDemoOnly, c.context)
      } catch (error) {
        code = error && error.code
      }
      if (code !== c.expectedErrorCode) {
        failures.push({
          fileName,
          message: `case "${c.description}": signFilterBlob threw code ${JSON.stringify(code)}, expected ${JSON.stringify(c.expectedErrorCode)}`,
        })
      }
    } else if (c.side === 'accept') {
      assertionCount++
      try {
        const blob = signFilterBlob(hexToBytes(vector.unsignedBlobHex), vector.signerPrivHexDemoOnly, c.context)
        verifyAndParseFilter(blob, { pinnedPubkeyHex: vector.pinnedPubkeyHex, context: c.context })
      } catch (error) {
        failures.push({
          fileName,
          message: `case "${c.description}": expected sign+verify round-trip to succeed, but threw: ${String(error)}`,
        })
      }
    } else if (c.side === 'verify') {
      assertionCount++
      if (typeof c.expectedErrorCode !== 'string') {
        failures.push({ fileName, message: `case "${c.description}" (side "verify") missing "expectedErrorCode"` })
        continue
      }
      let code
      try {
        verifyFilterBlob(hexToBytes(vector.signedBlobHex), c.context)
      } catch (error) {
        code = error && error.code
      }
      if (code !== c.expectedErrorCode) {
        failures.push({
          fileName,
          message: `case "${c.description}": verifyFilterBlob threw code ${JSON.stringify(code)}, expected ${JSON.stringify(c.expectedErrorCode)}`,
        })
      }
    } else if (c.side === 'verify-mismatch') {
      assertionCount++
      if (typeof c.expectedErrorCode !== 'string') {
        failures.push({ fileName, message: `case "${c.description}" (side "verify-mismatch") missing "expectedErrorCode"` })
        continue
      }
      let code
      try {
        verifyAndParseFilter(hexToBytes(vector.signedBlobHex), {
          pinnedPubkeyHex: vector.pinnedPubkeyHex,
          context: c.context,
        })
      } catch (error) {
        code = error && error.code
      }
      if (code !== c.expectedErrorCode) {
        failures.push({
          fileName,
          message: `case "${c.description}": verifyAndParseFilter threw code ${JSON.stringify(code)}, expected ${JSON.stringify(c.expectedErrorCode)}`,
        })
      }
    } else {
      failures.push({ fileName, message: `case "${c.description}" has unknown "side": ${JSON.stringify(c.side)}` })
    }
  }
}

// ---------------------------------------------------------------------------
// "reject" vectors — parseFilter MUST throw on every listed malformed blob
// ---------------------------------------------------------------------------

function checkRejectVector(fileName, vector) {
  if (!Array.isArray(vector.cases) || vector.cases.length === 0) {
    failures.push({ fileName, message: '"cases" must be a non-empty array' })
    return
  }
  for (const c of vector.cases) {
    assertionCount++
    if (typeof c.blobHex !== 'string') {
      failures.push({ fileName, message: `case missing blobHex: ${JSON.stringify(c)}` })
      continue
    }
    if (typeof c.expectedErrorCode !== 'string') {
      failures.push({
        fileName,
        message: `case "${c.description}" is missing "expectedErrorCode" (item 3: reject vectors assert on code, not message substrings)`,
      })
      continue
    }
    let threw = false
    let code
    let message = ''
    try {
      parseFilter(hexToBytes(c.blobHex))
    } catch (error) {
      threw = true
      code = error && error.code
      message = String(error && error.message)
    }
    if (!threw) {
      failures.push({
        fileName,
        message: `case "${c.description}" did NOT throw (expected parseFilter to reject it)`,
      })
      continue
    }
    // PRIMARY assertion: `code` (a TesseraErrorCode), not the message. Every
    // thrown error from this kit is a TesseraError (item 3) — a plain Error
    // with no `code` here is itself a failure (something in src/ regressed
    // to `throw new Error(...)`).
    if (code !== c.expectedErrorCode) {
      failures.push({
        fileName,
        message: `case "${c.description}" threw code ${JSON.stringify(code)}, expected ${JSON.stringify(c.expectedErrorCode)} (message was: ${message})`,
      })
    }
  }
}
