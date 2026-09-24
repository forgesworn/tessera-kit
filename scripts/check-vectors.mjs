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
//                                 parses the frozen signed blob
//                                 (`verifyAndParseFilter`); checks the parsed
//                                 `epoch` equals the vector's frozen `epoch`
//                                 and `membership.present`/`absent`; and
//                                 re-derives the signing digest and compares.
//   "reject"                     — asserts `parseFilter` THROWS on every
//                                 listed malformed blob, with a message
//                                 containing the case's
//                                 `expectedErrorSubstring`.
//
// Determinism precondition for a frozen "filter" vector: `opts` MUST pin
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

import {
  buildMembershipFilter,
  serializeFilter,
  testMembership,
  parseFilter,
  memberKey,
  deriveDecoys,
  verifyAndParseFilter,
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
  if (!isHexStringArray(vector.memberKeysHex) || vector.memberKeysHex.length === 0) {
    return '"memberKeysHex" must be a non-empty array of hex strings'
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
    let threw = false
    let message = ''
    try {
      memberKey(c.pubkeyHex, c.saltHex)
    } catch (error) {
      threw = true
      message = String(error && error.message)
    }
    if (!threw) {
      failures.push({
        fileName,
        message: `rejectCases case "${c.description}" did NOT throw (expected memberKey to reject it)`,
      })
      continue
    }
    if (
      typeof c.expectedErrorSubstring === 'string' &&
      !message.toLowerCase().includes(c.expectedErrorSubstring.toLowerCase())
    ) {
      failures.push({
        fileName,
        message: `rejectCases case "${c.description}" threw "${message}", expected to include "${c.expectedErrorSubstring}"`,
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
    filter = verifyAndParseFilter(blobBytes, { pinnedPubkeyHex: vector.pinnedPubkeyHex })
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

  // Re-derive the signing digest independently and compare (mirrors sign.ts's
  // computeDigest: sha256(blob[0..64) || sha256(blob[128..end)))).
  assertionCount++
  const head = blobBytes.subarray(0, 64)
  const fingerprintHash = sha256(blobBytes.subarray(128))
  const digest = bytesToHex(sha256(concatBytes(head, fingerprintHash)))
  if (digest !== vector.digestHexIndependent) {
    failures.push({
      fileName,
      message: `digestHexIndependent MISMATCH: expected ${vector.digestHexIndependent}, got ${digest}`,
    })
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
    let threw = false
    let message = ''
    try {
      parseFilter(hexToBytes(c.blobHex))
    } catch (error) {
      threw = true
      message = String(error && error.message)
    }
    if (!threw) {
      failures.push({
        fileName,
        message: `case "${c.description}" did NOT throw (expected parseFilter to reject it)`,
      })
      continue
    }
    if (
      typeof c.expectedErrorSubstring === 'string' &&
      !message.toLowerCase().includes(c.expectedErrorSubstring.toLowerCase())
    ) {
      failures.push({
        fileName,
        message: `case "${c.description}" threw "${message}", expected to include "${c.expectedErrorSubstring}"`,
      })
    }
  }
}
