// Frozen golden-vector checker for @forgesworn/tessera-kit.
//
// This is the cross-implementation / future-Rust-port CONTRACT for the KFLT
// codec. For each `vectors/*.golden.*.json` it:
//   1. rebuilds the Binary Fuse 16 filter from `memberKeysHex` + `opts` using the
//      REAL built code in dist/,
//   2. `serializeFilter`s it and asserts the resulting hex EXACTLY equals the
//      frozen `serializedBlobHex` (byte-for-byte — any layout drift fails here),
//   3. asserts every `membership.present` key tests TRUE and every
//      `membership.absent` key tests FALSE.
//
// The vector is the UNSIGNED serializeFilter output (signer[32,64) + sig[64,128)
// regions are zero). Schnorr signing is intentionally NOT covered: BIP340 aux
// randomness makes signatures non-deterministic, so they cannot be frozen — the
// sign/verify round-trip has its own tests in src/sign.test.ts.
//
// Determinism precondition for a frozen vector: `opts` MUST pin padding to a
// reproducible value — either `padToBucket: false` (no decoys) or a fixed
// `decoySeedHex` (stable decoys). Random-decoy padding is not reproducible and is
// rejected below so a non-reproducible vector can never silently pass.
//
// Exits non-zero on ANY mismatch or malformation (strict — this gates releases).

import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { buildMembershipFilter, serializeFilter, testMembership } from '../dist/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

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

for (const fileName of files) {
  const fullPath = path.join(vectorsDir, fileName)
  let vector
  try {
    vector = JSON.parse(readFileSync(fullPath, 'utf8'))
  } catch (error) {
    failures.push({ fileName, message: `Failed to parse JSON: ${String(error)}` })
    continue
  }

  const shapeError = validateShape(vector)
  if (shapeError) {
    failures.push({ fileName, message: shapeError })
    continue
  }

  // Determinism guard: a frozen vector MUST pin padding. Reject random-decoy
  // padding (padToBucket on/defaulted with no decoySeedHex) — it isn't reproducible.
  const opts = vector.opts
  const padToBucket = opts.padToBucket ?? true
  if (padToBucket && opts.decoySeedHex === undefined) {
    failures.push({
      fileName,
      message:
        'Non-reproducible vector: padToBucket is on with no decoySeedHex (random decoys). ' +
        'Freeze with padToBucket:false OR a fixed decoySeedHex.',
    })
    continue
  }

  // 1+2. Rebuild from the frozen inputs and assert byte-exact serialization.
  let actualHex
  try {
    const filter = buildMembershipFilter(vector.memberKeysHex, opts)
    actualHex = bytesToHex(serializeFilter(filter))
  } catch (error) {
    failures.push({ fileName, message: `build/serialize threw: ${String(error)}` })
    continue
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

  // Re-parse the filter once for the membership assertions. (Rebuilding from
  // memberKeysHex is equivalent here; we reuse the just-built filter via a fresh
  // build to keep each assertion independent of serialization state.)
  let filterForMembership
  try {
    filterForMembership = buildMembershipFilter(vector.memberKeysHex, opts)
  } catch (error) {
    failures.push({ fileName, message: `rebuild for membership threw: ${String(error)}` })
    continue
  }

  // 3a. Every declared-present key MUST test true.
  for (const key of vector.membership.present) {
    assertionCount++
    if (testMembership(filterForMembership, key) !== true) {
      failures.push({
        fileName,
        message: `membership.present FAILED: "${key}" tested false (expected present).`,
      })
    }
  }

  // 3b. Every declared-absent key MUST test false.
  for (const key of vector.membership.absent) {
    assertionCount++
    if (testMembership(filterForMembership, key) !== false) {
      failures.push({
        fileName,
        message: `membership.absent FAILED: "${key}" tested true (expected absent).`,
      })
    }
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
      'layout breaks every other implementation of this codec.',
  )
  process.exit(1)
}

console.log(`[vectors] OK (${files.length} file(s), ${assertionCount} assertions).`)

/** Strict structural validation of a golden vector file. Returns an error string or null. */
function validateShape(vector) {
  if (!vector || typeof vector !== 'object' || Array.isArray(vector)) {
    return 'Vector file must be a JSON object'
  }
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
