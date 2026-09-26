// Ad-hoc benchmark (item 12 of the gap survey: "no coverage, fuzzing,
// property framework, or benchmarks"). NOT run in CI or `npm test` — it is a
// plain Node script, invoked explicitly via `npm run bench`, which measures
// timing on THIS machine and prints it; there is nothing here to assert
// against (unlike the frozen `vectors/` correctness contract), so it has no
// place in an automated pass/fail run.
//
// Imports from `./dist` (the BUILT package, same as a real consumer would),
// not `./src` — `npm run bench` runs `npm run build` first (package.json),
// so this always measures the compiled output, matching gaps.md's own
// `scratchpad/bench.mjs`-style methodology (see PROTOCOL.md §11's reference
// to it).
//
// Measures, per size n ∈ {1_000, 100_000, 1_000_000}:
//   - build:            buildMembershipFilter (padToBucket:false, so timing
//                        isn't skewed by decoy generation — a separate concern)
//   - blob size:        serializeFilter's output length
//   - test:             testMembership, averaged over a sample of real members
//   - testMany:         the SAME sample, in one call, for comparison
//   - parse:            parseFilter on the serialized blob
//   - sign+verify:      signFilterBlob / verifyFilterBlob, timed once each
//                        (they are O(blob size) — one sha256 pass over the
//                        fingerprint array plus one Schnorr op — not
//                        per-member, so a single timing is representative)

import {
  buildMembershipFilter,
  testMembership,
  testMany,
  serializeFilter,
  parseFilter,
} from '../dist/index.js'
import { signFilterBlob, verifyFilterBlob } from '../dist/sign.js'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'

const SIGNER_PRIV = bytesToHex(randomBytes(32))
const CONTEXT = 'bench:context'
const SAMPLE_SIZE = 10_000

function fmtMs(ms) {
  return `${ms.toFixed(ms < 10 ? 2 : 0)} ms`
}

for (const n of [1_000, 100_000, 1_000_000]) {
  const keys = Array.from({ length: n }, () => bytesToHex(randomBytes(32)))
  const sample = keys.slice(0, Math.min(SAMPLE_SIZE, n))

  let t0 = performance.now()
  const f = buildMembershipFilter(keys, { epoch: 1, padToBucket: false })
  const buildMs = performance.now() - t0

  t0 = performance.now()
  const blob = serializeFilter(f)
  const serializeMs = performance.now() - t0

  t0 = performance.now()
  for (const k of sample) testMembership(f, k)
  const testLoopMs = performance.now() - t0

  t0 = performance.now()
  testMany(f, sample)
  const testManyMs = performance.now() - t0

  t0 = performance.now()
  const parsed = parseFilter(blob)
  const parseMs = performance.now() - t0

  t0 = performance.now()
  const signed = signFilterBlob(blob.slice(), SIGNER_PRIV, CONTEXT)
  const signMs = performance.now() - t0

  t0 = performance.now()
  const { ok } = verifyFilterBlob(signed, CONTEXT)
  const verifyMs = performance.now() - t0

  if (!ok) throw new Error('bench: sanity check failed — signature did not verify')
  if (parsed.type !== 1) throw new Error('bench: sanity check failed — parse produced the wrong type')

  console.log(`n=${n}`)
  console.log(`  build          ${fmtMs(buildMs)}`)
  console.log(`  serialize      ${fmtMs(serializeMs)} (blob ${(blob.length / 1024).toFixed(1)} KB)`)
  console.log(`  test (loop)    ${fmtMs(testLoopMs)} over ${sample.length} values (${((testLoopMs / sample.length) * 1000).toFixed(2)} us/value)`)
  console.log(`  testMany       ${fmtMs(testManyMs)} over ${sample.length} values (${((testManyMs / sample.length) * 1000).toFixed(2)} us/value)`)
  console.log(`  parse          ${fmtMs(parseMs)}`)
  console.log(`  sign           ${fmtMs(signMs)}`)
  console.log(`  verify         ${fmtMs(verifyMs)}`)
}
