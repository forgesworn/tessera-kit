// Sync check: `TesseraErrorCode` (src/errors.ts) vs. PROTOCOL.md §9's error
// codes table. These two must list EXACTLY the same set of codes — a code
// added to the union without a doc row (or vice versa) is the "stable
// contract" (§9) silently drifting from the actual type, which is exactly
// what happened before this test existed (19 codes were added to the union
// in a follow-up pass without a matching §9 row, caught by manual review
// rather than a check). This test parses BOTH sources as text (no runtime
// reflection of a TypeScript union is possible) and diffs the two sets.

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const srcPath = fileURLToPath(new URL('./errors.ts', import.meta.url))
const protocolPath = fileURLToPath(new URL('../PROTOCOL.md', import.meta.url))

/** Extract every `TesseraErrorCode` union member from errors.ts's source
 *  text. Each member is written one per line, in the file's own style:
 *  `  | 'SOME_CODE'` (optionally followed by other content on later lines,
 *  but the code itself is always the first quoted token after `|`). Matches
 *  ONLY inside the `export type TesseraErrorCode = ... ` declaration, up to
 *  the blank line that ends it (before the `TesseraError` class doc comment)
 *  — so a quoted SCREAMING_SNAKE string appearing elsewhere in the file
 *  (there isn't one today, but this keeps the extraction honest) can't leak
 *  in. */
function extractUnionCodes(): string[] {
  const src = readFileSync(srcPath, 'utf8')
  const startMarker = 'export type TesseraErrorCode ='
  const startIdx = src.indexOf(startMarker)
  if (startIdx === -1) {
    throw new Error('protocol-sync: could not find "export type TesseraErrorCode =" in errors.ts')
  }
  // The union ends at the first line that is blank (a run of union member
  // lines, each starting with optional whitespace then `|`, terminates at
  // the next line that does NOT start that way).
  const rest = src.slice(startIdx + startMarker.length)
  const lines = rest.split('\n')
  const codes: string[] = []
  for (const line of lines) {
    const trimmed = line.trim()
    // The union ends at the FIRST blank line encountered AFTER at least one
    // member has been collected — the line immediately following the `=`
    // marker is itself blank (nothing follows `=` on that line), so a naive
    // "break on any blank line" would stop before ever reading a member.
    if (trimmed.length === 0) {
      if (codes.length > 0) break
      continue
    }
    if (trimmed.startsWith('//')) continue // a comment line between members
    const m = /^\|\s*'([A-Z][A-Z0-9_]*)'/.exec(trimmed)
    if (m) codes.push(m[1] as string)
    // A non-comment, non-union-member, non-blank line (there shouldn't be
    // one before the union ends) would silently fall through here — the
    // count-mismatch assertion below still catches a truncated extraction.
  }
  return codes
}

/** Extract every code listed in PROTOCOL.md §9's "| Code | Thrown when |"
 *  table. Scoped to the text from the `## 9. Error codes` heading to the end
 *  of the file (§9 is the last section) so a backtick-wrapped
 *  SCREAMING_SNAKE constant elsewhere in the document (e.g. `KFLT_MAGIC`)
 *  can never be picked up. Rows in §9's OTHER table (`| Prefix | Owner |
 *  Meaning |`, whose first column is a prefix like `` `PARSE_*` ``) are
 *  excluded automatically: the trailing `*` means the cell content never
 *  fully matches `[A-Z][A-Z0-9_]*` up to the closing backtick. */
function extractDocCodes(): string[] {
  const doc = readFileSync(protocolPath, 'utf8')
  const headingMarker = '## 9. Error codes'
  const startIdx = doc.indexOf(headingMarker)
  if (startIdx === -1) {
    throw new Error('protocol-sync: could not find "## 9. Error codes" heading in PROTOCOL.md')
  }
  const section = doc.slice(startIdx)
  const lines = section.split('\n')
  const codes: string[] = []
  for (const line of lines) {
    const m = /^\|\s*`([A-Z][A-Z0-9_]*)`\s*\|/.exec(line)
    if (m) codes.push(m[1] as string)
  }
  return codes
}

describe('PROTOCOL.md §9 error-codes table stays in sync with TesseraErrorCode', () => {
  const unionCodes = extractUnionCodes()
  const docCodes = extractDocCodes()

  it('extraction actually found codes in both sources (sanity — a parser regression must not silently pass as "0 == 0")', () => {
    expect(unionCodes.length).toBeGreaterThan(50)
    expect(docCodes.length).toBeGreaterThan(50)
  })

  it('every code in the TesseraErrorCode union has a row in the §9 table', () => {
    const docSet = new Set(docCodes)
    const missing = unionCodes.filter((c) => !docSet.has(c))
    expect(missing, `codes in the union but MISSING from PROTOCOL.md §9: ${missing.join(', ')}`).toEqual([])
  })

  it('every code in the §9 table exists in the TesseraErrorCode union', () => {
    const unionSet = new Set(unionCodes)
    const extra = docCodes.filter((c) => !unionSet.has(c))
    expect(extra, `codes in PROTOCOL.md §9 but NOT in the TesseraErrorCode union (stale/renamed?): ${extra.join(', ')}`).toEqual([])
  })

  it('neither list has an internal duplicate (a doubled row/union member would hide a real gap)', () => {
    const dupUnion = unionCodes.filter((c, i) => unionCodes.indexOf(c) !== i)
    const dupDoc = docCodes.filter((c, i) => docCodes.indexOf(c) !== i)
    expect(dupUnion, `duplicate union members: ${dupUnion.join(', ')}`).toEqual([])
    expect(dupDoc, `duplicate §9 rows: ${dupDoc.join(', ')}`).toEqual([])
  })
})
