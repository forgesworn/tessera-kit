import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js'

const HEX64 = /^[0-9a-f]{64}$/

/** The value to insert/test: pubkey (open) or sha256(salt || pubkey) (keyed). */
export function memberKey(pubkeyHex: string, saltHex?: string): string {
  const pk = pubkeyHex.toLowerCase()
  if (!HEX64.test(pk)) throw new Error('memberKey: pubkey must be 64 lowercase hex chars')
  if (saltHex === undefined) return pk
  const salt = saltHex.toLowerCase()
  if (!/^[0-9a-f]*$/.test(salt) || salt.length % 2 !== 0) throw new Error('memberKey: salt must be even-length hex')
  return bytesToHex(sha256(concatBytes(hexToBytes(salt), hexToBytes(pk))))
}
