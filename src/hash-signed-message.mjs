import { blake2b } from '@noble/hashes/blake2.js'

import { concat_bytes } from './bytes.mjs'

export const SIGNED_MESSAGE_PREFIX = 'Nano Signed Message:\n'

const encoder = new TextEncoder()
const prefix_bytes = encoder.encode(SIGNED_MESSAGE_PREFIX)

export function get_signed_text(message) {
  return concat_bytes(prefix_bytes, encoder.encode(message))
}

// The message digest: blake2b-256 of the signed text. It identifies the
// signed content regardless of signing mode or signer.
export default function hash_signed_message(message) {
  return blake2b(get_signed_text(message), { dkLen: 32 })
}
