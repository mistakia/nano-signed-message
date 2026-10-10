import { blake2b } from '@noble/hashes/blake2.js'

import { to_bytes, concat_bytes, bytes_to_hex } from './bytes.mjs'
import { encode_nano_account } from './nano-account.mjs'

const STATE_BLOCK_PREAMBLE = new Uint8Array(32)
STATE_BLOCK_PREAMBLE[31] = 6
const ZERO_32 = new Uint8Array(32)
const ZERO_BALANCE = new Uint8Array(16)

// The dummy open state block a block-signing device (such as a Ledger) signs
// in block-envelope mode. Its representative field carries the message digest.
// With zero previous and zero link it can never settle on the network.
export default function create_block_envelope({ public_key, message_digest }) {
  const account_key = to_bytes(public_key, { length: 32, name: 'public_key' })
  const digest = to_bytes(message_digest, {
    length: 32,
    name: 'message_digest'
  })

  const hash = blake2b(
    concat_bytes(
      STATE_BLOCK_PREAMBLE,
      account_key,
      ZERO_32,
      digest,
      ZERO_BALANCE,
      ZERO_32
    ),
    { dkLen: 32 }
  )

  return {
    hash,
    block: {
      type: 'state',
      account: encode_nano_account(account_key),
      previous: bytes_to_hex(ZERO_32),
      representative: encode_nano_account(digest),
      balance: '0',
      link: bytes_to_hex(ZERO_32)
    }
  }
}
