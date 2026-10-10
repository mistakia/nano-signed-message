import { to_bytes, bytes_to_hex } from './bytes.mjs'
import create_block_envelope from './create-block-envelope.mjs'
import { get_public_key, sign } from './ed25519-blake2b.mjs'
import encode_signed_message from './encode-signed-message.mjs'
import hash_signed_message from './hash-signed-message.mjs'
import { decode_nano_account } from './nano-account.mjs'

export const SIGNING_MODES = Object.freeze({
  DIRECT: 'direct',
  BLOCK: 'block'
})

// Signs a payload with a Nano private key and returns the wire unit.
export default function sign_message({
  payload,
  private_key,
  mode = SIGNING_MODES.DIRECT
}) {
  const key = to_bytes(private_key, { length: 32, name: 'private_key' })
  const message = encode_signed_message(payload)

  const public_key = get_public_key(key)
  if (
    bytes_to_hex(decode_nano_account(payload.account)) !==
    bytes_to_hex(public_key)
  ) {
    throw new Error('payload.account does not match the private key')
  }

  const message_digest = hash_signed_message(message)
  let signed_hash
  if (mode === SIGNING_MODES.DIRECT) {
    signed_hash = message_digest
  } else if (mode === SIGNING_MODES.BLOCK) {
    signed_hash = create_block_envelope({ public_key, message_digest }).hash
  } else {
    throw new Error(`unknown signing mode ${mode}`)
  }

  return {
    message,
    signature: bytes_to_hex(sign(signed_hash, key))
  }
}
