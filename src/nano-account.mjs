import { blake2b } from '@noble/hashes/blake2.js'

import { to_bytes, concat_bytes, bytes_to_hex } from './bytes.mjs'
import { NanoSignedMessageError, ERROR_CODES } from './errors.mjs'

const ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'
const ACCOUNT_RE = /^nano_[13][13456789abcdefghijkmnopqrstuwxyz]{59}$/

const encode_base32 = (bytes) => {
  // bytes.length * 8 must be a multiple of 5
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  return output
}

const decode_base32 = (text) => {
  let bits = 0
  let value = 0
  const output = []
  for (const char of text) {
    value = (value << 5) | ALPHABET.indexOf(char)
    bits += 5
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Uint8Array.from(output)
}

const account_checksum = (public_key) =>
  blake2b(public_key, { dkLen: 5 }).reverse()

export function encode_nano_account(public_key) {
  const key = to_bytes(public_key, { length: 32, name: 'public_key' })
  // 4 zero bits pad the 256-bit key to 260 bits, 52 characters
  const padded = encode_base32(concat_bytes(new Uint8Array(3), key)).slice(4)
  return `nano_${padded}${encode_base32(account_checksum(key))}`
}

export function decode_nano_account(account) {
  if (typeof account !== 'string' || !ACCOUNT_RE.test(account)) {
    throw new NanoSignedMessageError(
      ERROR_CODES.INVALID_ACCOUNT,
      'account must be a nano_ address'
    )
  }

  const body = account.slice(5)
  const public_key = decode_base32(`1111${body.slice(0, 52)}`).slice(3)
  const checksum = decode_base32(body.slice(52))
  if (bytes_to_hex(account_checksum(public_key)) !== bytes_to_hex(checksum)) {
    throw new NanoSignedMessageError(
      ERROR_CODES.INVALID_ACCOUNT,
      'account checksum does not match'
    )
  }
  return public_key
}
