import { eddsa } from '@noble/curves/abstract/edwards.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { blake2b } from '@noble/hashes/blake2.js'

const blake2b_512 = (message) => blake2b(message, { dkLen: 64 })

const clamp = (bytes) => {
  bytes[0] &= 248
  bytes[31] &= 127
  bytes[31] |= 64
  return bytes
}

// Nano's ed25519-blake2b: RFC 8032 Ed25519 with BLAKE2b-512 in place of
// SHA-512. zip215: false rejects a non-canonical R or public key and S >= L,
// matching ed25519-donna, which nano-node uses.
const ed25519_blake2b = eddsa(ed25519.Point, blake2b_512, {
  adjustScalarBytes: clamp,
  zip215: false
})

export function get_public_key(private_key) {
  return ed25519_blake2b.getPublicKey(private_key)
}

export function sign(message, private_key) {
  return ed25519_blake2b.sign(message, private_key)
}

// Also rejects a public key of small order, for which anyone can forge.
export function verify({ signature, message, public_key }) {
  if (!is_valid_public_key(public_key)) return false
  try {
    return ed25519_blake2b.verify(signature, message, public_key, {
      zip215: false
    })
  } catch {
    return false
  }
}

export function is_valid_public_key(public_key) {
  try {
    const point = ed25519.Point.fromBytes(public_key, false)
    return !point.isSmallOrder()
  } catch {
    return false
  }
}
