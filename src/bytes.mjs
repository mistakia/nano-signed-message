import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

export { bytesToHex as bytes_to_hex }

export function to_bytes(value, { length, name }) {
  let bytes
  if (typeof value === 'string') {
    if (!/^[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) {
      throw new TypeError(`${name} must be hex`)
    }
    bytes = hexToBytes(value.toLowerCase())
  } else if (value instanceof Uint8Array) {
    bytes = value
  } else {
    throw new TypeError(`${name} must be a Uint8Array or hex string`)
  }

  if (length !== undefined && bytes.length !== length) {
    throw new TypeError(`${name} must be ${length} bytes`)
  }
  return bytes
}

export function concat_bytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((sum, a) => sum + a.length, 0))
  let offset = 0
  for (const array of arrays) {
    result.set(array, offset)
    offset += array.length
  }
  return result
}
