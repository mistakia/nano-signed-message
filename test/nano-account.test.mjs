import assert from 'node:assert/strict'

import {
  decode_nano_account,
  encode_nano_account,
  get_public_key,
  ERROR_CODES
} from '../index.mjs'
import { bytes_to_hex, to_bytes } from '../src/bytes.mjs'

// From the Nano protocol documentation's key derivation example
const PRIVATE_KEY =
  '9f0e444c69f77a49bd0be89db92c38fe713e0963165cca12faf5712d7657120f'
const PUBLIC_KEY =
  'c008b814a7d269a1fa3c6528b19201a24d797912db9996ff02a1ff356e45552b'
const ACCOUNT =
  'nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7'

describe('nano account codec', () => {
  it('derives the documented public key and account', () => {
    const public_key = get_public_key(
      to_bytes(PRIVATE_KEY, { length: 32, name: 'k' })
    )
    assert.equal(bytes_to_hex(public_key), PUBLIC_KEY)
    assert.equal(encode_nano_account(public_key), ACCOUNT)
    assert.equal(bytes_to_hex(decode_nano_account(ACCOUNT)), PUBLIC_KEY)
    assert.equal(bytes_to_hex(get_public_key(PRIVATE_KEY)), PUBLIC_KEY)
  })

  it('encodes the burn account', () => {
    assert.equal(
      encode_nano_account(new Uint8Array(32)),
      'nano_1111111111111111111111111111111111111111111111111111hifc8npp'
    )
  })

  it('rejects a bad checksum, the xrb_ prefix, uppercase and bad length', () => {
    const bad_checksum = `${ACCOUNT.slice(0, -1)}9`
    for (const account of [
      bad_checksum,
      ACCOUNT.replace('nano_', 'xrb_'),
      ACCOUNT.toUpperCase(),
      ACCOUNT.slice(0, -1),
      `nano_4${ACCOUNT.slice(6)}`,
      null
    ]) {
      assert.throws(
        () => decode_nano_account(account),
        { code: ERROR_CODES.INVALID_ACCOUNT },
        String(account)
      )
    }
  })
})
