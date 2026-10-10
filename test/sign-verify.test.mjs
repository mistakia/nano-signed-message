import assert from 'node:assert/strict'

import {
  encode_nano_account,
  get_public_key,
  sign_message,
  verify_signed_message,
  SIGNING_MODES,
  ERROR_CODES
} from '../index.mjs'
import { bytes_to_hex, to_bytes } from '../src/bytes.mjs'

const PRIVATE_KEY =
  '9f0e444c69f77a49bd0be89db92c38fe713e0963165cca12faf5712d7657120f'
const ACCOUNT = encode_nano_account(
  get_public_key(to_bytes(PRIVATE_KEY, { length: 32, name: 'k' }))
)
const NOW = 1760054400

const payload = (overrides = {}) => ({
  version: 1,
  domain: 'example.org',
  action: 'do_thing',
  account: ACCOUNT,
  issued_at: NOW,
  nonce: '0123456789abcdef0123456789abcdef',
  parameters: { value: 'x' },
  ...overrides
})

const verify = (wire, options = {}) =>
  verify_signed_message({
    ...wire,
    domain: 'example.org',
    actions: ['do_thing'],
    now: NOW,
    ...options
  })

describe('sign_message and verify_signed_message', () => {
  for (const mode of Object.values(SIGNING_MODES)) {
    it(`round-trips in ${mode} mode`, () => {
      const wire = sign_message({
        payload: payload(),
        private_key: PRIVATE_KEY,
        mode
      })
      const result = verify(wire)
      assert.equal(result.signing_mode, mode)
      assert.deepEqual(result.payload, payload())
      assert.equal(result.message_digest.length, 64)
    })
  }

  it('gives both modes the same message digest', () => {
    const direct = verify(
      sign_message({ payload: payload(), private_key: PRIVATE_KEY })
    )
    const block = verify(
      sign_message({
        payload: payload(),
        private_key: PRIVATE_KEY,
        mode: SIGNING_MODES.BLOCK
      })
    )
    assert.equal(direct.message_digest, block.message_digest)
  })

  it('accepts an uppercase signature', () => {
    const wire = sign_message({ payload: payload(), private_key: PRIVATE_KEY })
    assert.equal(
      verify({ ...wire, signature: wire.signature.toUpperCase() }).signing_mode,
      'direct'
    )
  })

  it('refuses to sign for an account the key does not control', () => {
    const other = encode_nano_account(new Uint8Array(32).fill(9))
    assert.throws(() =>
      sign_message({
        payload: payload({ account: other }),
        private_key: PRIVATE_KEY
      })
    )
  })

  it('refuses to sign an invalid payload', () => {
    assert.throws(
      () =>
        sign_message({
          payload: payload({ extra: 1 }),
          private_key: PRIVATE_KEY
        }),
      {
        code: ERROR_CODES.INVALID_PAYLOAD
      }
    )
    assert.throws(
      () =>
        sign_message({
          payload: payload({ parameters: { value: 0.5 } }),
          private_key: PRIVATE_KEY
        }),
      { code: ERROR_CODES.INVALID_VALUE }
    )
  })

  it('validates payload fields', () => {
    const cases = [
      { domain: 'Example.org' },
      { domain: 'example.org/' },
      { domain: '-example.org' },
      { action: 'DoThing' },
      { action: '1thing' },
      { issued_at: -1 },
      { issued_at: '1' },
      { expires_at: NOW },
      { nonce: 'abc' },
      { statement: 1 },
      { parameters: [] },
      { parameters: null },
      { version: '1' }
    ]
    for (const overrides of cases) {
      assert.throws(
        () =>
          sign_message({
            payload: payload(overrides),
            private_key: PRIVATE_KEY
          }),
        { code: ERROR_CODES.INVALID_PAYLOAD },
        JSON.stringify(overrides)
      )
    }
  })

  it('accepts a host with a port as domain', () => {
    const wire = sign_message({
      payload: payload({ domain: 'localhost:8080' }),
      private_key: PRIVATE_KEY
    })
    assert.equal(
      verify(wire, { domain: 'localhost:8080' }).payload.domain,
      'localhost:8080'
    )
  })

  it('enforces expires_at against now', () => {
    const wire = sign_message({
      payload: payload({ expires_at: NOW + 10 }),
      private_key: PRIVATE_KEY
    })
    assert.equal(verify(wire, { now: NOW + 9 }).payload.expires_at, NOW + 10)
    assert.throws(() => verify(wire, { now: NOW + 10 }), {
      code: ERROR_CODES.EXPIRED
    })
  })

  it('rejects a malformed wire unit', () => {
    const wire = sign_message({ payload: payload(), private_key: PRIVATE_KEY })
    assert.throws(
      () => verify({ ...wire, signature: wire.signature.slice(2) }),
      {
        code: ERROR_CODES.INVALID_WIRE_UNIT
      }
    )
    assert.throws(
      () => verify({ ...wire, message: JSON.parse(wire.message) }),
      {
        code: ERROR_CODES.INVALID_WIRE_UNIT
      }
    )
  })

  it('requires the caller to name a domain and actions', () => {
    const wire = sign_message({ payload: payload(), private_key: PRIVATE_KEY })
    assert.throws(
      () => verify_signed_message({ ...wire, actions: ['do_thing'] }),
      TypeError
    )
    assert.throws(
      () =>
        verify_signed_message({ ...wire, domain: 'example.org', actions: [] }),
      TypeError
    )
  })

  it('signs deterministically', () => {
    const first = sign_message({ payload: payload(), private_key: PRIVATE_KEY })
    const second = sign_message({
      payload: payload(),
      private_key: PRIVATE_KEY
    })
    assert.equal(first.signature, second.signature)
    assert.equal(
      bytes_to_hex(to_bytes(first.signature, { length: 64, name: 's' })),
      first.signature
    )
  })
})
