import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'

import {
  canonicalize_json,
  create_block_envelope,
  decode_nano_account,
  encode_signed_message,
  get_signed_text,
  hash_signed_message,
  verify_signed_message,
  SIGNING_MODES,
  ERROR_CODES
} from '../index.mjs'
import { bytes_to_hex } from '../src/bytes.mjs'

const require = createRequire(import.meta.url)
const native = require('@trashman/ed25519-blake2b')

const read_vectors = (name) =>
  JSON.parse(
    fs.readFileSync(new URL(`../test-vectors/${name}`, import.meta.url), 'utf8')
  )
const positive = read_vectors('positive.json')
const negative = read_vectors('negative.json')

const REGISTERED_PROFILES = [
  'nano.community set_account_meta',
  'nano.community set_representative_meta',
  'nano.community set_block_meta',
  'nano.community link_key',
  'nano.community accept_link',
  'nano.community revoke_key',
  'nano.community register_username',
  'nostr bind_nostr_key',
  'nostr pledge',
  'base.example.org create_session'
]

const signed_hash = (vector) =>
  vector.signing_mode === SIGNING_MODES.DIRECT
    ? vector.message_digest
    : vector.block_envelope.hash

describe('positive test vectors', () => {
  it('cover every registered profile in both modes', () => {
    for (const profile of REGISTERED_PROFILES) {
      const modes = positive.vectors
        .filter((v) => `${v.payload.domain} ${v.payload.action}` === profile)
        .map((v) => v.signing_mode)
      assert.deepEqual(modes.sort(), ['block', 'direct'], profile)
    }
  })

  for (const vector of positive.vectors) {
    describe(vector.description, () => {
      it('reproduces the message, signed text, digest and envelope', () => {
        assert.equal(encode_signed_message(vector.payload), vector.message)
        assert.equal(
          bytes_to_hex(get_signed_text(vector.message)),
          vector.signed_text
        )
        const digest = hash_signed_message(vector.message)
        assert.equal(bytes_to_hex(digest), vector.message_digest)
        const envelope = create_block_envelope({
          public_key: vector.public_key,
          message_digest: digest
        })
        assert.deepEqual(
          { ...envelope.block, hash: bytes_to_hex(envelope.hash) },
          vector.block_envelope
        )
      })

      it('verifies with the library and reports the mode', () => {
        const result = verify_signed_message({
          message: vector.message,
          signature: vector.signature,
          ...vector.verify
        })
        assert.equal(result.signing_mode, vector.signing_mode)
        assert.equal(result.public_key, vector.public_key)
        assert.equal(result.message_digest, vector.message_digest)
        assert.deepEqual(result.payload, vector.payload)
      })

      it('verifies with the native library', () => {
        assert.equal(
          native.verify(
            Buffer.from(vector.signature, 'hex'),
            Buffer.from(signed_hash(vector), 'hex'),
            Buffer.from(vector.public_key, 'hex')
          ),
          true
        )
      })

      it('verifies a hedged native signature of the same payload', () => {
        const signature = native
          .sign(
            Buffer.from(signed_hash(vector), 'hex'),
            vector.private_key,
            vector.public_key
          )
          .toString('hex')
        assert.notEqual(signature, vector.signature)
        const result = verify_signed_message({
          message: vector.message,
          signature,
          ...vector.verify
        })
        assert.equal(result.signing_mode, vector.signing_mode)
        assert.equal(result.message_digest, vector.message_digest)
      })
    })
  }
})

describe('negative test vectors', () => {
  for (const vector of negative.vectors) {
    it(`rejects: ${vector.description}`, () => {
      assert.throws(
        () =>
          verify_signed_message({
            message: vector.message,
            signature: vector.signature,
            ...vector.verify
          }),
        { code: vector.error }
      )
    })
  }

  const encoding_vectors = negative.vectors.filter((v) => 'native_valid' in v)

  it('include the signature-encoding cases', () => {
    assert.equal(encoding_vectors.length, 4)
  })

  for (const vector of encoding_vectors) {
    it(`native verifier returns ${vector.native_valid}: ${vector.description}`, () => {
      const public_key = bytes_to_hex(
        decode_nano_account(JSON.parse(vector.message).account)
      )
      assert.equal(
        native.verify(
          Buffer.from(vector.signature, 'hex'),
          Buffer.from(hash_signed_message(vector.message)),
          Buffer.from(public_key, 'hex')
        ),
        vector.native_valid
      )
    })
  }
})

// Changing any signed field must invalidate the signature. The verifier is
// pointed at the mutated domain and action so only the signature can fail.
describe('mutation of every signed field', () => {
  const other_account = positive.keys.B.account

  const mutate_value = (value) => {
    if (typeof value === 'number') return value + 1
    if (typeof value === 'string') {
      if (/^[0-9a-f]+$/.test(value)) {
        return value.slice(0, -1) + (value.endsWith('0') ? '1' : '0')
      }
      return `${value}x`
    }
    if (Array.isArray(value)) return [...value, value.length ? value[0] : 'x']
    return { ...value, mutated: true }
  }

  const mutations = (payload) => {
    const result = []
    for (const field of Object.keys(payload)) {
      if (field === 'version' || field === 'parameters') continue
      let value
      if (field === 'account') {
        value =
          payload.account === other_account
            ? positive.keys.A.account
            : other_account
      } else if (field === 'domain') {
        value = `other.${payload.domain}`
      } else if (field === 'action') {
        value = `${payload.action}_other`
      } else {
        value = mutate_value(payload[field])
      }
      result.push({ field, payload: { ...payload, [field]: value } })
    }
    for (const key of Object.keys(payload.parameters)) {
      result.push({
        field: `parameters.${key}`,
        payload: {
          ...payload,
          parameters: {
            ...payload.parameters,
            [key]: mutate_value(payload.parameters[key])
          }
        }
      })
    }
    result.push({
      field: 'parameters (added member)',
      payload: { ...payload, parameters: { ...payload.parameters, added: 'x' } }
    })
    return result
  }

  for (const vector of positive.vectors) {
    it(`fails for every field: ${vector.description}`, () => {
      const cases = mutations(vector.payload)
      const expected_fields = [
        ...Object.keys(vector.payload).filter(
          (f) => f !== 'version' && f !== 'parameters'
        ),
        ...Object.keys(vector.payload.parameters).map((k) => `parameters.${k}`)
      ]
      for (const field of expected_fields) {
        assert.ok(
          cases.some((c) => c.field === field),
          `no mutation for ${field}`
        )
      }

      for (const { field, payload } of cases) {
        assert.throws(
          () =>
            verify_signed_message({
              message: canonicalize_json(payload),
              signature: vector.signature,
              domain: payload.domain,
              actions: [payload.action],
              now: vector.verify.now
            }),
          { code: ERROR_CODES.INVALID_SIGNATURE },
          field
        )
      }
    })
  }
})

describe('cross-implementation agreement on random payloads', () => {
  it('verifies 50 hedged native signatures in each mode', () => {
    const { private_key, public_key, account } = positive.keys.A
    for (let i = 0; i < 50; i++) {
      const message = encode_signed_message({
        version: 1,
        domain: 'example.org',
        action: 'random_check',
        account,
        issued_at: 1760054400 + i,
        nonce: crypto.randomBytes(16).toString('hex'),
        parameters: { value: crypto.randomBytes(12).toString('base64') }
      })
      const digest = hash_signed_message(message)
      for (const mode of Object.values(SIGNING_MODES)) {
        const hash =
          mode === SIGNING_MODES.DIRECT
            ? digest
            : create_block_envelope({ public_key, message_digest: digest }).hash
        const signature = native
          .sign(Buffer.from(hash), private_key, public_key)
          .toString('hex')
        const result = verify_signed_message({
          message,
          signature,
          domain: 'example.org',
          actions: ['random_check'],
          now: 1760054400
        })
        assert.equal(result.signing_mode, mode)
      }
    }
  })
})
