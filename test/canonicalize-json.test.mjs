import assert from 'node:assert/strict'
import fs from 'node:fs'

import {
  canonicalize_json,
  parse_canonical_json,
  ERROR_CODES
} from '../index.mjs'

const jcs = JSON.parse(
  fs.readFileSync(new URL('../test-vectors/jcs.json', import.meta.url), 'utf8')
)

describe('canonicalize_json', () => {
  for (const { description, input, canonical } of jcs.canonicalize) {
    it(`serializes: ${description}`, () => {
      assert.equal(canonicalize_json(JSON.parse(input)), canonical)
    })
  }

  for (const { description, input } of jcs.refuse) {
    it(`refuses: ${description}`, () => {
      assert.throws(() => canonicalize_json(JSON.parse(input)), {
        code: ERROR_CODES.INVALID_VALUE
      })
    })
  }

  it('refuses values JSON cannot carry', () => {
    for (const value of [
      undefined,
      () => {},
      1n,
      NaN,
      Infinity,
      new Date(0),
      { a: undefined }
    ]) {
      assert.throws(() => canonicalize_json(value), {
        code: ERROR_CODES.INVALID_VALUE
      })
    }
  })
})

describe('parse_canonical_json', () => {
  it('returns the value of a canonical message', () => {
    assert.deepEqual(parse_canonical_json('{"a":[1,"b"],"c":null}'), {
      a: [1, 'b'],
      c: null
    })
  })

  it('rejects non-canonical forms', () => {
    for (const text of [
      '{"c":1,"a":2}',
      '{"a": 1}',
      '{"a":1.0}',
      '{"a":1,"a":1}',
      '"\\u0061"',
      ' 1'
    ]) {
      assert.throws(
        () => parse_canonical_json(text),
        { code: ERROR_CODES.NON_CANONICAL },
        text
      )
    }
  })

  it('rejects invalid JSON and non-strings', () => {
    assert.throws(() => parse_canonical_json('{'), {
      code: ERROR_CODES.INVALID_JSON
    })
    assert.throws(() => parse_canonical_json({}), {
      code: ERROR_CODES.INVALID_JSON
    })
  })
})
