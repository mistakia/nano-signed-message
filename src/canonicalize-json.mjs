import { NanoSignedMessageError, ERROR_CODES } from './errors.mjs'

const LONE_SURROGATE_RE =
  /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/

const invalid_value = (message) =>
  new NanoSignedMessageError(ERROR_CODES.INVALID_VALUE, message)

const serialize_string = (value) => {
  if (LONE_SURROGATE_RE.test(value)) {
    throw invalid_value('string contains a lone surrogate')
  }
  return JSON.stringify(value)
}

const serialize_number = (value) => {
  if (!Number.isSafeInteger(value)) {
    throw invalid_value(`number ${value} is not a safe integer`)
  }
  // String(-0) is '0', matching RFC 8785
  return String(value)
}

const is_plain_object = (value) => {
  if (value === null || typeof value !== 'object') return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

// RFC 8785 JSON Canonicalization Scheme restricted to strings, safe integers,
// booleans, null, arrays and plain objects. Object keys sort by UTF-16 code
// units, which is the default comparison of Array.prototype.sort.
export default function canonicalize_json(value) {
  if (value === null) return 'null'

  switch (typeof value) {
    case 'string':
      return serialize_string(value)
    case 'number':
      return serialize_number(value)
    case 'boolean':
      return value ? 'true' : 'false'
    case 'object':
      break
    default:
      throw invalid_value(`unsupported value type ${typeof value}`)
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize_json(item)).join(',')}]`
  }

  if (!is_plain_object(value)) {
    throw invalid_value('unsupported object type')
  }

  const members = Object.keys(value)
    .sort()
    .map((key) => {
      if (value[key] === undefined) {
        throw invalid_value(`member ${key} is undefined`)
      }
      return `${serialize_string(key)}:${canonicalize_json(value[key])}`
    })
  return `{${members.join(',')}}`
}

// Parses a message that must already be in canonical form. Re-serializing and
// comparing rejects reordered keys, whitespace, alternative escapes, number
// forms and duplicate keys, since JSON.parse keeps only the last duplicate.
export function parse_canonical_json(text) {
  if (typeof text !== 'string') {
    throw new NanoSignedMessageError(
      ERROR_CODES.INVALID_JSON,
      'message must be a string'
    )
  }

  let value
  try {
    value = JSON.parse(text)
  } catch (error) {
    throw new NanoSignedMessageError(
      ERROR_CODES.INVALID_JSON,
      `message is not valid JSON: ${error.message}`
    )
  }

  let canonical
  try {
    canonical = canonicalize_json(value)
  } catch (error) {
    if (error instanceof NanoSignedMessageError) {
      throw new NanoSignedMessageError(ERROR_CODES.NON_CANONICAL, error.message)
    }
    throw error
  }

  if (canonical !== text) {
    throw new NanoSignedMessageError(
      ERROR_CODES.NON_CANONICAL,
      'message is not in canonical form'
    )
  }

  return value
}
