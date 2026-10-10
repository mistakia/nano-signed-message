import { decode_nano_account } from './nano-account.mjs'
import { NanoSignedMessageError, ERROR_CODES } from './errors.mjs'

export const FORMAT_VERSION = 1

const DOMAIN_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$/
const ACTION_RE = /^[a-z][a-z0-9_]{0,63}$/
const NONCE_RE = /^[0-9a-f]{32}$/

const REQUIRED_FIELDS = [
  'version',
  'domain',
  'action',
  'account',
  'issued_at',
  'parameters'
]
const OPTIONAL_FIELDS = ['expires_at', 'nonce', 'statement']
const KNOWN_FIELDS = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS])

const invalid = (message) =>
  new NanoSignedMessageError(ERROR_CODES.INVALID_PAYLOAD, message)

const is_timestamp = (value) => Number.isSafeInteger(value) && value >= 0

const is_object = (value) =>
  value !== null && typeof value === 'object' && !Array.isArray(value)

// Validates the top-level payload schema. Value rules (integers, well-formed
// strings) are enforced by canonicalize_json, which every path runs.
export default function validate_payload(payload) {
  if (!is_object(payload)) {
    throw invalid('payload must be an object')
  }

  for (const key of Object.keys(payload)) {
    if (!KNOWN_FIELDS.has(key)) throw invalid(`unknown field ${key}`)
  }
  for (const key of REQUIRED_FIELDS) {
    if (payload[key] === undefined) throw invalid(`missing field ${key}`)
  }
  for (const key of OPTIONAL_FIELDS) {
    if (key in payload && payload[key] == null) {
      throw invalid(`optional field ${key} must be absent, not null`)
    }
  }

  const {
    version,
    domain,
    action,
    account,
    issued_at,
    expires_at,
    nonce,
    statement,
    parameters
  } = payload

  if (version !== FORMAT_VERSION) {
    throw invalid(`version must be ${FORMAT_VERSION}`)
  }
  if (
    typeof domain !== 'string' ||
    domain.length > 253 ||
    !DOMAIN_RE.test(domain)
  ) {
    throw invalid('invalid domain')
  }
  if (typeof action !== 'string' || !ACTION_RE.test(action)) {
    throw invalid('invalid action')
  }
  decode_nano_account(account)
  if (!is_timestamp(issued_at)) {
    throw invalid('issued_at must be a non-negative integer')
  }
  if (
    expires_at !== undefined &&
    (!is_timestamp(expires_at) || expires_at <= issued_at)
  ) {
    throw invalid('expires_at must be an integer greater than issued_at')
  }
  if (
    nonce !== undefined &&
    (typeof nonce !== 'string' || !NONCE_RE.test(nonce))
  ) {
    throw invalid('nonce must be 32 lowercase hex characters')
  }
  if (statement !== undefined && typeof statement !== 'string') {
    throw invalid('statement must be a string')
  }
  if (!is_object(parameters)) {
    throw invalid('parameters must be an object')
  }

  return payload
}
