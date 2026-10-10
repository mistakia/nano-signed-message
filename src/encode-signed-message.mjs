import canonicalize_json from './canonicalize-json.mjs'
import validate_payload from './validate-payload.mjs'

// Validates the payload and returns the canonical message string.
export default function encode_signed_message(payload) {
  validate_payload(payload)
  return canonicalize_json(payload)
}
