export class NanoSignedMessageError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'NanoSignedMessageError'
    this.code = code
  }
}

export const ERROR_CODES = Object.freeze({
  INVALID_WIRE_UNIT: 'invalid_wire_unit',
  INVALID_JSON: 'invalid_json',
  NON_CANONICAL: 'non_canonical',
  INVALID_VALUE: 'invalid_value',
  INVALID_PAYLOAD: 'invalid_payload',
  INVALID_ACCOUNT: 'invalid_account',
  WRONG_DOMAIN: 'wrong_domain',
  ACTION_NOT_ALLOWED: 'action_not_allowed',
  INVALID_SIGNATURE: 'invalid_signature',
  EXPIRED: 'expired'
})
