import { bytes_to_hex, to_bytes } from './bytes.mjs'
import { parse_canonical_json } from './canonicalize-json.mjs'
import create_block_envelope from './create-block-envelope.mjs'
import { verify, is_valid_public_key } from './ed25519-blake2b.mjs'
import { NanoSignedMessageError, ERROR_CODES } from './errors.mjs'
import hash_signed_message from './hash-signed-message.mjs'
import { decode_nano_account } from './nano-account.mjs'
import { SIGNING_MODES } from './sign-message.mjs'
import validate_payload from './validate-payload.mjs'

const SIGNATURE_RE = /^[0-9a-fA-F]{128}$/

const fail = (code, message) => {
  throw new NanoSignedMessageError(code, message)
}

// Verifies a wire unit against the domain the caller expects (one domain, or
// the fixed set of hosts it serves under) and the actions it allows. Returns the payload, signer public key, signing mode and message
// digest, or throws a NanoSignedMessageError with a code from ERROR_CODES.
export default function verify_signed_message({
  message,
  signature,
  domain,
  actions,
  now = Math.floor(Date.now() / 1000)
}) {
  const domains = Array.isArray(domain) ? domain : [domain]
  if (
    !domains.length ||
    !domains.every((item) => typeof item === 'string' && item)
  ) {
    throw new TypeError(
      'domain must be a string or a non-empty array of strings'
    )
  }
  if (!Array.isArray(actions) || !actions.length) {
    throw new TypeError('actions must be a non-empty array')
  }

  if (typeof message !== 'string') {
    fail(ERROR_CODES.INVALID_WIRE_UNIT, 'message must be a string')
  }
  if (typeof signature !== 'string' || !SIGNATURE_RE.test(signature)) {
    fail(ERROR_CODES.INVALID_WIRE_UNIT, 'signature must be 128 hex characters')
  }

  const payload = parse_canonical_json(message)
  validate_payload(payload)

  if (!domains.includes(payload.domain)) {
    fail(
      ERROR_CODES.WRONG_DOMAIN,
      `domain ${payload.domain} is not ${domains.join(' or ')}`
    )
  }
  if (!actions.includes(payload.action)) {
    fail(
      ERROR_CODES.ACTION_NOT_ALLOWED,
      `action ${payload.action} is not allowed`
    )
  }

  const public_key = decode_nano_account(payload.account)
  if (!is_valid_public_key(public_key)) {
    fail(ERROR_CODES.INVALID_ACCOUNT, 'account public key is not a valid point')
  }

  const message_digest = hash_signed_message(message)
  const signature_bytes = to_bytes(signature, { length: 64, name: 'signature' })

  let signing_mode
  if (
    verify({ signature: signature_bytes, message: message_digest, public_key })
  ) {
    signing_mode = SIGNING_MODES.DIRECT
  } else {
    const { hash } = create_block_envelope({ public_key, message_digest })
    if (verify({ signature: signature_bytes, message: hash, public_key })) {
      signing_mode = SIGNING_MODES.BLOCK
    } else {
      fail(
        ERROR_CODES.INVALID_SIGNATURE,
        'signature is not valid in either mode'
      )
    }
  }

  if (payload.expires_at !== undefined && now >= payload.expires_at) {
    fail(ERROR_CODES.EXPIRED, 'message has expired')
  }

  return {
    payload,
    public_key: bytes_to_hex(public_key),
    signing_mode,
    message_digest: bytes_to_hex(message_digest)
  }
}
