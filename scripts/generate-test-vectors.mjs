// Generates test-vectors/{positive,negative}.json from fixed test keys. The
// library signs deterministically, so a rerun reproduces the files exactly.
//
//   node scripts/generate-test-vectors.mjs

import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

import { blake2b } from '@noble/hashes/blake2.js'

import {
  canonicalize_json,
  create_block_envelope,
  encode_nano_account,
  get_public_key,
  get_signed_text,
  hash_signed_message,
  sign_message,
  SIGNING_MODES
} from '../index.mjs'
import { bytes_to_hex, to_bytes } from '../src/bytes.mjs'
import { sign } from '../src/ed25519-blake2b.mjs'
import { ERROR_CODES } from '../src/errors.mjs'

const require = createRequire(import.meta.url)
const native = require('@trashman/ed25519-blake2b')

const vectors_directory = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'test-vectors'
)

// Key A is the private key from the Nano protocol documentation's test vector.
// Key B is blake2b-256 of the ASCII string "nano-signed-message test key B".
const KEY_A = '9f0e444c69f77a49bd0be89db92c38fe713e0963165cca12faf5712d7657120f'
const KEY_B = bytes_to_hex(
  blake2b(new TextEncoder().encode('nano-signed-message test key B'), {
    dkLen: 32
  })
)

const key_info = (private_key) => {
  const public_key = bytes_to_hex(
    get_public_key(to_bytes(private_key, { length: 32, name: 'private_key' }))
  )
  return { private_key, public_key, account: encode_nano_account(public_key) }
}
const A = key_info(KEY_A)
const B = key_info(KEY_B)

const ISSUED_AT = 1760054400 // 2025-10-10T00:00:00Z
const NONCE = '6e616e6f2d7369676e65642d6d736721'
const NOSTR_PUBLIC_KEY =
  '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e'
const ISSUE_EVENT_ID =
  'd1b3f5a7c9e1d3b5f7a9c1e3d5b7f9a1c3e5d7b9f1a3c5e7d9b1f3a5c7e9d1b3'
const REFERENCE_BLOCK_HASH =
  '991cf190094c00f0b68e2e5f75f6bee95a2e0bd93ceaa4a6734db9f19b728948'

// NIP-19 npub: bech32 (not bech32m) of the 32-byte key with prefix "npub"
const encode_npub = (hex) => {
  const charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
  const polymod = (values) => {
    const generators = [
      0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    ]
    let checksum = 1
    for (const value of values) {
      const top = checksum >> 25
      checksum = ((checksum & 0x1ffffff) << 5) ^ value
      for (let i = 0; i < 5; i++) {
        if ((top >> i) & 1) checksum ^= generators[i]
      }
    }
    return checksum
  }
  const hrp = 'npub'
  const data = []
  let accumulator = 0
  let bits = 0
  for (const byte of to_bytes(hex, { length: 32, name: 'nostr key' })) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      data.push((accumulator >> bits) & 31)
    }
  }
  if (bits) data.push((accumulator << (5 - bits)) & 31)
  const expanded = [
    ...[...hrp].map((c) => c.charCodeAt(0) >> 5),
    0,
    ...[...hrp].map((c) => c.charCodeAt(0) & 31)
  ]
  const checksum = polymod([...expanded, ...data, 0, 0, 0, 0, 0, 0]) ^ 1
  const checksum_words = [5, 4, 3, 2, 1, 0].map(
    (i) => (checksum >> (5 * i)) & 31
  )
  return `${hrp}1${[...data, ...checksum_words].map((d) => charset[d]).join('')}`
}

const base_payload = ({ domain, action, signer, parameters, ...rest }) => ({
  version: 1,
  domain,
  action,
  account: signer.account,
  issued_at: ISSUED_AT,
  parameters,
  ...rest
})

const PROFILE_CASES = [
  {
    name: 'nano.community set_account_meta',
    signer: A,
    allowed_actions: [
      'set_account_meta',
      'set_representative_meta',
      'set_block_meta'
    ],
    payload: base_payload({
      domain: 'nano.community',
      action: 'set_account_meta',
      signer: A,
      nonce: NONCE,
      parameters: {
        content: { alias: 'Example Account' },
        references: [],
        tags: []
      }
    })
  },
  {
    name: 'nano.community set_representative_meta, non-ASCII text and an escaped newline',
    signer: A,
    allowed_actions: [
      'set_account_meta',
      'set_representative_meta',
      'set_block_meta'
    ],
    payload: base_payload({
      domain: 'nano.community',
      action: 'set_representative_meta',
      signer: A,
      nonce: NONCE,
      parameters: {
        content: {
          alias: 'Nœud — représentant',
          cpu_cores: 8,
          description: 'Line one\nLine two "quoted" 🦦',
          website: 'https://example.org'
        },
        references: [],
        tags: ['representative', 'europe']
      }
    })
  },
  {
    name: 'nano.community set_block_meta with references and an expiry',
    signer: A,
    allowed_actions: [
      'set_account_meta',
      'set_representative_meta',
      'set_block_meta'
    ],
    payload: base_payload({
      domain: 'nano.community',
      action: 'set_block_meta',
      signer: A,
      nonce: NONCE,
      expires_at: ISSUED_AT + 600,
      parameters: {
        content: { note: 'exchange deposit' },
        references: [REFERENCE_BLOCK_HASH],
        tags: ['exchange']
      }
    })
  },
  {
    name: 'nano.community link_key, signed by the account',
    signer: A,
    allowed_actions: ['link_key'],
    payload: base_payload({
      domain: 'nano.community',
      action: 'link_key',
      signer: A,
      nonce: NONCE,
      parameters: { linked_public_key: B.public_key }
    })
  },
  {
    name: 'nano.community accept_link, signed by the linked key',
    signer: B,
    allowed_actions: ['accept_link'],
    payload: base_payload({
      domain: 'nano.community',
      action: 'accept_link',
      signer: B,
      nonce: NONCE,
      parameters: { linked_account: A.account }
    })
  },
  {
    name: 'nano.community revoke_key, signed by the linked key',
    signer: B,
    allowed_actions: ['revoke_key'],
    payload: base_payload({
      domain: 'nano.community',
      action: 'revoke_key',
      signer: B,
      nonce: NONCE,
      parameters: { linked_public_key: B.public_key }
    })
  },
  {
    name: 'nano.community register_username',
    signer: A,
    allowed_actions: ['register_username'],
    payload: base_payload({
      domain: 'nano.community',
      action: 'register_username',
      signer: A,
      nonce: NONCE,
      parameters: { username: 'example_user' }
    })
  },
  {
    name: 'nostr bind_nostr_key',
    signer: A,
    allowed_actions: ['bind_nostr_key'],
    nostr_public_key: NOSTR_PUBLIC_KEY,
    payload: base_payload({
      domain: 'nostr',
      action: 'bind_nostr_key',
      signer: A,
      statement: `Verifying that I control the following Nostr public key: ${encode_npub(NOSTR_PUBLIC_KEY)}`,
      parameters: {}
    })
  },
  {
    name: 'nostr pledge',
    signer: A,
    allowed_actions: ['pledge'],
    payload: base_payload({
      domain: 'nostr',
      action: 'pledge',
      signer: A,
      parameters: {
        issue_event_id: ISSUE_EVENT_ID,
        amount_raw: '1000000000000000000000000000000',
        nostr_public_key: NOSTR_PUBLIC_KEY
      }
    })
  },
  {
    name: 'base create_session',
    signer: A,
    allowed_actions: ['create_session'],
    payload: base_payload({
      domain: 'base.example.org',
      action: 'create_session',
      signer: A,
      nonce: NONCE,
      parameters: {}
    })
  },
  {
    name: 'base claim_invite',
    signer: B,
    allowed_actions: ['claim_invite'],
    payload: base_payload({
      domain: 'base.example.org',
      action: 'claim_invite',
      signer: B,
      nonce: NONCE,
      parameters: { invite_id: '1b4e28ba-2fa1-41d2-883f-0016d3cca427' }
    })
  },
  {
    name: 'base claim_recovery',
    signer: B,
    allowed_actions: ['claim_recovery'],
    payload: base_payload({
      domain: 'base.example.org',
      action: 'claim_recovery',
      signer: B,
      nonce: NONCE,
      parameters: { recovery_id: '6f1c2d3e4a5b4c6d8e7f001122334455' }
    })
  }
]

const build_positive = (
  { name, signer, payload, allowed_actions, nostr_public_key },
  mode
) => {
  const { message, signature } = sign_message({
    payload,
    private_key: signer.private_key,
    mode
  })
  const digest = hash_signed_message(message)
  const envelope = create_block_envelope({
    public_key: signer.public_key,
    message_digest: digest
  })
  return {
    description: `${name}, ${mode} mode`,
    signing_mode: mode,
    private_key: signer.private_key,
    public_key: signer.public_key,
    account: signer.account,
    ...(nostr_public_key && { nostr_public_key }),
    payload,
    message,
    signed_text: bytes_to_hex(get_signed_text(message)),
    message_digest: bytes_to_hex(digest),
    block_envelope: { ...envelope.block, hash: bytes_to_hex(envelope.hash) },
    signature,
    verify: {
      domain: payload.domain,
      actions: allowed_actions,
      now: ISSUED_AT
    }
  }
}

const positive = []
for (const profile_case of PROFILE_CASES) {
  for (const mode of [SIGNING_MODES.DIRECT, SIGNING_MODES.BLOCK]) {
    positive.push(build_positive(profile_case, mode))
  }
}

// Signs arbitrary text the way a signer would, so a vector's rejection comes
// from the rule it names and not from a bad signature.
const sign_text = (message, private_key = KEY_A) =>
  bytes_to_hex(
    sign(
      hash_signed_message(message),
      to_bytes(private_key, { length: 32, name: 'private_key' })
    )
  )

const link_case = PROFILE_CASES.find((c) => c.payload.action === 'link_key')
const link_payload = link_case.payload
const link_canonical = canonicalize_json(link_payload)
const link_signature = sign_text(link_canonical)
const link_verify = {
  domain: 'nano.community',
  actions: ['link_key'],
  now: ISSUED_AT
}

const negative = []
const add_negative = ({
  description,
  rule,
  message,
  signature,
  verify = link_verify,
  error,
  native_valid
}) => {
  negative.push({
    description,
    rule,
    message,
    signature,
    verify,
    error,
    ...(native_valid !== undefined && { native_valid })
  })
}

// Message form
{
  const reordered = `{${Object.keys(link_payload)
    .reverse()
    .map(
      (key) => `${JSON.stringify(key)}:${canonicalize_json(link_payload[key])}`
    )
    .join(',')}}`
  add_negative({
    description: 'top-level keys in reverse order, validly signed',
    rule: 'canonical-serialization',
    message: reordered,
    signature: sign_text(reordered),
    error: ERROR_CODES.NON_CANONICAL
  })

  const spaced = JSON.stringify(JSON.parse(link_canonical), null, 2)
  add_negative({
    description: 'extra whitespace, validly signed',
    rule: 'canonical-serialization',
    message: spaced,
    signature: sign_text(spaced),
    error: ERROR_CODES.NON_CANONICAL
  })

  const duplicate = link_canonical.replace(
    '"action":"link_key",',
    '"action":"revoke_key","action":"link_key",'
  )
  add_negative({
    description: 'duplicate action member, validly signed',
    rule: 'canonical-serialization',
    message: duplicate,
    signature: sign_text(duplicate),
    error: ERROR_CODES.NON_CANONICAL
  })

  const surrogate = canonicalize_json({
    ...link_payload,
    statement: 'x'
  }).replace('"statement":"x"', '"statement":"\\ud800"')
  add_negative({
    description: 'statement holding a lone surrogate, validly signed',
    rule: 'value-rules',
    message: surrogate,
    signature: sign_text(surrogate),
    error: ERROR_CODES.NON_CANONICAL
  })

  const escaped = link_canonical.replace('"link_key"', '"\\u006cink_key"')
  add_negative({
    description: 'an unnecessary \\u escape, validly signed',
    rule: 'canonical-serialization',
    message: escaped,
    signature: sign_text(escaped),
    error: ERROR_CODES.NON_CANONICAL
  })
}

// Payload
{
  const meta = PROFILE_CASES[0].payload
  const meta_verify = {
    domain: 'nano.community',
    actions: PROFILE_CASES[0].allowed_actions,
    now: ISSUED_AT
  }

  const wrong_account = canonicalize_json({
    ...link_payload,
    account: B.account
  })
  add_negative({
    description: 'account names key B but key A signed',
    rule: 'account-binds-key',
    message: wrong_account,
    signature: sign_text(wrong_account, KEY_A),
    error: ERROR_CODES.INVALID_SIGNATURE
  })

  const float_text = canonicalize_json(meta).replace(
    '"content":{"alias":"Example Account"}',
    '"content":{"alias":"Example Account","cpu_cores":1.5}'
  )
  add_negative({
    description: 'a float inside parameters, validly signed',
    rule: 'value-rules',
    message: float_text,
    signature: sign_text(float_text),
    verify: meta_verify,
    error: ERROR_CODES.NON_CANONICAL
  })

  const unsafe_integer = canonicalize_json({ ...meta, issued_at: 1 }).replace(
    '"issued_at":1',
    '"issued_at":9007199254740993'
  )
  add_negative({
    description: 'an integer beyond 2^53 - 1, validly signed',
    rule: 'value-rules',
    message: unsafe_integer,
    signature: sign_text(unsafe_integer),
    verify: meta_verify,
    error: ERROR_CODES.NON_CANONICAL
  })

  const unknown_field = canonicalize_json({ ...link_payload, extra: true })
  add_negative({
    description: 'an unknown top-level field, validly signed',
    rule: 'payload',
    message: unknown_field,
    signature: sign_text(unknown_field),
    error: ERROR_CODES.INVALID_PAYLOAD
  })

  const null_nonce = canonicalize_json({ ...link_payload, nonce: null })
  add_negative({
    description: 'an optional field present as null, validly signed',
    rule: 'payload',
    message: null_nonce,
    signature: sign_text(null_nonce),
    error: ERROR_CODES.INVALID_PAYLOAD
  })

  const uppercase_nonce = canonicalize_json({
    ...link_payload,
    nonce: NONCE.toUpperCase()
  })
  add_negative({
    description: 'an uppercase nonce, validly signed',
    rule: 'field-syntax',
    message: uppercase_nonce,
    signature: sign_text(uppercase_nonce),
    error: ERROR_CODES.INVALID_PAYLOAD
  })

  const version_two = canonicalize_json({ ...link_payload, version: 2 })
  add_negative({
    description: 'version 2, validly signed',
    rule: 'payload',
    message: version_two,
    signature: sign_text(version_two),
    error: ERROR_CODES.INVALID_PAYLOAD
  })

  add_negative({
    description: 'linked_public_key changed after signing',
    rule: 'signature',
    message: canonicalize_json({
      ...link_payload,
      parameters: { linked_public_key: A.public_key }
    }),
    signature: link_signature,
    error: ERROR_CODES.INVALID_SIGNATURE
  })

  const other_domain = canonicalize_json({
    ...link_payload,
    domain: 'evil.example'
  })
  add_negative({
    description: 'signed for another domain',
    rule: 'domain',
    message: other_domain,
    signature: sign_text(other_domain),
    error: ERROR_CODES.WRONG_DOMAIN
  })

  add_negative({
    description:
      'a link_key message offered where only message actions are allowed',
    rule: 'action',
    message: link_canonical,
    signature: link_signature,
    verify: meta_verify,
    error: ERROR_CODES.ACTION_NOT_ALLOWED
  })

  // A claim is not a sign-in: the claimant's key must not open a session
  // through a claim it signed.
  const claim_payload = PROFILE_CASES.find(
    (c) => c.payload.action === 'claim_invite'
  ).payload
  const claim_canonical = canonicalize_json(claim_payload)
  add_negative({
    description:
      'a claim_invite message offered where only create_session is allowed',
    rule: 'action',
    message: claim_canonical,
    signature: sign_text(claim_canonical, KEY_B),
    verify: {
      domain: 'base.example.org',
      actions: ['create_session'],
      now: ISSUED_AT
    },
    error: ERROR_CODES.ACTION_NOT_ALLOWED
  })

  const expiring = canonicalize_json({
    ...link_payload,
    expires_at: ISSUED_AT + 60
  })
  add_negative({
    description: 'verified at expires_at',
    rule: 'expiry',
    message: expiring,
    signature: sign_text(expiring),
    verify: { ...link_verify, now: ISSUED_AT + 60 },
    error: ERROR_CODES.EXPIRED
  })
}

// Signature encoding
{
  const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n
  const FIELD = (1n << 255n) - 19n
  const to_le = (n) =>
    to_bytes(n.toString(16).padStart(64, '0'), {
      length: 32,
      name: 'n'
    }).reverse()
  const from_le = (bytes) =>
    BigInt(`0x${bytes_to_hex(Uint8Array.from(bytes).reverse())}`)

  const signature_bytes = to_bytes(link_signature, {
    length: 64,
    name: 'signature'
  })
  const link_digest = hash_signed_message(link_canonical)

  const s_plus_order = new Uint8Array(64)
  s_plus_order.set(signature_bytes.subarray(0, 32))
  s_plus_order.set(to_le(from_le(signature_bytes.subarray(32)) + ORDER), 32)
  add_negative({
    description: 'a valid signature with S replaced by S + L',
    rule: 'strict-verification',
    message: link_canonical,
    signature: bytes_to_hex(s_plus_order),
    error: ERROR_CODES.INVALID_SIGNATURE,
    native_valid: native.verify(
      Buffer.from(s_plus_order),
      Buffer.from(link_digest),
      Buffer.from(A.public_key, 'hex')
    )
  })

  // y = 3 is a curve point; y + p is its non-canonical encoding
  const non_canonical_r = new Uint8Array(64)
  non_canonical_r.set(to_le(3n + FIELD))
  non_canonical_r.set(signature_bytes.subarray(32), 32)
  add_negative({
    description: 'R replaced by a non-canonical point encoding',
    rule: 'strict-verification',
    message: link_canonical,
    signature: bytes_to_hex(non_canonical_r),
    error: ERROR_CODES.INVALID_SIGNATURE,
    native_valid: native.verify(
      Buffer.from(non_canonical_r),
      Buffer.from(link_digest),
      Buffer.from(A.public_key, 'hex')
    )
  })

  const non_canonical_key = to_le(3n + FIELD)
  const non_canonical_key_message = canonicalize_json({
    ...link_payload,
    account: encode_nano_account(non_canonical_key)
  })
  add_negative({
    description: 'account encoding a non-canonical public key',
    rule: 'strict-verification',
    message: non_canonical_key_message,
    signature: link_signature,
    error: ERROR_CODES.INVALID_ACCOUNT,
    native_valid: native.verify(
      Buffer.from(link_signature, 'hex'),
      Buffer.from(hash_signed_message(non_canonical_key_message)),
      Buffer.from(non_canonical_key)
    )
  })

  // Forge for the burn account (public key zero, a point of order 4) with
  // S = 0 and R a small-order point, searching nonces until one verifies
  // under the native verifier. No private key is involved.
  const burn_key = new Uint8Array(32)
  const small_order_r = [to_le(1n), new Uint8Array(32), to_le(FIELD - 1n)]
  let forged
  for (let counter = 0; !forged; counter++) {
    const nonce = counter.toString(16).padStart(32, '0')
    const message = canonicalize_json({
      ...link_payload,
      account: encode_nano_account(burn_key),
      nonce
    })
    const digest = Buffer.from(hash_signed_message(message))
    for (const r of small_order_r) {
      const signature = Buffer.concat([Buffer.from(r), Buffer.alloc(32)])
      if (native.verify(signature, digest, Buffer.from(burn_key))) {
        forged = { message, signature: bytes_to_hex(signature) }
        break
      }
    }
  }
  add_negative({
    description:
      'a forged signature for the burn account, whose public key has small order',
    rule: 'strict-verification',
    message: forged.message,
    signature: forged.signature,
    error: ERROR_CODES.INVALID_ACCOUNT,
    native_valid: true
  })
}

const write = (name, data) =>
  fs.writeFileSync(
    path.join(vectors_directory, name),
    `${JSON.stringify(data, null, 2)}\n`
  )

write('positive.json', {
  description:
    'Every conforming verifier MUST accept each vector, verifying at verify.now with verify.domain and verify.actions.',
  keys: { A, B },
  vectors: positive
})
write('negative.json', {
  description:
    'Every conforming verifier MUST reject each vector. error is the reference library code; native_valid is what the native ed25519-donna verifier returns for the bare signature check.',
  vectors: negative
})

console.log(`positive: ${positive.length}, negative: ${negative.length}`)
