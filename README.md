# nano-signed-message

Canonical signed messages for Nano accounts. A payload naming its domain, action, account and parameters is serialized as RFC 8785 canonical JSON, prefixed with `Nano Signed Message:\n`, hashed with blake2b-256 and signed with ed25519-blake2b, either directly or inside a dummy open block that a Ledger can sign.

The format is defined in [SPECIFICATION.md](SPECIFICATION.md). Test vectors for every registered profile are in [test-vectors/](test-vectors/).

Pure JavaScript over `@noble/curves` and `@noble/hashes`. Runs in node and in browsers.

## Install

```bash
npm install nano-signed-message
```

## Sign

```js
import { sign_message } from 'nano-signed-message'

const { message, signature } = sign_message({
  private_key, // 32 bytes, Uint8Array or hex
  payload: {
    version: 1,
    domain: 'nano.community',
    action: 'set_account_meta',
    account:
      'nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7',
    issued_at: Math.floor(Date.now() / 1000),
    nonce: '6e616e6f2d7369676e65642d6d736721',
    parameters: { content: { alias: 'Example' }, references: [], tags: [] }
  }
})
```

To sign with a block-signing device, compute the envelope and have the device sign `block`:

```js
import {
  encode_signed_message,
  hash_signed_message,
  create_block_envelope
} from 'nano-signed-message'

const message = encode_signed_message(payload)
const { block, hash } = create_block_envelope({
  public_key,
  message_digest: hash_signed_message(message)
})
```

## Verify

```js
import {
  verify_signed_message,
  NanoSignedMessageError
} from 'nano-signed-message'

const { payload, public_key, signing_mode, message_digest } =
  verify_signed_message({
    message,
    signature,
    domain: 'nano.community',
    actions: ['set_account_meta']
  })
```

`domain` is one string, or an array of the fixed hosts a service answers under. `verify_signed_message` checks the canonical form, the payload schema, the signature in both modes, the domain, the allowed actions and `expires_at`. It throws a `NanoSignedMessageError` whose `code` is one of `ERROR_CODES`. The caller applies its own time window and nonce tracking, and deduplicates by `message_digest`, never by signature.

## Develop

```bash
yarn test
yarn generate:test-vectors
```

## License

MIT
