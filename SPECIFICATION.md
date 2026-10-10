# Nano Signed Message — Specification, version 1

This document defines how a Nano account signs a message that is not a block, and how a verifier checks it. One format serves every application, so a signature always binds its content, its action, the signing key and the application it was made for.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as described in RFC 2119.

## Contents

- [Overview](#overview)
- [Payload](#payload)
- [Canonical serialization](#canonical-serialization)
- [Signed text and digest](#signed-text-and-digest)
- [Signing modes](#signing-modes)
- [Signature encoding and strict verification](#signature-encoding-and-strict-verification)
- [Wire unit](#wire-unit)
- [Verification algorithm](#verification-algorithm)
- [Verifier policy](#verifier-policy)
- [Registered profiles](#registered-profiles)
- [Registering a profile](#registering-a-profile)
- [Separation from other signatures](#separation-from-other-signatures)
- [Security considerations](#security-considerations)
- [Test vectors](#test-vectors)
- [Rationale and prior art](#rationale-and-prior-art)

## Overview

1. The signer builds a **payload**: a JSON object naming the domain the signature is for, the action it authorizes, the signing account, when it was issued, and the action's parameters.
2. The payload is serialized with RFC 8785 canonical JSON. The result is the **message**.
3. The **signed text** is the UTF-8 encoding of `"Nano Signed Message:\n"` followed by the message.
4. The **message digest** is blake2b-256 of the signed text.
5. The signer signs with ed25519-blake2b, the Nano block-signing algorithm, in one of two modes:
   - **direct**: over the 32-byte message digest
   - **block envelope**: over the hash of a dummy open state block whose representative field is the message digest, which a Ledger can sign today
6. The signer sends the **wire unit** `{"message": ..., "signature": ...}`. The verifier checks the canonical form, the payload schema, the signature in either mode, the expected domain and the allowed actions, then applies its own policy.

## Payload

The payload is a JSON object. A payload with any top-level member not listed here MUST be rejected.

| Field        | Required | Type    | Meaning                                                                                                               |
| ------------ | -------- | ------- | --------------------------------------------------------------------------------------------------------------------- |
| `version`    | yes      | integer | Format version. MUST be `1`.                                                                                          |
| `domain`     | yes      | string  | Who the signature is for: the DNS host of the verifying service, or a registered protocol identifier such as `nostr`. |
| `action`     | yes      | string  | What the signature authorizes, in lowercase snake_case.                                                               |
| `account`    | yes      | string  | The signer's `nano_` address. Its public key is the verifying key.                                                    |
| `issued_at`  | yes      | integer | Unix time in seconds when the signer made the payload.                                                                |
| `expires_at` | no       | integer | Unix time in seconds after which the signature authorizes nothing. MUST be greater than `issued_at`.                  |
| `nonce`      | no       | string  | 32 lowercase hex characters (128 bits), unique per signature. A profile may require it.                               |
| `statement`  | no       | string  | Human-readable text the signer agrees to. Its meaning is defined by the profile.                                      |
| `parameters` | yes      | object  | The action's arguments, defined by the profile. MAY be empty (`{}`).                                                  |

An optional field that does not apply is **absent**. It MUST NOT be present as `null`.

### Field syntax

- **`domain`** is 1 to 253 characters. It is a lowercase DNS name, optionally followed by `:` and a port, or a registered single-label protocol identifier. Each dot-separated label is 1 to 63 characters of `a-z`, `0-9` and `-`, and does not begin or end with `-`. Pattern: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$`.
- **`action`** is 1 to 64 characters matching `^[a-z][a-z0-9_]*$`.
- **`account`** is a `nano_` address: `nano_` followed by 60 characters of the Nano base32 alphabet `13456789abcdefghijkmnopqrstuwxyz`. The first 52 characters encode 4 zero bits and the 32-byte public key. The last 8 encode the 5-byte blake2b-40 checksum of the public key, byte-reversed. The `xrb_` prefix and uppercase letters MUST be rejected.
- **`issued_at`** and **`expires_at`** are integers from `0` to `2^53 − 1`.
- **`nonce`** matches `^[0-9a-f]{32}$`.

### Value rules

These apply to every value in the payload, including inside `parameters`.

- Allowed values are strings, integers, `true`, `false`, `null` (inside `parameters` only), arrays and objects.
- Numbers MUST be integers within ±(2^53 − 1). A number with a fractional part or an exponent that does not serialize as an integer MUST be rejected.
- Amounts in raw MUST be decimal strings, because a raw amount exceeds 2^53.
- Hex values defined by this specification or its profiles (nonces, public keys, block hashes, event ids) MUST be lowercase.
- Strings MUST be well-formed Unicode. A string containing a lone surrogate MUST be rejected.
- Strings are signed exactly as given. No Unicode normalization is applied by the signer or the verifier.

## Canonical serialization

The message is the payload serialized with the JSON Canonicalization Scheme (JCS), RFC 8785. For the value set above, that means:

- No whitespace between tokens.
- Object members sorted by their names compared as arrays of UTF-16 code units.
- Strings serialized as ECMAScript `JSON.stringify` serializes them: `"` and `\` escaped, control characters below U+0020 escaped as `\b`, `\t`, `\n`, `\f`, `\r` or `\u00xx` with lowercase hex, and every other character emitted literally.
- Integers serialized as their shortest decimal form, with no leading `+`, no leading zeros, no exponent, and `0` for negative zero.

A verifier MUST reject a message that is not already in canonical form, meaning re-serializing the parsed payload does not reproduce the message exactly. This rejects reordered keys, extra whitespace, alternative escapes and non-integer number forms. A verifier MUST reject a message with a duplicate object member name, at any depth, and a message that decodes to a string containing a lone surrogate. A parser that silently keeps the last duplicate does not meet this requirement on its own; comparing the re-serialization with the input does, because the re-serialization drops the duplicate.

## Signed text and digest

```
signed_text    = UTF-8("Nano Signed Message:\n") || UTF-8(message)
message_digest = blake2b-256(signed_text)
```

The prefix is the 21 bytes `4e 61 6e 6f 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a`. blake2b-256 is BLAKE2b with a 32-byte output and no key.

The message digest identifies the signed content. Two signatures over the same payload have the same digest, whatever the signing mode or signer implementation.

## Signing modes

The signature algorithm is ed25519-blake2b, the algorithm Nano uses for blocks: Ed25519 as in RFC 8032 with SHA-512 replaced by BLAKE2b-512 everywhere, both in deriving the secret scalar from the 32-byte private key and in computing the challenge. The Nano private key is the Ed25519 secret key.

A verifier MUST accept a signature that is valid in either mode, and SHOULD report which mode it was. The payload carries no mode field, so the mode is not signed and cannot be forged into a different meaning: both modes commit to the same digest.

### Direct mode

The signature is over the 32-byte message digest:

```
signature = ed25519_blake2b_sign(private_key, message_digest)
```

Any wallet or library that signs a 32-byte hash can produce it.

### Block-envelope mode

The signature is over the hash of a dummy open state block:

| Block field    | Bytes | Value                   |
| -------------- | ----- | ----------------------- |
| preamble       | 32    | 31 zero bytes then `06` |
| account        | 32    | the signer's public key |
| previous       | 32    | zero                    |
| representative | 32    | the message digest      |
| balance        | 16    | zero                    |
| link           | 32    | zero                    |

```
envelope_hash = blake2b-256(preamble || account || previous || message_digest || balance || link)
signature     = ed25519_blake2b_sign(private_key, envelope_hash)
```

As a state block, the envelope is `{"type": "state", "account": <signer's nano_ address>, "previous": "0" × 64, "representative": <nano_ address of the message digest>, "balance": "0", "link": "0" × 64}`. A hardware wallet that signs state blocks, such as the Ledger Nano app, signs it as an ordinary open block.

The envelope cannot settle on the network. An open block with a zero link has no source to receive, so the node treats it as a gap and never confirms it.

## Signature encoding and strict verification

- A signature is 64 bytes, `R || S`, encoded as 128 hex characters. Signers SHOULD emit lowercase. Verifiers MUST accept either case.
- Verification is strict. A verifier MUST reject:
  - an `R` that is not the canonical encoding of a curve point
  - an `S` that is not less than the group order L = 2^252 + 27742317777372353535851937790883648493
  - a public key that is not the canonical encoding of a curve point
  - a public key of small order, one of the 8 points in the torsion subgroup
- The last rule matters because any party can forge a signature for a small-order public key. The burn account `nano_1111111111111111111111111111111111111111111111111111hifc8npp`, public key zero, is one of them.
- The reference library pins `zip215: false` in `@noble/curves` for the encoding rules and checks the public key's order itself.
- These rules are stricter than the native ed25519-donna verifier that nano-node uses. The native verifier rejects a non-canonical public key, but it accepts `S ≥ L` and accepts forged signatures for small-order public keys. A verifier built on it MUST add the `S < L` and small-order checks before calling it. The test vectors record the native result for each signature-encoding case.

### Signatures are not identities

ed25519-blake2b signatures need not be deterministic. The widely used native signer mixes random bytes into its nonce, so signing the same digest twice gives two different valid signatures, and the block-envelope mode gives a third. A consumer MUST NOT use a signature to identify or deduplicate content. It uses the message digest instead.

## Wire unit

A signed message travels as:

```json
{ "message": "<the canonical message>", "signature": "<128 hex characters>" }
```

The message is carried as a string, not as a nested object, so its exact bytes survive any transport that re-serializes JSON. A consumer that stores a signed message stores the message string exactly as received.

A profile MAY define a more compact encoding when the verifier can rebuild the payload from context. The nostr profiles do this; see [Nostr proof encoding](#nostr-proof-encoding).

## Verification algorithm

Given a wire unit, the domain the verifier expects, the set of actions it allows, and the current time, a verifier performs these steps in order. Any failure rejects the message.

1. Check that `message` is a string and `signature` is 128 hex characters.
2. Parse `message` as JSON. Reject a parse error, a duplicate member name, or a lone surrogate.
3. Re-serialize the parsed value with JCS. Reject if the result is not identical to `message`.
4. Validate the payload against [Payload](#payload): required fields present, no unknown top-level fields, field syntax, value rules, `version` equal to `1`, `expires_at` greater than `issued_at` when present.
5. Reject if `domain` is not the expected domain. The verifier compares exact strings.
6. Reject if `action` is not in the allowed set.
7. Decode `account` to the public key, checking its checksum. Reject a small-order or non-canonical key.
8. Compute the signed text and the message digest.
9. Verify the signature over the message digest (direct mode). If that fails, compute the envelope hash for this public key and digest and verify the signature over it (block-envelope mode). Reject if neither verifies.
10. Reject if `expires_at` is present and the current time is at or after it.
11. Return the payload, the public key, the signing mode and the message digest.

The verifier then applies its profile policy: the time window, nonce tracking, and parameter validation.

## Verifier policy

A profile states its policy. These rules apply to every profile.

- **Time window.** A profile with a window checks it in both directions: `|now − issued_at| ≤ window`. A one-sided check accepts future-dated messages that outlive the nonce record kept for them.
- **Nonce retention.** A verifier that requires a nonce MUST remember each accepted nonce, or each accepted message digest, for at least twice the window, and MUST reject a repeat. Keying the record by message digest works with any signing mode, because a re-signed payload has the same digest.
- **Deduplication.** A verifier that stores messages SHOULD make the message digest unique. It MUST NOT deduplicate by signature.
- **Parameters.** The verifier MUST validate `parameters` against the profile and MUST take every acted-on value from the verified payload, never from elsewhere in the request.
- **Message size.** A verifier SHOULD cap the message length. 64 KiB is enough for every registered profile.

## Registered profiles

A profile is a `(domain, action)` pair with its parameters and verifier policy.

| Domain                   | Action                    | Signed by                     | Parameters                                         | Policy                           |
| ------------------------ | ------------------------- | ----------------------------- | -------------------------------------------------- | -------------------------------- |
| `nano.community`         | `set_account_meta`        | the account or its linked key | `content`, `references`, `tags`                    | nonce required; 10-minute window |
| `nano.community`         | `set_representative_meta` | the account or its linked key | `content`, `references`, `tags`                    | nonce required; 10-minute window |
| `nano.community`         | `set_block_meta`          | the account or its linked key | `content`, `references`, `tags`                    | nonce required; 10-minute window |
| `nano.community`         | `link_key`                | the account                   | `linked_public_key`                                | nonce required; 10-minute window |
| `nano.community`         | `accept_link`             | the linked key                | `linked_account`                                   | nonce required; 10-minute window |
| `nano.community`         | `revoke_key`              | the account or the linked key | `linked_public_key`                                | nonce required; 10-minute window |
| `nano.community`         | `register_username`       | the account or key            | `username`                                         | nonce required; 10-minute window |
| `nostr`                  | `bind_nostr_key`          | the account                   | none (`{}`); `statement` required                  | no nonce; no window              |
| `nostr`                  | `pledge`                  | the account                   | `issue_event_id`, `amount_raw`, `nostr_public_key` | no nonce; no window              |
| the base instance's host | `create_session`          | the user's wallet key         | none (`{}`)                                        | nonce required; 5-minute window  |

### nano.community

- **Message actions** (`set_account_meta`, `set_representative_meta`, `set_block_meta`) take:
  - `content`: an object holding the metadata fields to set. The nano.community API documents the fields per action.
  - `references`: an array of 64-character lowercase hex block hashes. MAY be empty.
  - `tags`: an array of strings. MAY be empty.
- **Linking a key takes both keys' consent.** The link request carries two wire units:
  - `link_key`, signed by the account, with `parameters.linked_public_key` the 64-character lowercase hex key being linked
  - `accept_link`, signed by the linked key, with `parameters.linked_account` the account's `nano_` address
  - The verifier checks that `linked_public_key` is the `accept_link` signer's key and that `linked_account` is the `link_key` signer's account. Without the second signature, an account could claim a key it does not control.
- **Signing with a linked key.** `account` is the linked key's own `nano_` address. The verifier resolves the account it acts for from its record of links.
- **`revoke_key`** takes `linked_public_key`, the key being revoked, and is accepted from that key or from the account it is linked to.
- **`register_username`** takes `username`, the exact username being registered.

### nostr

The nostr profiles have no nonce and no window, because the signature is a durable claim published in a nostr event rather than a one-time request. The npub and event fields bind each signature to one nostr key and one event.

- **`bind_nostr_key`** binds a Nano account to a nostr key, as a NIP-39 external identity in a kind 10011 event.
  - `parameters` is `{}`.
  - `statement` is `Verifying that I control the following Nostr public key: <npub>`, where `<npub>` is the NIP-19 bech32 encoding of the event's `pubkey`.
- **`pledge`** commits a Nano account to a bounty on a task-board issue.
  - `issue_event_id`: the 64-character lowercase hex id of the issue event.
  - `amount_raw`: the pledged amount in raw, as a decimal string with no leading zeros.
  - `nostr_public_key`: the 64-character lowercase hex `pubkey` of the pledge event's author.

#### Nostr proof encoding

A nostr event carries a compact proof, `<issued_at>:<signature>`, instead of the wire unit. For example, a binding is the tag `["i", "nano:<account>", "<issued_at>:<signature>"]`.

The verifier rebuilds the payload exactly:

- `version` 1
- `domain` `nostr` and the profile's `action`
- `account` from the tag, which MUST be a `nano_` address
- `issued_at` from the proof, a decimal integer with no leading zeros
- `parameters` as the profile states, `{}` for the binding and the three pledge fields from the event for the pledge
- `statement` only where the profile defines one
- every other optional field absent

It then runs the [verification algorithm](#verification-algorithm) on the rebuilt message and the signature. Republishing a replaceable event does not need a new Nano signature. The bare `<issued_at>:<signature>` form means format version 1, and a later version gets a distinct proof prefix. The tag name for pledges is defined by the task-board protocol.

### base

- **`create_session`** signs a user into a base instance with the user's wallet key.
  - `domain` is the instance's public host as a browser reports it in `location.host`, for example `base.example.org`, including a non-default port. A sign-in captured on one instance cannot replay on another.
  - `parameters` is `{}`.
  - The verifier requires a nonce and `|now − issued_at| ≤ 300` seconds, and keeps nonces for at least 600 seconds.

## Registering a profile

A new application registers its profiles by adding them to this document.

- **Domain.** Use the DNS host of the verifying service. A protocol with no single host, such as nostr, registers a single-label identifier, which this document then reserves.
- **Action.** Name what is authorized, not the endpoint that receives it. One action authorizes one kind of effect.
- **Parameters.** List every parameter, its type and its syntax under the [value rules](#value-rules). A verifier must be able to reject a payload whose parameters do not match.
- **Policy.** State whether a nonce is required, the time window if any, and who may sign.
- **Vectors.** Add positive and negative test vectors for the profile.

## Separation from other signatures

A signature made under this format cannot be replayed as a signature of anything else a Nano key signs, and the reverse holds too.

- **Blocks.** A direct-mode digest and a real block hash come from different preimages: one begins with the 21-byte text prefix `N…`, the other with the block preamble `00…06`. They match only through a blake2b-256 collision. A block-envelope signature is a block signature by design, over a block that cannot settle.
- **Raw JSON hashes.** JSON never begins with `N`, so the prefix separates this format from any scheme that signs the blake2b hash of bare JSON, such as base's version-0 sign-in.
- **Binary token preimages.** base's signed capabilities (`sigcap` prefix), share tokens (a fixed 53-byte preimage) and upload grants (`upload-grant-v1` prefix) never begin with `Nano Signed Message:`.
- **nanomemotools.** It signs `"Nano Signed Message:\n" ‖ message ‖ block hash`, so its signed text ends in a hex block hash, while this format's ends in `}`. The two cannot produce the same signed text.
- **Ledger nonce signing.** The Ledger Nano app signs `"Nano Signed Nonce:\n"` followed by a 16-byte nonce, 35 bytes in all, never a 32-byte digest.
- **Applications.** `domain` and `action` are signed, so a signature for one application or one action is invalid for every other.

## Security considerations

- **Blind signing in block-envelope mode.** A Ledger shows the envelope as an opening block with an unfamiliar representative. The user cannot see the message on the device. A signer SHOULD use block mode only through a tool that shows the message beside the device prompt, and SHOULD show the message digest's `nano_` encoding so the user can match it against the representative on screen.
- **Replay.** The format binds content but does not by itself stop replay. A profile that authorizes a one-time effect MUST require a nonce and a window, and the verifier MUST track nonces as in [Verifier policy](#verifier-policy).
- **Unicode.** Without normalization, two strings that render alike can have different digests. A verifier compares signed strings as code points, and an application that needs visual uniqueness, such as usernames, restricts its own alphabet.
- **Key reuse across applications.** A key signing for several applications is safe, because `domain` separates them. A verifier MUST check `domain` against a fixed value it controls, never against a value taken from the request.
- **Clock skew.** A two-way window tolerates a signer whose clock is behind or ahead by less than the window.

## Test vectors

The `test-vectors/` directory holds JSON vectors generated from fixed test keys by `scripts/generate-test-vectors.mjs`.

- `positive.json`: for every registered profile and both signing modes, the private and public keys, account, payload, canonical message, signed text in hex, message digest, envelope hash and a fixed signature. Every conforming verifier MUST accept each one.
- `negative.json`: wire units every conforming verifier MUST reject, each with the reason and the rule it breaks. They cover non-canonical messages, payload errors, wrong domain or action, and signature-encoding violations.
- `jcs.json`: serializer cases from RFC 8785 within the allowed value set, and values the serializer MUST refuse.

The fixed signatures were made by a deterministic signer. Another conforming signer produces different signatures for the same payloads, and a verifier MUST accept both.

## Rationale and prior art

- **No standard existed.** nano-node closed arbitrary-message signing unmerged (nano-node PR #647). nanocurrency-web's `tools.sign` signs with no prefix and a lossy string encoding. nanomemotools signs a prefixed message with a block hash. bananojs signs a dummy open block with the message hash as representative, which inspired the block-envelope mode, and is Banano-only.
- **Other ecosystems** settled on the same ingredients: Stellar SEP-53, Ethereum EIP-191 and EIP-712, Solana off-chain messages and NEAR NEP-413 all combine a domain prefix, a version, explicit structure and replay fields.
- **JSON with JCS** keeps the signed text readable on a screen and in logs, and lets any language produce it with a small serializer. Restricting values to integers removes the hard part of JCS, number formatting.
- **A text prefix and a digest** let any tool that signs 32-byte hashes sign this format, and let a block-signing device sign it through the envelope.
- **Two modes, no mode field.** Requiring the verifier to try both keeps the signed payload identical whichever device made the signature.
