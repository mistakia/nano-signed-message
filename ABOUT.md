---
title: nano-signed-message Repository Graph Entry
type: text
description: >-
  Graph entry for nano-signed-message, the specification, test vectors and pure-JS library for the
  canonical Nano signed-message format; maps its consumers in nano-community, base and nostr.
base_uri: user:repository/active/nano-signed-message/ABOUT.md
created_at: '2026-10-10T03:03:36.824Z'
entity_id: e8991213-ce61-4479-b541-daae13d8a4cd
owner_identity_uri: user:identity/trashman.md
public_read: false
relations:
  - follows [[user:guideline/directory-markdown-standards.md]]
tags:
  - user:tag/nano-cryptocurrency.md
  - user:tag/nano-community-project.md
updated_at: '2026-10-10T03:03:36.824Z'
---

## Purpose

Specification, test vectors and reference library for the canonical Nano signed-message format: `"Nano Signed Message:\n"` followed by an RFC 8785 canonical JSON payload, hashed with blake2b-256 and signed with ed25519-blake2b, either directly over the digest or inside a dummy open-block envelope a hardware wallet can sign. Published as the npm package `nano-signed-message`.

The normative contract is `SPECIFICATION.md` in the repo. For install and API, see `README.md`.

## Context

Nano had no message-signing standard. This repo is the shared one for every system that has a Nano key sign something other than a block. It was built in [[user:task/nano-cryptocurrency/nano-community/bind-signed-message-payloads.md]].

Pure JS over `@noble/curves` and `@noble/hashes`, so it runs in node and in browsers. The native `@trashman/ed25519-blake2b` is only a dev dependency, used to cross-check the test vectors.

## Notable Context

**Tags**: [[user:tag/nano-cryptocurrency.md]], [[user:tag/nano-community-project.md]].

**Consumers**:

- [[user:repository/active/nano-community/ABOUT.md]] — HTTP messages, key linking and revocation, username registration, the published CLI.
- `repository/active/base` — wallet-key sign-in (`create_session`).
- nostr Nano account bindings and pledges — [[user:task/nano-cryptocurrency/nano-community/nano-account-binding-and-pledged-bounties.md]].

**Sibling**: [[user:repository/active/ed25519-blake2b/ABOUT.md]] — native signer. Its signatures are hedged and non-deterministic, so consumers dedupe by `message_digest`, never by signature.

**Build essentials**:

```bash
yarn test                      # mocha: serializer, sign/verify, test vectors, native cross-check
yarn generate:test-vectors     # regenerate test-vectors/*.json from fixed keys
```

Install through `sandbox-install yarn install`. Remote creation and `npm publish` are operator-gated.

## Scope

**Belongs in this repo**: the format specification, its profile registry, test vectors, and the reference signer and verifier.

**Belongs elsewhere**:

- Per-consumer verifier policy (time windows, nonce tracking, storage) → the consuming repo.
- Ledger or other hardware signing tooling → a follow-up, not yet built.
- Native ed25519-blake2b bindings → `ed25519-blake2b/`.
