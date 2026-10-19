# Changelog

## Unreleased

- Add high-level addressed-issuer evidence readback and support server-sealed
  confidential qualification claims without exposing organization, channel,
  storage or decryption authority to browser callers.

## 0.2.4 - 2026-10-18

- Add authenticated high-level Gateway operations for recording and
  authoritatively reloading the canonical proof-bound social Demo publication.
- Authenticate both authoritative issuance submission and receipt reload with
  the BFF-owned bearer credential; browsers still cannot inject provider
  authority.
- Add the high-level confidential-artifact upload builder and Gateway client
  operations. Node BFFs now prepare one Schema.org document graph plus its
  DIDComm inline attachment, then store and retrieve exact binary bytes without
  implementing CID or attachment cryptography in portals.

- Pin the exact current Data Utils and SDK Core releases.
- Add the Node managed wallet with ML-DSA-65 actor-signing and ML-KEM-768
  document-at-rest keys; private key material never leaves wallet custody.
- Compose the trusted BFF user-presence ceremony with the one-use Core session
  and expose verified managed-signature proofs.
- Seal and unseal raw attachment bytes through the shared JWE cryptography so
  gateway persistence never stores readable PDF, Word or spreadsheet bytes.

## 0.2.3 - 2026-10-18

- Pin `antifraud-data-utils-ts@0.1.4` and `antifraud-sdk-core-ts@0.1.3`.
- Add the trusted Node/BFF document-delivery controller for canonical
  Schema.org graphs and inline or protected-link DIDComm attachments.
- Verify inline SHA3-384 bytes against the canonical MediaObject, enforce
  server-owned routing, media allowlists, byte limits, HTTPS endpoints and
  opaque idempotent receipts without logging or persisting raw bytes.

## 0.2.2 - 2026-10-18

- Pin `antifraud-sdk-core-ts@0.1.2` so backend applications can use the
  explicit participant-resolved, identity-resolved and not-resolved
  qualification issuer contract.
- Pin `antifraud-data-utils-ts@0.1.3` for the canonical confidential-document
  graph, governed CID validator and shared synthetic fixture.

## 0.2.1 - 2026-10-17

- Reuse the canonical credential-issuance request and receipt contract from
  `antifraud-data-utils-ts` instead of maintaining Node-specific duplicates.
- Compose the Node HTTP provider adapter with the runtime-neutral polling and
  terminal-state controller from `antifraud-sdk-core-ts`.

## 0.2.0 - 2026-10-17

- Add authenticated controller workspace readback and organization-scoped
  department, group, invitation, acceptance, employee membership, lifecycle
  and purge methods.
- Reject caller-owned organization authority in every controller mutation.
- Add addressed Clearing House inbox and decision methods for controller
  administration.

## 0.1.0 - 2026-10-17

- Add trusted-verifier and authoritative credential-provider HTTP adapters.
- Document trusted-server loading of workforce membership and shared group
  authorization, plus separate Communication notifications for assignment
  changes.
- Define trusted awarding-organization lookup by legal identifier and
  jurisdiction while preserving employer and source proof provenance.
- Add the authenticated neutral gateway client for identity evidence and
  education qualification evidence. The client rejects browser-supplied
  actor, zone, channel and smart-contract authority.
