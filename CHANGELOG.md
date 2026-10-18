# Changelog

## Unreleased

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
