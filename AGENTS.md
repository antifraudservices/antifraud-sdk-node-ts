# AGENTS.md

## Scope

This repository owns Node.js and backend-for-frontend transport adapters for trusted verifiers and authoritative credential providers. It contains no React, product policy, signing keys, tenant values, ledger deployment or authoritative claim source.

## Development contract

- Use red-green-refactor test-driven development.
- Begin every test file with the required flow-contract comment.
- Never return, persist or log a wallet presentation or disclosed claim.
- Never allow caller-supplied claims to stand in for authoritative-provider readback.
- Keep presentation verification and credential issuance as separate endpoints and states.
- Documentation and code are written in English.

