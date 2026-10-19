# Antifraud SDK Node

Node.js adapters for backend-for-frontend applications and services that use the neutral antifraud contracts.

## Status

Public implementation foundation. Version `0.2.4` provides controller
administration and evidence clients plus the Node HTTP adapter for the shared
credential-issuance controller. No production readiness is claimed yet.

## Responsibility

This package will implement Node.js transport and server-side adapters over [antifraud-sdk-core-ts](https://github.com/antifraudservices/antifraud-sdk-core-ts), including:

- trusted-verifier HTTP clients;
- index-provider HTTP clients;
- opaque transaction continuity;
- timeout, retry, cancellation, and error mapping;
- server-side credential retrieval;
- optional OpenID for Verifiable Credential Issuance client support when the provider exposes that protocol.
- authenticated identity-evidence and education-qualification gateway writes.
- authenticated organization-controller workspace reads and mutations.

It will not contain React components, product screens, ledger deployment code, provider signing keys, or tenant-specific configuration.

## Browser, backend, and provider boundary

A browser starts a presentation through its application backend. The backend may protect transaction continuity and call a trusted verifier, but it does not turn presentation verification into credential issuance.

After verification, an authorized index provider performs authoritative readback and signs the requested credential. The backend receives a signed credential or reference according to the provider contract. It never receives the signing authority.

OpenID for Verifiable Presentations and the High Assurance Interoperability Profile cover wallet presentation. OpenID for Verifiable Credential Issuance, when used, covers issuance. Adapters must keep their endpoints, states, errors, and audit events separate.

## Security boundary

This public repository contains reusable code only. Secrets, trust anchors, live endpoints, tenant identifiers, personal data, and environment manifests remain outside the package.

Opaque transaction identifiers may be retained only for the documented lifetime of the flow. Verifiable presentations and disclosed claims must not be written to logs or generic session storage.

## Workforce adapter boundary

Backend adapters load the employee assignment, current group membership, and
controller-managed group authorization from trusted server sources. A browser
must not submit those facts as authority. A separate subject or lawful
representative authorization is loaded only when the use case requires it.
There is no employee-specific Consent created for group membership.

Invitation acceptance and later department, group, suspension, or reactivation
changes are notified as Communication records. Adapters may transport those
notices, but a notification never grants a capability. Product backends remain
responsible for choosing the relevant group purpose and for enforcing any
domain-specific subject authorization.

For qualification evidence, a backend adapter resolves an awarding
organization through a trusted directory using legal identifier and
jurisdiction. It must preserve whether a proof was issued by the source or is
an employer's own attestation and must never promote browser-entered display
text into issuer authority.

## Neutral gateway client

`AntifraudGatewayClient` is the backend-for-frontend adapter for the current
identity-evidence and education-qualification routes. The application supplies
an opaque bearer credential through a server callback. The client never accepts
the authenticated employee, organization, group authorization, zone, channel,
or smart-contract name from browser input. The gateway derives those facts from
trusted server context.

`recordIdentityEvidence(...)` records subject identity, relationship, or
age-over evidence. `recordQualificationEvidence(...)` records an employer's
attestation about a qualification document and its content identifier. Neither
method turns an employer statement into an issuer credential.

`readControllerWorkspace(...)` reads the authenticated organization's
authoritative administration state. Department, group, invitation,
membership, lifecycle and purge methods never accept an organization reference
from the caller; the gateway derives it from the bearer credential.

`AuthoritativeCredentialProviderClient` implements only provider HTTP
transport. `createAuthoritativeCredentialIssuanceController(...)` composes it
with the runtime-neutral state and polling rules from `antifraud-sdk-core-ts`.
Canonical request validation and wire conversion remain owned by
`antifraud-data-utils-ts`; this package does not maintain a second copy.

## DIDComm binary attachment transport

`createTrustedDocumentDeliveryController` transports governed files through
DIDComm `attachments[]`: bounded files use `data.base64`; protected files use
`data.links + data.hash`. The trusted server supplies sender, recipient and
service bindings plus the media allowlist and inline byte limit. Inline bytes
are hashed with SHA3-384 and checked against the canonical Schema.org
`MediaObject`; the released Core controller keeps replay idempotent and stores
only opaque continuity. PDF, spreadsheet, Word, image, video and other allowed
media types share this contract. No FHIR resource or `DocumentReference`
belongs in Antifraud.

## Managed wallet and local user presence

`NodeManagedWallet` provisions separate ML-DSA-65 actor-signing and ML-KEM-768
document-at-rest keys. Only public descriptors, managed-signature proofs and
receipts cross the wallet boundary. `createManagedSigningBff(...)` composes the
runtime-neutral one-use session with a trusted local user-presence adapter;
the browser never submits authority or receives private material.

Raw attachment bytes are sealed as JWE through `protectArtifactBytes(...)`
and recovered only through `unprotectArtifactBytes(...)` after authorization.
The binary remains a DIDComm attachment referenced by a Schema.org document;
it is not a FHIR `DocumentReference`.

## Dependency direction

```text
antifraud-data-utils-ts
          ↓
antifraud-sdk-core-ts
          ↓
antifraud-sdk-node-ts
          ↓
backend-for-frontend applications and services
```

## Implementation gate

The first implementation increment requires contract tests against a local verifier/provider fixture, then integration proof against an explicitly named environment. Fixtures never count as real identity verification or credential issuance.

## License

Apache-2.0.
