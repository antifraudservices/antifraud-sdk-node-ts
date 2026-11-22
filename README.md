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

`listClearingHouseInbox(...)` returns privacy-minimized addressed references.
`readClearingHouseEvidence(...)` then opens the confidential employer evidence
only through the authenticated issuer BFF, so the issuer can inspect the
canonical classification before deciding without putting it in the index or
ledger anchor.

Use `readControllerResource('employees', { email })` to search employees
or `readControllerResource('licences')` to read licence totals independently.
The gateway derives the organization from the bearer credential. Department,
group, invitation, membership, lifecycle and purge methods use the same
authority boundary. `readControllerWorkspace()` is retained for compatibility
with older gateways.

`createControllerPlace(...)` and `createControllerClientService(...)` preserve
the Schema.org-first organization structure. Separate publication methods mark
each record for the public catalog; they never publish merely because a record
exists. `readControllerServiceCatalog(...)` uses authenticated controller
authority, while `readPublicOrganizationServiceCatalog(...)` retrieves the
public graph. Sector, jurisdiction, publisher and access URL stay owned by the
gateway configuration. Scheduling and FHIR conversion are outside this SDK
surface.

`AuthoritativeCredentialProviderClient` implements only provider HTTP
transport. `createAuthoritativeCredentialIssuanceController(...)` composes it
with the runtime-neutral state and polling rules from `antifraud-sdk-core-ts`.
Canonical request validation and wire conversion remain owned by
`antifraud-data-utils-ts`; this package does not maintain a second copy.

## Credential and compliance verification clients

`verifyCredentialPresentation({request, presentation})` submits a signed holder
presentation to the gateway Clearing House. The request binds the exact resource,
jurisdiction, verification capability and fresh nonce. The gateway loads current
actor, holder keys, issuer trust, credential status and permissions from its
configured authority. The SDK returns only the request-bound verification receipt
and its explicit state provider (`memory` or `fabric`).

`verifyGaiaXPresentation({presentation})` submits the tenant presentation through
the gateway to its configured Gaia-X compliance engine. The gateway verifies the
engine signature, current trust, rules version, validity and exact credential
coverage. The SDK checks the returned Standard Compliance credential profile and
returns its original signed JWT plus a narrow metadata summary. It never returns
the submitted presentation or arbitrary engine fields in that summary. The SDK
uses the authenticated gateway as its verifier; decoding the response profile is
not a second signature verification or a compliance-engine implementation.

Both operations use HTTPS, reject redirects and discard remote error bodies.
An explicit `allowLocalTestEndpoint` option accepts loopback HTTP only with
`NODE_ENV=test`. This option does not disable signature or authorization checks.

`npm run test:gateway:local` requires `ANTIFRAUD_GATEWAY_TEST_MODULE` to identify a
compiled local gateway module using a `file:` URL. This separate gate runs the
high-level SDK through real local HTTP and cryptographic verification, including
replay, revoked-credential and policy denials. Its memory-state proof does not
represent a Fabric or production deployment.

## Node signing keys for synthetic examples

The explicit `antifraud-sdk-node-ts/examples/deterministic-signing-key` subpath
exports `deriveDeterministicEcJwkPair` for governed synthetic examples. It
preserves the established ES384/ES256K derivation bytes for an exact seed and
purpose. Deterministic seeds are not production entropy. This helper is not
exported from the package root and does not belong in browser Data contracts.

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

`examples/client-assertion` builds disposable signed SMART/OpenID client JWTs
and exposes their generated public keys for local examples. These assertions
establish no registered-device authority. A production wallet signs with its
own enrolled key; verifiers independently check registration, audience,
validity and replay. This Node-only subpath is not part of the runtime root.

## Optional Pontus-X catalogue publication

Enable `PONTUS_X_PUBLICATION_ENABLED=true` in the BFF server configuration.
`createPontusXPublication` returns undefined by default. Register its action
only when the module is enabled. The SDK is independent of the portal,
Nautilus version and the application's catalogue package.

In the host controller settings, store whether each tenant can publish with
its own enrolled wallet. Default to host-only. Require host-controller
authorization to change that setting. Apply it to the tenant wallet setup
action and reload it from storage on every publication request. For host-owned
publication, require an authenticated host controller with access to that
tenant, and use the operator's enrolled wallet. Keep the source tenant ID with
the publication receipt and display the external owner's address separately.

For each request:

1. Pass the authenticated server-side session and local dataset ID to
   `publish`. The authorization callback must load the tenant and authoritative
   policy for the selected dataset. Resolve the network, controller authority
   and enrolled wallet addresses on the server.
2. In `connect`, open the authorized organization's signing provider from
   server configuration. For Nautilus 1.x, initialize Nautilus with that signer
   and return `createNautilusV1PublicationClient(nautilus, signer)`.
3. In `prepareAsset`, load the approved Schema.org Dataset and linked services
   from the tenant, and call `buildOceanDatasetPublication` from the portal's
   catalogue utilities with the selected SDK builders. The service factory
   supplies the provider-side file source, permissions and pricing.
4. Use a durable journal with a unique key over chain, tenant and dataset.
   Implement `start` as an atomic insert-if-absent. Retry with the same key
   to resume readback. A pending record without a transaction receipt requires
   reconciliation against the chain before any retry can create a new asset.
   Treat a publisher change for an existing DID as a separate ownership
   decision. The create action preserves the existing record.
5. In `projectDataset`, call `projectOceanDatasetEntries` with the indexed DDO.
   Present success only after the SDK confirms the indexed DID, chain and
   owner. The returned receipt contains the DID, metadata transaction hash,
   owner, publisher and the projected catalogue. Keep any retained original
   DDO private.

The publisher accepts the application's catalogue conversion functions
through these callbacks. A first live check should use an onboarded
organizational wallet and a synthetic dataset in
[Pontus-X Testnet](https://docs.pontus-x.eu/docs/getting-started/Publication-guide).

## Prepare an authorized wallet offer

Use `AuthoritativeCredentialProviderClient.requestWalletCredentialOffer` from
a backend configured with the exact HTTPS issuer URL and backend authentication.
Include the tenant path when the issuer URL has one.
Pass the opaque authorization reference from the verified professional journey.
The issuer resolves the subject and returns the offer URL and a separate
transaction code for the authenticated holder.
