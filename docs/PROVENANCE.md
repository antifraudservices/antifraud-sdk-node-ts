# Source provenance

The initial EUDI verifier HTTP client was migrated and made product-neutral from `connect-ica-identity-app`, commit `4a3a29055cde8e98c24fe642ee00d67f62392cbb`.

The authoritative credential-provider client is a new neutral adapter derived from the already documented provider boundary. It deliberately accepts subject, capability and verification references but rejects caller-supplied claims.

The source repositories were not modified. Existing DIDComm and legacy ICA clients were not copied wholesale because they include different endpoint families, authentication profiles and dependencies.

