# DIDComm attachment transport task

The Antifraud business record is a Schema.org `DigitalDocument` with one or
more `MediaObject` encodings. The Node adapter transports the corresponding
binary in DIDComm `attachments[]`; it never creates a FHIR
`DocumentReference`.

The released implementation:

1. consumes the released data-utils inline and linked attachment contract;
2. composes the released SDK Core orchestration;
3. enforces media allowlists, byte limits and exact CID/digest checks;
4. supports bounded `data.base64` and authorized `data.links + data.hash`;
5. proves a minimal PDF, protected-link transport, tampering rejection,
   idempotent replay and server-owned routing without logging bytes or secrets.

Additional media types, timeout handling and a real environment delivery remain
separate acceptance gates; local HTTP fixtures are not deployment evidence.
