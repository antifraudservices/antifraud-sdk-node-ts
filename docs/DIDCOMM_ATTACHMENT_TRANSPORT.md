# DIDComm attachment transport task

The Antifraud business record is a Schema.org `DigitalDocument` with one or
more `MediaObject` encodings. The Node adapter transports the corresponding
binary in DIDComm `attachments[]`; it never creates a FHIR
`DocumentReference`.

The implementation order is:

1. consume the released data-utils inline and linked attachment contract;
2. consume the released SDK Core orchestration;
3. enforce media allowlists, byte limits and exact CID/digest checks;
4. support bounded `data.base64` and authorized `data.links + data.hash`;
5. prove PDF and at least one non-PDF type without logging bytes or secrets;
6. prove tampering, replay, cross-tenant denial and timeout behavior.

Track execution in [GitHub issue #5](https://github.com/antifraudservices/antifraud-sdk-node-ts/issues/5).
