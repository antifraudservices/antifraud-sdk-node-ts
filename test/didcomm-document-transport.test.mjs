// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
// Journey: (1) resolve authenticated sender and recipient bindings on the server; (2) verify a minimal PDF against
// its canonical SHA3-384 MediaObject; (3) deliver the Schema.org graph and DIDComm attachment over authenticated HTTP;
// (4) persist only opaque idempotency continuity; (5) reject tampering and browser-owned authority before transport.
// Authorization invariant: the caller cannot select sender, recipient or DIDComm service.
// Persistence invariant: the receipt store and returned receipt contain neither PDF bytes nor bearer credentials.
import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import test from 'node:test'

import {
  SyntheticConfidentialDocumentFixture,
  assertSha3_384EvidenceContentIdMatchesDigest,
} from 'antifraud-data-utils-ts'

import {createTrustedDocumentDeliveryController} from '../dist/index.js'

const base58Alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58btc(bytes) {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  let encoded = ''
  while (value > 0n) {
    encoded = base58Alphabet[Number(value % 58n)] + encoded
    value /= 58n
  }
  return `z${encoded}`
}

function mediaObjectFor(bytes) {
  const digestBytes = createHash('sha3-384').update(bytes).digest()
  const digest = digestBytes.toString('base64')
  const contentId = base58btc(Uint8Array.from([0x01, 0x55, 0x15, 0x30, ...digestBytes]))
  assertSha3_384EvidenceContentIdMatchesDigest(contentId, digest)
  return Object.freeze({
    ...SyntheticConfidentialDocumentFixture.attachment,
    contentSize: bytes.byteLength,
    digest,
    contentId,
  })
}

const minimalPdfBytes = new TextEncoder().encode('%PDF-1.4\n%%EOF\n')
const minimalPdfMediaObject = mediaObjectFor(minimalPdfBytes)

function input(attachment) {
  return Object.freeze({
    operationId: 'urn:operation:node-document-delivery-opaque',
    messageId: 'urn:message:node-document-delivery-opaque',
    manifest: SyntheticConfidentialDocumentFixture.manifest,
    document: SyntheticConfidentialDocumentFixture.document,
    attachment,
  })
}

function fixture() {
  const requests = []
  const receipts = new Map()
  const controller = createTrustedDocumentDeliveryController({
    bearerCredential: async () => 'opaque-bearer',
    resolveTrustedContext: async () => ({
      senderReference: 'did:example:sender',
      recipientReference: 'did:example:recipient',
      serviceReference: 'https://recipient.example/didcomm',
    }),
    allowedMediaTypes: ['application/pdf'],
    maxInlineBytes: 1024,
    receipts: {
      get: async operationId => receipts.get(operationId),
      put: async (operationId, record) => { receipts.set(operationId, record) },
    },
    fetch: async (url, init) => {
      requests.push({url: String(url), init})
      return new Response(JSON.stringify({
        deliveryReference: 'urn:delivery:node-opaque',
        deliveredAt: '2026-10-18T20:00:00.000Z',
      }), {status: 202, headers: {'content-type': 'application/json'}})
    },
  })
  return {controller, receipts, requests}
}

test('delivers an integrity-verified minimal PDF through the released Core controller and DIDComm attachment contract', async () => {
  const {controller, receipts, requests} = fixture()
  const request = input(Object.freeze({
    kind: 'inline',
    mediaObject: minimalPdfMediaObject,
    bytes: minimalPdfBytes,
  }))

  const first = await controller.deliver(request)
  const replay = await controller.deliver(request)

  assert.deepEqual(replay, first)
  assert.equal(requests.length, 1)
  assert.equal(requests[0].url, 'https://recipient.example/didcomm')
  assert.equal(requests[0].init.headers.authorization, 'Bearer opaque-bearer')
  const wire = JSON.parse(requests[0].init.body)
  assert.equal(wire.from, 'did:example:sender')
  assert.deepEqual(wire.to, ['did:example:recipient'])
  assert.equal(wire.body.document.data[0].type, 'DigitalDocument')
  assert.deepEqual(Buffer.from(wire.attachments[0].data.base64, 'base64url'), Buffer.from(minimalPdfBytes))
  assert.equal(JSON.stringify(wire).includes('DocumentReference'), false)
  assert.equal(JSON.stringify(receipts.get(request.operationId)).includes('base64'), false)
  assert.equal(JSON.stringify(first).includes('opaque-bearer'), false)
})

test('delivers a canonical protected MediaObject link without exposing file bytes', async () => {
  const {controller, requests} = fixture()
  await controller.deliver(input(Object.freeze({
    kind: 'linked',
    mediaObject: SyntheticConfidentialDocumentFixture.attachment,
  })))

  const wire = JSON.parse(requests[0].init.body)
  assert.deepEqual(wire.attachments[0].data.links, [
    SyntheticConfidentialDocumentFixture.attachment.contentUrl,
  ])
  assert.match(wire.attachments[0].data.hash, /^z[1-9A-HJ-NP-Za-km-z]+$/)
  assert.equal('base64' in wire.attachments[0].data, false)
})

test('rejects tampered bytes, disallowed media, oversized inline files and caller-owned routing', async () => {
  const {controller, requests} = fixture()

  await assert.rejects(controller.deliver(input(Object.freeze({
    kind: 'inline',
    mediaObject: minimalPdfMediaObject,
    bytes: new TextEncoder().encode('%PDF-1.4\ntampered\n%%EOF\n'),
  }))), /digest does not match/i)

  await assert.rejects(controller.deliver(input(Object.freeze({
    kind: 'inline',
    mediaObject: {...minimalPdfMediaObject, mediaType: 'application/octet-stream'},
    bytes: minimalPdfBytes,
  }))), /media type is not allowed/i)

  await assert.rejects(controller.deliver(input(Object.freeze({
    kind: 'inline',
    mediaObject: {...minimalPdfMediaObject, contentSize: 2048},
    bytes: new Uint8Array(2048),
  }))), /inline byte limit/i)

  await assert.rejects(controller.deliver({
    ...input(Object.freeze({kind: 'linked', mediaObject: minimalPdfMediaObject})),
    trustedContext: {senderReference: 'did:example:browser'},
  }), /server-owned routing/i)
  assert.equal(requests.length, 0)
})
