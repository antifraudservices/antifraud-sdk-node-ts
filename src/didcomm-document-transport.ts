// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import {createHash} from 'node:crypto'

import {
  createDocumentDeliveryController,
  type DocumentDeliveryControllerPorts,
  type DocumentDeliveryRequest,
  type PreparedDocumentDelivery,
  type TrustedDocumentDeliveryContext,
} from 'antifraud-sdk-core-ts'

export type TrustedDocumentDeliveryInput = Omit<DocumentDeliveryRequest, 'trustedContext'>

export type TrustedDocumentDeliveryControllerOptions = Readonly<{
  bearerCredential(): Promise<string>
  resolveTrustedContext(): Promise<TrustedDocumentDeliveryContext>
  allowedMediaTypes: readonly string[]
  maxInlineBytes: number
  receipts: DocumentDeliveryControllerPorts['receipts']
  fetch?: typeof globalThis.fetch
}>

const CLIENT_OWNED_ROUTING = Object.freeze([
  'trustedContext',
  'senderReference',
  'recipientReference',
  'serviceReference',
])

function requireNonEmpty(value: string, path: string): string {
  const normalized = value.trim()
  if (!normalized) throw new TypeError(`${path} must not be empty`)
  return normalized
}

function validateOptions(options: TrustedDocumentDeliveryControllerOptions): void {
  if (!Number.isSafeInteger(options.maxInlineBytes) || options.maxInlineBytes <= 0) {
    throw new TypeError('maxInlineBytes must be a positive safe integer')
  }
  if (options.allowedMediaTypes.length === 0) {
    throw new TypeError('At least one allowed document media type is required')
  }
}

function validateAttachment(
  input: TrustedDocumentDeliveryInput,
  options: TrustedDocumentDeliveryControllerOptions,
): void {
  const mediaObject = input.attachment.mediaObject
  if (!options.allowedMediaTypes.includes(mediaObject.mediaType)) {
    throw new TypeError('Document media type is not allowed by the trusted server policy')
  }

  if (input.attachment.kind === 'inline') {
    if (input.attachment.bytes.byteLength > options.maxInlineBytes) {
      throw new TypeError('DIDComm attachment exceeds the configured inline byte limit')
    }
    const digest = createHash('sha3-384').update(input.attachment.bytes).digest('base64')
    if (digest !== mediaObject.digest) {
      throw new TypeError('DIDComm attachment byte digest does not match the Schema.org MediaObject')
    }
    return
  }

  const contentUrl = new URL(mediaObject.contentUrl)
  if (contentUrl.protocol !== 'https:') {
    throw new TypeError('Protected DIDComm attachment links must use HTTPS')
  }
}

function rejectClientOwnedRouting(input: TrustedDocumentDeliveryInput & Record<string, unknown>): void {
  for (const property of CLIENT_OWNED_ROUTING) {
    if (Object.hasOwn(input, property)) {
      throw new TypeError(`Document delivery uses server-owned routing (${property})`)
    }
  }
}

export function createTrustedDocumentDeliveryController(
  options: TrustedDocumentDeliveryControllerOptions,
) {
  validateOptions(options)
  const fetchImplementation = options.fetch ?? globalThis.fetch.bind(globalThis)
  const core = createDocumentDeliveryController({
    receipts: options.receipts,
    transport: {
      async send(delivery: PreparedDocumentDelivery) {
        const bearerCredential = requireNonEmpty(
          await options.bearerCredential(),
          'bearerCredential',
        )
        const endpoint = new URL(delivery.trustedContext.serviceReference)
        if (endpoint.protocol !== 'https:') {
          throw new TypeError('The trusted DIDComm service endpoint must use HTTPS')
        }
        const response = await fetchImplementation(endpoint, {
          method: 'POST',
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${bearerCredential}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            id: delivery.messageId,
            from: delivery.trustedContext.senderReference,
            to: [delivery.trustedContext.recipientReference],
            body: {document: delivery.documentGraph},
            attachments: delivery.attachments,
          }),
        })
        const payload: unknown = await response.json()
        if (!response.ok) {
          throw new Error(`DIDComm document delivery failed with HTTP ${response.status}`)
        }
        if (!payload || typeof payload !== 'object') {
          throw new TypeError('DIDComm delivery receipt must be an object')
        }
        const record = payload as Record<string, unknown>
        return Object.freeze({
          deliveryReference: requireNonEmpty(String(record.deliveryReference ?? ''), 'deliveryReference'),
          deliveredAt: requireNonEmpty(String(record.deliveredAt ?? ''), 'deliveredAt'),
        })
      },
    },
  })

  return Object.freeze({
    async deliver(input: TrustedDocumentDeliveryInput & Record<string, unknown>) {
      rejectClientOwnedRouting(input)
      validateAttachment(input, options)
      const trustedContext = await options.resolveTrustedContext()
      return core.deliver({...input, trustedContext})
    },
  })
}
