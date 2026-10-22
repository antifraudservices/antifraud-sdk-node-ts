// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import type {
  DidCommInlineBinaryAttachment,
  SchemaOrgDigitalDocumentDescriptor,
  SchemaOrgConfidentialDocumentGraphInput,
  ManagedSignatureProof,
  SocialPublicationContent,
  SocialPublicationDemoRecord,
} from 'antifraud-data-utils-ts'
import {
  buildDidCommInlineBinaryAttachment,
  buildSchemaOrgConfidentialDocumentGraph,
  buildSha3_384EvidenceContentIdFromDigest,
} from 'antifraud-data-utils-ts'
import { createHash } from 'node:crypto'

export type GatewayClientOptions = Readonly<{
  baseUrl: string
  bearerCredential(): Promise<string>
  fetch?: typeof globalThis.fetch
}>

export type IdentityEvidenceGatewayRequest = Readonly<{
  operationId: string
  subjectReference: string
  targets: readonly Readonly<Record<string, unknown>>[]
  evidence: readonly Readonly<Record<string, unknown>>[]
  encryptedClaims: string
}>

type QualificationEvidenceGatewayRequestBase = Readonly<{
  evidenceId: string
  subjectReference: string
  issuer: Readonly<{ legalIdentifier: string; jurisdiction: string }>
  qualificationReference: string
  documentCid: string
}>

export type QualificationEvidenceGatewayRequest = QualificationEvidenceGatewayRequestBase & (
  | Readonly<{confidentialClaims: Readonly<Record<string, unknown>>; encryptedClaims?: never}>
  | Readonly<{encryptedClaims: string; confidentialClaims?: never}>
)

export type ConfidentialArtifactGatewayRequest = Readonly<{
  document: SchemaOrgConfidentialDocumentGraphInput
  attachment: DidCommInlineBinaryAttachment
  fileName: string
}>

export type PrepareConfidentialArtifactUploadInput = Readonly<{
  bytes: Uint8Array
  fileName: string
  mediaType: string
  attachmentId: string
  manifest: SchemaOrgDigitalDocumentDescriptor
  document: SchemaOrgDigitalDocumentDescriptor
}>

/** Prepares the canonical Schema.org business record and DIDComm byte transport in one Node BFF call. */
export function prepareConfidentialArtifactUpload(
  input: PrepareConfidentialArtifactUploadInput,
): ConfidentialArtifactGatewayRequest {
  if (!(input.bytes instanceof Uint8Array) || input.bytes.byteLength === 0) {
    throw new TypeError('Confidential artifact bytes must not be empty.')
  }
  const fileName = input.fileName.trim()
  if (!fileName || /[\r\n]/u.test(fileName)) throw new TypeError('A safe artifact fileName is required.')
  const digestBytes = createHash('sha3-384').update(input.bytes).digest()
  const contentId = buildSha3_384EvidenceContentIdFromDigest(digestBytes)
  const attachment = Object.freeze({
    id: input.attachmentId,
    mediaType: input.mediaType,
    contentSize: input.bytes.byteLength,
    contentUrl: `/v1/confidential-artifacts/${encodeURIComponent(contentId)}`,
    digestAlgorithm: 'sha3-384' as const,
    digest: digestBytes.toString('base64'),
    contentId,
  })
  const document = Object.freeze({
    manifest: input.manifest,
    documents: Object.freeze([{...input.document, attachment}]) as SchemaOrgConfidentialDocumentGraphInput['documents'],
  })
  buildSchemaOrgConfidentialDocumentGraph(document)
  return Object.freeze({
    document,
    attachment: buildDidCommInlineBinaryAttachment({
      id: input.attachmentId,
      mediaType: input.mediaType,
      bytes: input.bytes,
    }),
    fileName,
  })
}

const CLIENT_OWNED_AUTHORITY = ['actor', 'channel', 'zone', 'smartContract'] as const
const CONTROLLER_OWNED_AUTHORITY = [...CLIENT_OWNED_AUTHORITY, 'organizationReference'] as const

function rejectClientOwnedAuthority(input: object): void {
  for (const property of CLIENT_OWNED_AUTHORITY) {
    if (Object.hasOwn(input, property)) {
      throw new TypeError(`The server-owned actor and infrastructure authority must not be supplied by the client (${property}).`)
    }
  }
}

function rejectControllerOwnedAuthority(input: object): void {
  for (const property of CONTROLLER_OWNED_AUTHORITY) {
    if (Object.hasOwn(input, property)) {
      throw new TypeError(`The server-owned actor and organization authority must not be supplied by the client (${property}).`)
    }
  }
}

export type ControllerWorkspace = Readonly<{
  organization: Readonly<{ reference: string; displayName: string; legalIdentifier?: string; jurisdiction?: string }>
  licences: Readonly<{ total: number; assigned: number; free: number }>
  departments: readonly Readonly<{ reference: string; name: string }>[]
  places: readonly Readonly<{
    reference: string
    name: string
    departmentReference: string
    containedInPlaceReference?: string
    geo?: Readonly<{ latitude: number; longitude: number; elevation?: number }>
    publishInCatalog: boolean
  }>[]
  services: readonly Readonly<{
    reference: string
    name: string
    description?: string
    serviceType: string
    departmentReference: string
    placeReferences: readonly string[]
    publishInCatalog: boolean
  }>[]
  catalog: Readonly<{ version: number; modifiedAt?: string }>
  groups: readonly Readonly<{ reference: string; name: string; capabilities: readonly string[]; authorizationReference: string }>[]
  invitations: readonly Readonly<{ reference: string; email: string; role: string; status: string; departmentReferences: readonly string[]; groupReferences: readonly string[] }>[]
  employees: readonly Readonly<{ reference: string; email: string; role: string; status: 'active' | 'inactive'; licenceReference: string; departmentReferences: readonly string[]; groupReferences: readonly string[]; deviceReferences: readonly string[] }>[]
  notifications: readonly Readonly<{ reference: string; recipientReference: string; event: string; recordedAt: string }>[]
}>

export type ClearingHouseItem = Readonly<{
  destinationOrganizationReference: string
  evidenceLocator: string
  sourceHostReference: string
  channelFamily: string
  lifecycleStatus: string
  deliveryState: string
  attemptCount: number
  queuedAt: string
  receiptReference?: string
}>

export class AntifraudGatewayClient {
  readonly #baseUrl: string
  readonly #bearerCredential: GatewayClientOptions['bearerCredential']
  readonly #fetch: typeof globalThis.fetch

  constructor(options: GatewayClientOptions) {
    this.#baseUrl = options.baseUrl.replace(/\/$/u, '')
    this.#bearerCredential = options.bearerCredential
    this.#fetch = options.fetch ?? globalThis.fetch
  }

  async recordIdentityEvidence(input: IdentityEvidenceGatewayRequest): Promise<Readonly<{
    channel: 'identity-global'
    transactionId: string
    anchor: Readonly<Record<string, unknown>>
  }>> {
    rejectClientOwnedAuthority(input)
    return this.#post('/v1/identity/evidence', input)
  }

  async recordQualificationEvidence(input: QualificationEvidenceGatewayRequest): Promise<Readonly<{
    channel: string
    transactionId: string
    status: string
    anchor: Readonly<Record<string, unknown>>
  }>> {
    rejectClientOwnedAuthority(input)
    return this.#post('/v1/education/qualification-evidence', input)
  }

  async storeConfidentialArtifact(input: ConfidentialArtifactGatewayRequest): Promise<Readonly<{
    document: Readonly<Record<string, unknown>>
    artifact: Readonly<{artifactId: string; objectName: string; byteCount: number}>
  }>> {
    rejectClientOwnedAuthority(input)
    return this.#post('/v1/confidential-artifacts', input)
  }

  async readConfidentialArtifact(artifactId: string): Promise<Readonly<{
    mediaType: string
    fileName: string
    bytes: Uint8Array
  }>> {
    const normalizedId = artifactId.trim()
    if (!normalizedId) throw new TypeError('An artifact identifier is required.')
    const response = await this.#authorizedFetch(
      `/v1/confidential-artifacts/${encodeURIComponent(normalizedId)}`,
      'GET',
    )
    if (!response.ok) await this.#throwGatewayError(response)
    const disposition = response.headers.get('content-disposition') ?? ''
    const fileName = disposition.match(/filename="([^"]+)"/u)?.[1] ?? 'artifact.bin'
    return Object.freeze({
      mediaType: response.headers.get('content-type') ?? 'application/octet-stream',
      fileName,
      bytes: new Uint8Array(await response.arrayBuffer()),
    })
  }

  async readControllerWorkspace(): Promise<ControllerWorkspace> {
    return this.#request('/v1/controller/workspace', 'GET')
  }

  async createControllerDepartment(input: Readonly<{ name: string }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/departments', 'POST', input)
  }

  async createControllerPlace(input: Readonly<{
    name: string
    departmentReference: string
    containedInPlaceReference?: string
    geo?: Readonly<{ latitude: number; longitude: number; elevation?: number }>
  }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/places', 'POST', input)
  }

  async createControllerClientService(input: Readonly<{
    name: string
    description?: string
    serviceType: string
    departmentReference: string
    placeReferences: readonly string[]
  }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/services', 'POST', input)
  }

  async setControllerPlaceCatalogPublication(placeReference: string, publishInCatalog: boolean): Promise<unknown> {
    return this.#request(
      `/v1/controller/places/${encodeURIComponent(placeReference)}/catalog-publication`,
      'PUT',
      { publishInCatalog },
    )
  }

  async setControllerClientServiceCatalogPublication(serviceReference: string, publishInCatalog: boolean): Promise<unknown> {
    return this.#request(
      `/v1/controller/services/${encodeURIComponent(serviceReference)}/catalog-publication`,
      'PUT',
      { publishInCatalog },
    )
  }

  async readControllerServiceCatalog(): Promise<Readonly<Record<string, unknown>>> {
    return this.#request('/v1/controller/service-catalog', 'GET')
  }

  async readPublicOrganizationServiceCatalog(organizationReference: string): Promise<Readonly<Record<string, unknown>>> {
    return this.#request(
      `/v1/public/organization-service-catalog/${encodeURIComponent(organizationReference)}`,
      'GET',
    )
  }

  async createControllerGroup(input: Readonly<{ name: string; capabilities: readonly string[] }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/groups', 'POST', input)
  }

  async createControllerInvitation(input: Readonly<{ email: string; role: string; groupReferences: readonly string[]; departmentReferences: readonly string[] }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/invitations', 'POST', input)
  }

  async acceptControllerInvitation(invitationReference: string, input: Readonly<{ deviceReference: string }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request(`/v1/controller/invitations/${encodeURIComponent(invitationReference)}/accept`, 'POST', input)
  }

  async setControllerEmployeeStatus(employeeReference: string, status: 'active' | 'inactive'): Promise<unknown> {
    return this.#request(`/v1/controller/employees/${encodeURIComponent(employeeReference)}/status`, 'PUT', { status })
  }

  async setControllerEmployeeMemberships(employeeReference: string, input: Readonly<{ groupReferences: readonly string[]; departmentReferences: readonly string[] }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request(`/v1/controller/employees/${encodeURIComponent(employeeReference)}/memberships`, 'PUT', input)
  }

  async purgeControllerEmployee(employeeReference: string): Promise<unknown> {
    return this.#request(`/v1/controller/employees/${encodeURIComponent(employeeReference)}`, 'DELETE')
  }

  async listClearingHouseInbox(): Promise<Readonly<{ items: readonly ClearingHouseItem[] }>> {
    return this.#request('/v1/clearing-house/inbox', 'GET')
  }

  async readClearingHouseEvidence(evidenceLocator: string): Promise<Readonly<{
    evidenceLocator: string
    confidentialClaims: Readonly<Record<string, unknown>>
  }>> {
    const normalizedLocator = evidenceLocator.trim()
    if (!normalizedLocator) throw new TypeError('An evidence locator is required.')
    return this.#request(`/v1/clearing-house/evidence/${encodeURIComponent(normalizedLocator)}`, 'GET')
  }

  async decideClearingHouseEvidence(evidenceLocator: string, input: Readonly<{ decision: 'confirmed' | 'rejected' | 'revoked'; issuerProofReference: string }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request(`/v1/clearing-house/evidence/${encodeURIComponent(evidenceLocator)}/decision`, 'POST', input)
  }

  async recordSocialPublication(input: Readonly<{
    content: SocialPublicationContent
    proof: ManagedSignatureProof
  }>): Promise<SocialPublicationDemoRecord> {
    rejectClientOwnedAuthority(input)
    return this.#post('/v1/social/publications', input)
  }

  async readSocialPublication(publicationId: string): Promise<SocialPublicationDemoRecord> {
    const normalizedId = publicationId.trim()
    if (!normalizedId) throw new TypeError('A social publication identifier is required.')
    return this.#request(`/v1/social/publications/${encodeURIComponent(normalizedId)}`, 'GET')
  }

  async #post<T>(path: string, body: object): Promise<T> {
    return this.#request(path, 'POST', body)
  }

  async #request<T>(path: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', body?: object): Promise<T> {
    const response = await this.#authorizedFetch(path, method, body)
    const payload: unknown = await response.json()
    if (!response.ok) {
      const message = payload && typeof payload === 'object' && 'error' in payload
        ? String(payload.error)
        : `Gateway request failed with HTTP ${response.status}.`
      throw new Error(message)
    }
    return payload as T
  }

  async #authorizedFetch(
    path: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    body?: object,
  ): Promise<Response> {
    const bearerCredential = (await this.#bearerCredential()).trim()
    if (!bearerCredential) throw new TypeError('A bearer credential is required.')
    return this.#fetch(`${this.#baseUrl}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${bearerCredential}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
  }

  async #throwGatewayError(response: Response): Promise<never> {
    let message = `Gateway request failed with HTTP ${response.status}.`
    try {
      const payload: unknown = await response.json()
      if (payload && typeof payload === 'object' && 'error' in payload) message = String(payload.error)
    } catch {
      // Binary endpoints may return an empty or non-JSON error body.
    }
    throw new Error(message)
  }
}
