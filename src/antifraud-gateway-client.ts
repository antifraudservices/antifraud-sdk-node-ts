// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

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

export type QualificationEvidenceGatewayRequest = Readonly<{
  evidenceId: string
  subjectReference: string
  issuer: Readonly<{ legalIdentifier: string; jurisdiction: string }>
  qualificationReference: string
  documentCid: string
  encryptedClaims: string
}>

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
  groups: readonly Readonly<{ reference: string; name: string; capabilities: readonly string[]; authorizationReference: string }>[]
  invitations: readonly Readonly<{ reference: string; email: string; role: string; status: string; departmentReferences: readonly string[]; groupReferences: readonly string[] }>[]
  employees: readonly Readonly<{ reference: string; email: string; role: string; status: 'active' | 'inactive'; licenceReference: string; departmentReferences: readonly string[]; groupReferences: readonly string[]; deviceReferences: readonly string[] }>[]
  notifications: readonly Readonly<{ reference: string; recipientReference: string; event: string; recordedAt: string }>[]
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

  async readControllerWorkspace(): Promise<ControllerWorkspace> {
    return this.#request('/v1/controller/workspace', 'GET')
  }

  async createControllerDepartment(input: Readonly<{ name: string }>): Promise<unknown> {
    rejectControllerOwnedAuthority(input)
    return this.#request('/v1/controller/departments', 'POST', input)
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

  async #post<T>(path: string, body: object): Promise<T> {
    return this.#request(path, 'POST', body)
  }

  async #request<T>(path: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', body?: object): Promise<T> {
    const bearerCredential = (await this.#bearerCredential()).trim()
    if (!bearerCredential) throw new TypeError('A bearer credential is required.')
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${bearerCredential}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const payload: unknown = await response.json()
    if (!response.ok) {
      const message = payload && typeof payload === 'object' && 'error' in payload
        ? String(payload.error)
        : `Gateway request failed with HTTP ${response.status}.`
      throw new Error(message)
    }
    return payload as T
  }
}
