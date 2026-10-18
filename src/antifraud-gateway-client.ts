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

function rejectClientOwnedAuthority(input: object): void {
  for (const property of CLIENT_OWNED_AUTHORITY) {
    if (Object.hasOwn(input, property)) {
      throw new TypeError(`The server-owned actor and infrastructure authority must not be supplied by the client (${property}).`)
    }
  }
}

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

  async #post<T>(path: string, body: object): Promise<T> {
    const bearerCredential = (await this.#bearerCredential()).trim()
    if (!bearerCredential) throw new TypeError('A bearer credential is required.')
    const response = await this.#fetch(`${this.#baseUrl}${path}`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${bearerCredential}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
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
