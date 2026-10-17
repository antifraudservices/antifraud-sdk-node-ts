export interface CredentialIssuanceRequest {
  subjectReference: string
  capability: string
  verificationTransactionId: string
}

export type CredentialIssuanceStatus = 'pending' | 'issued' | 'denied' | 'failed'

export interface CredentialIssuanceReceipt {
  issuanceId: string
  status: CredentialIssuanceStatus
  credential?: unknown
  credentialReference?: string
  reason?: string
}

export interface AuthoritativeCredentialProviderClientOptions {
  baseUrl: string
  fetch?: typeof globalThis.fetch
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function parseReceipt(value: unknown): CredentialIssuanceReceipt {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid credential-provider response')
  }
  const candidate = value as Record<string, unknown>
  const status = candidate.status
  if (
    !isNonEmptyString(candidate.issuance_id)
    || (status !== 'pending' && status !== 'issued' && status !== 'denied' && status !== 'failed')
  ) {
    throw new Error('Invalid credential-provider response')
  }
  return {
    issuanceId: candidate.issuance_id,
    status,
    ...('credential' in candidate ? { credential: candidate.credential } : {}),
    ...(isNonEmptyString(candidate.credential_reference)
      ? { credentialReference: candidate.credential_reference }
      : {}),
    ...(isNonEmptyString(candidate.reason) ? { reason: candidate.reason } : {}),
  }
}

export class AuthoritativeCredentialProviderClient {
  private readonly baseUrl: string
  private readonly fetch: typeof globalThis.fetch

  constructor(options: AuthoritativeCredentialProviderClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  async requestIssuance(
    input: CredentialIssuanceRequest & Record<string, unknown>,
  ): Promise<CredentialIssuanceReceipt> {
    if ('claims' in input) {
      throw new Error('Caller-supplied claims are not accepted; the provider must perform authoritative readback')
    }
    const response = await this.fetch(`${this.baseUrl}/credential-issuances`, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({
        subject_reference: input.subjectReference,
        capability: input.capability,
        verification_transaction_id: input.verificationTransactionId,
      }),
    })
    if (!response.ok) {
      throw new Error(`Credential issuance request failed with HTTP ${response.status}`)
    }
    return parseReceipt(await response.json())
  }

  async getIssuance(issuanceId: string): Promise<CredentialIssuanceReceipt> {
    const response = await this.fetch(
      `${this.baseUrl}/credential-issuances/${encodeURIComponent(issuanceId)}`,
      { headers: { accept: 'application/json' } },
    )
    if (!response.ok) {
      throw new Error(`Credential issuance lookup failed with HTTP ${response.status}`)
    }
    return parseReceipt(await response.json())
  }
}

