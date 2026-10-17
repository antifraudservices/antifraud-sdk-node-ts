export interface PresentationTransaction {
  transaction_id: string
  client_id: string
  request_uri: string
  request_uri_method: 'get' | 'post' | 'post_get'
}

export type PresentationResult =
  | { outcome: 'pending' }
  | { outcome: 'verified' }
  | { outcome: 'denied'; reason?: string }
  | { outcome: 'failed'; reason?: string }

export interface PresentationInitialization {
  dcqlQuery: unknown
  nonce: string
}

export interface EudiVerifierClientOptions {
  baseUrl: string
  fetch?: typeof globalThis.fetch
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

function parseTransaction(value: unknown): PresentationTransaction {
  if (!value || typeof value !== 'object') {
    throw new Error('Invalid EUDI verifier transaction response')
  }
  const candidate = value as Record<string, unknown>
  const method = candidate.request_uri_method
  if (
    !isNonEmptyString(candidate.transaction_id)
    || !isNonEmptyString(candidate.client_id)
    || !isNonEmptyString(candidate.request_uri)
    || (method !== 'get' && method !== 'post' && method !== 'post_get')
  ) {
    throw new Error('Invalid EUDI verifier transaction response')
  }
  return candidate as unknown as PresentationTransaction
}

function optionalReason(candidate: Record<string, unknown>): { reason?: string } {
  return isNonEmptyString(candidate.reason) ? { reason: candidate.reason } : {}
}

export class EudiVerifierClient {
  private readonly baseUrl: string
  private readonly fetch: typeof globalThis.fetch

  constructor(options: EudiVerifierClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  async initialize(input: PresentationInitialization): Promise<PresentationTransaction> {
    const response = await this.fetch(`${this.baseUrl}/ui/presentations`, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({
        type: 'vp_token',
        dcql_query: input.dcqlQuery,
        nonce: input.nonce,
        response_mode: 'direct_post.jwt',
        jar_mode: 'by_reference',
        request_uri_method: 'get',
        authorization_request_scheme: 'haip-vp',
        profile: 'haip',
      }),
    })
    if (!response.ok) {
      throw new Error(`EUDI verifier initialization failed with HTTP ${response.status}`)
    }
    return parseTransaction(await response.json())
  }

  async getResult(transactionId: string): Promise<PresentationResult> {
    const response = await this.fetch(
      `${this.baseUrl}/ui/presentations/${encodeURIComponent(transactionId)}`,
      { headers: { accept: 'application/json' } },
    )
    if (response.status === 404) return { outcome: 'pending' }
    if (!response.ok) {
      throw new Error(`EUDI verifier response lookup failed with HTTP ${response.status}`)
    }

    const value: unknown = await response.json()
    if (!value || typeof value !== 'object') {
      throw new Error('Invalid EUDI verifier result')
    }
    const candidate = value as Record<string, unknown>
    if ('vp_token' in candidate) return { outcome: 'verified' }
    if (candidate.outcome === 'verified') return { outcome: 'verified' }
    if (candidate.outcome === 'denied' || candidate.outcome === 'failed') {
      return { outcome: candidate.outcome, ...optionalReason(candidate) }
    }
    throw new Error('Invalid EUDI verifier result')
  }
}

