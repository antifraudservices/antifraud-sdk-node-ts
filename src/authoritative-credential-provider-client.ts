import {
  parseCredentialIssuanceReceiptWire,
  toCredentialIssuanceRequestWire,
  type CredentialIssuanceReceipt,
  type CredentialIssuanceRequest,
} from 'antifraud-data-utils-ts'
import {
  createCredentialIssuanceController,
  type CredentialIssuanceController,
  type CredentialIssuanceControllerOptions,
} from 'antifraud-sdk-core-ts'

export type {
  CredentialIssuanceReceipt,
  CredentialIssuanceRequest,
} from 'antifraud-data-utils-ts'

export interface AuthoritativeCredentialProviderClientOptions {
  baseUrl: string
  bearerCredential?: () => Promise<string>
  fetch?: typeof globalThis.fetch
}

export class AuthoritativeCredentialProviderClient {
  private readonly baseUrl: string
  private readonly bearerCredential: (() => Promise<string>) | undefined
  private readonly fetch: typeof globalThis.fetch

  constructor(options: AuthoritativeCredentialProviderClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '')
    this.bearerCredential = options.bearerCredential
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  private async headers(contentType = false): Promise<Record<string, string>> {
    const headers: Record<string, string> = { accept: 'application/json' }
    if (contentType) headers['content-type'] = 'application/json'
    if (this.bearerCredential) {
      headers.authorization = `Bearer ${await this.bearerCredential()}`
    }
    return headers
  }

  async requestIssuance(
    input: CredentialIssuanceRequest & Record<string, unknown>,
  ): Promise<CredentialIssuanceReceipt> {
    if ('claims' in input) {
      throw new Error('Caller-supplied claims are not accepted; the provider must perform authoritative readback')
    }
    const response = await this.fetch(`${this.baseUrl}/credential-issuances`, {
      method: 'POST',
      headers: await this.headers(true),
      body: JSON.stringify(toCredentialIssuanceRequestWire(input)),
    })
    if (!response.ok) {
      throw new Error(`Credential issuance request failed with HTTP ${response.status}`)
    }
    return parseCredentialIssuanceReceiptWire(await response.json())
  }

  /** Prepares a wallet offer for a reference that the issuer resolves and authorizes. */
  async requestWalletCredentialOffer(authorizationReference: string): Promise<{offerUri: string; transactionCode: string}> {
    if (typeof authorizationReference !== 'string' || !authorizationReference.trim() || authorizationReference.length > 1024) {
      throw new TypeError('An opaque wallet authorization reference is required')
    }
    const issuer = new URL(this.baseUrl)
    const issuerPath = issuer.pathname === '/' ? '' : issuer.pathname
    if (issuer.protocol !== 'https:' || `${issuer.origin}${issuerPath}` !== this.baseUrl
      || !/^(?:\/[A-Za-z0-9._~-]+)*$/u.test(issuerPath)) {
      throw new TypeError('Wallet offers require a trusted HTTPS issuer URL')
    }
    const offerPath = `${issuerPath}/credential-offers`
    const headers = await this.headers(true)
    if (!/^Bearer \S+$/.test(headers.authorization ?? '')) throw new Error('Wallet offers require backend authentication')
    const response = await this.fetch(`${this.baseUrl}/credential-offers`, {
      method: 'POST', headers, redirect: 'error', signal: AbortSignal.timeout(10000),
      body: JSON.stringify({authorization_reference: authorizationReference}),
    })
    if (response.status !== 201) throw new Error(`Wallet offer request failed with HTTP ${response.status}`)
    const value: unknown = await response.json()
    if (!value || typeof value !== 'object') throw new Error('Invalid wallet offer response')
    const {offerUri, transactionCode} = value as Record<string, unknown>
    if (typeof offerUri !== 'string' || typeof transactionCode !== 'string' || !/^\d{6}$/u.test(transactionCode)) {
      throw new Error('Invalid wallet offer response')
    }
    const offer = new URL(offerUri)
    const referencePrefix = `${offerPath}/`
    if (offer.origin !== issuer.origin || offer.href !== offerUri
      || offer.username || offer.password || offer.search || offer.hash
      || !offer.pathname.startsWith(referencePrefix)
      || !/^[A-Za-z0-9_-]{43}$/u.test(offer.pathname.slice(referencePrefix.length))) {
      throw new Error('Wallet offer URL does not match the trusted issuer')
    }
    return {offerUri: offer.href, transactionCode}
  }

  async getIssuance(issuanceId: string): Promise<CredentialIssuanceReceipt> {
    const response = await this.fetch(
      `${this.baseUrl}/credential-issuances/${encodeURIComponent(issuanceId)}`,
      { headers: await this.headers() },
    )
    if (!response.ok) {
      throw new Error(`Credential issuance lookup failed with HTTP ${response.status}`)
    }
    return parseCredentialIssuanceReceiptWire(await response.json())
  }
}

export interface AuthoritativeCredentialIssuanceControllerOptions
  extends AuthoritativeCredentialProviderClientOptions {
  wait?: CredentialIssuanceControllerOptions['wait']
}

function waitWithTimer(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds))
}

export function createAuthoritativeCredentialIssuanceController(
  options: AuthoritativeCredentialIssuanceControllerOptions,
): CredentialIssuanceController {
  return createCredentialIssuanceController({
    provider: new AuthoritativeCredentialProviderClient(options),
    wait: options.wait ?? waitWithTimer,
  })
}
