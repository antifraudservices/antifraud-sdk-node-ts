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
