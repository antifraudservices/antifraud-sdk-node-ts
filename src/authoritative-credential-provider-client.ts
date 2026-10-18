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
  fetch?: typeof globalThis.fetch
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
      { headers: { accept: 'application/json' } },
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
