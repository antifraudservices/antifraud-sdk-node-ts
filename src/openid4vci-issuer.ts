import type {JsonWebKey} from 'node:crypto'
import {defineCredentialIssuanceRequest} from 'antifraud-data-utils-ts'
import {parseOpenIdIssuerUrl} from './openid-issuer-url.js'
import {verifyWalletProof} from './openid4vci-holder-proof.js'
import {
  createPreAuthorizedWalletOffers, preAuthorizedCodeGrantType,
  type PreAuthorizedWalletOfferOptions, type WalletIssuanceCommand,
} from './preauthorized-wallet-offers.js'

export type OpenId4VciIssuerOptions = Readonly<PreAuthorizedWalletOfferOptions & {
  credentialConfigurations: Readonly<Record<string, {format: 'dc+sd-jwt'; vct: string; scope?: string}>>
  /** Recheck issuer policy against current authoritative state, then sign. */
  issue(command: WalletIssuanceCommand, holderKey: JsonWebKey, configurationId: string): Promise<string | undefined>
}>

const noStore = {'cache-control': 'no-store', pragma: 'no-cache'}
const requestError = (status: number, error: string) => Response.json({error}, {status, headers: noStore})

async function boundedBody(request: Request, maxBytes: number): Promise<string | undefined> {
  const reader = request.body?.getReader()
  if (!reader) return undefined
  const chunks: Uint8Array[] = []
  let received = 0
  try {
    for (;;) {
      const chunk = await reader.read()
      if (chunk.done) return received ? Buffer.concat(chunks, received).toString('utf8') : undefined
      received += chunk.value.byteLength
      if (received > maxBytes) {
        await reader.cancel()
        return undefined
      }
      chunks.push(chunk.value)
    }
  } finally {
    reader.releaseLock()
  }
}

function readCredentialRequest(raw: string | undefined) {
  try {
    const value: unknown = JSON.parse(raw ?? '')
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 2) return undefined
    const {credential_configuration_id: configurationId, proofs} = value as Record<string, unknown>
    if (typeof configurationId !== 'string' || !proofs || typeof proofs !== 'object'
      || Object.keys(proofs).length !== 1 || !('jwt' in proofs) || !Array.isArray(proofs.jwt)
      || proofs.jwt.length !== 1 || typeof proofs.jwt[0] !== 'string') return undefined
    return {configurationId, proof: proofs.jwt[0]}
  } catch {
    return undefined
  }
}

/** Serves one tenant issuer. Account authorization and key custody are supplied by its host. */
export function createOpenId4VciIssuer(options: OpenId4VciIssuerOptions) {
  const {credentialIssuer, credentialConfigurations} = options
  const issuerUrl = parseOpenIdIssuerUrl(credentialIssuer)
  const issuerPath = issuerUrl.pathname === '/' ? '' : issuerUrl.pathname
  const offerPath = `${issuerPath}/credential-offers`
  const offers = createPreAuthorizedWalletOffers(options)
  const now = options.now ?? Date.now
  const ids = Object.keys(credentialConfigurations)
  if (!ids.length || ids.some(id => !id || !credentialConfigurations[id]?.vct)) {
    throw new TypeError('At least one configured credential is required')
  }

  async function redeem(request: Request) {
    const token = /^Bearer (\S+)$/iu.exec(request.headers.get('authorization') ?? '')?.[1]
    const grant = token ? await offers.resolveGrant(token) : undefined
    if (!grant) return Response.json({error: 'invalid_token'}, {
      status: 401, headers: {...noStore, 'www-authenticate': 'Bearer error="invalid_token"'},
    })
    if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/json') {
      return requestError(400, 'invalid_credential_request')
    }
    const input = readCredentialRequest(await boundedBody(request, 16 * 1024))
    if (!input || input.configurationId !== grant.configurationId) return requestError(400, 'invalid_credential_request')
    let proof: ReturnType<typeof verifyWalletProof>
    try {
      proof = verifyWalletProof(input.proof, credentialIssuer, now())
    } catch {
      return requestError(400, 'invalid_proof')
    }
    if (!await grant.consumeNonce(proof.nonce, grant.command)) return requestError(400, 'invalid_nonce')
    const credential = await options.issue(grant.command, proof.holderKey, grant.configurationId)
    if (!credential) return requestError(400, 'credential_request_denied')
    if (!credential.endsWith('~')) throw new Error('The signer must return a serialized SD-JWT credential')
    return Response.json({credentials: [{credential}]}, {headers: noStore})
  }

  async function exchange(request: Request) {
    if (request.headers.get('content-type')?.split(';')[0]?.trim() !== 'application/x-www-form-urlencoded') {
      return requestError(400, 'invalid_request')
    }
    const raw = await boundedBody(request, 8192)
    const form = new URLSearchParams(raw)
    const required = ['grant_type', 'pre-authorized_code', 'tx_code']
    if (required.some(key => form.getAll(key).length !== 1) || form.getAll('client_id').length > 1) {
      return requestError(400, 'invalid_request')
    }
    if (form.get('grant_type') !== preAuthorizedCodeGrantType) return requestError(400, 'unsupported_grant_type')
    const token = await offers.exchange(form.get('pre-authorized_code')!, form.get('tx_code')!)
    return token ? Response.json(token, {headers: noStore}) : requestError(400, 'invalid_grant')
  }

  return {
    async prepare(command: WalletIssuanceCommand, configurationId: string) {
      if (!Object.hasOwn(credentialConfigurations, configurationId)) throw new TypeError('Unknown credential configuration')
      const validated = defineCredentialIssuanceRequest(command)
      return offers.prepare({...validated, actorReference: command.actorReference}, configurationId)
    },
    /** Unrelated routes are left to the owning gateway. */
    async handle(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url)
      if (url.origin !== issuerUrl.origin) return undefined
      const {pathname} = url
      if (request.method === 'GET') {
        if (pathname === `/.well-known/openid-credential-issuer${issuerPath}`) return Response.json({
          credential_issuer: credentialIssuer, authorization_servers: [credentialIssuer],
          credential_endpoint: `${credentialIssuer}/credential`, nonce_endpoint: `${credentialIssuer}/nonce`,
          credential_configurations_supported: Object.fromEntries(Object.entries(credentialConfigurations)
            .map(([id, configuration]) => [id, {...configuration, cryptographic_binding_methods_supported: ['jwk'],
              proof_types_supported: {jwt: {proof_signing_alg_values_supported: ['ES256']}}}])),
        })
        if (pathname === `/.well-known/oauth-authorization-server${issuerPath}`) return Response.json({
          issuer: credentialIssuer, token_endpoint: `${credentialIssuer}/token`,
          grant_types_supported: [preAuthorizedCodeGrantType], token_endpoint_auth_methods_supported: ['none'],
          'pre-authorized_grant_anonymous_access_supported': true,
        })
        if (pathname.startsWith(offerPath + '/')) {
          const offer = await offers.readOffer(pathname.slice(offerPath.length + 1))
          return offer ? Response.json(offer, {headers: noStore}) : requestError(404, 'not_found')
        }
      }
      if (request.method === 'POST') {
        if (pathname === `${issuerPath}/token`) return exchange(request)
        if (pathname === `${issuerPath}/nonce`) return Response.json({c_nonce: await offers.issueNonce()}, {headers: noStore})
        if (pathname === `${issuerPath}/credential`) return redeem(request)
      }
      return undefined
    },
  }
}
