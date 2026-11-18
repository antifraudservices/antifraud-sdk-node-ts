// Flow contract: send presentation and Gaia-X submissions only to the authenticated gateway routes, bind safe receipts to the request, project only SC metadata, and never expose a wallet input or arbitrary disclosed claims through results or errors. Fetch doubles isolate transport parsing; the separate live gateway test proves the real HTTP/cryptographic boundary.
import assert from 'node:assert/strict'
import test from 'node:test'
import {IdentityAttestationCapability, SyntheticManagedSignatureRequestFixture as fixture} from 'antifraud-data-utils-ts'
import {AntifraudGatewayClient} from '../dist/index.js'

const request = {nonce: fixture.draft.requestId, resourceReference: fixture.draft.manifest.id,
  jurisdiction: 'CA', capability: IdentityAttestationCapability.VerifyClaim}
// Shape-only JWTs are transport fixtures, not authenticated or cryptographically verified evidence.
const compact = (payload, typ) => [
  Buffer.from(JSON.stringify({alg: 'ES384', typ, kid: fixture.trustedContext.signingKey.verificationMethod})).toString('base64url'),
  Buffer.from(JSON.stringify(payload)).toString('base64url'), Buffer.from('synthetic-signature').toString('base64url'),
].join('.')
const presentation = compact({vp: {type: ['VerifiablePresentation']}}, 'vp+jwt')
const receipt = {verified: true, tenantReference: fixture.trustedContext.relyingParty,
  actorReference: fixture.trustedContext.signerReference, credentialReferences: [fixture.draft.requestId],
  requestHash: 'c5fb43bf057ca4a12eb681cec5d4051c1a288b06c17c7dbb347a0761d38b9e26', checkedAt: fixture.draft.createdAt, stateProvider: 'memory'}
const sc = {issuer: fixture.trustedContext.signerReference, id: fixture.draft.requestId,
  type: ['VerifiableCredential', 'gx:LabelCredential'], validFrom: fixture.draft.createdAt, validUntil: fixture.draft.expiresAt,
  credentialSubject: {'gx:labelLevel': 'SC', 'gx:rulesVersion': 'CD25.03',
    'gx:compliantCredentials': [{id: fixture.draft.manifest.id, digestSRI: `sha256-${'a'.repeat(64)}`}]}}

test('exposes the two high-level verification client operations', () => {
  assert.equal(typeof AntifraudGatewayClient.prototype.verifyCredentialPresentation, 'function')
  assert.equal(typeof AntifraudGatewayClient.prototype.verifyGaiaXPresentation, 'function')
})
test('uses bearer-authenticated gateway routes and returns only safe request-bound metadata', async () => {
  const calls = []
  const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty,
    bearerCredential: async () => fixture.draft.operationId,
    async fetch(url, init) {calls.push({url, init});return new Response(JSON.stringify({...receipt, vp_token: presentation, disclosedClaims: {private: true}}))}})
  assert.deepEqual(await client.verifyCredentialPresentation({request, presentation}), receipt)
  assert.equal(calls[0].url.endsWith('/v1/clearing-house/presentations/verify'), true)
  assert.equal(calls[0].init.headers.authorization, `Bearer ${fixture.draft.operationId}`)
  assert.equal(calls[0].init.redirect, 'error')
  assert.ok(calls[0].init.signal instanceof AbortSignal)
  assert.deepEqual(JSON.parse(calls[0].init.body), {request, presentation})
})
test('preserves the signed SC artifact while projecting no arbitrary engine fields', async () => {
  const credentialJwt = compact(sc, 'vc+jwt')
  const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty,
    bearerCredential: async () => fixture.draft.operationId,
    async fetch() {return new Response(JSON.stringify({credentialJwt, credential: {...sc, privateClaims: {name: 'not-returned'}}, vp_token: presentation}))}})
  const result = await client.verifyGaiaXPresentation({presentation})
  assert.equal(result.credentialJwt, credentialJwt)
  assert.deepEqual(result.credential, {id: sc.id, type: sc.type, issuer: sc.issuer, validFrom: sc.validFrom, validUntil: sc.validUntil,
    rulesVersion: sc.credentialSubject['gx:rulesVersion'], compliantCredentials: sc.credentialSubject['gx:compliantCredentials']})
  assert.equal(JSON.stringify(result).includes(presentation), false)
  assert.equal(JSON.stringify(result.credential).includes('privateClaims'), false)
})
test('rejects client-selected authority before transport', async () => {
  const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty,
    bearerCredential: async () => fixture.draft.operationId, async fetch() {assert.fail('invalid authority must not reach transport')}})
  await assert.rejects(client.verifyCredentialPresentation({request, presentation, actor: fixture.trustedContext.signerReference}), /server-owned|authority|submission/i)
  await assert.rejects(client.verifyCredentialPresentation({request: {...request, jwks: {keys: []}}, presentation}), /authority|request/i)
  await assert.rejects(client.verifyGaiaXPresentation({presentation, endpoint: fixture.trustedContext.relyingParty}), /authority|submission/i)
})
test('does not turn failed, substituted or malformed results into verification', async () => {
  for (const value of [{...receipt, verified: false}, {...receipt, requestHash: '0'.repeat(64)}, {...receipt, credentialReferences: [presentation]}]) {
    const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty, bearerCredential: async () => fixture.draft.operationId,
      async fetch() {return new Response(JSON.stringify(value))}})
    await assert.rejects(client.verifyCredentialPresentation({request, presentation}))
  }
  for (const value of [{credentialJwt: presentation, credential: sc}, {credentialJwt: compact({...sc, type: ['VerifiablePresentation']}, 'vc+jwt'), credential: sc}, {credentialJwt: 'unsigned', credential: sc}]) {
    const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty, bearerCredential: async () => fixture.draft.operationId,
      async fetch() {return new Response(JSON.stringify(value))}})
    await assert.rejects(client.verifyGaiaXPresentation({presentation}))
  }
})
test('does not expose a wallet presentation or disclosed claims through gateway errors', async () => {
  const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty, bearerCredential: async () => fixture.draft.operationId,
    async fetch() {return new Response(JSON.stringify({error: `private ${presentation}`}), {status: 403})}})
  await assert.rejects(client.verifyCredentialPresentation({request, presentation}), error => {
    assert.match(error.message, /403/); assert.equal(error.message.includes(presentation), false); return true
  })
})


test('does not submit verification to an unencrypted public endpoint', async () => {
  const client = new AntifraudGatewayClient({baseUrl: fixture.trustedContext.relyingParty.replace('https:', 'http:'),
    bearerCredential: async () => fixture.draft.operationId, async fetch() {assert.fail('plaintext public transport is forbidden')}})
  await assert.rejects(client.verifyCredentialPresentation({request, presentation}), /HTTPS|endpoint/i)
})
