// Flow contract: 1. The BFF signs a real login assertion. 2. The SDK submits the registered holder's signed presentation to a local gateway. 3. The gateway checks current authority and returns a bound receipt. 4. The SDK submits a tenant VP through that gateway to a signed test-engine boundary. 5. Replay, revocation, policy mismatch and unknown login are denied. Authorization and persistence invariants: no caller-supplied keys or actor authority, no wallet echo, and the memory provider is never reported as Fabric.
import assert from 'node:assert/strict'
import {createPrivateKey, randomUUID, sign} from 'node:crypto'
import {once} from 'node:events'
import {createServer} from 'node:http'
import test from 'node:test'
import {IdentityAttestationCapability, SyntheticManagedSignatureRequestFixture as fixture} from 'antifraud-data-utils-ts'
import {canonicalRequestDigest, verifyPinnedJwt} from 'antifraud-data-utils-ts/clearing-house'
import {AntifraudGatewayClient} from '../dist/index.js'
import {deriveDeterministicEcJwkPair} from '../dist/examples/deterministic-signing-key.js'

const moduleLocation = process.env.ANTIFRAUD_GATEWAY_TEST_MODULE
if (!moduleLocation || new URL(moduleLocation).protocol !== 'file:') {
  throw new Error('ANTIFRAUD_GATEWAY_TEST_MODULE must identify the compiled local gateway artifact for this live boundary gate.')
}
const gatewayApi = await import(moduleLocation)
function jwt(payload, pair, typ = 'JWT') {
  const header = Buffer.from(JSON.stringify({alg: pair.alg, kid: pair.publicJwk.kid, typ})).toString('base64url')
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signature = sign('sha384', Buffer.from(`${header}.${body}`), {key: createPrivateKey({key: pair.privateJwk, format: 'jwk'}), dsaEncoding: 'ieee-p1363'}).toString('base64url')
  return `${header}.${body}.${signature}`
}
async function listen(server, t) {
  server.listen(0, '127.0.0.1'); await once(server, 'listening')
  t.after(() => {server.closeAllConnections(); server.close()})
  const address = server.address(); assert.ok(address && typeof address === 'object')
  return `http://127.0.0.1:${address.port}`
}

test('proves the high-level SDK, gateway and signed SC-result HTTP boundaries with current-state denials', async t => {
  const previousEnvironment = process.env.NODE_ENV
  process.env.NODE_ENV = 'test'
  t.after(() => {if (previousEnvironment === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previousEnvironment})
  const now = Math.floor(Date.now() / 1000)
  const authKey = deriveDeterministicEcJwkPair({seed: fixture.trustedContext.authenticatedUserId, purpose: fixture.draft.requestId})
  const holderKey = deriveDeterministicEcJwkPair({seed: fixture.trustedContext.registeredDeviceId, purpose: fixture.trustedContext.purpose})
  const issuerKey = deriveDeterministicEcJwkPair({seed: fixture.trustedContext.relyingParty, purpose: fixture.trustedContext.purpose})
  const engineKey = deriveDeterministicEcJwkPair({seed: fixture.draft.manifest.id, purpose: fixture.draft.operationId})
  const actor = {tenantId: fixture.trustedContext.relyingParty, organizationReference: fixture.trustedContext.relyingParty,
    employeeReference: fixture.trustedContext.signerReference, assignmentReference: fixture.trustedContext.authenticatedUserId,
    active: true, groupReferences: [fixture.draft.operationId], capabilities: [IdentityAttestationCapability.VerifyClaim],
    groupAuthorization: {groupReference: fixture.draft.operationId, authorizationReference: fixture.draft.requestId,
      controllerReference: fixture.trustedContext.authenticatedUserId, status: 'active', capabilities: [IdentityAttestationCapability.VerifyClaim]}}
  const request = {nonce: randomUUID(), resourceReference: fixture.draft.manifest.id,
    jurisdiction: 'CA', capability: IdentityAttestationCapability.VerifyClaim}
  const holder = {actor: structuredClone(actor), holderReference: fixture.trustedContext.registeredDeviceId,
    status: 'active', expiresAt: now + 300, jwks: {keys: [holderKey.publicJwk]}}
  const credentialState = {id: fixture.draft.requestId, issuer: actor.tenantId, status: 'active', expiresAt: now + 300}
  const permission = {...request, tenantId: actor.tenantId, organizationReference: actor.organizationReference,
    employeeReference: actor.employeeReference, status: 'active', expiresAt: now + 300, requiredCredentialTypes: ['VerifiableCredential']}
  const authority = {kind: 'memory', async readHolder() {return holder},
    async readIssuer() {return {issuer: actor.tenantId, status: 'active', jwks: {keys: [issuerKey.publicJwk]}}},
    async readCredentialStatus() {return credentialState}, async readPermission() {return permission}}
  const presentationVerifier = new gatewayApi.CredentialPresentationVerifier({networkKind: 'test', authority,
    replay: new gatewayApi.MemoryPresentationReplayStore(), clock: () => now})
  const credential = jwt({iss: actor.tenantId, sub: actor.employeeReference, iat: now, exp: now + 120, jti: fixture.draft.requestId,
    vc: {id: fixture.draft.requestId, type: ['VerifiableCredential'], credentialSubject: {id: actor.employeeReference}}}, issuerKey, 'vc+jwt')
  const professionalVp = () => jwt({iss: holder.holderReference, sub: actor.employeeReference, aud: actor.tenantId,
    iat: now, exp: now + 60, jti: randomUUID(), nonce: request.nonce,
    request_hash: canonicalRequestDigest(request), vp: {verifiableCredential: [credential]}}, holderKey, 'vp+jwt')
  const description = {id: fixture.draft.manifest.id, type: ['VerifiableCredential'],
    issuer: actor.tenantId, credentialSubject: {id: actor.organizationReference}}
  const engine = createServer(async (incoming, response) => {
    let body = ''; for await (const chunk of incoming) body += chunk
    await verifyPinnedJwt(body, {keys: [issuerKey.publicJwk]}, actor.tenantId, now)
    response.writeHead(201, {'content-type': 'application/vc+jwt'})
    response.end(jwt({issuer: {id: fixture.trustedContext.signerReference}, id: fixture.draft.requestId,
      type: ['VerifiableCredential', 'gx:LabelCredential'],
      validFrom: new Date((now - 1) * 1000).toISOString(), validUntil: new Date((now + 60) * 1000).toISOString(),
      credentialSubject: {'gx:labelLevel': 'SC', 'gx:rulesVersion': 'CD25.03',
        'gx:compliantCredentials': [{id: description.id, digestSRI: `sha256-${canonicalRequestDigest(description)}`}]}}, engineKey, 'vc+jwt'))
  })
  const engineUrl = await listen(engine, t)
  const gaiaXVerifier = new gatewayApi.GaiaXComplianceVerifier({clock: () => now, allowLocalTestEndpoint: true,
    authority: {async readSubmissionContext() {return {actor, tenantIssuer: actor.tenantId, tenantKeys: {keys: [issuerKey.publicJwk]},
      trust: {endpoint: engineUrl, issuer: fixture.trustedContext.signerReference, jwks: {keys: [engineKey.publicJwk]}, rulesVersion: 'CD25.03'}}}}})
  const bearer = jwt({iss: actor.tenantId, sub: actor.employeeReference, aud: actor.tenantId,
    iat: now, exp: now + 60, jti: randomUUID()}, authKey)
  const gateway = createServer(gatewayApi.createAntifraudGatewayHttpHandler({
    gateway: new gatewayApi.EducationQualificationGateway({ledger: new gatewayApi.InMemoryQualificationLedger(),
      index: new gatewayApi.InMemoryAddressedReferenceIndex(), directory: new gatewayApi.StaticIssuerDirectory([])}),
    presentationVerifier, gaiaXVerifier,
    async resolveActor(token) {
      try {
        const verified = await verifyPinnedJwt(token, {keys: [authKey.publicJwk]}, actor.tenantId, now, {audience: actor.tenantId})
        return verified.sub === actor.employeeReference ? actor : undefined
      } catch {return undefined}
    },
  }))
  const gatewayUrl = await listen(gateway, t)
  const client = new AntifraudGatewayClient({baseUrl: gatewayUrl, bearerCredential: async () => bearer, allowLocalTestEndpoint: true})
  const presentation = professionalVp()
  const result = await client.verifyCredentialPresentation({request, presentation})
  assert.equal(result.verified, true)
  assert.equal(result.stateProvider, 'memory')
  assert.equal(result.requestHash, canonicalRequestDigest(request))
  assert.equal(JSON.stringify(result).includes(presentation), false)
  await assert.rejects(client.verifyCredentialPresentation({request, presentation}), /400/)
  credentialState.status = 'revoked'
  await assert.rejects(client.verifyCredentialPresentation({request, presentation: professionalVp()}), /400/)
  credentialState.status = 'active'; permission.resourceReference = fixture.draft.operationId
  await assert.rejects(client.verifyCredentialPresentation({request, presentation: professionalVp()}), /400/)
  permission.resourceReference = request.resourceReference
  const tenantVp = jwt({iss: actor.tenantId, iat: now, exp: now + 60, jti: randomUUID(),
    vp: {type: ['VerifiablePresentation'], verifiableCredential: [description]}}, issuerKey, 'vp+jwt')
  const compliance = await client.verifyGaiaXPresentation({presentation: tenantVp})
  assert.equal(compliance.credential.rulesVersion, 'CD25.03')
  assert.deepEqual(compliance.credential.compliantCredentials, [{id: description.id, digestSRI: `sha256-${canonicalRequestDigest(description)}`}])
  assert.equal(JSON.stringify(compliance).includes(tenantVp), false)
  const unknownLogin = new AntifraudGatewayClient({baseUrl: gatewayUrl, bearerCredential: async () => bearer.slice(0, -8), allowLocalTestEndpoint: true})
  await assert.rejects(unknownLogin.verifyCredentialPresentation({request, presentation: professionalVp()}), /401/)
})
