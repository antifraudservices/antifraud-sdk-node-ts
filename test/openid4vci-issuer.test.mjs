// Flow contract: reuse shared synthetic fixtures. The tenant URL owns metadata,
// offer, code exchange, nonce and credential. No other issuer can redeem the proof.
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import test from 'node:test'
import { credentialIssuanceRequestFixture } from 'antifraud-data-utils-ts'
import { createOpenId4VciIssuer } from '../dist/index.js'

test('the tenant serves its own metadata, authenticates a wallet proof and issues once', async () => {
  const issuer = 'https://gateway.example/synthetic-tenant/identity/wallet'
  const profile = 'test-professional'
  const proofKey = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKey = proofKey.publicKey.export({ format: 'jwk' })
  const command = { ...credentialIssuanceRequestFixture, actorReference: 'urn:actor:fixture' }
  const records = new Map()
  let issuanceCount = 0
  const service = createOpenId4VciIssuer({
    credentialIssuer: issuer, credentialConfigurations: {[profile]: {format: 'dc+sd-jwt', vct: issuer + '/type'}},
    secret: randomBytes(32),
    store: {
      create: async (ref, state) => { records.set(ref, state) },
      read: async ref => records.get(ref),
      compareAndSet: async (ref, revision, state) => {
        if (records.get(ref)?.revision !== revision) return false
        records.set(ref, state)
        return true
      },
      consumeForIssuance: async ({ reference, revision }) => {
        if (records.get(reference)?.revision !== revision) return false
        records.delete(reference)
        return true
      },
    },
    issue: async (authorized, holderKey, configurationId) => {
      assert.deepEqual(authorized, command)
      assert.deepEqual(holderKey, publicKey)
      assert.equal(configurationId, profile)
      issuanceCount++
      return 'synthetic-issuer-signed-jwt~'
    },
  })
  const dispatch = (href, options = {}) => service.handle(new Request(href, options))
  const url = new URL(issuer)
  const metadata = await dispatch(url.origin + '/.well-known/openid-credential-issuer' + url.pathname)
  assert.equal((await metadata.json()).credential_issuer, issuer)
  assert.equal(await dispatch(url.origin + '/.well-known/openid-credential-issuer'), undefined)
  const prepared = await service.prepare(command, profile)
  assert.ok(prepared.offerUri.startsWith(issuer + '/credential-offers/'))
  const offer = await (await dispatch(prepared.offerUri)).json()
  assert.equal(offer.credential_issuer, issuer)
  const [grant] = Object.keys(offer.grants)
  const tokenResponse = await dispatch(issuer + '/token', {method: 'POST', body: new URLSearchParams({
    grant_type: grant, tx_code: prepared.transactionCode, 'pre-authorized_code': offer.grants[grant]['pre-authorized_code'],
  })})
  assert.equal(tokenResponse.status, 200)
  const {access_token} = await tokenResponse.json()
  const {c_nonce} = await (await dispatch(issuer + '/nonce', {method: 'POST'})).json()
  function redeem(audience) {
    const encode = input => Buffer.from(JSON.stringify(input)).toString('base64url')
    const unsigned = `${encode({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: publicKey })}.${encode({
      aud: audience, iat: Math.floor(Date.now()/1000), nonce: c_nonce,
    })}`
    const signature = sign('sha256', Buffer.from(unsigned), {key: proofKey.privateKey, dsaEncoding: 'ieee-p1363'}).toString('base64url')
    return dispatch(issuer + '/credential', { method: 'POST', headers: {
      authorization: `Bearer ${access_token}`, 'content-type': 'application/json',
    }, body: JSON.stringify({credential_configuration_id: profile, proofs: {jwt: [`${unsigned}.${signature}`]}})})
  }
  assert.equal((await redeem(url.origin)).status, 400)
  assert.equal(issuanceCount, 0)
  const issued = await redeem(issuer)
  assert.equal(issued.status, 200)
  assert.equal(issued.headers.get('cache-control'), 'no-store')
  assert.equal((await redeem(issuer)).status, 401)
  assert.equal(issuanceCount, 1)
})
