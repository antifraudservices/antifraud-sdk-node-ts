// Flow contract: reuse shared synthetic fixtures. The tenant URL owns metadata,
// offer, code exchange, nonce and credential. No other issuer can redeem the proof.
import assert from 'node:assert/strict'
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import test from 'node:test'
import { credentialIssuanceRequestFixture } from 'antifraud-data-utils-ts'
import * as sdk from '../dist/index.js'
import { createMdocIssuanceFixture } from './fixtures/mdoc-issuance.mjs'

test('the tenant advertises SD-JWT VC, authenticates a wallet proof and issues once', () => verifyIssuance('dc+sd-jwt'))
test('the tenant advertises mdoc, authenticates a wallet proof and issues once', () => verifyIssuance('mso_mdoc'))
test('a review superseded before wallet redemption cannot be signed', () => verifyIssuance('mso_mdoc', true))

async function verifyIssuance(format, supersedeReview = false) {
  const issuer = 'https://gateway.example/synthetic-tenant/identity/wallet'
  const profile = 'test-professional'
  const mdoc = format === 'mso_mdoc' ? await createMdocIssuanceFixture() : undefined
  const sdJwtFixture = 'synthetic-issuer-signed-jwt~'
  const configuration = mdoc
    ? {format, doctype: mdoc.docType}
    : {format, vct: issuer + '/type'}
  const proofKey = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  const publicKey = proofKey.publicKey.export({ format: 'jwk' })
  const command = { ...credentialIssuanceRequestFixture, actorReference: 'urn:actor:fixture' }
  const records = new Map()
  let pending = Promise.resolve()
  let issuanceCount = 0
  const repository = {
    runTransaction(operation) {
      const result = pending.then(() => operation({
        get: async (collection, id) => structuredClone(records.get(collection)?.get(id)),
        put: async (collection, recordsToWrite) => {
          const entries = records.get(collection) ?? new Map()
          for (const record of recordsToWrite) entries.set(record.id, structuredClone(record))
          records.set(collection, entries)
          return true
        },
      }))
      pending = result.then(() => undefined, () => undefined)
      return result
    },
  }
  const issuerOptions = {
    credentialIssuer: issuer, credentialConfigurations: {[profile]: configuration},
    secret: randomBytes(32),
    store: sdk.createTransactionalWalletOfferStore({credentialIssuer:issuer,repository}),
  }
  const authorizationReference = randomBytes(32).toString('base64url')
  const preparedMdoc = mdoc?.command(publicKey)
  let revision = randomBytes(32).toString('base64url')
  const service = mdoc ? sdk.createReviewedMdocWalletIssuer({
    ...issuerOptions, configurationId: profile, docType: mdoc.docType,
    readReview: async reference => reference === authorizationReference ? {
      revision, validUntil: preparedMdoc.validUntil.getTime(), namespaces: preparedMdoc.namespaces,
    } : undefined,
    sign: async (input) => {
      assert.deepEqual(input.holderKey, publicKey)
      issuanceCount++
      return mdoc.signMdoc(input)
    },
  }) : sdk.createOpenId4VciIssuer({
    ...issuerOptions,
    issue: async (authorized, holderKey, configurationId) => {
      assert.deepEqual(authorized, command)
      assert.deepEqual(holderKey, publicKey)
      assert.equal(configurationId, profile)
      issuanceCount++
      return mdoc ? mdoc.signMdoc(mdoc.command(holderKey)) : sdJwtFixture
    },
  })
  const dispatch = (href, options = {}) => service.handle(new Request(href, options))
  const url = new URL(issuer)
  const metadata = await dispatch(url.origin + '/.well-known/openid-credential-issuer' + url.pathname)
  const published = await metadata.json()
  assert.equal(published.credential_issuer, issuer)
  for (const [key, value] of Object.entries(configuration)) {
    assert.equal(published.credential_configurations_supported[profile][key], value)
  }
  assert.deepEqual(published.credential_configurations_supported[profile].cryptographic_binding_methods_supported,
    [format === 'mso_mdoc' ? 'cose_key' : 'jwk'])
  assert.equal(await dispatch(url.origin + '/.well-known/openid-credential-issuer'), undefined)
  const prepared = mdoc ? await service.prepare(authorizationReference) : await service.prepare(command, profile)
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
  function redeem(audience, signingKey = proofKey.privateKey) {
    const encode = input => Buffer.from(JSON.stringify(input)).toString('base64url')
    const unsigned = `${encode({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: publicKey })}.${encode({
      aud: audience, iat: Math.floor(Date.now()/1000), nonce: c_nonce,
    })}`
    const signature = sign('sha256', Buffer.from(unsigned), {key: signingKey, dsaEncoding: 'ieee-p1363'}).toString('base64url')
    return dispatch(issuer + '/credential', { method: 'POST', headers: {
      authorization: `Bearer ${access_token}`, 'content-type': 'application/json',
    }, body: JSON.stringify({credential_configuration_id: profile, proofs: {jwt: [`${unsigned}.${signature}`]}})})
  }
  assert.equal((await redeem(url.origin)).status, 400)
  const unrelatedWallet = generateKeyPairSync('ec', {namedCurve: 'P-256'})
  assert.equal((await redeem(issuer, unrelatedWallet.privateKey)).status, 400)
  assert.equal(issuanceCount, 0)
  if (supersedeReview) {
    revision = randomBytes(32).toString('base64url')
    const response = await redeem(issuer)
    assert.equal(response.status, 400)
    assert.deepEqual(await response.json(), {error:'credential_request_denied'})
    assert.equal(issuanceCount, 0)
    return
  }
  const attempts = await Promise.all([redeem(issuer), redeem(issuer)])
  const successes = attempts.filter(response => response.status === 200)
  assert.equal(successes.length, 1)
  const issued = successes[0]
  const denied = attempts.find(response => response !== issued)
  assert.deepEqual(await denied.json(), {error: denied.status === 401 ? 'invalid_token' : 'invalid_nonce'})
  assert.ok(denied.status === 400 || denied.status === 401)
  assert.equal(issued.status, 200)
  assert.equal(issued.headers.get('cache-control'), 'no-store')
  const result = await issued.json()
  if (mdoc) {
    assert.equal(result.credentials.length, 1)
    mdoc.assertCredential(result.credentials[0].credential, publicKey)
  } else assert.deepEqual(result, {credentials: [{credential: sdJwtFixture}]})
  assert.equal((await redeem(issuer)).status, 401)
  assert.equal(issuanceCount, 1)
}
