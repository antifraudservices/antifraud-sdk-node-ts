// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  AuthoritativeCredentialProviderClient,
  EudiVerifierClient,
} from '../dist/index.js'

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {'content-type': 'application/json'},
  })
}

test('initializes a by-reference HAIP presentation and returns opaque continuity', async () => {
  const requests = []
  const client = new EudiVerifierClient({
    baseUrl: 'https://verifier.example',
    fetch: async (url, init) => {
      requests.push({url, init})
      return jsonResponse(200, {
        transaction_id: 'opaque-transaction',
        client_id: 'x509_san_dns:verifier.example',
        request_uri: 'https://verifier.example/request/opaque',
        request_uri_method: 'get',
      })
    },
  })

  const transaction = await client.initialize({
    dcqlQuery: {credentials: []},
    nonce: 'opaque-nonce',
  })

  assert.equal(transaction.transaction_id, 'opaque-transaction')
  assert.deepEqual(JSON.parse(requests[0].init.body), {
    type: 'vp_token',
    dcql_query: {credentials: []},
    nonce: 'opaque-nonce',
    response_mode: 'direct_post.jwt',
    jar_mode: 'by_reference',
    request_uri_method: 'get',
    authorization_request_scheme: 'haip-vp',
    profile: 'haip',
  })
})

test('maps a wallet response to verified without returning the presentation', async () => {
  const client = new EudiVerifierClient({
    baseUrl: 'https://verifier.example',
    fetch: async () => jsonResponse(200, {
      vp_token: {credential: ['sensitive-wallet-presentation']},
    }),
  })

  const result = await client.getResult('opaque-transaction')

  assert.deepEqual(result, {outcome: 'verified'})
  assert.equal(JSON.stringify(result).includes('sensitive-wallet-presentation'), false)
})

test('requests provider issuance with references and rejects caller claims', async () => {
  const requests = []
  const client = new AuthoritativeCredentialProviderClient({
    baseUrl: 'https://provider.example',
    fetch: async (url, init) => {
      requests.push({url, init})
      return jsonResponse(202, {
        issuance_id: 'opaque-issuance',
        status: 'pending',
      })
    },
  })

  await assert.rejects(
    client.requestIssuance({
      subjectReference: 'urn:subject:opaque',
      capability: 'identity.relationship.attest',
      verificationTransactionId: 'opaque-transaction',
      claims: {name: 'caller supplied'},
    }),
    /Caller-supplied claims are not accepted/,
  )

  const result = await client.requestIssuance({
    subjectReference: 'urn:subject:opaque',
    capability: 'identity.relationship.attest',
    verificationTransactionId: 'opaque-transaction',
  })

  assert.deepEqual(result, {issuanceId: 'opaque-issuance', status: 'pending'})
  assert.deepEqual(JSON.parse(requests[0].init.body), {
    subject_reference: 'urn:subject:opaque',
    capability: 'identity.relationship.attest',
    verification_transaction_id: 'opaque-transaction',
  })
})

