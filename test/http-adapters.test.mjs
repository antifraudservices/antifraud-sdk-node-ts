// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  AntifraudGatewayClient,
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

test('calls neutral identity and qualification gateway routes without client-owned actor or infrastructure', async () => {
  const requests = []
  const client = new AntifraudGatewayClient({
    baseUrl: 'https://gateway.example',
    bearerCredential: async () => 'opaque-bearer',
    fetch: async (url, init) => {
      requests.push({url, init})
      if (String(url).endsWith('/v1/identity/evidence')) return jsonResponse(201, {
        channel: 'identity-global', transactionId: 'tx:identity:1',
        anchor: {evidenceId: 'identity-evidence:001', targetKinds: ['predicate']},
      })
      return jsonResponse(201, {
        channel: 'qualification-education-eu', transactionId: 'tx:qualification:1',
        status: 'pending-issuer-confirmation', anchor: {evidenceId: 'qualification-evidence:001'},
      })
    },
  })

  await assert.rejects(() => client.recordIdentityEvidence({
    operationId: 'identity-evidence:bad', subjectReference: 'person:opaque', targets: [], evidence: [],
    encryptedClaims: 'jwe', actor: {employeeReference: 'browser-injected'},
  }), /server-owned actor/i)

  const identity = await client.recordIdentityEvidence({
    operationId: 'identity-evidence:001', subjectReference: 'person:employee:opaque',
    targets: [{kind: 'predicate', predicate: 'age-over', sourceSubjectReference: 'person:employee:opaque', sourceClaimPath: 'org.schema.Person.birthDate', threshold: 21, result: true}],
    evidence: [{id: 'check:001', type: 'document', observedAt: '2026-10-17T20:00:00.000Z', checks: [{checkMethod: 'document-review', checkId: 'review:001'}]}],
    encryptedClaims: 'jwe.identity.001',
  })
  assert.equal(identity.channel, 'identity-global')

  const qualification = await client.recordQualificationEvidence({
    evidenceId: 'qualification-evidence:001', subjectReference: 'person:employee:opaque',
    issuer: {legalIdentifier: 'EXAMPLE-UNIVERSITY', jurisdiction: 'ES'},
    qualificationReference: 'qualification:opaque', documentCid: 'zQmOpaque',
    encryptedClaims: 'jwe.qualification.001',
  })
  assert.equal(qualification.channel, 'qualification-education-eu')
  assert.deepEqual(requests.map(request => request.url), [
    'https://gateway.example/v1/identity/evidence',
    'https://gateway.example/v1/education/qualification-evidence',
  ])
  for (const request of requests) {
    assert.equal(request.init.headers.authorization, 'Bearer opaque-bearer')
    assert.equal(request.init.body.includes('actor'), false)
    assert.equal(request.init.body.includes('channel'), false)
    assert.equal(request.init.body.includes('smartContract'), false)
  }
})

test('reads and mutates controller administration without caller-owned organization authority', async () => {
  const requests = []
  const client = new AntifraudGatewayClient({
    baseUrl: 'https://gateway.example',
    bearerCredential: async () => 'controller-bearer',
    fetch: async (url, init) => {
      requests.push({url: String(url), init})
      if (!init || init.method === 'GET') return jsonResponse(200, {organization: {reference: 'organization:one'}, departments: []})
      return jsonResponse(init.method === 'POST' ? 201 : 200, {ok: true})
    },
  })

  await client.readControllerWorkspace()
  await client.createControllerDepartment({name: 'Operations'})
  await client.createControllerGroup({name: 'Reviewers', capabilities: ['identity.evidence.record']})
  await client.createControllerInvitation({email: 'reviewer@example.invalid', role: 'Reviewer', groupReferences: [], departmentReferences: []})
  await client.setControllerEmployeeStatus('employee:one', 'inactive')
  await client.setControllerEmployeeMemberships('employee:one', {groupReferences: [], departmentReferences: []})
  await client.purgeControllerEmployee('employee:one')
  await client.listClearingHouseInbox()
  await client.decideClearingHouseEvidence('evidence:one', {decision: 'confirmed', issuerProofReference: 'proof:issuer:one'})

  await assert.rejects(
    client.createControllerDepartment({name: 'Injected', organizationReference: 'organization:other'}),
    /server-owned actor and organization authority/i,
  )
  assert.deepEqual(requests.map(request => [request.init?.method ?? 'GET', request.url]), [
    ['GET', 'https://gateway.example/v1/controller/workspace'],
    ['POST', 'https://gateway.example/v1/controller/departments'],
    ['POST', 'https://gateway.example/v1/controller/groups'],
    ['POST', 'https://gateway.example/v1/controller/invitations'],
    ['PUT', 'https://gateway.example/v1/controller/employees/employee%3Aone/status'],
    ['PUT', 'https://gateway.example/v1/controller/employees/employee%3Aone/memberships'],
    ['DELETE', 'https://gateway.example/v1/controller/employees/employee%3Aone'],
    ['GET', 'https://gateway.example/v1/clearing-house/inbox'],
    ['POST', 'https://gateway.example/v1/clearing-house/evidence/evidence%3Aone/decision'],
  ])
})
