// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import test from 'node:test'
import {createNautilusV1PublicationClient, createPontusXPublication} from '../dist/index.js'

const fixture = JSON.parse(readFileSync(new URL('./fixtures/pontus-x-publication.json', import.meta.url)))
const {actor, tenantId, datasetId, chainId, walletAddress, otherAddress, receipt} = fixture
const request = {actor, datasetId}
const asset = { ...receipt.ddo, chainId, nft: {owner: walletAddress} }

function setup({
  enabled = 'true', controller = actor, owner = walletAddress,
  authority = 'tenant', allowTenantPublication = true, ...overrides
} = {}) {
  const records = new Map()
  const events = []
  const keyFor = key => JSON.stringify(key)
  const journal = {
    async get(key) {return records.get(keyFor(key))},
    async start(key) {
      const id = keyFor(key)
      if (records.has(id)) return records.get(id)
      records.set(id, {state: 'pending'})
      return {state: 'started'}
    },
    async recordSubmission(key, submission) {
      records.set(keyFor(key), {state: 'submitted', submission})
    },
  }
  const client = createNautilusV1PublicationClient({
    async publish(input) {
      assert.equal(input, datasetId)
      events.push('publish')
      if (overrides.publish) return overrides.publish()
      return receipt
    },
    async getAquariusAsset(did) {
      assert.equal(did, receipt.ddo.id)
      events.push('read')
      if (overrides.read) return overrides.read()
      return asset
    },
  }, {
    async getAddress() {return owner},
    async getChainId() {return chainId},
  })
  const publication = createPontusXPublication({
    env: {PONTUS_X_PUBLICATION_ENABLED: enabled},
    journal,
    async authorize(request) {
      events.push('authorize')
      if (request.actor !== controller) return undefined
      return {
        tenantId, datasetId, chainId, authority, allowTenantPublication,
        tenantWalletAddress: walletAddress, hostWalletAddress: otherAddress,
      }
    },
    async connect(scope) {events.push('connect'); assert.equal(scope.publisher, authority); return client},
    async prepareAsset(scope) {return scope.datasetId},
    projectDataset(ddo, scope) {return {id: ddo.id, source: scope.datasetId}},
  })
  return {publication, events}
}

test('disables publication by default and checks tenant controller access before connecting', async () => {
  const disabled = setup({enabled: ''})
  assert.equal(disabled.publication, undefined)
  assert.deepEqual(disabled.events, [])
  const denied = setup({controller: otherAddress})
  await assert.rejects(denied.publication.publish(request), {code: 'not-authorized'})
  assert.deepEqual(denied.events, ['authorize'])
  const wrongDataset = setup()
  await assert.rejects(wrongDataset.publication.publish({actor, datasetId: receipt.ddo.id}), {code: 'not-authorized'})
  assert.deepEqual(wrongDataset.events, ['authorize'])
})

test('obeys host-only policy and attributes operator publications to the operator wallet', async () => {
  const self = setup({allowTenantPublication: false})
  await assert.rejects(self.publication.publish(request), {code: 'not-authorized'})
  assert.deepEqual(self.events, ['authorize'])
  const operator = setup({
    authority: 'host', allowTenantPublication: false, owner: otherAddress,
    read: async () => ({...asset, nft: {owner: otherAddress}}),
  })
  const result = await operator.publication.publish(request)
  assert.equal(result.publisher, 'host')
  assert.equal(result.owner, otherAddress)
})

test('binds the signer to the enrolled organization', async () => {
  const mismatched = setup({owner: otherAddress})
  await assert.rejects(mismatched.publication.publish(request), {code: 'signer-mismatch'})
  assert.ok(!mismatched.events.includes('publish'))
})

test('returns verified readback and imports it, then reads the same DID on retries', async () => {
  const {publication, events} = setup()
  const result = await publication.publish(request)
  assert.deepEqual(result, {
    did: receipt.ddo.id, transactionHash: receipt.setMetadataTxReceipt.transactionHash,
    publisher: 'tenant', owner: walletAddress,
    catalogue: {id: receipt.ddo.id, source: datasetId},
  })
  assert.deepEqual(await publication.publish(request), result)
  assert.equal(events.filter(event => event === 'publish').length, 1)
  assert.equal(events.filter(event => event === 'read').length, 2)
})

test('retries index readback without minting again and rejects mismatched ownership', async () => {
  let indexed
  const {publication, events} = setup({read: async () => indexed})
  await assert.rejects(publication.publish(request), {code: 'readback-unavailable'})
  indexed = {...asset, nft: {owner: otherAddress}}
  await assert.rejects(publication.publish(request), {code: 'readback-mismatch'})
  indexed = asset
  assert.equal((await publication.publish(request)).did, asset.id)
  assert.equal(events.filter(event => event === 'publish').length, 1)
})

test('requires reconciliation after an ambiguous write and prevents concurrent duplicate submissions', async () => {
  const initiated = Promise.withResolvers()
  const write = Promise.withResolvers()
  const {publication, events} = setup({publish: () => {initiated.resolve(); return write.promise}})
  const first = publication.publish(request)
  await initiated.promise
  await assert.rejects(publication.publish(request), {code: 'reconciliation-required'})
  write.reject(new Error('ambiguous provider failure'))
  await assert.rejects(first, {code: 'reconciliation-required'})
  await assert.rejects(publication.publish(request), {code: 'reconciliation-required'})
  assert.equal(events.filter(event => event === 'publish').length, 1)
})
