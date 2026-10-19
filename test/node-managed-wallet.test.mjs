// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict'
import test from 'node:test'

import {
  ManagedSigningAlgorithm,
  ManagedSigningKeyPurpose,
  SyntheticManagedSignatureRequestFixture,
  UserPresenceMethod,
} from 'antifraud-data-utils-ts'
import { NodeManagedWallet, createManagedSigningBff } from '../dist/index.js'

const fixture = SyntheticManagedSignatureRequestFixture

test('keeps ML-DSA-65 and ML-KEM-768 private material inside the managed wallet', async () => {
  const wallet = new NodeManagedWallet()
  const publicKeys = await wallet.provision('urn:wallet-owner:synthetic', {
    seedMaterial: 'synthetic-test-seed',
  })

  assert.deepEqual(publicKeys.actorSigning, {
    purpose: ManagedSigningKeyPurpose.ActorSigning,
    algorithm: ManagedSigningAlgorithm.MlDsa65,
    verificationMethod: publicKeys.actorSigning.verificationMethod,
    publicJwk: publicKeys.actorSigning.publicJwk,
  })
  assert.equal(publicKeys.actorSigning.publicJwk.alg, ManagedSigningAlgorithm.MlDsa65)
  assert.equal(publicKeys.documentAtRest.publicJwk.crv, 'ML-KEM-768')
  assert.equal(JSON.stringify(publicKeys).includes('secret'), false)
  assert.equal(JSON.stringify(publicKeys).includes('dBytes'), false)

  const sealed = await wallet.protectArtifact('urn:wallet-owner:synthetic', {
    claims: {name: 'Synthetic confidential evidence'},
  })
  assert.equal(sealed.includes('Synthetic confidential evidence'), false)
  assert.deepEqual(
    await wallet.unprotectArtifact('urn:wallet-owner:synthetic', sealed),
    {claims: {name: 'Synthetic confidential evidence'}},
  )

  const pdfBytes = Buffer.from('%PDF-1.4\nsynthetic attachment\n%%EOF')
  const sealedBytes = await wallet.protectArtifactBytes('urn:wallet-owner:synthetic', pdfBytes)
  assert.equal(sealedBytes.includes('%PDF'), false)
  assert.deepEqual(
    await wallet.unprotectArtifactBytes('urn:wallet-owner:synthetic', sealedBytes),
    new Uint8Array(pdfBytes),
  )

  const other = new NodeManagedWallet()
  await other.provision('urn:wallet-owner:other')
  await assert.rejects(
    other.unprotectArtifact('urn:wallet-owner:other', sealed),
    /recipient|decrypt|authentication|JWE/iu,
  )
})

test('composes local user presence, one-use Core session and verified wallet proof', async () => {
  const wallet = new NodeManagedWallet()
  const ownerId = fixture.trustedContext.authenticatedUserId
  const publicKeys = await wallet.provision(ownerId, {seedMaterial: 'synthetic-test-seed'})
  const bff = createManagedSigningBff({
    wallet,
    userPresence: async ({method}) => ({
      biometricAvailable: true,
      verified: method === UserPresenceMethod.Biometric,
    }),
  })
  const trustedContext = {
    ...fixture.trustedContext,
    signingKey: {
      purpose: ManagedSigningKeyPurpose.ActorSigning,
      algorithm: ManagedSigningAlgorithm.MlDsa65,
      verificationMethod: publicKeys.actorSigning.verificationMethod,
    },
  }
  await bff.create(fixture.draft, trustedContext)
  const context = {
    requestId: fixture.draft.requestId,
    authenticatedUserId: trustedContext.authenticatedUserId,
    registeredDeviceId: trustedContext.registeredDeviceId,
    operationId: fixture.draft.operationId,
    manifestDigest: fixture.draft.manifest.digest,
    relyingParty: trustedContext.relyingParty,
    purpose: trustedContext.purpose,
  }
  await bff.authorize({
    ...context,
    method: UserPresenceMethod.Biometric,
    authorizedAt: '2026-10-18T20:01:00.000Z',
  })
  const proof = await bff.sign({...context, signedAt: '2026-10-18T20:02:00.000Z'})

  assert.equal(proof.status, 'verified')
  assert.equal(proof.verificationMethod, publicKeys.actorSigning.verificationMethod)
  assert.equal(await wallet.verifyManagedProof(proof), true)
  await assert.rejects(
    bff.sign({...context, signedAt: '2026-10-18T20:02:00.000Z'}),
    /already consumed/u,
  )
})
