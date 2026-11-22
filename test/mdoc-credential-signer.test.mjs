// Flow contract: an authorized projection is signed as an ISO mdoc using a
// managed ES256 key and binds only the verified wallet key. Node generates
// synthetic certificate material for the test without external executables.
import assert from 'node:assert/strict'
import {generateKeyPairSync, sign} from 'node:crypto'
import test from 'node:test'
import {createMdocCredentialSigner} from 'antifraud-sdk-node-ts/mdoc-credential-signer'
import {createMdocIssuanceFixture} from './fixtures/mdoc-issuance.mjs'

test('produces an issuer-signed mdoc bound to the holder and the configured certificate', async () => {
  const fixture = await createMdocIssuanceFixture()
  const {publicKey, privateKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'})
  const holderKey = publicKey.export({format: 'jwk'})
  const command = fixture.command(holderKey)
  fixture.assertCredential(await fixture.signMdoc(command), holderKey)

  const wrongSigner = createMdocCredentialSigner({
    certificateChain: fixture.certificateChain,
    signEs256: async bytes => sign('sha256', bytes, {key: privateKey, dsaEncoding: 'ieee-p1363'}),
  })
  await assert.rejects(wrongSigner(command), /certificate/u)
  await assert.rejects(fixture.signMdoc({...command, validUntil: new Date(command.signed.getTime() + 120_000)}), /validity/u)
})
