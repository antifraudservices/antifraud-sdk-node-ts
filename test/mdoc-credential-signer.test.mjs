// Flow contract: an authorized projection is signed as an ISO mdoc using a
// managed ES256 key and binds only the verified wallet key. Node generates
// synthetic certificate material for the test without external executables.
import assert from 'node:assert/strict'
import {generateKeyPairSync, sign, verify, webcrypto, X509Certificate} from 'node:crypto'
import test from 'node:test'
import {IssuerSigned} from '@owf/mdoc'
import 'reflect-metadata'
import { X509CertificateGenerator } from '@peculiar/x509'
import {createMdocCredentialSigner} from 'antifraud-sdk-node-ts/mdoc-credential-signer'

test('produces an issuer-signed mdoc bound to the holder and the configured certificate', async () => {
  const order = {name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'}
  const issuer = await webcrypto.subtle.generateKey(order, false, ['sign', 'verify'])
  const now = new Date()
  const notBefore = new Date(now.getTime() - 60_000)
  const notAfter = new Date(now.getTime() + 60_000)
  const certificate = await X509CertificateGenerator.createSelfSigned({
    name: 'CN=synthetic issuer', notBefore, notAfter, signingAlgorithm: order, keys: issuer,
  }, webcrypto)
  const {publicKey, privateKey} = generateKeyPairSync('ec', {namedCurve: 'P-256'})
  const holderKey = publicKey.export({format: 'jwk'})
  const signMdoc = createMdocCredentialSigner({
    certificateChain: [new Uint8Array(certificate.rawData)],
    signEs256: async bytes => new Uint8Array(await webcrypto.subtle.sign(order, issuer.privateKey, bytes)),
  })
  const docType = 'eu.europa.ec.av.1'
  const claims = {age_over_18: true}
  const command = {
    docType, namespaces: {[docType]: claims}, holderKey, signed: now,
    validUntil: new Date(now.getTime() + 30_000),
  }
  const issued = IssuerSigned.fromEncodedForOid4Vci(await signMdoc(command))
  assert.deepEqual(issued.getPrettyClaims(docType), claims)
  const {deviceKey} = issued.issuerAuth.mobileSecurityObject.deviceKeyInfo
  assert.equal(deviceKey.jwk.x, holderKey.x)
  assert.equal(deviceKey.jwk.y, holderKey.y)
  const issuerPublicKey = new X509Certificate(new Uint8Array(certificate.rawData)).publicKey
  assert.equal(verify('sha256', issued.issuerAuth.toBeSigned(),
    {key: issuerPublicKey, dsaEncoding: 'ieee-p1363'}, issued.issuerAuth.signature), true)

  const wrongSigner = createMdocCredentialSigner({
    certificateChain: [new Uint8Array(certificate.rawData)],
    signEs256: async bytes => sign('sha256', bytes, {key: privateKey, dsaEncoding: 'ieee-p1363'}),
  })
  await assert.rejects(wrongSigner(command), /certificate/u)
  await assert.rejects(signMdoc({...command, validUntil: new Date(now.getTime() + 120_000)}), /validity/u)
})
