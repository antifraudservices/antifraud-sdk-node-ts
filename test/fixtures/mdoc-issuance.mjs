// Flow contract: use a synthetic certificate to verify issuer signing and wallet key binding.
import assert from 'node:assert/strict'
import {verify, webcrypto, X509Certificate} from 'node:crypto'
import {IssuerSigned} from '@owf/mdoc'
import 'reflect-metadata'
import {X509CertificateGenerator} from '@peculiar/x509'
import {createMdocCredentialSigner} from 'antifraud-sdk-node-ts/mdoc-credential-signer'

export async function createMdocIssuanceFixture() {
  const algorithm = {name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'}
  const keys = await webcrypto.subtle.generateKey(algorithm, false, ['sign', 'verify'])
  const signed = new Date()
  const certificate = await X509CertificateGenerator.createSelfSigned({
    name: 'CN=synthetic issuer',
    notBefore: new Date(signed.getTime() - 60_000),
    notAfter: new Date(signed.getTime() + 60_000),
    signingAlgorithm: algorithm,
    keys,
  }, webcrypto)
  const certificateChain = [new Uint8Array(certificate.rawData)]
  const issuerPublicKey = new X509Certificate(certificateChain[0]).publicKey
  const signMdoc = createMdocCredentialSigner({
    certificateChain,
    signEs256: async bytes => new Uint8Array(await webcrypto.subtle.sign(algorithm, keys.privateKey, bytes)),
  })
  const docType = 'eu.europa.ec.av.1'
  const claims = {age_over_18: true}
  return {
    certificateChain, signMdoc, docType,
    command: holderKey => ({
      docType, namespaces: {[docType]: claims}, holderKey, signed,
      validUntil: new Date(signed.getTime() + 30_000),
    }),
    assertCredential: (credential, holderKey) => {
      const document = IssuerSigned.fromEncodedForOid4Vci(credential)
      const {issuerAuth} = document
      assert.deepEqual(document.getPrettyClaims(docType), claims)
      const {deviceKey} = issuerAuth.mobileSecurityObject.deviceKeyInfo
      assert.equal(deviceKey.jwk.x, holderKey.x)
      assert.equal(deviceKey.jwk.y, holderKey.y)
      assert.equal(verify('sha256', issuerAuth.toBeSigned(),
        {key: issuerPublicKey, dsaEncoding: 'ieee-p1363'}, issuerAuth.signature), true)
    },
  }
}
