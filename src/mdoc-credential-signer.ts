import {createHash, createPublicKey, randomBytes, verify, X509Certificate, type JsonWebKey} from 'node:crypto'
import {CoseKey, DeviceKey, Issuer, SignatureAlgorithm, type MdocContext} from '@owf/mdoc'

type MdocCredentialSignerOptions = Readonly<{
  certificateChain: readonly Uint8Array[]
  /** Return the 64-byte IEEE P1363 signature over the COSE Signature1 input. */
  signEs256(input: Uint8Array): Promise<Uint8Array>
}>

type MdocCredentialInput = Readonly<{
  docType: string
  namespaces: Readonly<Record<string, Readonly<Record<string, unknown>>>>
  holderKey: JsonWebKey
  signed: Date
  validUntil: Date
}>

function requireP256PublicKey(jwk: JsonWebKey) {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || 'd' in jwk || !jwk.x || !jwk.y) {
    throw new TypeError('The mdoc key must be a public P-256 JWK')
  }
  return createPublicKey({key: {kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y}, format: 'jwk'})
}

function issuerOnly(): never {
  throw new Error('The mdoc signing context supports issuance only')
}

/** Serialize a signed IssuerSigned structure using a host-managed document signing key. */
export function createMdocCredentialSigner(options: MdocCredentialSignerOptions) {
  const chain = options.certificateChain.map(certificate => new X509Certificate(Buffer.from(certificate)))
  const leaf = chain[0]
  if (!leaf || leaf.ca) throw new TypeError('A document signer certificate is required')
  for (const [index, parent] of chain.slice(1).entries()) {
    const child = chain[index]!
    if (!parent.ca || !child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      throw new TypeError('Invalid document signer certificate chain')
    }
  }
  const issuerPublicKey = requireP256PublicKey(leaf.publicKey.export({format: 'jwk'}))
  const signingKey = CoseKey.fromJwk(issuerPublicKey.export({format: 'jwk'}))
  const earliest = Math.max(...chain.map(certificate => certificate.validFromDate.getTime()))
  const latest = Math.min(...chain.map(certificate => certificate.validToDate.getTime()))

  const context: Pick<MdocContext, 'crypto' | 'cose'> = {
    crypto: {
      random: randomBytes,
      digest: ({digestAlgorithm, bytes}) => createHash(digestAlgorithm).update(bytes).digest(),
      hdkf: issuerOnly,
    },
    cose: {
      sign1: {
        async sign({algorithm, toBeSigned}) {
          if (algorithm !== SignatureAlgorithm.ES256) throw new TypeError('Expected ES256 signing')
          const signature = await options.signEs256(Uint8Array.from(toBeSigned))
          if (signature.length !== 64 || !verify('sha256', toBeSigned,
            {key: issuerPublicKey, dsaEncoding: 'ieee-p1363'}, signature)) {
            throw new Error('The signature does not match the document signer certificate')
          }
          return signature
        },
        verify: issuerOnly,
      },
      mac0: {authenticate: issuerOnly, verify: issuerOnly},
    },
  }

  return async ({docType, namespaces, holderKey, signed, validUntil}: MdocCredentialInput) => {
    const signedAt = signed.getTime()
    const expiresAt = validUntil.getTime()
    if (!(earliest <= signedAt && signedAt < expiresAt && expiresAt <= latest)) {
      throw new TypeError('The mdoc validity must fit the certificate validity period')
    }
    const devicePublicKey = requireP256PublicKey(holderKey).export({format: 'jwk'})
    const issuer = new Issuer(docType, context)
    for (const [namespace, claims] of Object.entries(namespaces)) {
      issuer.addIssuerNamespace(namespace, claims)
    }
    const credential = await issuer.sign({
      signingKey,
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      validityInfo: {signed: new Date(signedAt), validFrom: new Date(signedAt), validUntil: new Date(expiresAt)},
      deviceKeyInfo: {deviceKey: DeviceKey.fromJwk(devicePublicKey)},
      certificates: chain.map(certificate => certificate.raw),
    })
    return credential.encodedForOid4Vci
  }
}
