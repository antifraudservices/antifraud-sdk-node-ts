import { createHash, randomBytes, randomUUID } from 'node:crypto'

import {
  Content,
  CryptographyService,
  ManagedSigningAlgorithm,
  ManagedSigningKeyPurpose,
  type ICryptoHelper,
  type ManagedSignatureProof,
  type ManagedSignatureProofResult,
  type ManagedSignatureRequest,
  type MldsaPublicJwk,
  type MlkemPrivateJwk,
  type MlkemPublicJwk,
} from 'antifraud-data-utils-ts'
import {
  ManagedSigningSessionController,
  createManagedSigningSessionRepositoryInMemory,
  type ManagedSigningUserPresencePort,
} from 'antifraud-sdk-core-ts'

type StoredWallet = Readonly<{
  actorSigning: Readonly<{
    publicJWKey: MldsaPublicJwk & { kid: string }
    secretKeyBytes: Uint8Array
  }>
  documentAtRest: Readonly<{
    publicJWKey: MlkemPublicJwk & { kid: string }
    secretKeyBytes: Uint8Array
  }>
}>

export type ManagedWalletPublicKeys = Readonly<{
  actorSigning: Readonly<{
    purpose: typeof ManagedSigningKeyPurpose.ActorSigning
    algorithm: typeof ManagedSigningAlgorithm.MlDsa65
    verificationMethod: string
    publicJwk: MldsaPublicJwk & { kid: string }
  }>
  documentAtRest: Readonly<{
    purpose: 'document-at-rest'
    algorithm: 'ML-KEM-768'
    verificationMethod: string
    publicJwk: MlkemPublicJwk & { kid: string }
  }>
}>

class NodeCryptoHelper implements ICryptoHelper {
  async getRandomBytes(byteCount: number): Promise<Uint8Array> {
    return randomBytes(byteCount)
  }

  async digestString(data: string, algorithm: string): Promise<string> {
    return createHash(algorithm.replaceAll('-', '').toLowerCase()).update(data).digest('hex')
  }

  randomUUID(): string {
    return randomUUID()
  }
}

function deriveSeed(source: string, purpose: string, bytes: number): Uint8Array {
  const chunks: Buffer[] = []
  let counter = 0
  while (Buffer.concat(chunks).byteLength < bytes) {
    chunks.push(createHash('sha512')
      .update(source)
      .update('\u0000')
      .update(purpose)
      .update('\u0000')
      .update(String(counter))
      .digest())
    counter += 1
  }
  return Buffer.concat(chunks).subarray(0, bytes)
}

/** Node custody adapter. Public descriptors leave the wallet; private material never does. */
export class NodeManagedWallet {
  readonly #cryptography = new CryptographyService(new NodeCryptoHelper())
  readonly #wallets = new Map<string, StoredWallet>()

  async provision(
    ownerId: string,
    options: Readonly<{seedMaterial?: string}> = {},
  ): Promise<ManagedWalletPublicKeys> {
    const existing = this.#wallets.get(ownerId)
    if (existing) return this.#publicKeys(existing)
    const seed = options.seedMaterial
    const actorSigning = await this.#cryptography.generateKeyPairMlDsa(
      seed ? deriveSeed(`${seed}:${ownerId}`, 'actor-signing', 32) : undefined,
      ManagedSigningAlgorithm.MlDsa65,
    )
    const documentAtRest = await this.#cryptography.generateKeyPairMlKem(
      seed ? deriveSeed(`${seed}:${ownerId}`, 'document-at-rest', 64) : undefined,
      'ML-KEM-768',
    )
    const stored = Object.freeze({actorSigning, documentAtRest})
    this.#wallets.set(ownerId, stored)
    return this.#publicKeys(stored)
  }

  async signManifest(
    request: ManagedSignatureRequest,
    createdAt: string,
  ): Promise<ManagedSignatureProofResult> {
    const wallet = this.#requireWallet(request.authenticatedUserId)
    const expectedMethod = this.#actorVerificationMethod(wallet)
    if (request.signingKey.verificationMethod !== expectedMethod) {
      throw new Error('Managed signing request is not bound to the wallet actor-signing key')
    }
    const signature = await this.#cryptography.signBytes(
      Buffer.from(request.manifest.digest, 'base64'),
      wallet.actorSigning.secretKeyBytes,
      ManagedSigningAlgorithm.MlDsa65,
    )
    const verified = await this.#cryptography.verifyBytes(
      signature,
      Buffer.from(request.manifest.digest, 'base64'),
      wallet.actorSigning.publicJWKey,
    )
    return Object.freeze({
      proofId: `urn:uuid:${randomUUID()}`,
      signature: Content.bytesToRawBase64UrlSafe(signature),
      createdAt,
      verified,
    })
  }

  async verifyManagedProof(proof: ManagedSignatureProof): Promise<boolean> {
    for (const wallet of this.#wallets.values()) {
      if (this.#actorVerificationMethod(wallet) !== proof.verificationMethod) continue
      return this.#cryptography.verifyBytes(
        Buffer.from(proof.signature, 'base64url'),
        Buffer.from(proof.manifest.digest, 'base64'),
        wallet.actorSigning.publicJWKey,
      )
    }
    return false
  }

  async protectArtifact(ownerId: string, content: object): Promise<string> {
    const wallet = this.#requireWallet(ownerId)
    const privateKey: MlkemPrivateJwk = {
      ...wallet.documentAtRest.publicJWKey,
      dBytes: wallet.documentAtRest.secretKeyBytes,
    }
    return this.#cryptography.encryptJweToCompact(content, {
      typ: 'antifraud-confidential-artifact+jwe',
      cty: 'application/json',
      enc: 'A256GCM',
      gdc_pq_profile: 'confidential-pqc-v1',
      gdc_key_purpose: 'document-at-rest',
      gdc_owner_binding: createHash('sha256').update(ownerId).digest('base64url'),
    }, privateKey, wallet.documentAtRest.publicJWKey)
  }

  async unprotectArtifact(ownerId: string, compactJwe: string): Promise<object> {
    return this.#unprotectArtifactPayload(ownerId, compactJwe)
  }

  async protectArtifactBytes(ownerId: string, bytes: Uint8Array): Promise<string> {
    if (bytes.byteLength === 0) throw new Error('Artifact bytes are required')
    return this.protectArtifact(ownerId, {
      encoding: 'base64url',
      bytes: Content.bytesToRawBase64UrlSafe(bytes),
    })
  }

  async unprotectArtifactBytes(ownerId: string, compactJwe: string): Promise<Uint8Array> {
    const payload = await this.#unprotectArtifactPayload(ownerId, compactJwe) as Record<string, unknown>
    if (payload.encoding !== 'base64url' || typeof payload.bytes !== 'string') {
      throw new Error('JWE does not contain a managed binary artifact')
    }
    return Content.base64ToBytes(payload.bytes)
  }

  async #unprotectArtifactPayload(ownerId: string, compactJwe: string): Promise<object> {
    const wallet = this.#requireWallet(ownerId)
    const privateKey: MlkemPrivateJwk = {
      ...wallet.documentAtRest.publicJWKey,
      dBytes: wallet.documentAtRest.secretKeyBytes,
    }
    const result = await this.#cryptography.decryptJwe(compactJwe, privateKey)
    const header = result.protectedHeader as Record<string, unknown>
    const binding = createHash('sha256').update(ownerId).digest('base64url')
    if (
      header.typ !== 'antifraud-confidential-artifact+jwe'
      || header.gdc_key_purpose !== 'document-at-rest'
      || header.gdc_owner_binding !== binding
    ) {
      throw new Error('JWE is not bound to this managed artifact owner')
    }
    return JSON.parse(Content.bytesToStringUTF8(result.decryptedBytes)) as object
  }

  #requireWallet(ownerId: string): StoredWallet {
    const wallet = this.#wallets.get(ownerId)
    if (!wallet) throw new Error(`Managed wallet is not provisioned for ${ownerId}`)
    return wallet
  }

  #actorVerificationMethod(wallet: StoredWallet): string {
    return `did:key:${wallet.actorSigning.publicJWKey.kid}#${wallet.actorSigning.publicJWKey.kid}`
  }

  #publicKeys(wallet: StoredWallet): ManagedWalletPublicKeys {
    return Object.freeze({
      actorSigning: Object.freeze({
        purpose: ManagedSigningKeyPurpose.ActorSigning,
        algorithm: ManagedSigningAlgorithm.MlDsa65,
        verificationMethod: this.#actorVerificationMethod(wallet),
        publicJwk: Object.freeze({...wallet.actorSigning.publicJWKey}),
      }),
      documentAtRest: Object.freeze({
        purpose: 'document-at-rest' as const,
        algorithm: 'ML-KEM-768' as const,
        verificationMethod: `did:key:${wallet.documentAtRest.publicJWKey.kid}#${wallet.documentAtRest.publicJWKey.kid}`,
        publicJwk: Object.freeze({...wallet.documentAtRest.publicJWKey}),
      }),
    })
  }
}

export function createManagedSigningBff(input: Readonly<{
  wallet: NodeManagedWallet
  userPresence: (
    input: Parameters<ManagedSigningUserPresencePort['verify']>[0],
  ) => Promise<Readonly<{biometricAvailable: boolean; verified: boolean}>>
}>): ManagedSigningSessionController {
  return new ManagedSigningSessionController({
    repository: createManagedSigningSessionRepositoryInMemory(),
    userPresence: {
      async verify(request) {
        const result = await input.userPresence(request)
        return Object.freeze({...result, method: request.method})
      },
    },
    wallet: input.wallet,
  })
}
