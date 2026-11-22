import {createHmac} from 'node:crypto'
import {IdentityAttestationCapability} from 'antifraud-data-utils-ts/identity-assurance'
import {createOpenId4VciIssuer, type OpenId4VciIssuerOptions} from './openid4vci-issuer.js'
import type {createMdocCredentialSigner} from './mdoc-credential-signer.js'

type SignMdoc = ReturnType<typeof createMdocCredentialSigner>
type Review = Readonly<{
  revision: string
  validUntil: number
  namespaces: Readonly<Record<string, Readonly<Record<string, boolean>>>>
}>

const opaqueReference = /^[A-Za-z0-9_-]{43}$/u

/** Issues a reviewed mdoc through the normal OpenID4VCI route and wallet proof. */
export function createReviewedMdocWalletIssuer(options: Readonly<
  Pick<OpenId4VciIssuerOptions, 'credentialIssuer' | 'secret' | 'store' | 'now'> & {
    configurationId: string
    docType: string
    readReview(authorizationReference: string): Promise<Review | undefined>
    sign: SignMdoc
  }
>) {
  const {credentialIssuer, configurationId, docType, secret} = options
  const now = options.now ?? Date.now
  const digest = (purpose: string, values: unknown) => 'urn:sha256:' + createHmac('sha256', secret)
    .update(JSON.stringify([credentialIssuer, purpose, values])).digest('hex')

  async function currentReview(reference: string) {
    if (!opaqueReference.test(reference)) return undefined
    const review = await options.readReview(reference)
    if (!review?.revision || !Number.isSafeInteger(review.validUntil) || review.validUntil <= now()) return undefined
    const namespaces = Object.entries(review.namespaces).sort(([left], [right]) => left.localeCompare(right))
      .map(([namespace, values]) => [namespace, Object.entries(values).sort(([left], [right]) => left.localeCompare(right))] as const)
    return {
      namespaces: Object.fromEntries(namespaces.map(([namespace, values]) => [namespace, Object.fromEntries(values)])),
      validUntil: review.validUntil,
      binding: digest('review', [reference, docType, review.revision, review.validUntil, namespaces]),
    }
  }

  const issuer = createOpenId4VciIssuer({
    credentialIssuer, secret, store: options.store, now,
    credentialConfigurations: {[configurationId]: {format: 'mso_mdoc', doctype: docType}},
    async issue(command, holderKey) {
      const reference = command.verificationTransactionId
      if (command.actorReference !== digest('authorization', reference) ||
        command.capability !== IdentityAttestationCapability.VerifyClaim) return undefined
      const review = await currentReview(reference)
      if (!review || review.binding !== command.subjectReference) return undefined
      const credential = await options.sign({
        docType, namespaces: review.namespaces, holderKey,
        signed: new Date(now()), validUntil: new Date(review.validUntil),
      })
      return (await currentReview(reference))?.binding === review.binding ? credential : undefined
    },
  })

  return {
    handle: issuer.handle,
    async prepare(authorizationReference: string) {
      const current = await currentReview(authorizationReference)
      if (!current) return undefined
      return issuer.prepare({
        actorReference: digest('authorization', authorizationReference),
        subjectReference: current.binding,
        verificationTransactionId: authorizationReference,
        capability: IdentityAttestationCapability.VerifyClaim,
      }, configurationId)
    },
  }
}
