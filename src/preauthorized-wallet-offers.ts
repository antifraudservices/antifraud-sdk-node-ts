import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto'
import type { CredentialIssuanceRequest } from 'antifraud-data-utils-ts'
import { parseOpenIdIssuerUrl } from './openid-issuer-url.js'

export type WalletIssuanceCommand = Readonly<CredentialIssuanceRequest & {actorReference: string}>

interface WalletIssuanceGrant {
  command: WalletIssuanceCommand
  configurationId: string
  consumeNonce(nonce: string, command: WalletIssuanceCommand): Promise<boolean>
}

export const preAuthorizedCodeGrantType = 'urn:ietf:params:oauth:grant-type:pre-authorized_code'
const offerLifetime = 5 * 60_000
const accessLifetime = 2 * 60_000
const nonceLifetime = 2 * 60_000
const allowedAttempts = 5
const referencePattern = /^[A-Za-z0-9_-]{43}$/u
const authorizedReferencePattern = /^([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/u
const noncePattern = /^([A-Za-z0-9_-]{43})\.(\d{1,16})\.([A-Za-z0-9_-]{43})$/u

export interface StoredWalletOffer {
  readonly command: WalletIssuanceCommand
  readonly configurationId: string
  readonly expiresAt: number
  readonly attempts: number
  readonly revision: number
  readonly pinDigest: string
  readonly state: 'offered' | 'authorized' | 'used'
}

/** A durable adapter must implement unique creation and atomic compare-and-set. */
export interface WalletOfferStore {
  create(reference: string, offer: StoredWalletOffer): Promise<void>
  read(reference: string): Promise<StoredWalletOffer | undefined>
  compareAndSet(reference: string, revision: number, offer: StoredWalletOffer): Promise<boolean>
  /** Atomically reserves the issuer-wide nonce and marks this grant used. */
  consumeForIssuance(input: {reference: string; revision: number; nonceDigest: string; nonceExpiresAt: number}): Promise<boolean>
}

export interface PreAuthorizedWalletOfferOptions {
  credentialIssuer: string
  secret: Uint8Array
  store: WalletOfferStore
  now?: () => number
}

export function createPreAuthorizedWalletOffers(options: PreAuthorizedWalletOfferOptions) {
  parseOpenIdIssuerUrl(options.credentialIssuer)
  const credentialIssuer = options.credentialIssuer
  if (options.secret.length < 32) {
    throw new TypeError('Wallet offers require at least 32 secret bytes')
  }
  const now = options.now ?? Date.now
  const secret = Buffer.from(options.secret)
  const mac = (purpose: string, value: string) => createHmac('sha256', secret).update(`${credentialIssuer}\0${purpose}\0${value}`).digest('base64url')
  const equal = (left: string, right: string) => left.length === right.length
    && timingSafeEqual(Buffer.from(left), Buffer.from(right))
  const identifier = () => randomBytes(32).toString('base64url')
  const signedReference = (purpose: string, reference: string) => `${reference}.${mac(purpose, reference)}`
  const validReference = (purpose: string, token: string) => {
    const match = authorizedReferencePattern.exec(token)
    const reference = match?.[1]
    return reference && match[2] && equal(mac(purpose, reference), match[2]) ? reference : undefined
  }
  const isActive = (value: StoredWalletOffer | undefined, state: StoredWalletOffer['state']): value is StoredWalletOffer =>
    Boolean(value && value.state === state && value.expiresAt > now())

  async function prepare(command: WalletIssuanceCommand, configurationId: string) {
    if (!configurationId.trim() || !command.actorReference || !command.subjectReference || !command.verificationTransactionId) {
      throw new TypeError('Wallet offer requires a server-resolved issuance command and configuration')
    }
    const reference = identifier()
    const transactionCode = randomInt(1_000_000).toString().padStart(6, '0')
    await options.store.create(reference, {
      command: {...command}, configurationId, expiresAt: now() + offerLifetime,
      attempts: 0, revision: 0, pinDigest: mac('pin', `${reference}.${transactionCode}`), state: 'offered',
    })
    return {offerUri: `${credentialIssuer}/credential-offers/${reference}`, transactionCode}
  }

  async function readOffer(reference: string) {
    if (!referencePattern.test(reference)) return undefined
    const entry = await options.store.read(reference)
    if (!isActive(entry, 'offered') || entry.attempts >= allowedAttempts) return undefined
    return {
      credential_issuer: credentialIssuer,
      credential_configuration_ids: [entry.configurationId],
      grants: {[preAuthorizedCodeGrantType]: {
        'pre-authorized_code': signedReference('code', reference),
        tx_code: {input_mode: 'numeric', length: 6},
      }},
    }
  }

  async function exchange(code: string, transactionCode: string) {
    const reference = validReference('code', code)
    if (!reference || !/^\d{6}$/u.test(transactionCode)) return undefined
    // The stored revision makes the code exchange and PIN-attempt limit atomic.
    for (let retry = 0; retry <= allowedAttempts; retry += 1) {
      const entry = await options.store.read(reference)
      if (!isActive(entry, 'offered') || entry.attempts >= allowedAttempts) return undefined
      const matches = equal(entry.pinDigest, mac('pin', `${reference}.${transactionCode}`))
      const changed = await options.store.compareAndSet(reference, entry.revision, {
        ...entry, revision: entry.revision + 1, attempts: entry.attempts + 1,
        ...(matches ? {state: 'authorized', expiresAt: now() + accessLifetime, pinDigest: ''} : {}),
      })
      if (changed) return matches ? {access_token: signedReference('access', reference), token_type: 'Bearer', expires_in: accessLifetime / 1000} : undefined
    }
    return undefined
  }

  async function issueNonce() {
    const challenge = `${identifier()}.${now()}`
    return `${challenge}.${mac('nonce', challenge)}`
  }

  async function resolveGrant(token: string): Promise<WalletIssuanceGrant | undefined> {
    const reference = validReference('access', token)
    if (!reference) return undefined
    const entry = await options.store.read(reference)
    if (!isActive(entry, 'authorized')) return undefined
    return {
      command: {...entry.command}, configurationId: entry.configurationId,
      async consumeNonce(nonce, command) {
        const [, random, timestamp, signature] = noncePattern.exec(nonce) ?? []
        const time = now()
        if (!random || !timestamp || !signature || Number(timestamp) > time || time - Number(timestamp) >= nonceLifetime
          || !equal(mac('nonce', `${random}.${timestamp}`), signature) || entry.expiresAt <= time
          || command.actorReference !== entry.command.actorReference || command.subjectReference !== entry.command.subjectReference
          || command.verificationTransactionId !== entry.command.verificationTransactionId || command.capability !== entry.command.capability) return false
        return options.store.consumeForIssuance({reference, revision: entry.revision,
          nonceDigest: mac('used-nonce', nonce), nonceExpiresAt: Number(timestamp) + nonceLifetime})
      },
    }
  }

  return {credentialIssuer, prepare, readOffer, exchange, issueNonce, resolveGrant}
}
