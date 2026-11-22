import {createHash} from 'node:crypto'
import type {StoredWalletOffer, WalletOfferStore} from './preauthorized-wallet-offers.js'

interface WalletRecords {
  get<T extends {id: string}>(collection: string, id: string): Promise<T | undefined>
  put<T extends {id: string}>(collection: string, records: T[]): Promise<boolean>
}

interface WalletRepository {
  runTransaction<T>(operation: (records: WalletRecords) => Promise<T>): Promise<T>
}

type OfferRecord = StoredWalletOffer & {id: string}
type NonceRecord = {id: string; expiresAt: number}
const opaqueReference = /^[A-Za-z0-9_-]{43}$/u

/** Persists opaque grants in the host's transactional repository. */
export function createTransactionalWalletOfferStore(options: Readonly<{
  credentialIssuer: string;
  repository: WalletRepository;
  now?: () => number;
}>): WalletOfferStore {
  const issuer = new URL(options.credentialIssuer)
  if (issuer.protocol !== 'https:' || issuer.username || issuer.password || issuer.search || issuer.hash) {
    throw new TypeError('A trusted HTTPS credential issuer is required')
  }
  const issuerHash = createHash('sha256').update(issuer.href).digest('hex')
  const collection = 'wallet-offers-' + issuerHash
  const transact = options.repository.runTransaction.bind(options.repository)
  const now = options.now ?? Date.now
  const readOffer = (records: WalletRecords, id: string) => records.get<OfferRecord>(collection, id)
  const key = (type: 'offer' | 'nonce', reference: string) => {
    if (!opaqueReference.test(reference)) throw new TypeError('Invalid wallet storage reference')
    return type + '_' + reference
  }
  async function write(records: WalletRecords, ...entries: (OfferRecord | NonceRecord)[]) {
    if (!await records.put(collection, entries)) throw new Error('Wallet storage write failed')
  }

  return {
    async create(reference, offer) {
      const id = key('offer', reference)
      await transact(async records => {
        if (await readOffer(records, id)) throw new Error('Wallet offer already exists')
        await write(records, {...offer, id})
      })
    },
    async read(reference) {
      const id = key('offer', reference)
      return transact(async records => {
        const row = await readOffer(records, id)
        if (!row || row.expiresAt <= now()) return undefined
        const {id: _id, ...offer} = row
        return offer
      })
    },
    async compareAndSet(reference, revision, offer) {
      const id = key('offer', reference)
      return transact(async records => {
        const current = await readOffer(records, id)
        if (!current || current.state !== 'offered' || current.revision !== revision || current.expiresAt <= now()
          || offer.revision !== revision + 1 || (offer.state !== 'offered' && offer.state !== 'authorized')) return false
        await write(records, {...offer, id})
        return true
      })
    },
    async consumeForIssuance({reference, revision, nonceDigest, nonceExpiresAt}) {
      const id = key('offer', reference)
      const nonceId = key('nonce', nonceDigest)
      return transact(async records => {
        const current = await readOffer(records, id)
        const nonce = await records.get<NonceRecord>(collection, nonceId)
        const time = now()
        if (!current || current.state !== 'authorized' || current.revision !== revision
          || current.expiresAt <= time || nonceExpiresAt <= time || nonce) return false
        await write(records, {...current, state: 'used', revision: revision + 1}, {id: nonceId, expiresAt: nonceExpiresAt})
        return true
      })
    },
  }
}
