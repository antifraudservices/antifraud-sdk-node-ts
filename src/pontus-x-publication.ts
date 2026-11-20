/** The organization whose registered wallet owns the external publication. */
export type PontusXPublisher = 'tenant' | 'host'

/** Trusted authorization result, loaded by the BFF from the authenticated session and host settings. */
export type PontusXPublicationAuthorization = Readonly<{
  tenantId: string
  datasetId: string
  chainId: number
  authority: PontusXPublisher
  allowTenantPublication: boolean
  tenantWalletAddress?: string
  hostWalletAddress?: string
}>

export type PontusXPublicationKey = Readonly<Pick<PontusXPublicationAuthorization, 'tenantId' | 'datasetId' | 'chainId'>>
export type PontusXPublicationScope = PontusXPublicationKey & Readonly<{
  publisher: PontusXPublisher
  walletAddress: string
}>

export type PontusXSubmission = Readonly<{did: string; transactionHash: string}>
export type PontusXRecordedSubmission = PontusXSubmission & Readonly<{publisher: PontusXPublisher; owner: string}>

type PublicationRecord =
  | Readonly<{state: 'pending'}>
  | Readonly<{state: 'submitted'; submission: PontusXRecordedSubmission}>

/** A durable journal with one atomic reservation per chain, tenant and dataset. */
export interface PontusXPublicationJournal {
  get(key: PontusXPublicationKey): Promise<PublicationRecord | undefined>
  /** Atomically inserts a pending record and returns started, or returns the existing record. */
  start(key: PontusXPublicationKey): Promise<PublicationRecord | Readonly<{state: 'started'}>>
  /** Records the confirmed transaction on the reserved key before any index reads. */
  recordSubmission(key: PontusXPublicationKey, submission: PontusXRecordedSubmission): Promise<void>
}

export interface PontusXPublicationClient<Asset> {
  getAddress(): Promise<string>
  getChainId(): Promise<number>
  publish(asset: Asset): Promise<PontusXSubmission>
  readAsset(did: string): Promise<Readonly<{id: string; owner: string; chainId: number; ddo: unknown}> | undefined>
}

type PublicationRequest<Actor> = Readonly<{actor: Actor; datasetId: string}>

export interface PontusXPublicationOptions<Actor, Asset, Catalogue> {
  env?: Readonly<{PONTUS_X_PUBLICATION_ENABLED?: string}>
  journal: PontusXPublicationJournal
  authorize(request: PublicationRequest<Actor>): Promise<PontusXPublicationAuthorization | undefined>
  connect(scope: PontusXPublicationScope): Promise<PontusXPublicationClient<Asset>>
  prepareAsset(scope: PontusXPublicationScope): Promise<Asset>
  projectDataset(ddo: unknown, scope: PontusXPublicationScope): Catalogue | Promise<Catalogue>
}

type PublicationErrorCode = 'not-authorized' | 'signer-mismatch' | 'reconciliation-required'
  | 'publisher-conflict' | 'readback-unavailable' | 'readback-mismatch'

/** Stable failure classification suitable for BFF error handling. */
export class PontusXPublicationError extends Error {
  constructor(readonly code: PublicationErrorCode) {
    super(code)
    this.name = 'PontusXPublicationError'
  }
}

const addressPattern = /^0x[0-9a-f]{40}$/iu
const didPattern = /^did:(?:op|ope):[0-9a-f]{64}$/iu
const transactionPattern = /^0x[0-9a-f]{64}$/iu

/** Creates an opt-in server publisher. Only a host controller can publish with the operator wallet. */
export function createPontusXPublication<Actor, Asset, Catalogue>(
  options: PontusXPublicationOptions<Actor, Asset, Catalogue>,
) {
  if (options.env?.PONTUS_X_PUBLICATION_ENABLED !== 'true') return undefined
  const {journal} = options

  async function publish(request: PublicationRequest<Actor>) {
    const access = await options.authorize(request)
    if (!access || !access.tenantId || !request.datasetId || access.datasetId !== request.datasetId ||
      !Number.isSafeInteger(access.chainId) || access.chainId <= 0 ||
      (access.authority !== 'host' && (access.authority !== 'tenant' || access.allowTenantPublication !== true))) {
      throw new PontusXPublicationError('not-authorized')
    }
    const {tenantId, datasetId, chainId, authority: publisher} = access
    const walletAddress = publisher === 'host' ? access.hostWalletAddress : access.tenantWalletAddress
    if (!walletAddress || !addressPattern.test(walletAddress)) throw new PontusXPublicationError('not-authorized')

    const key = {tenantId, datasetId, chainId}
    const scope = {...key, publisher, walletAddress}
    let record = await journal.get(key)
    if (record?.state === 'pending') throw new PontusXPublicationError('reconciliation-required')
    const client = await options.connect(scope)
    if ((await client.getAddress()).toLowerCase() !== walletAddress.toLowerCase() || await client.getChainId() !== chainId) {
      throw new PontusXPublicationError('signer-mismatch')
    }

    if (!record) {
      const asset = await options.prepareAsset(scope)
      const reservation = await journal.start(key)
      if (reservation.state === 'started') {
        try {
          const receipt = await client.publish(asset)
          if (!didPattern.test(receipt.did) || !transactionPattern.test(receipt.transactionHash)) {
            throw new TypeError('Missing publish receipt')
          }
          const submission = {...receipt, publisher, owner: walletAddress}
          await journal.recordSubmission(key, submission)
          record = {state: 'submitted', submission}
        } catch {
          throw new PontusXPublicationError('reconciliation-required')
        }
      } else {
        record = reservation
      }
    }

    if (record.state === 'pending') throw new PontusXPublicationError('reconciliation-required')
    const {submission} = record
    if (submission.publisher !== publisher || submission.owner.toLowerCase() !== walletAddress.toLowerCase()) {
      throw new PontusXPublicationError('publisher-conflict')
    }

    const indexed = await client.readAsset(submission.did).catch(() => undefined)
    if (!indexed) throw new PontusXPublicationError('readback-unavailable')
    if (indexed.id !== submission.did || indexed.chainId !== chainId ||
      indexed.owner.toLowerCase() !== walletAddress.toLowerCase()) {
      throw new PontusXPublicationError('readback-mismatch')
    }
    const catalogue = await options.projectDataset(indexed.ddo, scope)
    return {...submission, catalogue}
  }

  return {publish}
}

interface NautilusV1<Asset> {
  publish(asset: Asset): Promise<{ddo: {id: string}; setMetadataTxReceipt: {transactionHash: string}}>
  getAquariusAsset(did: string): Promise<{id: string; chainId: number; nft?: {owner: string}} | undefined>
}

/** Adapts a Nautilus 1.x instance and the same signer used to initialize it. */
export function createNautilusV1PublicationClient<Asset>(
  sdk: NautilusV1<Asset>,
  signer: Readonly<{getAddress(): Promise<string>; getChainId(): Promise<number>}>,
): PontusXPublicationClient<Asset> {
  return {
    getAddress: () => signer.getAddress(),
    getChainId: () => signer.getChainId(),
    async publish(asset) {
      const {ddo, setMetadataTxReceipt} = await sdk.publish(asset)
      return {did: ddo.id, transactionHash: setMetadataTxReceipt.transactionHash}
    },
    async readAsset(did) {
      const ddo = await sdk.getAquariusAsset(did)
      if (!ddo?.nft || typeof ddo.nft.owner !== 'string') return undefined
      return {id: ddo.id, owner: ddo.nft.owner, chainId: ddo.chainId, ddo}
    },
  }
}
