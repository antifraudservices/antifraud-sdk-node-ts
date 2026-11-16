import {IdentityAttestationCapability} from 'antifraud-data-utils-ts'
import {canonicalRequestDigest} from 'antifraud-data-utils-ts/clearing-house'
import {decodeUnverifiedJsonOrJwtObject} from 'antifraud-data-utils-ts/credential-decoding'
import type {CredentialPresentationSubmission, CredentialPresentationVerificationResult, GaiaXComplianceSubmission} from 'antifraud-data-utils-ts/verification-contracts'

export type GaiaXComplianceVerificationSummary = Readonly<{
  /** Original SC credential returned after verification by the configured gateway. */
  credentialJwt: string
  credential: Readonly<{
    id: string
    type: readonly string[]
    issuer: string
    validFrom: string
    validUntil: string
    rulesVersion: string
    compliantCredentials: readonly Readonly<{id: string; digestSRI: string}>[]
  }>
}>

export function validatePresentationSubmission(input: CredentialPresentationSubmission): void {
  assertExactKeys(input, ['request', 'presentation'])
  assertPresentation(input.presentation, 262_144)
  assertExactKeys(input.request, ['nonce', 'resourceReference', 'jurisdiction', 'capability'])
  if (!text(input.request.nonce, 256) || !text(input.request.resourceReference, 1024)
    || !text(input.request.jurisdiction, 16) || !/^[A-Z]{2}(?:-[A-Z0-9]{1,3})?$/u.test(input.request.jurisdiction)
    || input.request.capability !== IdentityAttestationCapability.VerifyClaim) {
    throw new TypeError('An exact resource, jurisdiction, nonce and verification capability request is required.')
  }
}
export function validateGaiaXSubmission(input: GaiaXComplianceSubmission): void {
  assertExactKeys(input, ['presentation'])
  assertPresentation(input.presentation, 1_048_576)
}

/** Project the server receipt, never the submitted wallet or additional response fields. */
export function parsePresentationReceipt(value: unknown, input: CredentialPresentationSubmission): CredentialPresentationVerificationResult {
  const receipt = record(value)
  if (receipt.verified !== true || !safeReference(receipt.tenantReference, input.presentation)
    || !safeReference(receipt.actorReference, input.presentation)
    || receipt.requestHash !== canonicalRequestDigest(input.request)
    || !text(receipt.checkedAt, 64) || !Number.isFinite(Date.parse(receipt.checkedAt))
    || !['memory', 'fabric'].includes(String(receipt.stateProvider))
    || !Array.isArray(receipt.credentialReferences) || !receipt.credentialReferences.length
    || !receipt.credentialReferences.every(reference => safeReference(reference, input.presentation))) {
    throw new Error('The gateway did not return a valid request-bound verification receipt.')
  }
  return Object.freeze({verified: true, tenantReference: receipt.tenantReference, actorReference: receipt.actorReference,
    credentialReferences: Object.freeze([...receipt.credentialReferences]) as readonly string[],
    requestHash: receipt.requestHash as string, checkedAt: receipt.checkedAt, stateProvider: receipt.stateProvider as 'memory' | 'fabric'})
}

/**
 * This validates the expected response profile, not its cryptographic signature.
 * The authenticated gateway owns engine trust and signature verification.
 */
export function parseGaiaXSummary(value: unknown, input: GaiaXComplianceSubmission): GaiaXComplianceVerificationSummary {
  const response = record(value), compact = response.credentialJwt
  if (!text(compact, 1_048_576) || compact === input.presentation
    || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(compact)) {
    throw new Error('The gateway did not return a signed Standard Compliance credential.')
  }
  let header: Record<string, unknown>
  try {header = record(JSON.parse(Buffer.from(compact.split('.')[0]!, 'base64url').toString('utf8')))}
  catch {throw new Error('The gateway compliance credential header is invalid.')}
  if (!['vc+jwt', 'vc+ld+json+jwt'].includes(String(header.typ)) || !text(header.alg, 64)
    || header.alg === 'none' || header.crit !== undefined || header.b64 === false) {
    throw new Error('The gateway compliance credential profile is invalid.')
  }
  const payload = record(decodeUnverifiedJsonOrJwtObject(compact))
  if (payload.vp !== undefined || payload.vp_token !== undefined || payload.presentation !== undefined) {
    throw new Error('A wallet presentation is not a Standard Compliance result.')
  }
  const credential = metadata(record(payload.vc ?? payload), input.presentation)
  if (payload.iss !== undefined && payload.iss !== credential.issuer) throw new Error('Compliance credential issuer fields conflict.')
  const transportMetadata = metadata(record(response.credential), input.presentation)
  if (canonicalRequestDigest(transportMetadata) !== canonicalRequestDigest(credential)) {
    throw new Error('Compliance metadata does not match its signed artifact.')
  }
  return Object.freeze({credentialJwt: compact, credential})
}

function metadata(value: Record<string, unknown>, presentation: string): GaiaXComplianceVerificationSummary['credential'] {
  const subject = record(value.credentialSubject)
  const issuer = typeof value.issuer === 'string' ? value.issuer : record(value.issuer).id
  const coverage = subject['gx:compliantCredentials']
  if (!safeReference(value.id, presentation) || !safeReference(issuer, presentation)
    || !Array.isArray(value.type) || !value.type.includes('VerifiableCredential') || !value.type.includes('gx:LabelCredential')
    || value.type.some(type => type !== 'VerifiableCredential' && type !== 'gx:LabelCredential')
    || !text(value.validFrom, 64) || !text(value.validUntil, 64)
    || !Number.isFinite(Date.parse(value.validFrom)) || !Number.isFinite(Date.parse(value.validUntil))
    || Date.parse(value.validUntil) <= Date.parse(value.validFrom)
    || subject['gx:labelLevel'] !== 'SC' || !text(subject['gx:rulesVersion'], 512)
    || !Array.isArray(coverage) || !coverage.length || coverage.length > 100) {
    throw new Error('The gateway result is not the expected Standard Compliance credential profile.')
  }
  const identifiers = new Set<string>()
  const compliantCredentials = coverage.map(item => {
    const entry = record(item), id = entry.id ?? entry['@id'], digestSRI = entry.digestSRI ?? entry['gx:digestSRI']
    if (!safeReference(id, presentation) || identifiers.has(id) || typeof digestSRI !== 'string' || !/^sha256-[0-9a-f]{64}$/u.test(digestSRI)) {
      throw new Error('The compliance credential coverage metadata is invalid.')
    }
    identifiers.add(id)
    return Object.freeze({id, digestSRI})
  })
  return Object.freeze({id: value.id, type: Object.freeze([...value.type]) as readonly string[], issuer,
    validFrom: value.validFrom, validUntil: value.validUntil, rulesVersion: subject['gx:rulesVersion'],
    compliantCredentials: Object.freeze(compliantCredentials)})
}
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('A structured verification response is required.')
  return value as Record<string, unknown>
}
function text(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length <= maximum && value.trim().length > 0
}
function safeReference(value: unknown, presentation: string): value is string {
  return text(value, 4096) && value !== presentation && !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(value)
}
function assertExactKeys(value: unknown, keys: readonly string[]): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) {
    throw new TypeError('Client-selected authority is not accepted in this verification submission.')
  }
}
function assertPresentation(value: unknown, maximum: number): void {
  if (!text(value, maximum)) throw new TypeError('A bounded signed presentation is required.')
}
