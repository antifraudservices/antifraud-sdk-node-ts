import {createPublicKey, verify, type JsonWebKey} from 'node:crypto'

function decodeProofPart(part: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid wallet proof object')
  return parsed as Record<string, unknown>
}

export function verifyWalletProof(proof: string, issuer: string, now: number): {holderKey: JsonWebKey; nonce: string} {
  if (typeof proof !== 'string' || proof.length > 8192 || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(proof)) {
    throw new Error('Invalid wallet proof JWT')
  }
  const [headerPart = '', payloadPart = '', signaturePart = ''] = proof.split('.')
  const header = decodeProofPart(headerPart)
  if (header.typ !== 'openid4vci-proof+jwt' || header.alg !== 'ES256'
    || 'crit' in header || 'kid' in header || 'x5c' in header || 'jku' in header || 'x5u' in header) {
    throw new Error('Unsupported wallet proof header')
  }
  const key = header.jwk as JsonWebKey | undefined
  if (!key || key.d !== undefined || key.kty !== 'EC' || key.crv !== 'P-256'
    || typeof key.x !== 'string' || typeof key.y !== 'string'
    || !/^[\w-]{43}$/.test(key.x) || !/^[\w-]{43}$/.test(key.y)) {
    throw new Error('Wallet proof requires a public P-256 JWK')
  }
  const holderKey = {kty: key.kty, crv: key.crv, x: key.x, y: key.y}
  const signature = Buffer.from(signaturePart, 'base64url')
  if (signature.length !== 64 || !verify('sha256', Buffer.from(`${headerPart}.${payloadPart}`), {
    key: createPublicKey({key: holderKey, format: 'jwk'}), dsaEncoding: 'ieee-p1363',
  }, signature)) throw new Error('Invalid wallet proof signature')
  const payload = decodeProofPart(payloadPart)
  if (payload.aud !== issuer) throw new Error('Invalid wallet proof audience')
  if (typeof payload.iat !== 'number' || !Number.isSafeInteger(payload.iat) || !Number.isFinite(now)
    || payload.iat < now / 1000 - 300 || payload.iat > now / 1000 + 30) throw new Error('Wallet proof is outside its validity window')
  if (typeof payload.nonce !== 'string' || !payload.nonce) throw new Error('Wallet proof nonce is required')
  return {holderKey, nonce: payload.nonce}
}
