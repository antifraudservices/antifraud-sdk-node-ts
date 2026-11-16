// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.

import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { exportJWK, SignJWT, type JWK, type JWTHeaderParameters } from 'jose';

export type ClientAssertionJwtAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'EdDSA';

export type BuildClientAssertionJwtInput = {
  clientId: string;
  audience: string;
  issuer?: string;
  subject?: string;
  algorithm?: ClientAssertionJwtAlgorithm;
  expiresIn?: string | number;
  issuedAt?: number | Date;
  nonce?: string;
  additionalClaims?: Record<string, unknown>;
  protectedHeader?: Record<string, unknown>;
  includePublicJwkInHeader?: boolean;
};

type GeneratedKeyPair = {
  privateKey: KeyObject;
  publicKey: KeyObject;
};

function resolveAlgorithmDefaults(algorithm: ClientAssertionJwtAlgorithm): GeneratedKeyPair {
  switch (algorithm) {
    case 'ES256':
      return generateKeyPairSync('ec', { namedCurve: 'P-256' });
    case 'ES384':
      return generateKeyPairSync('ec', { namedCurve: 'P-384' });
    case 'ES512':
      return generateKeyPairSync('ec', { namedCurve: 'P-521' });
    case 'EdDSA':
      return generateKeyPairSync('ed25519');
    default:
      throw new Error(`Unsupported client assertion algorithm '${algorithm}'.`);
  }
}

function resolveIssuedAt(value?: number | Date): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
  if (value instanceof Date) return Math.trunc(value.getTime() / 1000);
  return undefined;
}

/**
 * Builds one ephemeral signed example client-authentication JWT for SMART/OpenID token
 * requests that use `client_assertion`.
 *
 * Defaults:
 * - algorithm: `ES384`
 * - expiration: `5m`
 * - protected header embeds the generated public JWK
 *
 * The helper is intentionally Node-oriented because it relies on
 * `generateKeyPairSync(...)`. Frontends or wallets that already manage their
 * own keys should build the same JWT shape with their own signer and can still
 * reuse the returned contract fields from this JSDoc.
 */
export async function buildClientAssertionJwt(input: BuildClientAssertionJwtInput): Promise<string> {
  const clientId = String(input.clientId || '').trim();
  const audience = String(input.audience || '').trim();
  if (!clientId) throw new Error('buildClientAssertionJwt requires clientId.');
  if (!audience) throw new Error('buildClientAssertionJwt requires audience.');

  const algorithm = input.algorithm || 'ES384';
  const { privateKey, publicKey } = resolveAlgorithmDefaults(algorithm);
  const publicJwk = await exportJWK(publicKey) as JWK;
  const protectedHeader: JWTHeaderParameters = {
    alg: algorithm,
    typ: 'JWT',
    ...(input.includePublicJwkInHeader === false ? {} : { jwk: publicJwk }),
    ...(input.protectedHeader || {}),
  };

  const jwt = new SignJWT({
    ...(input.nonce ? { nonce: input.nonce } : {}),
    ...(input.additionalClaims || {}),
  })
    .setProtectedHeader(protectedHeader)
    .setIssuer(String(input.issuer || clientId).trim())
    .setSubject(String(input.subject || clientId).trim())
    .setAudience(audience);

  const issuedAt = resolveIssuedAt(input.issuedAt);
  if (typeof issuedAt === 'number') {
    jwt.setIssuedAt(issuedAt);
  } else {
    jwt.setIssuedAt();
  }

  return jwt
    .setExpirationTime(input.expiresIn ?? '5m')
    .sign(privateKey);
}

/**
 * Builds one signed client-authentication JWT and exposes the generated public
 * JWK for callers that also need to register or persist the verification key.
 */
export async function buildClientAssertionFixture(input: BuildClientAssertionJwtInput): Promise<{
  jwt: string;
  publicJwk: JWK;
}> {
  const algorithm = input.algorithm || 'ES384';
  const { privateKey, publicKey } = resolveAlgorithmDefaults(algorithm);
  const publicJwk = await exportJWK(publicKey) as JWK;
  const protectedHeader: JWTHeaderParameters = {
    alg: algorithm,
    typ: 'JWT',
    ...(input.includePublicJwkInHeader === false ? {} : { jwk: publicJwk }),
    ...(input.protectedHeader || {}),
  };

  const clientId = String(input.clientId || '').trim();
  const audience = String(input.audience || '').trim();
  if (!clientId) throw new Error('buildClientAssertionFixture requires clientId.');
  if (!audience) throw new Error('buildClientAssertionFixture requires audience.');

  const jwt = new SignJWT({
    ...(input.nonce ? { nonce: input.nonce } : {}),
    ...(input.additionalClaims || {}),
  })
    .setProtectedHeader(protectedHeader)
    .setIssuer(String(input.issuer || clientId).trim())
    .setSubject(String(input.subject || clientId).trim())
    .setAudience(audience);

  const issuedAt = resolveIssuedAt(input.issuedAt);
  if (typeof issuedAt === 'number') {
    jwt.setIssuedAt(issuedAt);
  } else {
    jwt.setIssuedAt();
  }

  return {
    jwt: await jwt.setExpirationTime(input.expiresIn ?? '5m').sign(privateKey),
    publicJwk,
  };
}
