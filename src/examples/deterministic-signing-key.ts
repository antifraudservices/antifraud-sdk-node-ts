// Copyright 2026 Antifraud Services Inc. under the Apache License, Version 2.0.
// Reviewed Node-only fixture derivation from deterministic-jwk.ts, source commit
// 97fcd4142411666a4d3a40cd0ea29864775a51ef. Never use public fixture seeds for operational keys.

import { createECDH, createHash } from 'node:crypto';
import type { ClassicPublicJwk } from 'antifraud-data-utils-ts/cryptography';

/**
 * Legacy JOSE signature algorithms still commonly used by BFF, controller, and
 * test fixtures before a runtime switches to post-quantum signers.
 *
 * Notes:
 * - `ES384` maps to the NIST P-384 curve
 * - `ES256K` maps to the secp256k1 curve often used by wallet-oriented flows
 *
 * Post-quantum deterministic key generation remains available through
 * `ICryptography.generateKeyPairMlDsa(...)` and
 * `ICryptography.generateKeyPairMlKem(...)`.
 */
export type DeterministicEcJwkAlgorithm = 'ES256K' | 'ES384';

type EcCurveConfig = {
  readonly alg: DeterministicEcJwkAlgorithm;
  readonly nodeCurve: string;
  readonly jwkCrv: string;
  readonly coordinateBytes: number;
};

const EC_CURVE_BY_ALG: Record<DeterministicEcJwkAlgorithm, EcCurveConfig> = {
  ES256K: {
    alg: 'ES256K',
    nodeCurve: 'secp256k1',
    jwkCrv: 'secp256k1',
    coordinateBytes: 32,
  },
  ES384: {
    alg: 'ES384',
    nodeCurve: 'secp384r1',
    jwkCrv: 'P-384',
    coordinateBytes: 48,
  },
};

/**
 * Deterministic EC signing material derived from a stable textual seed.
 *
 * This helper exists for:
 * - reproducible tests
 * - explicitly synthetic local examples
 * - external-signing examples where auditors must regenerate the same public
 *   JWK without importing PEM files or depending on random key generation
 *
 * Important:
 * - the derived private key is deterministic for the same
 *   `seed + purpose + alg`
 * - ECDSA signatures generated later may still differ across crypto providers,
 *   so callers should normally assert signature verification rather than the
 *   full compact token bytes
 */
export type DeterministicEcJwkPair = {
  publicJwk: ClassicPublicJwk & { use: 'sig'; kid: string };
  privateJwk: ClassicPublicJwk & { use: 'sig'; kid: string; d: string };
  alg: DeterministicEcJwkAlgorithm;
  seed: string;
  purpose: string;
};

function sha256Base64Url(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('base64url');
}

/**
 * Expands an arbitrary text seed into enough bytes for one EC private scalar.
 *
 * Each block includes both a deterministic `attempt` and `counter`, so callers
 * can keep retrying reproducible candidates until the target curve accepts one.
 */
function expandSeedBytes(seed: string, purpose: string, size: number, attempt: number): Buffer {
  const chunks: Buffer[] = [];
  let counter = 0;
  while (Buffer.concat(chunks).length < size) {
    chunks.push(
      createHash('sha512')
        .update(seed, 'utf8')
        .update(':', 'utf8')
        .update(purpose, 'utf8')
        .update(':', 'utf8')
        .update(String(attempt), 'utf8')
        .update(':', 'utf8')
        .update(String(counter), 'utf8')
        .digest(),
    );
    counter += 1;
  }
  return Buffer.concat(chunks).subarray(0, size);
}

/**
 * Derives one reproducible EC JWK pair from a stable seed string.
 *
 * @param input.seed Stable textual seed chosen by the caller.
 * @param input.purpose Logical namespace such as `virtual-bff`, `controller`,
 * or `demo-host`.
 * @param input.alg JOSE algorithm/curve family. Defaults to `ES384`.
 *
 * @see RFC 7517 JSON Web Key (JWK)
 * @see RFC 7518 JSON Web Algorithms (JWA)
 */
export function deriveDeterministicEcJwkPair(input: {
  seed: string;
  purpose: string;
  alg?: DeterministicEcJwkAlgorithm;
}): DeterministicEcJwkPair {
  if (!input || typeof input.seed !== 'string' || typeof input.purpose !== 'string') {
    throw new TypeError('Synthetic seed and purpose must be exact strings.');
  }
  const alg = input.alg ?? 'ES384';
  if (alg !== 'ES384' && alg !== 'ES256K') throw new TypeError('Unsupported deterministic EC example algorithm.');
  const curve = EC_CURVE_BY_ALG[alg];

  for (let attempt = 0; attempt < 256; attempt += 1) {
    const candidate = expandSeedBytes(input.seed, input.purpose, curve.coordinateBytes, attempt);
    try {
      const ecdh = createECDH(curve.nodeCurve);
      ecdh.setPrivateKey(candidate);
      const privateKey = ecdh.getPrivateKey();
      const publicKey = ecdh.getPublicKey(undefined, 'uncompressed');
      const x = publicKey.subarray(1, 1 + curve.coordinateBytes);
      const y = publicKey.subarray(1 + curve.coordinateBytes, 1 + (curve.coordinateBytes * 2));
      const kid = `${input.purpose}-${alg.toLowerCase()}-${sha256Base64Url(`${input.seed}:${input.purpose}:${alg}`).slice(0, 16)}`;

      return {
        alg,
        seed: input.seed,
        purpose: input.purpose,
        publicJwk: {
          kty: 'EC',
          crv: curve.jwkCrv,
          alg,
          use: 'sig',
          kid,
          x: x.toString('base64url'),
          y: y.toString('base64url'),
        },
        privateJwk: {
          kty: 'EC',
          crv: curve.jwkCrv,
          alg,
          use: 'sig',
          kid,
          x: x.toString('base64url'),
          y: y.toString('base64url'),
          d: privateKey.toString('base64url'),
        },
      };
    } catch {
      // Retry the next deterministic candidate until the curve accepts it.
    }
  }
  throw new Error(`Could not derive a valid ${alg} key from the supplied synthetic seed.`);
}
