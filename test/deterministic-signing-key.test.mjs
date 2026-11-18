// Flow contract: the explicit Node-only example subpath preserves reviewed seed/purpose/algorithm key bytes, separates namespaces and produces verifiable synthetic keys without adding key derivation to the public runtime entry point or browser Data package.
import assert from 'node:assert/strict'
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto'
import {readFile} from 'node:fs/promises'
import test from 'node:test'
import {SyntheticManagedSignatureRequestFixture as fixture} from 'antifraud-data-utils-ts'
import * as runtime from '../dist/index.js'

const vectors = [
  {seed: fixture.trustedContext.authenticatedUserId, purpose: fixture.trustedContext.purpose},
  {seed: fixture.trustedContext.authenticatedUserId, purpose: fixture.trustedContext.purpose, alg: 'ES384'},
  {seed: fixture.trustedContext.authenticatedUserId, purpose: fixture.trustedContext.purpose, alg: 'ES256K'},
  {seed: ` ${fixture.trustedContext.authenticatedUserId}\u0000☃ `, purpose: ` ${fixture.draft.operationId}\n`, alg: 'ES384'},
]
// Static vectors reviewed against deterministic-jwk.ts at source commit
// 97fcd4142411666a4d3a40cd0ea29864775a51ef. Private scalars are represented only
// by digests; every derivation input is a governed public synthetic fixture.
const reviewed = Object.freeze([
  {
    "publicJwk": "{\"kty\":\"EC\",\"crv\":\"P-384\",\"alg\":\"ES384\",\"use\":\"sig\",\"kid\":\"synthetic-publication-manifest-signing-es384-r_hK1C3QZAsOLgnD\",\"x\":\"Tt6NVI6yIkhGp232QPokJVP4hNczdeo0L3jPGSKCyFz53vngLnHKyj1oy-p14UHH\",\"y\":\"8HfFl4Qkk5Ks6T4ROp0Z-K92Ex-MTsnEO4LSsmPZuXGqqQo7ovDYdabHGewwWtXP\"}",
    "privateJwkDigest": "d5c60b97611c9ce8e18f7a51d01077361ab9201b028c33ed6a0ad927a5d7593b"
  },
  {
    "publicJwk": "{\"kty\":\"EC\",\"crv\":\"P-384\",\"alg\":\"ES384\",\"use\":\"sig\",\"kid\":\"synthetic-publication-manifest-signing-es384-r_hK1C3QZAsOLgnD\",\"x\":\"Tt6NVI6yIkhGp232QPokJVP4hNczdeo0L3jPGSKCyFz53vngLnHKyj1oy-p14UHH\",\"y\":\"8HfFl4Qkk5Ks6T4ROp0Z-K92Ex-MTsnEO4LSsmPZuXGqqQo7ovDYdabHGewwWtXP\"}",
    "privateJwkDigest": "d5c60b97611c9ce8e18f7a51d01077361ab9201b028c33ed6a0ad927a5d7593b"
  },
  {
    "publicJwk": "{\"kty\":\"EC\",\"crv\":\"secp256k1\",\"alg\":\"ES256K\",\"use\":\"sig\",\"kid\":\"synthetic-publication-manifest-signing-es256k-gudYTdE1nWZ9Svss\",\"x\":\"VdYS5A783JQRDUEZjVW2nGcRI8c6RHStB2w_xVLajB4\",\"y\":\"4Sk0hyltUNfz60bTp-COPSkIo8VHd3leQWzumlKjwqU\"}",
    "privateJwkDigest": "1e11fdbe085fdc1502f651283cc8d23a9ca8d95a3063bfa0b939368e54aae562"
  },
  {
    "publicJwk": "{\"kty\":\"EC\",\"crv\":\"P-384\",\"alg\":\"ES384\",\"use\":\"sig\",\"kid\":\" urn:operation:synthetic-publication-signing-v1\\n-es384-ilLGiCfHc4aPx0F-\",\"x\":\"cPAxdKbiOrNdL7cm-cI_6uzF02nhL2gDo7vxWfbrxLQtKKKVYIL6xK1U_Dg-Y7CT\",\"y\":\"ROG97t7K8LlguXDPPkx-1-yj55SOnQk-LqX3Zf0BKR0BPvJaglO8UzPPzYCIooC0\"}",
    "privateJwkDigest": "4f3396b8fab22f7227a012286b27861108744d18245f9ab5d7a7d5bf9ee4a420"
  }
])

async function example() {return import('../dist/examples/deterministic-signing-key.js')}

test('exposes deterministic fixture derivation only through its explicit Node example subpath', async () => {
  const metadata = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
  assert.deepEqual(metadata.exports['./examples/deterministic-signing-key'], {
    types: './dist/examples/deterministic-signing-key.d.ts', default: './dist/examples/deterministic-signing-key.js',
  })
  assert.equal(Object.hasOwn(runtime, 'deriveDeterministicEcJwkPair'), false)
  assert.equal(typeof (await example()).deriveDeterministicEcJwkPair, 'function')
})
test('preserves every reviewed public field and private scalar digest for both curves and exact text bytes', async () => {
  const {deriveDeterministicEcJwkPair} = await example()
  for (const [index, input] of vectors.entries()) {
    const pair = deriveDeterministicEcJwkPair(input)
    assert.equal(JSON.stringify(pair.publicJwk), reviewed[index].publicJwk)
    assert.equal(createHash('sha256').update(JSON.stringify(pair.privateJwk)).digest('hex'), reviewed[index].privateJwkDigest)
    assert.equal(pair.seed, input.seed)
    assert.equal(pair.purpose, input.purpose)
    assert.equal(pair.alg, input.alg ?? 'ES384')
  }
  assert.deepEqual(deriveDeterministicEcJwkPair(vectors[0]), deriveDeterministicEcJwkPair(vectors[1]))
  assert.notDeepEqual(deriveDeterministicEcJwkPair(vectors[0]).publicJwk, deriveDeterministicEcJwkPair(vectors[3]).publicJwk)
})
test('signs and verifies actual bytes with each derived key and rejects altered bytes', async () => {
  const {deriveDeterministicEcJwkPair} = await example()
  const payload = Buffer.from(fixture.draft.manifest.digest)
  for (const input of [vectors[1], vectors[2]]) {
    const pair = deriveDeterministicEcJwkPair(input)
    const algorithm = pair.alg === 'ES384' ? 'sha384' : 'sha256'
    const signature = sign(algorithm, payload, {key: createPrivateKey({key: pair.privateJwk, format: 'jwk'}), dsaEncoding: 'ieee-p1363'})
    assert.equal(verify(algorithm, payload, {key: createPublicKey({key: pair.publicJwk, format: 'jwk'}), dsaEncoding: 'ieee-p1363'}, signature), true)
    assert.equal(verify(algorithm, Buffer.from(fixture.draft.operationId), {key: createPublicKey({key: pair.publicJwk, format: 'jwk'}), dsaEncoding: 'ieee-p1363'}, signature), false)
  }
})
test('rejects unsupported algorithms without exposing seed text in the error', async () => {
  const {deriveDeterministicEcJwkPair} = await example()
  assert.throws(() => deriveDeterministicEcJwkPair({...vectors[0], alg: 'none'}), error => {
    assert.equal(error.message.includes(vectors[0].seed), false)
    return true
  })
})
