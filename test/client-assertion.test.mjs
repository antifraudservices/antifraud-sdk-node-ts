// Flow contract: the explicit Node example creates a fresh signed client JWT;
// its generated public key proves possession only and grants no registration.
import test from 'node:test'
import assert from 'node:assert/strict'
import {jwtVerify,importJWK,decodeProtectedHeader} from 'jose'
import {SyntheticManagedSignatureRequestFixture as f} from 'antifraud-data-utils-ts'
import {buildClientAssertionFixture,buildClientAssertionJwt} from 'antifraud-sdk-node-ts/examples/client-assertion'

for(const algorithm of ['ES256','ES384','ES512','EdDSA'])test(`verifies ${algorithm} against the exact generated key, audience and caller identity`,async()=>{
 const input={clientId:f.trustedContext.authenticatedUserId,audience:f.draft.operationId,algorithm,additionalClaims:{jti:f.draft.operationId}}
 const proof=await buildClientAssertionFixture(input)
 const key=await importJWK(proof.publicJwk,algorithm)
 const result=await jwtVerify(proof.jwt,key,{issuer:input.clientId,subject:input.clientId,audience:input.audience})
 assert.equal(result.payload.jti,input.additionalClaims.jti)
 assert.equal(decodeProtectedHeader(proof.jwt).alg,algorithm)
 await assert.rejects(jwtVerify(proof.jwt,key,{audience:input.clientId}))
 assert.equal(typeof await buildClientAssertionJwt(input),'string')
})
