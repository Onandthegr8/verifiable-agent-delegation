/*
 * Off-chain agent crypto for the benchmark: Ed25519 key generation, raw
 * public-key export, and canonical signing that matches the chaincode's
 * canonical.ts byte-for-byte (sorted keys, no whitespace).
 */
'use strict';
const { generateKeyPairSync, sign } = require('crypto');

function newAgent(did, role) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    // raw 32-byte public key = SPKI DER minus the 12-byte Ed25519 prefix
    const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex');
    return { did, role, privateKey, pubKeyHex: raw };
}

function canonicalJSON(obj) {
    const sorted = {};
    for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
    return Buffer.from(JSON.stringify(sorted));
}

function credentialBytes(c) {
    return canonicalJSON({
        id: c.id, iss: c.issuer, sub: c.subject,
        scope: [...c.scope].sort(), nb: c.nb, na: c.na,
    });
}

function actionBytes(a) {
    return canonicalJSON({
        sub: a.didS, type: a.actionType, payload: a.payload,
        nonce: a.nonce, cred: a.credId,
    });
}

/** Issue a signed delegation credential (eq. 2). */
function issueCredential(issuer, subjectDid, scope, nb, na, id) {
    const c = { id, issuer: issuer.did, subject: subjectDid, scope, nb, na };
    c.sig = sign(null, credentialBytes(c), issuer.privateKey).toString('hex');
    return c;
}

/** Build a signed action transaction for the authorizeAction call. */
function signAction(agent, actionType, payload, nonce, credId) {
    const a = { didS: agent.did, actionType, payload, nonce, credId };
    a.sig = sign(null, actionBytes(a), agent.privateKey).toString('hex');
    return a;
}

module.exports = { newAgent, issueCredential, signAction };
