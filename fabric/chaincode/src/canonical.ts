/*
 * Canonical serialization and Ed25519 verification shared by the contracts.
 *
 * The on-chain logic mirrors the Python reference implementation in
 * ../../prototype/prototype.py: a credential / action is serialized to a
 * deterministic JSON byte string (keys sorted, no whitespace) and signed with
 * Ed25519. The same canonical form is used for signing (off-chain, by the
 * issuing/acting agent) and for verification here, so the bytes always match.
 */
import { createPublicKey, verify } from 'crypto';

export interface CredentialFields {
    id: string;
    issuer: string;   // did_O
    subject: string;  // did_S
    scope: string[];  // permitted action types
    nb: number;       // not-before (epoch seconds)
    na: number;       // not-after
}

export interface ActionFields {
    didS: string;
    actionType: string;
    payload: string;
    nonce: string;
    credId: string;
}

/** Deterministic JSON with sorted keys and no whitespace. */
function canonicalJSON(obj: Record<string, unknown>): Buffer {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
    return Buffer.from(JSON.stringify(sorted));
}

/** Canonical bytes a credential issuer signs (eq. 2). */
export function credentialBytes(c: CredentialFields): Buffer {
    return canonicalJSON({
        id: c.id, iss: c.issuer, sub: c.subject,
        scope: [...c.scope].sort(), nb: c.nb, na: c.na,
    });
}

/** Canonical bytes an agent signs for a proposed action; binds the nonce. */
export function actionBytes(a: ActionFields): Buffer {
    return canonicalJSON({
        sub: a.didS, type: a.actionType, payload: a.payload,
        nonce: a.nonce, cred: a.credId,
    });
}

// DER SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 public key.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function ed25519PublicKey(rawHex: string) {
    const der = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawHex, 'hex')]);
    return createPublicKey({ key: der, format: 'der', type: 'spki' });
}

/** Verify an Ed25519 signature (hex) over `message` against a raw public key (hex). */
export function verifyEd25519(rawPubKeyHex: string, message: Buffer, sigHex: string): boolean {
    try {
        return verify(null, message, ed25519PublicKey(rawPubKeyHex), Buffer.from(sigHex, 'hex'));
    } catch {
        return false;
    }
}
