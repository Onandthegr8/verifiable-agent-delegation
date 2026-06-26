/* Shared world-state record shapes and composite-key object types. */

export interface Identity {
    did: string;
    pubKey: string;   // raw Ed25519 public key, hex
    role: string;
    issuer: string;
    created: string;  // tx timestamp, ISO 8601
}

export interface Credential {
    id: string;
    issuer: string;   // did_O
    subject: string;  // did_S
    scope: string[];
    nb: number;       // not-before (epoch seconds)
    na: number;       // not-after
    sig: string;      // issuer signature over credentialBytes(), hex
}

export interface ActionTx {
    didS: string;
    actionType: string;
    payload: string;
    credId: string;
    nonce: string;
    sig: string;      // agent signature over actionBytes(), hex
}

// Composite-key object types -- shared across all three contracts in this
// chaincode, so any contract can read another's state by key.
export const KEY = {
    IDENTITY: 'identity',
    CRED: 'cred',
    REVOKED: 'revoked',
    NONCE: 'nonce',
    ROOT: 'root',
    ATTEST: 'attest',
} as const;
