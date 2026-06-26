/*
 * Revocation & Policy contract.
 * Holds the revocation list and the consumed-nonce set, and runs the on-chain
 * Auth() check of eq. 4 in the exact order of Algorithm 1. On approval it
 * consumes the nonce and anchors an attestation (eq. 5). Rejected attempts are
 * recorded too, so even blocked actions leave a tamper-evident trace.
 */
import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';
import { createHash } from 'crypto';
import { actionBytes, verifyEd25519 } from './canonical';
import { DelegationRegistry } from './delegationRegistry';
import { ActionTx, Credential, Identity, KEY } from './types';

interface Decision { verdict: 'Approve' | 'Reject'; reason?: string; chainId?: string; }

@Info({ title: 'RevocationPolicy', description: 'Revocation, replay protection, and Auth() enforcement' })
export class RevocationPolicy extends Contract {
    constructor() {
        super('RevocationPolicy');
    }

    @Transaction()
    async revoke(ctx: Context, credId: string): Promise<void> {
        await ctx.stub.putState(ctx.stub.createCompositeKey(KEY.REVOKED, [credId]), Buffer.from('1'));
    }

    @Transaction(false)
    @Returns('boolean')
    async isRevoked(ctx: Context, credId: string): Promise<boolean> {
        const d = await ctx.stub.getState(ctx.stub.createCompositeKey(KEY.REVOKED, [credId]));
        return !!d && d.length > 0;
    }

    private async exists(ctx: Context, objType: string, attrs: string[]): Promise<boolean> {
        const d = await ctx.stub.getState(ctx.stub.createCompositeKey(objType, attrs));
        return !!d && d.length > 0;
    }

    private async getJSON<T>(ctx: Context, objType: string, attrs: string[]): Promise<T | null> {
        const d = await ctx.stub.getState(ctx.stub.createCompositeKey(objType, attrs));
        return d && d.length > 0 ? (JSON.parse(d.toString()) as T) : null;
    }

    private effectiveScope(chain: Credential[]): Set<string> {
        if (chain.length === 0) return new Set<string>();
        let eff = new Set<string>(chain[0].scope);
        for (let i = 1; i < chain.length; i++) {
            const s = new Set<string>(chain[i].scope);
            eff = new Set<string>(Array.from(eff).filter((x) => s.has(x)));   // intersection
        }
        return eff;
    }

    /**
     * Auth(a, S) = Ident AND Fresh AND Chain AND Scope AND Valid AND not Revoked.
     * Submit this transaction for every high-impact action; it is the on-chain
     * twin of decide() in the Python reference implementation.
     */
    @Transaction()
    @Returns('string')
    async authorizeAction(ctx: Context, txJson: string): Promise<string> {
        const tx: ActionTx = JSON.parse(txJson);
        const decision = await this.decide(ctx, tx);

        if (decision.verdict === 'Approve') {
            // consume nonce, anchor attestation bound to the chain (eq. 5)
            await ctx.stub.putState(ctx.stub.createCompositeKey(KEY.NONCE, [tx.nonce]), Buffer.from('1'));
            const h = createHash('sha256')
                .update([tx.didS, tx.actionType, tx.nonce, 'ok', decision.chainId].join('|'))
                .digest('hex');
            await ctx.stub.putState(
                ctx.stub.createCompositeKey(KEY.ATTEST, [h]),
                Buffer.from(JSON.stringify({ hash: h, didS: tx.didS, action: tx.actionType,
                                             nonce: tx.nonce, chainId: decision.chainId, result: 'ok' })),
            );
        } else {
            // log the blocked attempt
            const h = createHash('sha256')
                .update([tx.didS, tx.actionType, tx.nonce, decision.reason].join('|')).digest('hex');
            await ctx.stub.putState(
                ctx.stub.createCompositeKey(KEY.ATTEST, [`reject-${h}`]),
                Buffer.from(JSON.stringify({ didS: tx.didS, action: tx.actionType,
                                             nonce: tx.nonce, result: 'rejected', reason: decision.reason })),
            );
        }
        return JSON.stringify(decision);
    }

    /** The pure check, in Algorithm 1 order and reject reasons. */
    private async decide(ctx: Context, tx: ActionTx): Promise<Decision> {
        // 1. Ident -- signature over the action verifies against the registered key
        const idRec = await this.getJSON<Identity>(ctx, KEY.IDENTITY, [tx.didS]);
        if (!idRec) return { verdict: 'Reject', reason: 'IdentityFailed' };
        const sigOk = verifyEd25519(
            idRec.pubKey,
            actionBytes({ didS: tx.didS, actionType: tx.actionType, payload: tx.payload,
                          nonce: tx.nonce, credId: tx.credId }),
            tx.sig,
        );
        if (!sigOk) return { verdict: 'Reject', reason: 'IdentityFailed' };

        // 2. Fresh -- nonce not previously consumed
        if (await this.exists(ctx, KEY.NONCE, [tx.nonce])) {
            return { verdict: 'Reject', reason: 'ReplayedNonce' };
        }

        // 3. Chain -- traces to a trusted root, leaf bound to this subject
        const chainJson = await new DelegationRegistry().getChain(ctx, tx.credId);
        const chain: Credential[] = JSON.parse(chainJson);
        if (chain.length === 0 || chain[0].subject !== tx.didS) {
            return { verdict: 'Reject', reason: 'BrokenChain' };
        }
        const root = chain[chain.length - 1];
        if (!(await this.exists(ctx, KEY.ROOT, [root.issuer]))) {
            return { verdict: 'Reject', reason: 'BrokenChain' };
        }

        // 4. Valid + not Revoked -- per credential, at execution time
        const now = Number(ctx.stub.getTxTimestamp().seconds);
        for (const c of chain) {
            if (await this.exists(ctx, KEY.REVOKED, [c.id]) || !(c.nb <= now && now <= c.na)) {
                return { verdict: 'Reject', reason: 'InvalidCredential' };
            }
        }

        // 5. Scope -- action within the effective (intersected) scope
        if (!this.effectiveScope(chain).has(tx.actionType)) {
            return { verdict: 'Reject', reason: 'OutOfScope' };
        }

        return { verdict: 'Approve', chainId: tx.credId };
    }
}
