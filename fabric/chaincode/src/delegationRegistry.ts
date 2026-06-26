/*
 * Delegation Registry contract (eq. 2).
 * Anchors signed delegation credentials and reconstructs the authority chain
 * from a leaf credential back to a trusted root.
 */
import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';
import { credentialBytes, verifyEd25519 } from './canonical';
import { Credential, Identity, KEY } from './types';

@Info({ title: 'DelegationRegistry', description: 'Anchors grants and resolves authority chains' })
export class DelegationRegistry extends Contract {
    constructor() {
        super('DelegationRegistry');
    }

    private async resolvePubKey(ctx: Context, did: string): Promise<string | null> {
        const data = await ctx.stub.getState(ctx.stub.createCompositeKey(KEY.IDENTITY, [did]));
        if (!data || data.length === 0) return null;
        return (JSON.parse(data.toString()) as Identity).pubKey;
    }

    /** Anchor a credential; rejects it if the issuer's signature does not verify. */
    @Transaction()
    async anchorCredential(ctx: Context, credJson: string): Promise<void> {
        const c: Credential = JSON.parse(credJson);
        const issuerPk = await this.resolvePubKey(ctx, c.issuer);
        if (!issuerPk) throw new Error(`unknown issuer ${c.issuer}`);
        const ok = verifyEd25519(
            issuerPk,
            credentialBytes({ id: c.id, issuer: c.issuer, subject: c.subject,
                              scope: c.scope, nb: c.nb, na: c.na }),
            c.sig,
        );
        if (!ok) throw new Error('forged delegation: issuer signature invalid');
        await ctx.stub.putState(
            ctx.stub.createCompositeKey(KEY.CRED, [c.id]),
            Buffer.from(JSON.stringify(c)),
        );
    }

    @Transaction(false)
    @Returns('string')
    async getCredential(ctx: Context, credId: string): Promise<string> {
        const data = await ctx.stub.getState(ctx.stub.createCompositeKey(KEY.CRED, [credId]));
        if (!data || data.length === 0) throw new Error(`unknown credential ${credId}`);
        return data.toString();
    }

    /**
     * Walk leaf -> root via issuer/subject links. Returns the chain as a JSON
     * array [leaf, ..., root grant]. Used by the authorization check and for
     * post-hoc audit / chain reconstruction.
     */
    @Transaction(false)
    @Returns('string')
    async getChain(ctx: Context, credId: string): Promise<string> {
        const all = await this.loadAllCredentials(ctx);
        const byId = new Map(all.map((c) => [c.id, c]));
        const bySubject = new Map(all.map((c) => [c.subject, c]));
        const chain: Credential[] = [];
        const seen = new Set<string>();
        let cur = byId.get(credId);
        while (cur && !seen.has(cur.id)) {
            chain.push(cur);
            seen.add(cur.id);
            cur = bySubject.get(cur.issuer);   // the grant that empowered this issuer
        }
        return JSON.stringify(chain);
    }

    private async loadAllCredentials(ctx: Context): Promise<Credential[]> {
        const out: Credential[] = [];
        const iter = await ctx.stub.getStateByPartialCompositeKey(KEY.CRED, []);
        for (let r = await iter.next(); !r.done; r = await iter.next()) {
            out.push(JSON.parse(r.value.value.toString()));
        }
        await iter.close();
        return out;
    }
}
