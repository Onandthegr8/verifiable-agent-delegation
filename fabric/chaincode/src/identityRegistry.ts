/*
 * Identity Registry contract (eq. 1: A = <did, pk, sk>).
 * Binds each agent DID to its Ed25519 public key plus metadata.
 */
import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';
import { Identity, KEY } from './types';

@Info({ title: 'IdentityRegistry', description: 'Maps agent DID -> public key' })
export class IdentityRegistry extends Contract {
    constructor() {
        super('IdentityRegistry');
    }

    private txTime(ctx: Context): string {
        const ts = ctx.stub.getTxTimestamp();
        return new Date(Number(ts.seconds) * 1000).toISOString();
    }

    @Transaction()
    async registerIdentity(ctx: Context, did: string, pubKey: string,
                           role: string, issuer: string): Promise<void> {
        const key = ctx.stub.createCompositeKey(KEY.IDENTITY, [did]);
        const existing = await ctx.stub.getState(key);
        if (existing && existing.length > 0) {
            throw new Error(`identity ${did} already registered`);
        }
        const id: Identity = { did, pubKey, role, issuer, created: this.txTime(ctx) };
        await ctx.stub.putState(key, Buffer.from(JSON.stringify(id)));
    }

    @Transaction(false)
    @Returns('string')
    async resolveIdentity(ctx: Context, did: string): Promise<string> {
        const key = ctx.stub.createCompositeKey(KEY.IDENTITY, [did]);
        const data = await ctx.stub.getState(key);
        if (!data || data.length === 0) throw new Error(`unknown DID ${did}`);
        return data.toString();
    }

    /** Mark a DID as a trusted root authority (chains must terminate here). */
    @Transaction()
    async registerTrustedRoot(ctx: Context, did: string): Promise<void> {
        const key = ctx.stub.createCompositeKey(KEY.ROOT, [did]);
        await ctx.stub.putState(key, Buffer.from('1'));
    }
}
