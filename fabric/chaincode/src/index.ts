/*
 * Chaincode entry point. Exports the three contracts that make up the
 * Governance Plane of the framework:
 *   - IdentityRegistry   : DID -> public-key bindings (and trusted roots)
 *   - DelegationRegistry : signed grants + authority-chain reconstruction
 *   - RevocationPolicy   : revocation, replay protection, and Auth() enforcement
 */
import { IdentityRegistry } from './identityRegistry';
import { DelegationRegistry } from './delegationRegistry';
import { RevocationPolicy } from './revocationPolicy';

export { IdentityRegistry, DelegationRegistry, RevocationPolicy };

export const contracts: unknown[] = [IdentityRegistry, DelegationRegistry, RevocationPolicy];
