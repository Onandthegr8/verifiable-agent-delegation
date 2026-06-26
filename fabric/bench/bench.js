/*
 * End-to-end Hyperledger Fabric benchmark for the agent-delegation chaincode.
 *
 * This is the harness that will REPLACE the modeled ~400 ms ledger figure in
 * the paper with a real, measured number. It connects to the fabric-samples
 * test-network, sets up the identity/delegation world, then measures:
 *   - per-action end-to-end latency (submit -> commit) for a legitimate action,
 *   - single-client throughput,
 *   - a concurrency sweep (1..N simultaneous agents) to locate the point where
 *     throughput stops scaling / latency degrades (the handoff targets ~50).
 *
 * It writes fabric_results.json. NOTHING here is run or reported in the paper
 * until this is executed on a real Fabric network -- see ../README.md. No
 * latency numbers are hard-coded.
 *
 * Usage:
 *   node bench.js --iterations 500 --sweep 1,5,10,25,50,75,100
 *
 * Connection settings are read from environment variables (see ../README.md);
 * defaults assume the standard fabric-samples/test-network layout.
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const grpc = require('@grpc/grpc-js');
const { connect, signers } = require('@hyperledger/fabric-gateway');
const { newAgent, issueCredential, signAction } = require('./agents');

// ---- connection configuration (test-network defaults) ----------------------
const CFG = {
    channel: process.env.CHANNEL_NAME || 'mychannel',
    chaincode: process.env.CHAINCODE_NAME || 'agentdelegation',
    mspId: process.env.MSP_ID || 'Org1MSP',
    peerEndpoint: process.env.PEER_ENDPOINT || 'localhost:7051',
    peerHostAlias: process.env.PEER_HOST_ALIAS || 'peer0.org1.example.com',
    cryptoPath: process.env.CRYPTO_PATH ||
        path.resolve(os.homedir(), 'fabric-samples', 'test-network', 'organizations',
            'peerOrganizations', 'org1.example.com'),
};

function firstFile(dir) {
    return path.join(dir, fs.readdirSync(dir)[0]);
}

async function newGateway() {
    const tlsCert = fs.readFileSync(path.join(CFG.cryptoPath, 'peers',
        'peer0.org1.example.com', 'tls', 'ca.crt'));
    const client = new grpc.Client(CFG.peerEndpoint,
        grpc.credentials.createSsl(tlsCert),
        { 'grpc.ssl_target_name_override': CFG.peerHostAlias });

    const userDir = path.join(CFG.cryptoPath, 'users', 'User1@org1.example.com', 'msp');
    const cert = fs.readFileSync(firstFile(path.join(userDir, 'signcerts')));
    const key = crypto.createPrivateKey(fs.readFileSync(firstFile(path.join(userDir, 'keystore'))));

    return connect({
        client,
        identity: { mspId: CFG.mspId, credentials: cert },
        signer: signers.newPrivateKeySigner(key),
        evaluateOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 15000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });
}

// ---- helpers ---------------------------------------------------------------
const nonce = () => crypto.randomBytes(16).toString('hex');
const utf8 = (b) => Buffer.from(b).toString('utf8');

function percentile(sorted, p) {
    return sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
}

async function setupWorld(contract) {
    const now = Math.floor(Date.now() / 1000);
    const root = newAgent('did:agent:root', 'root');
    const orch = newAgent('did:agent:orchestrator', 'orchestrator');
    const spec = newAgent('did:agent:risk', 'specialist');

    await contract.submitTransaction('IdentityRegistry:registerIdentity', root.did, root.pubKeyHex, 'root', 'self');
    await contract.submitTransaction('IdentityRegistry:registerIdentity', orch.did, orch.pubKeyHex, 'orchestrator', root.did);
    await contract.submitTransaction('IdentityRegistry:registerIdentity', spec.did, spec.pubKeyHex, 'specialist', orch.did);
    await contract.submitTransaction('IdentityRegistry:registerTrustedRoot', root.did);

    const cRoot = issueCredential(root, orch.did, ['assess_risk', 'screen_fraud', 'transfer'], now - 100, now + 100000, 'cred:root');
    const cSpec = issueCredential(orch, spec.did, ['assess_risk'], now - 100, now + 100000, 'cred:spec');
    await contract.submitTransaction('DelegationRegistry:anchorCredential', JSON.stringify(cRoot));
    await contract.submitTransaction('DelegationRegistry:anchorCredential', JSON.stringify(cSpec));

    return { spec, cSpec };
}

/** Submit one legitimate authorizeAction and return its end-to-end latency (ms). */
async function timedLegitAction(contract, spec, cSpec) {
    const tx = signAction(spec, 'assess_risk', '', nonce(), cSpec.id);
    const t0 = process.hrtime.bigint();
    await contract.submitTransaction('RevocationPolicy:authorizeAction', JSON.stringify(tx));
    return Number(process.hrtime.bigint() - t0) / 1e6;
}

async function measureLatency(contract, world, iterations) {
    const lat = [];
    for (let i = 0; i < iterations; i++) lat.push(await timedLegitAction(contract, world.spec, world.cSpec));
    lat.sort((a, b) => a - b);
    return {
        iterations,
        mean_ms: lat.reduce((a, b) => a + b, 0) / lat.length,
        p50_ms: percentile(lat, 0.5),
        p95_ms: percentile(lat, 0.95),
        p99_ms: percentile(lat, 0.99),
    };
}

/** Concurrency sweep: fire `c` actions at once, repeat, report throughput. */
async function sweep(contract, world, concurrencies, rounds) {
    const out = [];
    for (const c of concurrencies) {
        const t0 = process.hrtime.bigint();
        for (let r = 0; r < rounds; r++) {
            await Promise.all(Array.from({ length: c }, () => timedLegitAction(contract, world.spec, world.cSpec)));
        }
        const secs = Number(process.hrtime.bigint() - t0) / 1e9;
        const total = c * rounds;
        out.push({ concurrency: c, total_tx: total, wall_s: secs, throughput_tx_s: total / secs });
    }
    return out;
}

async function main() {
    const args = require('node:util').parseArgs({
        options: {
            iterations: { type: 'string', default: '500' },
            sweep: { type: 'string', default: '1,5,10,25,50,75,100' },
            rounds: { type: 'string', default: '3' },
        },
    }).values;

    const gateway = await newGateway();
    try {
        const network = gateway.getNetwork(CFG.channel);
        const contract = network.getContract(CFG.chaincode);

        console.log('Setting up identity/delegation world ...');
        const world = await setupWorld(contract);

        console.log('Measuring end-to-end latency (legitimate action) ...');
        const latency = await measureLatency(contract, world, parseInt(args.iterations, 10));
        console.log('  mean %sms  p95 %sms', latency.mean_ms.toFixed(1), latency.p95_ms.toFixed(1));

        console.log('Running concurrency sweep ...');
        const concurrencies = args.sweep.split(',').map((s) => parseInt(s, 10));
        const sweepResults = await sweep(contract, world, concurrencies, parseInt(args.rounds, 10));
        for (const s of sweepResults) {
            console.log('  concurrency %d -> %s tx/s', s.concurrency, s.throughput_tx_s.toFixed(1));
        }

        const results = {
            measured_on: new Date().toISOString(),
            network: 'hyperledger-fabric test-network',
            channel: CFG.channel,
            chaincode: CFG.chaincode,
            latency,
            sweep: sweepResults,
            note: 'End-to-end measured ledger latency/throughput. Use these to replace the ' +
                  'modeled 400 ms figure in the paper (Table II, Section V).',
        };
        fs.writeFileSync(path.join(__dirname, 'fabric_results.json'), JSON.stringify(results, null, 2));
        console.log('Wrote fabric_results.json');
    } finally {
        gateway.close();
    }
}

main().catch((e) => { console.error(e); process.exit(1); });
