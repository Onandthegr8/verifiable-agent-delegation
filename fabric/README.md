# Hyperledger Fabric network (Governance Plane)

This directory is the **on-chain** counterpart to the Python reference implementation in
`../prototype/`. The three contracts are deployed as chaincode on a permissioned Fabric
network, and `bench/` measures the **real end-to-end ledger latency and throughput** that will
replace the modeled ~400 ms figure currently cited in the paper (Table II, Section V).

> **Status: run on a live network (2026-06-26).** Deployed on the `fabric-samples` Fabric 2.5.10
> test-network (single Raft orderer, two orgs, one peer each, one CA each) in WSL2 + Docker Desktop.
> The off-chain signing in `bench/agents.js` interoperates with the on-chain `authorizeAction`
> end-to-end (the benchmark's `setupWorld` registers identities, anchors credentials, and authorizes
> actions with no errors). With the orderer configured for a latency-sensitive workload
> (`BatchTimeout: 250ms`, `MaxMessageCount: 2`), measured end-to-end latency is **mean 406 ms,
> p95 509 ms** over 500 trials (`bench/fabric_results.json`); end-to-end throughput rises with
> concurrency and plateaus near 45 tx/s. These measured numbers replaced the modeled 400 ms in the
> paper (Table II, Section V/VI). (The unmodified test-network default, `BatchTimeout: 2s`, gives
> ~2100 ms — latency tracks the batch interval, a deployment parameter, not the framework.)
>
> **Deploy via CCAAS, not the default build.** Fabric 2.5's legacy peer-side `docker build` is
> incompatible with Docker Engine 29.x (fails with `write /var/run/docker.sock: broken pipe`). Use
> `network.sh deployCCAAS` with the `Dockerfile` in `chaincode/` — the chaincode runs as an external
> service the peers reach over gRPC. Nothing here is fabricated.

## Layout

```
fabric/
  chaincode/   TypeScript chaincode: three contracts mirroring Algorithm 1
    src/
      identityRegistry.ts    DID -> public key (eq. 1); trusted roots
      delegationRegistry.ts  anchor signed grants (eq. 2); getChain()
      revocationPolicy.ts    revocation + nonce + authorizeAction() = Auth() (eq. 4)
      canonical.ts           canonical serialization + Ed25519 verify
      types.ts, index.ts
  network/
    deploy.sh    bring up test-network + deploy the chaincode
  bench/
    bench.js     end-to-end latency + throughput + concurrency sweep
    agents.js    off-chain Ed25519 signing matching canonical.ts
```

The chaincode logic is the on-chain twin of `prototype.py`: `authorizeAction` runs the same
six-part `Auth()` check (`Ident ∧ Fresh ∧ Chain ∧ Scope ∧ Valid ∧ ¬Revoked`) in the exact order
of Algorithm 1, anchors an attestation (eq. 5) on approval, and logs blocked attempts.

## Prerequisites

- Docker Desktop / Docker Engine + Docker Compose
- Node.js >= 18
- Hyperledger Fabric 2.5 binaries and Docker images, plus a cloned
  [`fabric-samples`](https://github.com/hyperledger/fabric-samples)
  (install via the official `install-fabric.sh`)

Set `FABRIC_SAMPLES` to the clone if it is not at `~/fabric-samples`.

## Run

```bash
# 1. build / type-check the chaincode
cd chaincode && npm install && npm run build && cd ..

# 2. start the network and deploy the chaincode
bash network/deploy.sh

# 3. run the benchmark
cd bench && npm install && node bench.js --iterations 500 --sweep 1,5,10,25,50,75,100
```

`bench.js` writes `bench/fabric_results.json` with measured end-to-end latency (mean/p50/p95/p99),
single-client throughput, and a concurrency sweep intended to locate where throughput stops
scaling (the handoff targets degradation past ~50 concurrent agents).

## Feeding results back into the paper

Once `fabric_results.json` exists:

1. Replace the **modeled** "Ledger anchor ... 400 ms" row in Table II with the measured mean (and
   add p95). Keep it clearly labelled *measured* and drop the `\cite{jan2025}` modeled annotation.
2. Update Section V "Measured vs. Modeled" to note the ledger figure is now measured on this
   network, with the network topology (orderer/peer/endorsement policy) stated.
3. Add the concurrency-sweep result to Section VI (Overhead and Scalability) — this is the
   "biggest credibility upgrade" called out in the project handoff.
