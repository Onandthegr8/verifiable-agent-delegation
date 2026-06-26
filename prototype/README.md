# Authorization-layer reference implementation

`prototype.py` is the self-contained, runnable reference implementation behind the
measured results in the paper *"Verifiable Identity and Delegation for Orchestrated
Multi-Agent AI Systems: A Blockchain-Anchored Framework."*

It isolates the part of the framework that is new — cryptographic identity, scoped and
revocable delegation chains, replay protection, and the `Auth()` predicate — so its
**correctness** and **cost** can be measured without a live ledger or an LLM in the loop.

## What it measures

Three configurations:

| | identity model | checks |
|---|---|---|
| **B0** | none | none — runs everything |
| **B1** | allow-list (prior work) | name on a whitelist |
| **B2** | ours | DID signature + delegation chain + scope + window + revocation + nonce |

over six scenarios: **S1** legitimate, **S2** spoof, **S3** out-of-scope, **S4** revoked,
**S5** expired, **S6** replay. It reports, per configuration, the % of attacks blocked, the
% of executed actions whose authority chain can be reconstructed, per-decision latency
(mean + p95), revocation latency, and single-core throughput.

It also runs two extra checks:
- a **chain-depth sweep** (depths 1–10) that measures `Auth()` latency vs. delegation-chain length
  and fits a line — confirming the cost is linear in chain length (~3.4 µs per extra credential);
- a **reject-path coverage** self-test that asserts every `Auth()` outcome is reachable with the
  expected reason (`IdentityFailed` for both a bad signature and an unknown DID, `ReplayedNonce`,
  `BrokenChain`, `InvalidCredential` for revoked and expired, `OutOfScope`, and `Approve`). The run
  fails loudly if any path misbehaves.

## Run

```bash
pip install -r requirements.txt
python prototype.py            # full run: 2000 enforcement / 5000 overhead trials
python prototype.py --quick    # fast smoke run
```

Outputs (written next to the script):

- `results.json` — every measured number, plus the host environment it was measured on.
- `results_fig.png` — enforcement-by-scenario and latency-composition figure used in the paper.

## Measured vs. modeled

**Everything this script prints is measured on the host it runs on.** The ~400 ms
permissioned-ledger anchoring cost is **not** measured here; it is a separate **modeled**
figure taken from prior work (Jan et al., arXiv:2512.20985) and is only added to the measured
crypto cost for the "mean decision latency" row, which is labelled accordingly. Standing up a
real Hyperledger Fabric network and measuring end-to-end ledger latency is future work — see
`../fabric/`.

## Reproducibility notes

- **Enforcement results are deterministic** and hardware-independent: B2 blocks 100% of S2–S6
  and reconstructs 100% of chains; B0 and B1 block 0%; all three pass 100% of S1.
- **Latency and throughput are hardware-dependent.** The numbers in the paper's Table II were
  measured on an Intel Core i3-7020U @ 2.30 GHz (Windows 10, Python 3.12.10, cryptography 49.0).
  Re-running on different hardware will produce different latency/throughput; `results.json`
  always records the actual host so the figures stay honest.
- Per-decision latencies are averaged over back-to-back invocations to factor out OS-scheduling
  jitter (the timed `decide()` path is side-effect free, so repetition is valid); the p95 is
  taken from single calls so it still reflects the tail.
