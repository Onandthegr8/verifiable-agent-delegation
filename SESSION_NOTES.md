# Session notes — 2026-06-18

Picked up the paper project from `PROJECT_HANDOFF.md`. The handoff described a full set of
artifacts, but on disk only the paper outputs existed (in `Downloads`) — **`prototype.py` and
`results.json` were missing**, so the paper's "measured" numbers were not reproducible. This
session rebuilt and ran the prototype, verified/fixed the references, and scaffolded the Fabric
network. Everything now lives under this project directory.

## What was done

### 1. Project consolidated
- `paper/` — canonical LaTeX package (`main.tex`, `references.bib`, 3 figures) + rebuilt
  `overleaf_project.zip`.
- `prototype/` — the reference implementation (new).
- `fabric/` — Hyperledger Fabric chaincode + benchmark (new, code only).

### 2. Prototype rebuilt and run — numbers are now reproducible
`prototype/prototype.py` implements exactly the paper's model (Ed25519 identities, signed
delegation chains with narrowing scope, nonce replay protection, the `Auth()` predicate in
Algorithm 1 order, attestations) and the B0/B1/B2 baselines over S1–S6. Run with
`python prototype/prototype.py`; raw output in `prototype/results.json`.

- **Enforcement reproduces the paper exactly** (deterministic): B2 blocks 100% of S2–S6 and
  reconstructs 100% of chains; B0 and B1 block 0%; all pass 100% of S1.
- **Overhead was re-measured on this machine** (the paper's old Xeon/Colab numbers were replaced).
  Host: **Intel Core i3-7020U @ 2.30 GHz, 12 GB RAM, Windows 10, Python 3.12.10, cryptography 49.0**.

| Metric | old (paper) | new (measured here) |
|---|---|---|
| Auth mean | 0.411 ms | **0.235 ms** |
| Auth p95 | 0.500 ms | **0.387 ms** |
| Identity verify | 0.125 ms | 0.202 ms |
| Nonce check | 0.0005 ms | 0.0003 ms |
| Revocation latency | 0.322 ms | 0.220 ms |
| Throughput (B2) | 2,436 tx/s | **4,252 tx/s** |
| Mean decision latency (B2) | 400.4 ms | 400.2 ms |

The `main.tex` Table II, the Section V environment line, the abstract, the figure caption, and
the Section VII figures were all updated to match. `results_fig.png` was regenerated from the real
data (panel (b) now uses a log axis so the crypto-vs-ledger ratio is visible). The modeled 400 ms
ledger anchor stays modeled and cited to [jan2025].

### 3. References verified and fixed
- The four flagged arXiv IDs **all resolve** to real papers (jan2025 2512.20985, xu2026 2602.14219,
  tiva2025 2511.15712, wang2024survey 2308.11432 / FCS 2024).
- Fixed `xu2026` author (single author Minghui Xu, was "and others") and added the missing author to
  `tiva2025` (Vivek Acharya).
- **Merged the duplicate survey**: `wu2024survey` and `wang2023survey` were the same work; kept one
  entry (`wang2024survey`) citing the published *Frontiers of Computer Science* 2024 version and
  fixed the in-text citation.
- All 19 `\cite` keys resolve to the 19 bib entries (no dangling/orphan).

### 4. Fabric network scaffolded (code only — not run)
`fabric/` has the three contracts as TypeScript chaincode mirroring Algorithm 1, a `deploy.sh` for
the fabric-samples test-network, and `bench/bench.js` to measure real end-to-end latency/throughput
+ a concurrency sweep. It needs Docker/Node/Fabric to run; **no Fabric numbers are in the paper**
until it is run. See `fabric/README.md`.

### 5. Paper polished
- Made it **single-author** (P Anand Kumar) — removed the co-author/advisor placeholder blocks.
- Added a **worked delegation-chain example** (Section IV) walking root -> orchestrator -> specialist
  and the S3 out-of-scope rejection.
- Noted that **`Auth()` cost is linear in chain length** (Section VI), dominated by the single
  action-signature verification.
- Added **private-key theft** to the out-of-scope threats (Section IV), tied to why revocation matters.
- Drafted a **"Use of AI Assistance"** statement before the references — verify wording against the
  chosen venue's exact policy/placement.

## What's left
- **Run the Fabric benchmark** on a Docker-equipped machine and replace the modeled 400 ms with the
  measured number (biggest credibility upgrade).
- **Pick the venue**, run a similarity check, and confirm the AI-disclosure wording/placement matches
  that venue's policy.
- Check the page count on Overleaf after the additions (IEEE conference limit is typically 6 pages).
- Account sign-ins, uploads, and submission remain the author's to do directly.
