# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

This is **not** a conventional software project — it is an IEEE research paper plus the artifacts
that back its claims. The deliverable is the paper; the code exists to *produce and defend the
numbers in it*. Read `PROJECT_HANDOFF.md` (the original brief) and `SESSION_NOTES.md` (what was done
since) before making changes.

Three coupled parts:

- `paper/` — the canonical IEEEtran LaTeX source (`main.tex`, `references.bib`, three figures) and a
  rebuilt `overleaf_project.zip`. **Edit here, then rebuild the zip.** The paper is compiled on
  Overleaf, not locally.
- `prototype/` — `prototype.py`, a self-contained Python reference implementation of the paper's
  authorization layer. **This is the source of every number the paper labels "measured."** Running it
  writes `results.json` (raw numbers) and `results_fig.png` (the paper's results figure).
- `fabric/` — Hyperledger Fabric chaincode (`chaincode/`) + an end-to-end benchmark (`bench/`). This
  is the on-chain counterpart to `prototype.py`. **Run on a live Fabric 2.5.10 test-network
  (2026-06-26)** via WSL2 + Docker Desktop; `bench/fabric_results.json` holds the measured end-to-end
  ledger latency. With the orderer set for a latency workload (`BatchTimeout: 250ms`,
  `MaxMessageCount: 2` in `test-network/configtx/configtx.yaml`) it is **mean 406 ms, p95 509 ms**,
  throughput plateau ~45 tx/s; this replaced the modeled 400 ms in the paper. (The 2 s default gives
  ~2100 ms — latency tracks the batch interval.) Deploy with **CCAAS** (`network.sh deployCCAAS`,
  using `chaincode/Dockerfile`) — the legacy peer-side build is broken on Docker Engine 29.x.

## Non-negotiable integrity rules

These are the author's stated constraints and override normal "make it pass" instincts:

- **Never fabricate or hand-tune numbers.** If a measurement changes, change the *paper* to match,
  never the code to hit a target.
- **Measured vs. modeled stay strictly separate.** The ~400 ms ledger-anchoring cost is *modeled*
  (taken from ref `jan2025`) and must always be labelled as such and cited — it is never folded into
  a measured cell. Everything in `prototype.py`'s output is measured on this host.
- **The paper must match `results.json`.** After any prototype run, re-sync Table II, the Section V
  environment line, and the inline numbers in `main.tex` to the committed `results.json` exactly.
  Deterministic enforcement cells (100/0 blocking, chain reconstruction) must reproduce; latency and
  throughput are host-dependent and get updated to the actual run.

## The three-layer correspondence (the core architecture)

The same authorization logic exists in three places and must stay in lockstep:

1. **Paper** — `Auth()` predicate (eq. 4) and **Algorithm 1** in `main.tex`, in a fixed check order
   with named reject reasons (`IdentityFailed`, `ReplayedNonce`, `BrokenChain`, `InvalidCredential`,
   `OutOfScope`).
2. **`prototype/prototype.py`** — `B2Authorizer.decide()` implements that exact order and those exact
   reasons. `decide()` is a *pure* check (no side effects) so it can be timed and repeated;
   `authorize()` = `decide()` + consume-nonce + anchor-attestation. Overhead timing always uses
   `decide()`. Three baselines: `B0` (no checks), `B1` (allow-list = prior work), `B2` (ours).
3. **`fabric/chaincode/src/revocationPolicy.ts`** — `authorizeAction()` is the on-chain twin, same
   order/reasons. `IdentityRegistry`, `DelegationRegistry`, and `RevocationPolicy` are the three
   contracts; `canonical.ts` does deterministic JSON serialization + Ed25519 verify, mirrored
   off-chain by `bench/agents.js` (their signing must byte-match the chaincode's verification).

If you change the check order, the reject reasons, the scope-intersection rule, or the canonical
serialization in one layer, change all three and the paper.

## Toolchain (Windows; nothing is on PATH)

The bare `python`/`node` on PATH are stubs or absent. Use full paths.

- **Python**: the project venv at `.venv\Scripts\python.exe` (has `cryptography`, `matplotlib`,
  `numpy`). The real base interpreter is `%LOCALAPPDATA%\Programs\Python\Python312\python.exe`.
- **Node**: installed via winget as a zip, **not on PATH** —
  `%LOCALAPPDATA%\Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_*\node-v*-win-x64\node.exe`
  (npm in the same dir). Prepend that dir to `$env:Path` per session.
- **Docker + WSL**: the Fabric network runs in **WSL2 Ubuntu** with Docker Desktop integration. Drive
  it with `wsl -d Ubuntu -u root` (default user `anand` can't see root's `/root/fabric-samples` or
  Docker). Helper scripts live in `C:\Users\anand\fabric-work\` (no-space path; `/mnt/c` chokes on the
  spaces in this project's path). Deploy chaincode via CCAAS (Docker 29.x broke the peer-side build).
- Prefer PowerShell and stay inside the project dir; the Bash tool's view and operations crossing
  `Downloads` have shown filesystem inconsistency.

## Commands

```powershell
# Run the prototype (full: 2000 enforcement / 5000 overhead trials). Writes results.json + figure.
& ".venv\Scripts\python.exe" prototype\prototype.py
& ".venv\Scripts\python.exe" prototype\prototype.py --quick   # fast smoke run

# Regenerate ONLY the figure from an existing results.json (avoids re-perturbing the numbers):
cd prototype; & "..\.venv\Scripts\python.exe" -c "import json,prototype; prototype.make_figure(json.load(open('results.json')),'results_fig.png')"

# Type-check the chaincode (needs Node on PATH for this session):
cd fabric\chaincode; npm install; npx tsc --noEmit

# Rebuild the Overleaf upload package after editing the paper:
Compress-Archive -Path paper\main.tex,paper\references.bib,paper\fig_arch.png,paper\fig_flow.png,paper\results_fig.png -DestinationPath paper\overleaf_project.zip -Force
```

There is **no separate test suite**: `prototype.py` self-tests. Its enforcement run and the
reject-path coverage check act as the tests — the script exits non-zero (`SystemExit`) if any
`Auth()` reject path stops behaving as expected. To "run the tests," run the prototype.

## Reconciliation workflow (do this every time the prototype changes)

1. Run `prototype.py`; it overwrites `results.json` and `results_fig.png`.
2. Read `results.json`; update the matching numbers in `paper/main.tex` (Table II, Section V env
   line, abstract, conclusion, figure caption, Section VII figures) to match exactly.
3. Copy `prototype/results_fig.png` over `paper/results_fig.png`.
4. Rebuild `paper/overleaf_project.zip`.
5. Sanity-check: every `\cite{}` key in `main.tex` resolves to an entry in `references.bib` (no
   dangling/orphan), and no stale numbers remain.

## Paper compile notes

IEEEtran on Overleaf with **pdfLaTeX**; recompile twice so bibtex resolves references. Target is a
6-page IEEE conference paper — watch the page count when adding prose.
