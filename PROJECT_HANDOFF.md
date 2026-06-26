# Project Handoff: Verifiable Identity and Delegation for Multi-Agent AI Systems

This document summarizes a research-paper project so it can be resumed in a new
session. Paste it in and continue from "What's left to do."

---

## 1. What the project is

A computer science research paper (IEEE conference format) by P Anand Kumar
(Chennai Institute of Technology). The paper proposes a security framework for
**orchestrated multi-agent AI systems** and backs it with a working prototype
and measured results.

**Working title:** *Verifiable Identity and Delegation for Orchestrated
Multi-Agent AI Systems: A Blockchain-Anchored Framework*

**The problem it solves.** In multi-agent AI systems, a central orchestrator
delegates subtasks to specialist agents that take real actions (run code, move
data, trigger transactions). Current platforms identify agents with a static
**allow-list of names**, which only answers "is this name known?" It cannot
prove the agent is cryptographically who it claims to be, whether it was
authorized for *this specific action*, whether that authority is still valid,
or reconstruct the chain of authority for an audit.

**The contribution.** Give every agent a real cryptographic identity and make
every orchestrator-to-specialist hand-off a signed, scoped, revocable
delegation credential anchored on a permissioned ledger. The headline novelty
is **delegation** — one agent passing bounded, revocable authority to another —
which prior work did not handle (it stopped at the allow-list).

---

## 2. Architecture (four planes)

- **Identity Plane** — a Passport (issuer) service mints credentials; an
  Identity Registry maps each agent DID -> public key.
- **Orchestration Plane** — the root authority (user/org), the orchestrator,
  and the specialist agents (e.g. roadmap, assessment, mentor).
- **Governance Plane** — a permissioned ledger (Hyperledger Fabric) running
  three smart contracts: Identity Registry, Delegation Registry, and
  Revocation & Policy.
- **Execution Plane** — MCP (Model Context Protocol) connectors call external
  tools and anchor an attestation of each completed action.

### Core mechanisms
- **Identity:** each agent has an Ed25519 key pair and a DID. It proves who it
  is by signing actions; the signature is checked against its registered key.
  (Replaces the forgeable name-on-a-list approach.)
- **Delegation credential:** a signed object naming issuer DID, subject DID,
  scope (allowed action types), validity window [t_nb, t_na], and the issuer's
  signature. Scope can only **shrink** down the chain, never grow.
- **Authorization check** (runs before any high-impact action). All must hold:
  1. **Ident** — signature verifies against the registered key
  2. **Fresh** — action nonce has not been used before (replay protection)
  3. **Chain** — delegation chain traces back to a trusted root
  4. **Scope** — action is within the effective (intersected) scope
  5. **Valid + not Revoked** — inside the validity window; no credential in the
     chain is revoked
- **Attestation:** after execution, a hash over (subject DID, action, nonce,
  result, chain id) is anchored on the ledger. Even *blocked* attempts are
  logged, so attacks leave an audit trail.

---

## 3. Key decisions made

- **Topic chosen** to fill a real gap: the closest prior work (an IEEE ICCA
  2025 / arXiv:2512.20985 paper) uses a whitelist for identity and models
  neither delegation nor revocation. Our delta = cryptographic DIDs + scoped,
  revocable delegation chains.
- **Scope kept tight:** one permissioned chain, identity + delegation done
  well. Cross-chain interoperability and sharding deliberately left as future
  work.
- **No fabricated results — firm rule.** We never invented experimental
  numbers. Instead we built a real prototype and measured it.
- **Measured vs. modeled, kept strictly separate.** The cryptographic
  authorization layer is *measured*. The permissioned-ledger anchoring latency
  (~400 ms/action) is *modeled* from prior work [1] and labeled as such
  everywhere — never folded silently into measured numbers.
- **Replay protection added** after review: a per-action nonce bound into the
  signature, plus a SeenNonce check and ConsumeNonce on approval. Closes a gap
  where a captured-and-resent legitimate action would otherwise pass.
- **Writing style:** prose was rewritten in a plainer, more direct voice
  (improving the writing itself — explicitly NOT to defeat an AI detector,
  which was declined as an integrity matter).

---

## 4. Prototype and measured results

A self-contained Python reference implementation (`prototype.py`) of the
authorization layer: Ed25519 identities, DID-to-key registry, signed delegation
credentials with scope and validity windows, chain resolution, revocation
registry, consumed-nonce registry, and the Auth() predicate.

Three baselines compared: **B0** (no blockchain), **B1** (allow-list, =prior
work identity model), **B2** (our DID + delegation framework).

Six scenarios: S1 legitimate, S2 spoofed identity, S3 out-of-scope, S4 revoked,
S5 expired, S6 replayed action.

### Enforcement (measured)
| Scenario | B0 | B1 | B2 |
|---|---|---|---|
| S1 legitimate success | 100% | 100% | 100% |
| S2 spoof blocked | 0% | 0% | 100% |
| S3 out-of-scope blocked | 0% | 0% | 100% |
| S4 revoked blocked | 0% | 0% | 100% |
| S5 expired blocked | 0% | 0% | 100% |
| S6 replay blocked | 0% | 0% | 100% |
| Chain reconstruction | 0% | 0% | 100% |

### Overhead (measured, except ledger anchor which is modeled)
- Full Auth() check: **0.411 ms** mean, **0.500 ms** p95
- Identity (signature) verify alone: **0.125 ms**
- Replay (nonce) check: **0.0005 ms** (hash-set lookup, effectively free)
- Revocation latency: **0.322 ms**
- Auth-layer throughput: **~2,436 tx/s** on one core
- Ledger anchor: **400 ms** (MODELED from prior work [1], not measured)
- Test env: single Intel Xeon core @ 2.10 GHz, Python 3.12, cryptography 46.0,
  2,000 trials per enforcement scenario, 5,000 per overhead measurement.

**Takeaway:** B2 blocks every attack the baselines miss, reconstructs the full
authority chain for every action, and the cryptographic cost is negligible
(~0.1%) next to the ledger anchoring. The ledger, not the crypto, is the
bottleneck.

---

## 5. Current state of artifacts

All delivered and mutually consistent:
- `overleaf_project.zip` — LaTeX package to drag into Overleaf (main.tex,
  references.bib, 3 figure PNGs). Compiles clean; set compiler to pdfLaTeX,
  recompile twice so bibtex resolves. **6 pages.**
- `main.tex` — full IEEEtran source (8 sections, equations, Algorithm 1,
  4 tables, 3 figures).
- `references.bib` — 20 references in BibTeX. **Header note flags which
  entries need verification.**
- `agent_delegation_paper.docx` / `.pdf` — Word version + rendered PDF,
  6 pages, validates.
- `prototype.py` — runnable, produces all the measured numbers above.
- `results.json` — raw measured output.
- `fig_arch.png`, `fig_flow.png`, `results_fig.png` — figures.

Paper structure: I. Introduction, II. Background, III. Related Work,
IV. Proposed Framework, V. Experimental Setup, VI. Results & Discussion,
VII. Security Analysis, VIII. Conclusion.

---

## 6. What's left to do (priority order)

1. **Build the real Hyperledger Fabric network and measure it.** Biggest
   credibility upgrade. Replace the modeled 400 ms with real end-to-end
   latency/throughput, and measure degradation as concurrent agents climb past
   ~50. (Infrastructure work the author must run; a build-and-measure plan can
   be drafted.)
2. **Verify every reference exists.** Especially arXiv IDs — open each, confirm
   title/authors/ID, re-export BibTeX from the real source. Highest-risk item.
3. **Fill in author placeholders** `[Co-author Name]` / `[Advisor Name]` with
   real contributors; advisor should consent to authorship.
4. **Run a similarity check** (related-work echoes prior-work vocabulary) and
   **write the AI-disclosure statement** per the target venue's policy. Target
   venue not yet chosen — pick it so the disclosure and scope can be finalized.
5. **Optional strengthening:** add a worked delegation-chain example; note that
   Auth() cost is linear in chain length; add key-compromise to the
   out-of-scope threats explicitly.

### Standing integrity notes (carried throughout the project)
- Never submit fabricated/placeholder numbers.
- Keep measured vs. modeled clearly separated.
- Disclose AI assistance per venue policy rather than concealing it.
- Account sign-ins, uploads, and submissions are the author's to do directly.

---

## 7. Realistic venue expectation
With the working prototype + (eventually) real Fabric measurements: IEEE/Springer
conferences or workshops, or a mid-tier journal such as *Blockchain: Research
and Applications*. Top-tier security venues (S&P, CCS) only if the delegation
protocol is developed much further. A tight, well-evaluated system at a solid
venue beats an oversold one.
