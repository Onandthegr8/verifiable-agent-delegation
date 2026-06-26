"""
prototype.py
============
Reference implementation of the authorization layer described in
"Verifiable Identity and Delegation for Orchestrated Multi-Agent AI Systems:
 A Blockchain-Anchored Framework."

This isolates the part of the framework that is actually new -- cryptographic
identity, scoped/revocable delegation chains, replay protection, and the
Auth() predicate -- without the noise of a live ledger or an LLM, so its
correctness and cost can be measured on their own.

It evaluates three configurations
    B0  no blockchain        (runs everything, no checks)
    B1  allow-list           (the identity model of prior work [jan2025])
    B2  ours                 (DID identities + delegation + nonce + revocation)
over six scenarios
    S1 legitimate  S2 spoof  S3 out-of-scope  S4 revoked  S5 expired  S6 replay
and measures per-decision overhead and single-core throughput.

Outputs:
    results.json       raw measured numbers
    results_fig.png    enforcement-by-scenario and latency-composition figure

Run:  python prototype.py            (2000 enforcement / 5000 overhead trials)
      python prototype.py --quick    (fast smoke run)

NOTE ON MEASURED vs MODELED: every number this script emits is MEASURED on the
host it runs on. The ~400 ms permissioned-ledger anchoring cost is NOT measured
here; it is a separate MODELED figure taken from prior work [jan2025] and is
only combined with the measured crypto cost for the "mean decision latency"
row, which is labelled accordingly.
"""

import argparse
import hashlib
import json
import os
import platform
import secrets
import statistics
import time
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MODELED_LEDGER_MS = 400.0  # modeled anchoring cost from [jan2025]; never measured here


# --------------------------------------------------------------------------- #
# Identity  (eq. 1:  A = <did, pk, sk>)                                        #
# --------------------------------------------------------------------------- #
@dataclass
class Agent:
    did: str
    sk: Ed25519PrivateKey
    role: str

    @property
    def pk(self):
        return self.sk.public_key()


def new_agent(did: str, role: str) -> Agent:
    return Agent(did=did, sk=Ed25519PrivateKey.generate(), role=role)


class IdentityRegistry:
    """Maps did -> public key plus metadata (role, issuer, creation time)."""

    def __init__(self):
        self._m = {}

    def register(self, agent: Agent, issuer: str):
        self._m[agent.did] = {
            "pk": agent.pk,
            "role": agent.role,
            "issuer": issuer,
            "created": time.time(),
        }

    def resolve(self, did: str):
        e = self._m.get(did)
        return e["pk"] if e else None


# --------------------------------------------------------------------------- #
# Delegation credentials                                                       #
# (eq. 2:  DC = <id, did_O, did_S, scope, [nb, na], sig>)                      #
# --------------------------------------------------------------------------- #
@dataclass
class Credential:
    id: str
    issuer: str            # did_O
    subject: str           # did_S
    scope: frozenset       # permitted action types
    nb: float              # not-before
    na: float              # not-after
    sig: bytes = b""       # issuer signature over the canonical form


def cred_bytes(c: Credential) -> bytes:
    return json.dumps(
        {"id": c.id, "iss": c.issuer, "sub": c.subject,
         "scope": sorted(c.scope), "nb": c.nb, "na": c.na},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def issue_credential(issuer: Agent, subject_did: str, scope, nb: float, na: float,
                     cid: str = None) -> Credential:
    c = Credential(
        id=cid or "cred:" + secrets.token_hex(8),
        issuer=issuer.did, subject=subject_did,
        scope=frozenset(scope), nb=nb, na=na,
    )
    c.sig = issuer.sk.sign(cred_bytes(c))   # issuer signs; scope/window are now fixed
    return c


class DelegationRegistry:
    """Records grants and reconstructs the authority chain back to a root."""

    def __init__(self, idr: IdentityRegistry):
        self.idr = idr
        self.creds = {}

    def anchor(self, c: Credential) -> bool:
        pk = self.idr.resolve(c.issuer)
        if pk is None:
            return False
        try:
            pk.verify(c.sig, cred_bytes(c))   # forged delegation is rejected here
        except InvalidSignature:
            return False
        self.creds[c.id] = c
        return True

    def get_chain(self, cid: str):
        """Walk leaf -> root via issuer/subject links; returns [leaf, ..., root grant]."""
        chain, seen, cur = [], set(), self.creds.get(cid)
        while cur is not None and cur.id not in seen:
            chain.append(cur)
            seen.add(cur.id)
            cur = next((c for c in self.creds.values() if c.subject == cur.issuer), None)
        return chain


def root_is_trusted(chain, trusted_roots) -> bool:
    return bool(chain) and chain[-1].issuer in trusted_roots


# --------------------------------------------------------------------------- #
# Revocation & Policy contract                                                 #
# --------------------------------------------------------------------------- #
class RevocationPolicy:
    def __init__(self):
        self.revoked = set()    # revoked credential ids
        self.nonces = set()     # consumed nonces (replay protection)

    def revoke(self, cid: str):
        self.revoked.add(cid)

    def is_revoked(self, cid: str) -> bool:
        return cid in self.revoked

    @staticmethod
    def in_window(c: Credential, now: float) -> bool:
        return c.nb <= now <= c.na

    @staticmethod
    def scope_of(chain):
        """Effective scope = intersection down the chain (it can only narrow)."""
        eff = None
        for c in chain:
            eff = c.scope if eff is None else (eff & c.scope)
        return eff if eff is not None else frozenset()

    @staticmethod
    def in_scope(action_type: str, scope) -> bool:
        return action_type in scope

    def seen_nonce(self, n: str) -> bool:
        return n in self.nonces

    def consume_nonce(self, n: str):
        self.nonces.add(n)


# --------------------------------------------------------------------------- #
# Actions, transactions, ledger                                                #
# --------------------------------------------------------------------------- #
@dataclass
class Action:
    type: str
    payload: str = ""


@dataclass
class Tx:
    did_s: str
    action: Action
    cred_id: str
    nonce: str
    sig: bytes


def action_bytes(action: Action, nonce: str, cred_id: str, did_s: str) -> bytes:
    # the nonce is bound INTO the signed message -> a valid signature also
    # certifies freshness of this specific invocation
    return json.dumps(
        {"sub": did_s, "type": action.type, "payload": action.payload,
         "nonce": nonce, "cred": cred_id},
        sort_keys=True, separators=(",", ":"),
    ).encode()


def sign_action(agent: Agent, action: Action, nonce: str, cred_id: str) -> bytes:
    return agent.sk.sign(action_bytes(action, nonce, cred_id, agent.did))


class Ledger:
    def __init__(self):
        self.attestations = []   # executed actions
        self.rejected = []       # blocked attempts (logged too)

    def attest(self, tx: Tx, result: str, chain_id: str) -> str:
        # eq. 5:  h = H(did_S || a || n || result || chainId)
        h = hashlib.sha256(
            b"|".join([tx.did_s.encode(), tx.action.type.encode(),
                       tx.nonce.encode(), result.encode(), chain_id.encode()])
        ).hexdigest()
        self.attestations.append(
            {"hash": h, "did_s": tx.did_s, "action": tx.action.type,
             "nonce": tx.nonce, "chain_id": chain_id})
        return h

    def log_reject(self, tx: Tx, reason: str):
        self.rejected.append({"did_s": tx.did_s, "action": tx.action.type, "reason": reason})


# --------------------------------------------------------------------------- #
# Authorizers                                                                  #
# --------------------------------------------------------------------------- #
class B0Authorizer:
    """No blockchain: every action runs, nothing is checked or recorded."""
    name = "B0"

    def decide(self, tx: Tx, now: float):
        return ("Approve", None)            # no checks at all

    def authorize(self, tx: Tx, now: float):
        return self.decide(tx, now)

    def can_reconstruct(self, attestation) -> bool:
        return False


class B1Authorizer:
    """Allow-list: authorized iff the identifier is on a whitelist (prior work)."""
    name = "B1"

    def __init__(self, allowlist, ledger: Ledger):
        self.allow = set(allowlist)
        self.ledger = ledger

    def decide(self, tx: Tx, now: float):
        # the whole authorization check is one membership test
        return ("Approve", None) if tx.did_s in self.allow else ("Reject", "NotOnAllowlist")

    def authorize(self, tx: Tx, now: float):
        verdict, reason = self.decide(tx, now)
        if verdict == "Approve":
            # logs the action (execution-bound audit trail) but with no authority chain
            self.ledger.attest(tx, "ok", "n/a")
        else:
            self.ledger.log_reject(tx, reason)
        return (verdict, reason)

    def can_reconstruct(self, attestation) -> bool:
        return attestation["chain_id"] != "n/a"   # always False: no chain is recorded


class B2Authorizer:
    """Ours: the full Auth() predicate of eq. 4, in the order of Algorithm 1."""
    name = "B2"

    def __init__(self, idr, dreg, rev, trusted_roots, ledger):
        self.idr, self.dreg, self.rev = idr, dreg, rev
        self.trusted_roots, self.ledger = trusted_roots, ledger

    def decide(self, tx: Tx, now: float):
        """The Auth() predicate of eq. 4 -- a pure check with no side effects.
        Implements Algorithm 1's order and reject reasons exactly."""
        # 1. Ident -- signature over the action verifies against the registered key
        pk = self.idr.resolve(tx.did_s)
        if pk is None:
            return ("Reject", "IdentityFailed")
        try:
            pk.verify(tx.sig, action_bytes(tx.action, tx.nonce, tx.cred_id, tx.did_s))
        except InvalidSignature:
            return ("Reject", "IdentityFailed")

        # 2. Fresh -- nonce not previously consumed
        if self.rev.seen_nonce(tx.nonce):
            return ("Reject", "ReplayedNonce")

        # 3. Chain -- traces to a trusted root and the leaf is bound to this subject
        chain = self.dreg.get_chain(tx.cred_id)
        if not chain or chain[0].subject != tx.did_s or not root_is_trusted(chain, self.trusted_roots):
            return ("Reject", "BrokenChain")

        # 4. Valid + not Revoked -- per credential, at execution time
        for c in chain:
            if self.rev.is_revoked(c.id) or not self.rev.in_window(c, now):
                return ("Reject", "InvalidCredential")

        # 5. Scope -- action within the effective (intersected) scope
        if not self.rev.in_scope(tx.action.type, self.rev.scope_of(chain)):
            return ("Reject", "OutOfScope")

        return ("Approve", None)

    def authorize(self, tx: Tx, now: float):
        verdict, reason = self.decide(tx, now)
        if verdict == "Approve":
            # consume the nonce and anchor the attestation bound to the chain (eq. 5)
            self.rev.consume_nonce(tx.nonce)
            self.ledger.attest(tx, "ok", tx.cred_id)
        else:
            self.ledger.log_reject(tx, reason)
        return (verdict, reason)

    def can_reconstruct(self, attestation) -> bool:
        chain = self.dreg.get_chain(attestation["chain_id"])
        return root_is_trusted(chain, self.trusted_roots)


# --------------------------------------------------------------------------- #
# World setup -- an automated banking/finance platform                         #
#   root authority -> orchestrator -> specialist (risk-assessment agent)       #
# --------------------------------------------------------------------------- #
SCOPE_ORCH = {"assess_risk", "screen_fraud", "transfer"}   # broad authority at the orchestrator
SCOPE_SPEC = {"assess_risk"}                               # narrowed for the specialist


def make_env():
    now = time.time()
    idr = IdentityRegistry()
    root = new_agent("did:agent:root", "root")
    orch = new_agent("did:agent:orchestrator", "orchestrator")
    spec = new_agent("did:agent:risk", "specialist")
    adversary = new_agent("did:agent:adversary", "adversary")   # not registered

    idr.register(root, issuer="self")
    idr.register(orch, issuer=root.did)
    idr.register(spec, issuer=orch.did)

    dreg = DelegationRegistry(idr)
    rev = RevocationPolicy()
    ledger = Ledger()

    # root -> orchestrator (broad), orchestrator -> specialist (narrowed)
    c_root = issue_credential(root, orch.did, SCOPE_ORCH, now - 100, now + 10_000, cid="cred:root")
    c_spec = issue_credential(orch, spec.did, SCOPE_SPEC, now - 100, now + 10_000, cid="cred:spec")
    # an already-expired grant, used only by the S5 scenario
    c_exp = issue_credential(orch, spec.did, SCOPE_SPEC, now - 1_000, now - 500, cid="cred:exp")
    for c in (c_root, c_spec, c_exp):
        dreg.anchor(c)

    trusted_roots = {root.did}
    allowlist = {orch.did, spec.did}   # B1 knows the legitimate agent names
    return dict(now=now, idr=idr, dreg=dreg, rev=rev, ledger=ledger,
                root=root, orch=orch, spec=spec, adversary=adversary,
                c_root=c_root, c_spec=c_spec, c_exp=c_exp,
                trusted_roots=trusted_roots, allowlist=allowlist)


def make_authorizer(baseline: str, env):
    if baseline == "B0":
        return B0Authorizer()
    if baseline == "B1":
        return B1Authorizer(env["allowlist"], Ledger())
    return B2Authorizer(env["idr"], env["dreg"], env["rev"],
                        env["trusted_roots"], Ledger())


def fresh_nonce() -> str:
    return secrets.token_hex(16)


def build_tx(env, scenario: str, nonce: str) -> Tx:
    """Construct the transaction a given scenario presents to the authorizer."""
    spec, adv = env["spec"], env["adversary"]
    if scenario == "S1":                       # legitimate, in-scope, valid
        a = Action("assess_risk")
        return Tx(spec.did, a, env["c_spec"].id, nonce, sign_action(spec, a, nonce, env["c_spec"].id))
    if scenario == "S2":                       # spoof: victim DID, attacker key
        a = Action("assess_risk")
        return Tx(spec.did, a, env["c_spec"].id, nonce, sign_action(adv, a, nonce, env["c_spec"].id))
    if scenario == "S3":                       # out-of-scope action
        a = Action("transfer")
        return Tx(spec.did, a, env["c_spec"].id, nonce, sign_action(spec, a, nonce, env["c_spec"].id))
    if scenario == "S4":                       # revoked credential
        a = Action("assess_risk")
        return Tx(spec.did, a, env["c_spec"].id, nonce, sign_action(spec, a, nonce, env["c_spec"].id))
    if scenario == "S5":                       # expired credential
        a = Action("assess_risk")
        return Tx(spec.did, a, env["c_exp"].id, nonce, sign_action(spec, a, nonce, env["c_exp"].id))
    raise ValueError(scenario)


# --------------------------------------------------------------------------- #
# Enforcement experiment                                                       #
# --------------------------------------------------------------------------- #
SCENARIOS = ["S1", "S2", "S3", "S4", "S5", "S6"]


def run_enforcement(baseline: str, trials: int):
    """Returns {S1_success_pct, S2..S6_blocked_pct, chain_reconstruction_pct}."""
    out = {}

    # S1 -- legitimate: fraction approved (success). Also feeds chain reconstruction.
    env = make_env()
    auth = make_authorizer(baseline, env)
    approved = 0
    for _ in range(trials):
        tx = build_tx(env, "S1", fresh_nonce())
        if auth.authorize(tx, env["now"])[0] == "Approve":
            approved += 1
    out["S1_success_pct"] = 100.0 * approved / trials

    # chain reconstruction over the executed (S1) actions
    led = getattr(auth, "ledger", None)
    if led is None or not led.attestations:
        out["chain_reconstruction_pct"] = 0.0
    else:
        ok = sum(1 for att in led.attestations if auth.can_reconstruct(att))
        out["chain_reconstruction_pct"] = 100.0 * ok / len(led.attestations)

    # S2, S3, S5 -- single-shot attacks; fraction rejected (blocked)
    for sc in ("S2", "S3", "S5"):
        env = make_env()
        auth = make_authorizer(baseline, env)
        blocked = 0
        for _ in range(trials):
            tx = build_tx(env, sc, fresh_nonce())
            if auth.authorize(tx, env["now"])[0] == "Reject":
                blocked += 1
        out[f"{sc}_blocked_pct"] = 100.0 * blocked / trials

    # S4 -- revoked: revoke the specialist's grant, then attempt the action
    env = make_env()
    env["rev"].revoke(env["c_spec"].id)
    auth = make_authorizer(baseline, env)
    blocked = 0
    for _ in range(trials):
        tx = build_tx(env, "S4", fresh_nonce())
        if auth.authorize(tx, env["now"])[0] == "Reject":
            blocked += 1
    out["S4_blocked_pct"] = 100.0 * blocked / trials

    # S6 -- replay: authorize a legitimate action, then resend it verbatim
    env = make_env()
    auth = make_authorizer(baseline, env)
    blocked = 0
    for _ in range(trials):
        tx = build_tx(env, "S1", fresh_nonce())
        auth.authorize(tx, env["now"])            # first time: legitimate
        if auth.authorize(tx, env["now"])[0] == "Reject":   # replayed verbatim
            blocked += 1
    out["S6_blocked_pct"] = 100.0 * blocked / trials

    return out


# --------------------------------------------------------------------------- #
# Overhead experiment                                                          #
# --------------------------------------------------------------------------- #
def _time_per_call(fn, trials, inner=20):
    """Per-call latency in ms, robust on a loaded multi-tasking host.

    The MEAN is taken over `trials` samples, each of which is itself the average
    of `inner` back-to-back calls -- this averages out OS-scheduling spikes that
    would otherwise dominate a single sub-millisecond timing. The P95 is taken
    from a separate pass of raw single-call timings so it still reflects the true
    tail. The timed operation must be side-effect free (we use the pure decide()
    path, never authorize()), so repeating it is valid."""
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        for _ in range(inner):
            fn()
        samples.append((time.perf_counter() - t0) * 1000.0 / inner)
    mean = statistics.fmean(samples)

    raw = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        raw.append((time.perf_counter() - t0) * 1000.0)
    raw.sort()
    p95 = raw[min(len(raw) - 1, int(0.95 * len(raw)))]
    return mean, p95


def run_overhead(trials: int):
    res = {"auth_mean_ms": {}, "auth_p95_ms": {}}

    # We time only the authorization CHECK (decide), matching the paper's
    # definition of Auth(). Transactions are built BEFORE timing so signing
    # and serialization never pollute the measurement. decide() is side-effect
    # free, so a single pre-built tx can be reused with inner amortization.
    env = make_env()
    now = env["now"]
    legit_tx = build_tx(env, "S1", fresh_nonce())   # a valid, in-scope action

    # B0 -- no checks
    b0 = B0Authorizer()
    res["auth_mean_ms"]["B0"], res["auth_p95_ms"]["B0"] = \
        _time_per_call(lambda: b0.decide(legit_tx, now), trials, inner=200)

    # B1 -- allow-list membership test
    b1 = B1Authorizer(env["allowlist"], Ledger())
    res["auth_mean_ms"]["B1"], res["auth_p95_ms"]["B1"] = \
        _time_per_call(lambda: b1.decide(legit_tx, now), trials, inner=200)

    # B2 -- full Auth(): verify signature, test nonce, walk chain, intersect
    #       scopes, check window and revocation list
    b2 = B2Authorizer(env["idr"], env["dreg"], env["rev"], env["trusted_roots"], Ledger())
    res["auth_mean_ms"]["B2"], res["auth_p95_ms"]["B2"] = \
        _time_per_call(lambda: b2.decide(legit_tx, now), trials)

    # identity-verify-only (the Ed25519 verification step)
    pk = env["idr"].resolve(env["spec"].did)
    msg = action_bytes(legit_tx.action, legit_tx.nonce, legit_tx.cred_id, legit_tx.did_s)
    sig = legit_tx.sig
    def verify_only():
        try:
            pk.verify(sig, msg)
        except InvalidSignature:
            pass
    res["identity_verify_ms"], _ = _time_per_call(verify_only, trials, inner=20)

    # nonce-check-only (hash-set membership)
    rev = env["rev"]; rev.consume_nonce(legit_tx.nonce)
    res["nonce_check_ms"], _ = _time_per_call(lambda: rev.seen_nonce(legit_tx.nonce), trials, inner=2000)

    # revocation latency -- time for a revoked action to be detected/blocked
    renv = make_env(); renv["rev"].revoke(renv["c_spec"].id)
    b2r = B2Authorizer(renv["idr"], renv["dreg"], renv["rev"], renv["trusted_roots"], Ledger())
    revoked_tx = build_tx(renv, "S4", fresh_nonce())
    res["revocation_latency_ms"], _ = _time_per_call(
        lambda: b2r.decide(revoked_tx, renv["now"]), trials)

    # single-core throughput from the measured mean Auth() cost
    res["throughput_tx_s"] = {
        b: (1000.0 / m if m > 0 else float("inf")) for b, m in res["auth_mean_ms"].items()
    }
    # mean decision latency = measured crypto + MODELED ledger anchor (B1/B2 anchor; B0 does not)
    res["mean_decision_latency_ms"] = {
        "B0": res["auth_mean_ms"]["B0"],
        "B1": res["auth_mean_ms"]["B1"] + MODELED_LEDGER_MS,
        "B2": res["auth_mean_ms"]["B2"] + MODELED_LEDGER_MS,
    }
    return res


# --------------------------------------------------------------------------- #
# Chain-depth sweep -- shows Auth() cost is linear in delegation-chain length  #
# --------------------------------------------------------------------------- #
def build_chain_env(depth: int):
    """A world with a delegation chain of `depth` credentials (root -> ... ->
    leaf). The leaf agent holds the deepest credential and acts. All scopes are
    {'assess_risk'} and all windows are valid, so a legitimate action is approved."""
    now = time.time()
    idr = IdentityRegistry()
    dreg = DelegationRegistry(idr)
    rev = RevocationPolicy()
    root = new_agent("did:agent:root", "root")
    idr.register(root, issuer="self")

    prev, creds = root, []
    for i in range(depth):
        role = "specialist" if i == depth - 1 else "intermediary"
        sub = new_agent(f"did:agent:a{i}", role)
        idr.register(sub, issuer=prev.did)
        c = issue_credential(prev, sub.did, SCOPE_SPEC, now - 100, now + 10_000, cid=f"cred:{i}")
        dreg.anchor(c)
        creds.append(c)
        prev = sub
    return dict(now=now, idr=idr, dreg=dreg, rev=rev,
                leaf=prev, leaf_cred=creds[-1], trusted_roots={root.did})


def build_leaf_tx(env, nonce: str) -> Tx:
    a = Action("assess_risk")
    leaf = env["leaf"]
    return Tx(leaf.did, a, env["leaf_cred"].id, nonce, sign_action(leaf, a, nonce, env["leaf_cred"].id))


def run_depth_sweep(depths, trials: int):
    """Measure mean Auth() latency vs. chain depth and fit a line; the slope is
    the marginal cost of one extra credential (turns the 'linear in chain
    length' claim into a measured result)."""
    import numpy as np
    means = []
    for d in depths:
        env = build_chain_env(d)
        b2 = B2Authorizer(env["idr"], env["dreg"], env["rev"], env["trusted_roots"], Ledger())
        tx = build_leaf_tx(env, fresh_nonce())
        mean, _ = _time_per_call(lambda: b2.decide(tx, env["now"]), trials, inner=20)
        means.append(mean)
    slope, intercept = np.polyfit(depths, means, 1)   # ms per credential, ms
    return {"depths": list(depths), "mean_ms": means,
            "marginal_us_per_credential": float(slope * 1000.0),
            "intercept_ms": float(intercept)}


# --------------------------------------------------------------------------- #
# Reject-path coverage -- assert every Auth() rejection reason is reachable     #
# --------------------------------------------------------------------------- #
def verify_reject_paths():
    """Construct one transaction per Auth() outcome and confirm decide()
    returns the expected reason. Exercises paths the S1-S6 scenarios do not
    (unknown DID, BrokenChain)."""
    out = {}

    def b2_for(env):
        return B2Authorizer(env["idr"], env["dreg"], env["rev"], env["trusted_roots"], Ledger())

    env = make_env()
    out["IdentityFailed_badsig"] = b2_for(env).decide(build_tx(env, "S2", fresh_nonce()), env["now"])[1] == "IdentityFailed"

    # unknown DID -> resolve() returns None
    env = make_env(); a, n = Action("assess_risk"), fresh_nonce()
    ghost = new_agent("did:agent:ghost", "x")   # never registered
    tx = Tx(ghost.did, a, env["c_spec"].id, n, sign_action(ghost, a, n, env["c_spec"].id))
    out["IdentityFailed_unknownDID"] = b2_for(env).decide(tx, env["now"])[1] == "IdentityFailed"

    # replay -> consume the nonce, then resend
    env = make_env(); b2 = b2_for(env); tx = build_tx(env, "S1", fresh_nonce())
    b2.authorize(tx, env["now"])
    out["ReplayedNonce"] = b2.decide(tx, env["now"])[1] == "ReplayedNonce"

    # BrokenChain -> issuer of the top credential is not a trusted root
    env = make_env()
    stray = new_agent("did:agent:stray", "intermediary"); env["idr"].register(stray, issuer="self")
    leaf = new_agent("did:agent:leaf2", "specialist"); env["idr"].register(leaf, issuer=stray.did)
    c = issue_credential(stray, leaf.did, SCOPE_SPEC, env["now"] - 100, env["now"] + 10_000, cid="cred:stray")
    env["dreg"].anchor(c)
    a, n = Action("assess_risk"), fresh_nonce()
    tx = Tx(leaf.did, a, c.id, n, sign_action(leaf, a, n, c.id))
    out["BrokenChain"] = b2_for(env).decide(tx, env["now"])[1] == "BrokenChain"

    env = make_env(); env["rev"].revoke(env["c_spec"].id)
    out["InvalidCredential_revoked"] = b2_for(env).decide(build_tx(env, "S4", fresh_nonce()), env["now"])[1] == "InvalidCredential"

    env = make_env()
    out["InvalidCredential_expired"] = b2_for(env).decide(build_tx(env, "S5", fresh_nonce()), env["now"])[1] == "InvalidCredential"

    env = make_env()
    out["OutOfScope"] = b2_for(env).decide(build_tx(env, "S3", fresh_nonce()), env["now"])[1] == "OutOfScope"

    env = make_env()
    out["Approve"] = b2_for(env).decide(build_tx(env, "S1", fresh_nonce()), env["now"])[0] == "Approve"
    return out


# --------------------------------------------------------------------------- #
# Figure                                                                       #
# --------------------------------------------------------------------------- #
def make_figure(results, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    enf = results["enforcement"]
    over = results["overhead"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9, 3.6))

    # (a) enforcement by scenario
    attacks = ["S2", "S3", "S4", "S5", "S6"]
    labels = {"S2": "spoof", "S3": "scope", "S4": "revoked", "S5": "expired", "S6": "replay"}
    x = range(len(attacks))
    w = 0.26
    for i, (b, color) in enumerate([("B0", "#bbbbbb"), ("B1", "#7aa6c2"), ("B2", "#2c7fb8")]):
        vals = [enf[b][f"{s}_blocked_pct"] for s in attacks]
        ax1.bar([xi + (i - 1) * w for xi in x], vals, w, label=b, color=color)
    ax1.set_xticks(list(x))
    ax1.set_xticklabels([f"{s}\n{labels[s]}" for s in attacks], fontsize=8)
    ax1.set_ylabel("attacks blocked (%)")
    ax1.set_ylim(0, 105)
    ax1.set_title("(a) Enforcement by scenario")
    ax1.legend(fontsize=8, loc="center left")

    # (b) per-decision latency composition, log scale so both magnitudes show.
    # The measured crypto cost and the modeled ledger anchor differ by ~1700x;
    # a linear axis would render the crypto bar invisible, so we use log y.
    crypto = over["auth_mean_ms"]["B2"]
    ledger = MODELED_LEDGER_MS
    bars = ax2.bar(["crypto auth\n(measured)", "ledger anchor\n(modeled)"],
                   [crypto, ledger], color=["#2c7fb8", "#d9d9d9"])
    ax2.set_yscale("log")
    ax2.set_ylim(0.001, 1000)
    ax2.set_ylabel("per-decision latency (ms, log scale)")
    ax2.set_title("(b) Latency composition")
    for b, v in zip(bars, [crypto, ledger]):
        ax2.text(b.get_x() + b.get_width() / 2, v * 1.3,
                 (f"{v:.3f} ms" if v < 1 else f"{v:.0f} ms"), ha="center", fontsize=8)
    ax2.text(0.5, 0.92, f"crypto is ~{ledger / crypto:.0f}x cheaper",
             transform=ax2.transAxes, ha="center", fontsize=8, style="italic")

    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def _cpu_name():
    """Friendly CPU model string (Windows registry), with a portable fallback."""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        return winreg.QueryValueEx(k, "ProcessorNameString")[0].strip()
    except Exception:
        return platform.processor() or "unknown"


def _ram_gb():
    try:
        import ctypes

        class MS(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
        m = MS(); m.dwLength = ctypes.sizeof(MS)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return round(m.ullTotalPhys / (1024 ** 3), 1)
    except Exception:
        return None


def host_env():
    import cryptography
    return {
        "platform": platform.platform(),
        "cpu_name": _cpu_name(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "ram_gb": _ram_gb(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--enforcement-trials", type=int, default=2000)
    ap.add_argument("--overhead-trials", type=int, default=5000)
    ap.add_argument("--quick", action="store_true", help="fast smoke run (50/200 trials)")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results.json"))
    ap.add_argument("--fig", default=os.path.join(os.path.dirname(__file__), "results_fig.png"))
    args = ap.parse_args()

    en_trials = 50 if args.quick else args.enforcement_trials
    ov_trials = 200 if args.quick else args.overhead_trials

    print(f"Host: {host_env()['platform']} | {host_env()['processor']}")
    print(f"Enforcement trials/scenario: {en_trials}   Overhead trials: {ov_trials}\n")

    enforcement = {b: run_enforcement(b, en_trials) for b in ("B0", "B1", "B2")}
    overhead = run_overhead(ov_trials)
    overhead["chain_depth_sweep"] = run_depth_sweep([1, 2, 4, 6, 8, 10], 50 if args.quick else 1000)
    reject_paths = verify_reject_paths()

    results = {
        "env": host_env(),
        "config": {"enforcement_trials": en_trials, "overhead_trials": ov_trials,
                   "modeled_ledger_ms": MODELED_LEDGER_MS},
        "enforcement": enforcement,
        "overhead": overhead,
        "reject_path_coverage": reject_paths,
    }

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)

    # ----- console summary -----
    print("Enforcement (% blocked for S2-S6, % success for S1, % chain reconstruction)")
    hdr = ["metric", "B0", "B1", "B2"]
    rows = [["S1 success"] + [f'{enforcement[b]["S1_success_pct"]:.0f}' for b in "B0 B1 B2".split()]]
    for s in ("S2", "S3", "S4", "S5", "S6"):
        rows.append([f"{s} blocked"] + [f'{enforcement[b][f"{s}_blocked_pct"]:.0f}' for b in "B0 B1 B2".split()])
    rows.append(["chain recon"] + [f'{enforcement[b]["chain_reconstruction_pct"]:.0f}' for b in "B0 B1 B2".split()])
    widths = [max(len(r[i]) for r in [hdr] + rows) for i in range(4)]
    for r in [hdr] + rows:
        print("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))

    print("\nOverhead (ms) and throughput")
    print(f"  Auth mean:   B0={overhead['auth_mean_ms']['B0']:.4f}  "
          f"B1={overhead['auth_mean_ms']['B1']:.4f}  B2={overhead['auth_mean_ms']['B2']:.4f}")
    print(f"  Auth p95:    B0={overhead['auth_p95_ms']['B0']:.4f}  "
          f"B1={overhead['auth_p95_ms']['B1']:.4f}  B2={overhead['auth_p95_ms']['B2']:.4f}")
    print(f"  Identity verify: {overhead['identity_verify_ms']:.4f}   "
          f"Nonce check: {overhead['nonce_check_ms']:.5f}   "
          f"Revocation latency: {overhead['revocation_latency_ms']:.4f}")
    print(f"  Throughput B2: {overhead['throughput_tx_s']['B2']:.0f} tx/s   "
          f"(modeled ledger anchor: {MODELED_LEDGER_MS:.0f} ms)")
    print(f"  Mean decision latency: B1={overhead['mean_decision_latency_ms']['B1']:.1f} ms  "
          f"B2={overhead['mean_decision_latency_ms']['B2']:.1f} ms")

    sw = overhead["chain_depth_sweep"]
    print("\nChain-depth sweep (Auth() mean ms by chain length)")
    print("  " + "  ".join(f"d{d}={m:.3f}" for d, m in zip(sw["depths"], sw["mean_ms"])))
    print(f"  marginal cost: {sw['marginal_us_per_credential']:.2f} us per extra credential")

    print("\nReject-path coverage")
    for reason, ok in reject_paths.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {reason}")
    if not all(reject_paths.values()):
        raise SystemExit("ERROR: a reject path did not behave as expected")

    make_figure(results, args.fig)
    print(f"\nWrote {args.out}\nWrote {args.fig}")


if __name__ == "__main__":
    main()
