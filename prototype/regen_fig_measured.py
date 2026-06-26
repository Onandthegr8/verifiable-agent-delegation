"""
Regenerate results_fig.png for the paper using the MEASURED Fabric ledger
latency (from ../fabric/bench/fabric_results.json) instead of the modeled
400 ms. Panel (a) enforcement and the measured crypto cost still come from
prototype/results.json; only the ledger bar in panel (b) now reflects the
real end-to-end commit latency measured on the Hyperledger Fabric test-network.

Both bars in panel (b) are therefore measured. prototype.py's own
MODELED_LEDGER_MS is left untouched -- this script is paper-figure only.
"""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(__file__)
results = json.load(open(os.path.join(HERE, "results.json")))
fabric = json.load(open(os.path.join(HERE, "..", "fabric", "bench", "fabric_results.json")))

enf = results["enforcement"]
over = results["overhead"]
crypto = over["auth_mean_ms"]["B2"]          # measured, prototype
ledger = fabric["latency"]["mean_ms"]        # measured, Fabric end-to-end

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

# (b) per-decision latency composition (both measured), log scale.
bars = ax2.bar(["crypto auth\n(measured)", "ledger commit\n(measured)"],
               [crypto, ledger], color=["#2c7fb8", "#9ecae1"])
ax2.set_yscale("log")
ax2.set_ylim(0.001, 10000)
ax2.set_ylabel("per-decision latency (ms, log scale)")
ax2.set_title("(b) Latency composition")
for b, v in zip(bars, [crypto, ledger]):
    ax2.text(b.get_x() + b.get_width() / 2, v * 1.6,
             (f"{v:.3f} ms" if v < 1 else f"{v:.0f} ms"), ha="center", fontsize=8)
ax2.text(0.27, 0.74, f"crypto is\n~{ledger / crypto:.0f}x cheaper",
         transform=ax2.transAxes, ha="center", fontsize=8, style="italic")

fig.tight_layout()
out = os.path.join(HERE, "results_fig.png")
fig.savefig(out, dpi=200)
plt.close(fig)
print(f"crypto={crypto:.4f} ms  ledger(measured)={ledger:.1f} ms  ratio={ledger/crypto:.0f}x")
print(f"wrote {out}")
