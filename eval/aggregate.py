#!/usr/bin/env python3
"""Aggregates the runs under a results directory into one table and plots.

    eval/aggregate.py eval/results [--plots]

Each run directory holds the cluster files and a runs/ subdirectory with
the nodes' metrics, transcript and output files.

Per run: the largest decision round over the nodes, the longest time to
decision (network runs only), the mean bytes and messages sent per node,
the mean signature verification time, CPU time and peak memory per node
(for simulator runs, of the one process), and whether every node decided
the same output. Simulator runs report the honest nodes only. Per experiment and size: mean and standard
deviation over the repetitions. Writes summary.csv and summary.md next to
the runs and, with --plots and matplotlib, one PNG per metric.
"""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

METRICS = [
    ("decision_round", "decision round (max over nodes)"),
    ("decided_after_ms", "time to decision, ms (max over nodes)"),
    ("bytes_sent", "bytes sent per node (mean)"),
    ("msgs_sent", "messages sent per node (mean)"),
    ("sig_verifies", "signatures verified per node (mean)"),
    ("sig_verify_ms", "signature verification per node, ms (mean)"),
    ("cpu_ms", "CPU time per node, ms (mean)"),
    ("max_rss_mb", "peak memory per node, MB (mean)"),
    ("late_msgs", "late messages (sum over nodes)"),
]


def read_run(d):
    meta = json.loads((d / "run.json").read_text())
    if not meta["ok"]:
        return None
    rows = []
    outputs = set()
    runs = d / "runs"
    for f in sorted(runs.glob("node-*.metrics.jsonl")):
        node = int(f.stem.split("-")[1].split(".")[0])
        summary = next(json.loads(l) for l in f.read_text().splitlines() if '"summary"' in l)
        out = json.loads((runs / f"node-{node}.output.json").read_text())
        outputs.add(json.dumps(out["output"], sort_keys=True))
        res = out.get("resources", {})
        rows.append({
            "decision_round": summary["decision_round"],
            "decided_after_ms": out.get("decided_after_ms"),
            "bytes_sent": summary["bytes_sent"],
            "msgs_sent": summary["msgs_sent"],
            "sig_verifies": summary["sig_verifies"],
            "sig_verify_ms": summary["sig_verify_ns"] / 1e6,
            "cpu_ms": res.get("cpu_user_ms", 0) + res.get("cpu_sys_ms", 0),
            "max_rss_mb": res.get("max_rss_kb", 0) / 1024,
            "late_msgs": summary["late_msgs"],
        })
    if not rows or any(r["decision_round"] is None for r in rows):
        return None
    return {
        **meta,
        "nodes": len(rows),
        "agreement": len(outputs) == 1,
        "decision_round": max(r["decision_round"] for r in rows),
        "decided_after_ms": max(r["decided_after_ms"] or 0 for r in rows),
        "bytes_sent": statistics.mean(r["bytes_sent"] for r in rows),
        "msgs_sent": statistics.mean(r["msgs_sent"] for r in rows),
        "sig_verifies": statistics.mean(r["sig_verifies"] for r in rows),
        "sig_verify_ms": statistics.mean(r["sig_verify_ms"] for r in rows),
        "cpu_ms": statistics.mean(r["cpu_ms"] for r in rows),
        "max_rss_mb": statistics.mean(r["max_rss_mb"] for r in rows),
        "late_msgs": sum(r["late_msgs"] for r in rows),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("results")
    ap.add_argument("--plots", action="store_true")
    args = ap.parse_args()
    root = Path(args.results)

    groups = defaultdict(list)
    for run_json in sorted(root.glob("*/*/rep*/run.json")):
        r = read_run(run_json.parent)
        if r is None:
            print(f"skipping incomplete run {run_json.parent}")
            continue
        groups[(r["experiment"], r["n"], r["t"])].append(r)

    header = ["experiment", "mode", "protocol", "broadcast", "n", "t", "input_bytes", "byzantine", "reps", "agreement"]
    for key, _ in METRICS:
        header += [f"{key}_mean", f"{key}_std"]
    table = []
    for (exp, n, t), runs in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        row = {
            "experiment": exp, "mode": runs[0].get("mode", "net"),
            "protocol": runs[0]["protocol"], "broadcast": runs[0]["broadcast"],
            "n": n, "t": t, "input_bytes": runs[0].get("input_bytes", 0),
            "byzantine": runs[0].get("byzantine", 0),
            "reps": len(runs), "agreement": all(r["agreement"] for r in runs),
        }
        for key, _ in METRICS:
            vals = [r[key] for r in runs]
            row[f"{key}_mean"] = statistics.mean(vals)
            row[f"{key}_std"] = statistics.stdev(vals) if len(vals) > 1 else 0.0
        table.append(row)

    with open(root / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(table)

    lines = ["| experiment | mode | n | t | input B | byz | reps | agree | " + " | ".join(label for _, label in METRICS) + " |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | " + " | ".join("---" for _ in METRICS) + " |"]
    for row in table:
        cells = [row["experiment"], row["mode"], str(row["n"]), str(row["t"]), str(row["input_bytes"]),
                 str(row["byzantine"]), str(row["reps"]), "yes" if row["agreement"] else "NO"]
        for key, _ in METRICS:
            m, s = row[f"{key}_mean"], row[f"{key}_std"]
            cells.append(f"{m:,.0f} +- {s:,.0f}" if s else f"{m:,.0f}")
        lines.append("| " + " | ".join(cells) + " |")
    (root / "summary.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))

    if args.plots:
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            print("matplotlib not installed; no plots")
            return
        for key, label in METRICS:
            fig, ax = plt.subplots(figsize=(6, 4))
            for exp in sorted({row["experiment"] for row in table}):
                pts = sorted((row["n"], row[f"{key}_mean"], row[f"{key}_std"]) for row in table if row["experiment"] == exp)
                ax.errorbar([p[0] for p in pts], [p[1] for p in pts], yerr=[p[2] for p in pts], marker="o", capsize=3, label=exp)
            ax.set_xlabel("n")
            ax.set_ylabel(label)
            if key in ("bytes_sent", "msgs_sent", "cpu_ms", "max_rss_mb"):
                ax.set_yscale("log")
            ax.grid(True, alpha=0.3)
            ax.legend()
            fig.tight_layout()
            fig.savefig(root / f"{key}.png", dpi=150)
            plt.close(fig)
        print(f"plots written to {root}")


if __name__ == "__main__":
    main()
