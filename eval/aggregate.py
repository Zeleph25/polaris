#!/usr/bin/env python3
"""Aggregates the runs under a results directory into one table and plots.

    eval/aggregate.py eval/results [--plots]

Each run directory holds the cluster files and a runs/ subdirectory with
the nodes' metrics, transcript and output files.

Per run: the largest decision round over the nodes, the longest time to
decision, the mean bytes and messages sent and received per node (under
attack, what an honest node receives is what it has to process), the mean
signature
verification time, CPU time and peak memory per node, and whether every
node decided the same output. Time, CPU and memory come from network runs
only: the simulator runs every node in one process, so it has no per-node
value for them, and their cells are empty for its rows. Simulator runs
report the honest nodes only. Per experiment and size: mean and standard
deviation over the repetitions, the worker threads the nodes' runtimes
had and the round length (both empty for simulator runs, a range if they
differ). Writes summary.csv and summary.md next to
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
    ("bytes_recv", "bytes received per node (mean)"),
    ("msgs_recv", "messages received per node (mean)"),
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
    net = meta.get("mode", "net") == "net"
    rows = []
    outputs = set()
    workers = set()
    runs = d / "runs"
    for f in sorted(runs.glob("node-*.metrics.jsonl")):
        node = int(f.stem.split("-")[1].split(".")[0])
        summary = next(json.loads(l) for l in f.read_text().splitlines() if '"summary"' in l)
        out = json.loads((runs / f"node-{node}.output.json").read_text())
        outputs.add(json.dumps(out["output"], sort_keys=True))
        if out.get("worker_threads") is not None:
            workers.add(out["worker_threads"])
        res = out.get("resources", {})
        rows.append({
            "decision_round": summary["decision_round"],
            "decided_after_ms": out.get("decided_after_ms") if net else None,
            "bytes_sent": summary["bytes_sent"],
            "msgs_sent": summary["msgs_sent"],
            "bytes_recv": summary.get("bytes_recv"),
            "msgs_recv": summary.get("msgs_recv"),
            "sig_verifies": summary["sig_verifies"],
            "sig_verify_ms": summary["sig_verify_ns"] / 1e6,
            "cpu_ms": res.get("cpu_user_ms", 0) + res.get("cpu_sys_ms", 0) if net else None,
            "max_rss_mb": res.get("max_rss_kb", 0) / 1024 if net else None,
            "late_msgs": summary["late_msgs"],
        })
    if not rows or any(r["decision_round"] is None for r in rows):
        return None
    return {
        **meta,
        "nodes": len(rows),
        "agreement": len(outputs) == 1,
        "worker_threads": workers,
        "decision_round": max(r["decision_round"] for r in rows),
        "decided_after_ms": max(r["decided_after_ms"] or 0 for r in rows) if net else None,
        "bytes_sent": statistics.mean(r["bytes_sent"] for r in rows),
        "msgs_sent": statistics.mean(r["msgs_sent"] for r in rows),
        "bytes_recv": mean_or_none(r["bytes_recv"] for r in rows),
        "msgs_recv": mean_or_none(r["msgs_recv"] for r in rows),
        "sig_verifies": statistics.mean(r["sig_verifies"] for r in rows),
        "sig_verify_ms": statistics.mean(r["sig_verify_ms"] for r in rows),
        "cpu_ms": statistics.mean(r["cpu_ms"] for r in rows) if net else None,
        "max_rss_mb": statistics.mean(r["max_rss_mb"] for r in rows) if net else None,
        "late_msgs": sum(r["late_msgs"] for r in rows),
    }


def mean_or_none(values):
    """The mean, or None if a value is missing (results from before the
    field was recorded)."""
    values = list(values)
    return None if any(v is None for v in values) else statistics.mean(values)


def span(values):
    """One value, a range, or empty."""
    if not values:
        return ""
    lo, hi = min(values), max(values)
    return str(lo) if lo == hi else f"{lo}-{hi}"


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

    header = ["experiment", "mode", "protocol", "broadcast", "n", "t", "input_bytes", "byzantine", "reps", "agreement",
              "worker_threads", "round_ms"]
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
            "worker_threads": span(set().union(*(r["worker_threads"] for r in runs))),
            "round_ms": span({r["round_ms"] for r in runs if r.get("round_ms") is not None}),
        }
        for key, _ in METRICS:
            vals = [r[key] for r in runs if r[key] is not None]
            row[f"{key}_mean"] = statistics.mean(vals) if vals else ""
            row[f"{key}_std"] = (statistics.stdev(vals) if len(vals) > 1 else 0.0) if vals else ""
        table.append(row)

    with open(root / "summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(table)

    lines = ["| experiment | mode | n | t | input B | byz | reps | agree | workers | round ms | " + " | ".join(label for _, label in METRICS) + " |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | " + " | ".join("---" for _ in METRICS) + " |"]
    for row in table:
        cells = [row["experiment"], row["mode"], str(row["n"]), str(row["t"]), str(row["input_bytes"]),
                 str(row["byzantine"]), str(row["reps"]), "yes" if row["agreement"] else "NO",
                 row["worker_threads"] or "-", row["round_ms"] or "-"]
        for key, _ in METRICS:
            m, s = row[f"{key}_mean"], row[f"{key}_std"]
            cells.append("-" if m == "" else f"{m:,.0f} +- {s:,.0f}" if s else f"{m:,.0f}")
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
                pts = sorted((row["n"], row[f"{key}_mean"], row[f"{key}_std"]) for row in table
                             if row["experiment"] == exp and row[f"{key}_mean"] != "")
                if not pts:
                    continue
                ax.errorbar([p[0] for p in pts], [p[1] for p in pts], yerr=[p[2] for p in pts], marker="o", capsize=3, label=exp)
            ax.set_xlabel("n")
            ax.set_ylabel(label)
            if key in ("bytes_sent", "msgs_sent", "bytes_recv", "msgs_recv", "cpu_ms", "max_rss_mb"):
                ax.set_yscale("log")
            ax.grid(True, alpha=0.3)
            ax.legend()
            fig.tight_layout()
            fig.savefig(root / f"{key}.png", dpi=150)
            plt.close(fig)
        print(f"plots written to {root}")


if __name__ == "__main__":
    main()
