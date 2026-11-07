#!/usr/bin/env python3
"""Runs an experiment matrix: for every experiment, size and repetition,
generates a cluster with `polaris genconfig`, starts one `polaris node`
process per node on this host, waits for all of them, and keeps their
output files together with a run.json describing the run.

    eval/run.py eval/matrix.toml --out eval/results [--only ic-wxsd]

The binary is target/release/polaris unless --binary says otherwise; build
it first with `cargo build --release`.
"""

import argparse
import json
import subprocess
import sys
import time
import tomllib
from pathlib import Path


def run_once(binary, exp, n, t, rep, out, defaults, port):
    d = out / exp["name"] / f"n{n}-t{t}" / f"rep{rep}"
    d.mkdir(parents=True, exist_ok=True)
    round_ms = exp.get("round_ms", defaults["round_ms"])
    gen = [
        str(binary), "genconfig",
        "--protocol", exp["protocol"],
        "--broadcast", exp.get("broadcast", "dolev-strong"),
        "--n", str(n), "--t", str(t),
        "--out", str(d),
        "--base-port", str(port),
        "--round-ms", str(round_ms),
        "--start-in-s", str(exp.get("start_in_s", defaults["start_in_s"])),
        "--max-rounds", str(exp.get("max_rounds", defaults["max_rounds"])),
        "--seed", str(rep + 1),
    ]
    if "view_spacing" in exp:
        gen += ["--view-spacing", str(exp["view_spacing"])]
    subprocess.run(gen, check=True, capture_output=True)

    started = time.time()
    procs = []
    for i in range(n):
        log = open(d / f"node-{i}.log", "w")
        procs.append(subprocess.Popen(
            [str(binary), "node", "--config", str(d / f"node-{i}.toml")],
            stdout=log, stderr=subprocess.STDOUT,
        ))
    codes = [p.wait() for p in procs]
    elapsed = time.time() - started
    ok = all(c == 0 for c in codes)
    (d / "run.json").write_text(json.dumps({
        "experiment": exp["name"], "protocol": exp["protocol"],
        "broadcast": exp.get("broadcast", "dolev-strong"),
        "n": n, "t": t, "rep": rep, "round_ms": round_ms,
        "exit_codes": codes, "ok": ok, "wall_s": round(elapsed, 3),
    }, indent=2))
    status = "ok" if ok else f"FAILED {codes}"
    print(f"{exp['name']:<14} n={n:<3} t={t:<3} rep={rep} {elapsed:6.1f} s  {status}", flush=True)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("matrix")
    ap.add_argument("--out", default="eval/results")
    ap.add_argument("--binary", default="target/release/polaris")
    ap.add_argument("--only", help="run only the experiment with this name")
    args = ap.parse_args()

    matrix = tomllib.loads(Path(args.matrix).read_text())
    defaults = matrix.get("defaults", {})
    defaults.setdefault("round_ms", 500)
    defaults.setdefault("reps", 3)
    defaults.setdefault("start_in_s", 3)
    defaults.setdefault("base_port", 7000)
    defaults.setdefault("max_rounds", 400)
    binary = Path(args.binary)
    if not binary.exists():
        sys.exit(f"{binary} not found; run cargo build --release")
    out = Path(args.out)
    port = defaults["base_port"]
    failures = 0
    for exp in matrix["experiment"]:
        if args.only and exp["name"] != args.only:
            continue
        for n, t in exp["sizes"]:
            for rep in range(exp.get("reps", defaults["reps"])):
                if not run_once(binary, exp, n, t, rep, out, defaults, port):
                    failures += 1
                # A fresh port range per run keeps lingering sockets out of the way.
                port += n
                if port > 60000:
                    port = defaults["base_port"]
    if failures:
        sys.exit(f"{failures} run(s) failed")


if __name__ == "__main__":
    main()
