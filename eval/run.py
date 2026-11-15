#!/usr/bin/env python3
"""Runs an experiment matrix: for every experiment, size and repetition,
either generates a cluster with `polaris genconfig` and starts one
`polaris node` process per node (mode "net", the default), or runs
`polaris sim` with Byzantine nodes (mode "sim"); then keeps the output
files together with a run.json describing the run.

    eval/run.py eval/matrix.toml --out eval/results [--only ic-wxsd]

Network runs stay on this host unless the matrix has a [hosts] table:

    [hosts]
    list = ["adam@lab1", "adam@lab2", "adam@lab3"]   # ssh targets
    workdir = "polaris-eval"                          # under the remote home
    binary = "polaris-eval/polaris"                   # the remote binary

Then node i runs on the i-th host round robin: the run's cluster directory
is pushed to every host with rsync, each host's nodes are started by one
ssh session that waits for them, and the runs/ directories and logs come
back with rsync. The hosts need the binary built for them, reachable ports
from base_port up, and clocks synchronized (chrony or ntp) to well within
one round; give start_in_s enough room for the copies and the ssh startup.

The local binary is target/release/polaris unless --binary says
otherwise; build it first with `cargo build --release`.

`worker_threads` (in [defaults] or an experiment) sets the worker threads
of every node's runtime for network runs: a number, or "auto" for the
cores of a host divided by the nodes it runs, at least 1. Without it a
node starts one worker per core, whatever else runs on the host.
--worker-threads overrides the file for every experiment ("default" for
one worker per core).

--round-ms-from takes the minimums.csv of eval/round_search.py: a network
run whose experiment and size have a measured minimum longer than its
round length runs at that minimum instead (docs/design.md, decision 15).
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import time
import tomllib
from pathlib import Path


def run_sim(binary, exp, n, t, rep, d, defaults):
    cmd = [
        str(binary), "sim",
        "--protocol", exp["protocol"],
        "--broadcast", exp.get("broadcast", "dolev-strong"),
        "--n", str(n), "--t", str(t),
        "--byzantine", str(exp.get("byzantine", t)),
        "--adversary", exp.get("adversary", "mixed"),
        "--seed", str(rep + 1),
        "--max-rounds", str(exp.get("max_rounds", defaults["max_rounds"])),
        "--input-bytes", str(exp.get("input_bytes", 0)),
        "--out", str(d / "runs"),
    ]
    if "view_spacing" in exp:
        cmd += ["--view-spacing", str(exp["view_spacing"])]
    if exp.get("aggregate_votes"):
        cmd += ["--aggregate-votes"]
    if exp.get("share_accusations"):
        cmd += ["--share-accusations"]
    if exp.get("share_disclosures"):
        cmd += ["--share-disclosures"]
    started = time.time()
    with open(d / "sim.log", "w") as log:
        code = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode
    return [code], time.time() - started


def host_name(target):
    """`user@host` -> `host`, for the peer addresses."""
    return target.split("@", 1)[-1]


def host_cores(target, tools, cache={}):
    """Cores of an ssh target, asked once per target."""
    if target not in cache:
        out = subprocess.run([tools["ssh"], target, "nproc"], check=True,
                             capture_output=True, text=True).stdout
        cache[target] = int(out.split()[-1])
    return cache[target]


def worker_threads(exp, defaults, n, hosts, tools):
    """The --worker-threads of a network run, or None for one per core."""
    w = exp.get("worker_threads", defaults.get("worker_threads"))
    if w != "auto":
        return w
    if not hosts:
        return max(1, (os.cpu_count() or 1) // n)
    targets = hosts["list"]
    per_host = -(-n // len(targets))
    cores = min(host_cores(h, tools) for h in targets[:n])
    return max(1, cores // per_host)


def run_net(binary, exp, n, t, rep, d, defaults, port, hosts, tools, workers):
    round_ms = exp.get("round_ms", defaults["round_ms"])
    gen = [
        str(binary), "genconfig",
        "--protocol", exp["protocol"],
        "--broadcast", exp.get("broadcast", "dolev-strong"),
        "--n", str(n), "--t", str(t),
        "--out", str(d),
        "--base-port", str(port),
        "--round-ms", str(round_ms),
        "--start-in-s", str(exp.get("start_in_s", defaults["start_in_s"] if not hosts else max(defaults["start_in_s"], 20))),
        "--max-rounds", str(exp.get("max_rounds", defaults["max_rounds"])),
        "--seed", str(rep + 1),
        "--input-bytes", str(exp.get("input_bytes", 0)),
    ]
    if "view_spacing" in exp:
        gen += ["--view-spacing", str(exp["view_spacing"])]
    if exp.get("aggregate_votes"):
        gen += ["--aggregate-votes"]
    if exp.get("share_accusations"):
        gen += ["--share-accusations"]
    if exp.get("share_disclosures"):
        gen += ["--share-disclosures"]
    if workers is not None:
        gen += ["--worker-threads", str(workers)]
    if hosts:
        gen += ["--hosts", ",".join(host_name(h) for h in hosts["list"])]
    subprocess.run(gen, check=True, capture_output=True)

    started = time.time()
    if not hosts:
        procs = []
        for i in range(n):
            log = open(d / f"node-{i}.log", "w")
            procs.append(subprocess.Popen(
                [str(binary), "node", "--config", str(d / f"node-{i}.toml")],
                stdout=log, stderr=subprocess.STDOUT,
            ))
        codes = [p.wait() for p in procs]
        return codes, time.time() - started

    targets = hosts["list"]
    remote = f"{hosts.get('workdir', 'polaris-eval')}/{d.parent.parent.name}-{d.parent.name}-{d.name}"
    rbin = hosts.get("binary", "polaris-eval/polaris")
    if not rbin.startswith("/"):
        rbin = f"~/{rbin}"
    for h in targets:
        subprocess.run([tools["rsync"], "-az", "--delete", f"{d}/", f"{h}:{remote}/"], check=True)
    sessions = []
    for k, h in enumerate(targets):
        ids = [i for i in range(n) if i % len(targets) == k]
        if not ids:
            continue
        launch = " ".join(
            f"{rbin} node --config node-{i}.toml > node-{i}.log 2>&1 & " for i in ids)
        script = f"cd ~/{remote} || exit 1; {launch} wait"
        sessions.append(subprocess.Popen([tools["ssh"], h, script]))
    codes = [p.wait() for p in sessions]
    for h in targets:
        subprocess.run([tools["rsync"], "-az", f"{h}:{remote}/runs/", f"{d}/runs/"], check=True)
        subprocess.run([tools["rsync"], "-az", "--include=node-*.log", "--exclude=*",
                        f"{h}:{remote}/", f"{d}/"], check=True)
    return codes, time.time() - started


def run_once(binary, exp, n, t, rep, out, defaults, port, hosts, tools):
    d = out / exp["name"] / f"n{n}-t{t}" / f"rep{rep}"
    d.mkdir(parents=True, exist_ok=True)
    mode = exp.get("mode", "net")
    workers = None
    if mode == "sim":
        codes, elapsed = run_sim(binary, exp, n, t, rep, d, defaults)
    else:
        workers = worker_threads(exp, defaults, n, hosts, tools)
        codes, elapsed = run_net(binary, exp, n, t, rep, d, defaults, port, hosts, tools, workers)
    ok = all(c == 0 for c in codes)
    (d / "run.json").write_text(json.dumps({
        "experiment": exp["name"], "mode": mode, "protocol": exp["protocol"],
        "broadcast": exp.get("broadcast", "dolev-strong"),
        "n": n, "t": t, "rep": rep, "input_bytes": exp.get("input_bytes", 0),
        "hosts": [host_name(h) for h in hosts["list"]] if (hosts and mode == "net") else ["localhost"],
        "round_ms": exp.get("round_ms", defaults["round_ms"]) if mode == "net" else None,
        "worker_threads": workers,
        "byzantine": exp.get("byzantine", t) if mode == "sim" else 0,
        "adversary": exp.get("adversary", "mixed") if mode == "sim" else None,
        "exit_codes": codes, "ok": ok, "wall_s": round(elapsed, 3),
    }, indent=2))
    status = "ok" if ok else f"FAILED {codes}"
    print(f"{exp['name']:<14} n={n:<3} t={t:<3} rep={rep} {elapsed:6.1f} s  {status}", flush=True)
    return ok


def load_matrix(path, worker_threads=None):
    """The experiments of a matrix file and its defaults, filled in;
    worker_threads, if given, overrides the file."""
    matrix = tomllib.loads(Path(path).read_text())
    defaults = matrix.setdefault("defaults", {})
    defaults.setdefault("round_ms", 500)
    defaults.setdefault("reps", 3)
    defaults.setdefault("start_in_s", 3)
    defaults.setdefault("base_port", 7000)
    defaults.setdefault("max_rounds", 400)
    if worker_threads is not None:
        w = None if worker_threads == "default" else worker_threads if worker_threads == "auto" else int(worker_threads)
        defaults["worker_threads"] = w
        for exp in matrix["experiment"]:
            exp.pop("worker_threads", None)
    return matrix, defaults


def load_minimums(path):
    """(experiment, n, t) -> minimum round length in ms, from the
    minimums.csv of eval/round_search.py; None where no length of its ladder
    was sustained."""
    with open(path, newline="") as f:
        return {(r["experiment"], int(r["n"]), int(r["t"])): (int(r["minimum_ms"]) if r["minimum_ms"] else None)
                for r in csv.DictReader(f)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("matrix")
    ap.add_argument("--out", default="eval/results")
    ap.add_argument("--binary", default="target/release/polaris")
    ap.add_argument("--only", help="run only the experiment with this name")
    ap.add_argument("--worker-threads", help='a number, "auto" or "default"; overrides the matrix')
    ap.add_argument("--round-ms-from", help="minimums.csv of eval/round_search.py")
    ap.add_argument("--ssh", default="ssh", help="the ssh command (for tests)")
    ap.add_argument("--rsync", default="rsync", help="the rsync command (for tests)")
    args = ap.parse_args()

    matrix, defaults = load_matrix(args.matrix, args.worker_threads)
    minimums = load_minimums(args.round_ms_from) if args.round_ms_from else {}
    binary = Path(args.binary)
    if not binary.exists():
        sys.exit(f"{binary} not found; run cargo build --release")
    out = Path(args.out)
    hosts = matrix.get("hosts")
    tools = {"ssh": args.ssh, "rsync": args.rsync}
    port = defaults["base_port"]
    failures = 0
    for exp in matrix["experiment"]:
        if args.only and exp["name"] != args.only:
            continue
        for n, t in exp["sizes"]:
            run_exp = exp
            if (exp["name"], n, t) in minimums:
                base = exp.get("round_ms", defaults["round_ms"])
                minimum = minimums[(exp["name"], n, t)]
                if minimum is None:
                    print(f"{exp['name']} n={n} t={t}: no round length of the search was sustained; "
                          f"running at {base} ms", flush=True)
                elif minimum > base:
                    run_exp = {**exp, "round_ms": minimum}
            for rep in range(exp.get("reps", defaults["reps"])):
                if not run_once(binary, run_exp, n, t, rep, out, defaults, port, hosts, tools):
                    failures += 1
                # A fresh port range per run keeps lingering sockets out of the way.
                port += n
                if port > 60000:
                    port = defaults["base_port"]
    if failures:
        sys.exit(f"{failures} run(s) failed")


if __name__ == "__main__":
    main()
