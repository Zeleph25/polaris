#!/usr/bin/env python3
"""Finds the shortest round length at which network runs keep up.

    python3 eval/round_search.py eval/hosts.hetzner.toml --sizes 64:32,64:48 \
        --out eval/results/hetzner-ccx63/search

For every network experiment of the matrix at the given sizes (n:t), the
ladder (250, 500, 1000, 2000 and 4000 ms by default) is tried from the
shortest length up. A length is sustained when every repetition runs with
zero late messages, every process exits normally and all of them decide the
same output; it fails at its first repetition that does not. After the
first sustained length, one length halfway between it and the last failed
one is tried, and the minimum is the shorter of the sustained ones. With no
failed length below the first sustained one, that one is the minimum; with
none sustained, there is no minimum. docs/design.md, decision 15, gives the
reasons.

Every run is kept under <out>/r<ms>/, laid out as run.py lays out its
results. minimums.csv and minimums.md in <out> list, per experiment and
size, the lengths tried and the minimum; run.py --round-ms-from reads the
csv. The repetitions, the worker threads and everything else come from the
matrix, as for run.py.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run  # noqa: E402


def sustained(d, n):
    """Whether the run in d kept up, and if not, why."""
    meta = json.loads((d / "run.json").read_text())
    if not meta["ok"]:
        return False, "a process failed"
    runs = d / "runs"
    outputs = [json.loads(f.read_text())["output"] for f in runs.glob("node-*.output.json")]
    if len(outputs) != n:
        return False, f"{len(outputs)} of {n} outputs"
    if len({json.dumps(o, sort_keys=True) for o in outputs}) != 1:
        return False, "outputs differ"
    late = 0
    for f in runs.glob("node-*.metrics.jsonl"):
        late += json.loads(f.read_text().splitlines()[-1])["late_msgs"]
    if late:
        return False, f"{late} late messages"
    return True, "no late message"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("matrix")
    ap.add_argument("--sizes", required=True, help="n:t pairs, comma-separated, e.g. 64:32,64:48")
    ap.add_argument("--ladder", default="250,500,1000,2000,4000", help="round lengths in ms, shortest first")
    ap.add_argument("--out", required=True)
    ap.add_argument("--binary", default="target/release/polaris")
    ap.add_argument("--only", help="search only the experiment with this name")
    ap.add_argument("--worker-threads", help='a number, "auto" or "default"; overrides the matrix')
    args = ap.parse_args()

    matrix, defaults = run.load_matrix(args.matrix, args.worker_threads)
    sizes = [tuple(int(x) for x in s.split(":")) for s in args.sizes.split(",")]
    ladder = sorted(int(x) for x in args.ladder.split(","))
    binary = Path(args.binary)
    if not binary.exists():
        sys.exit(f"{binary} not found; run cargo build --release")
    out = Path(args.out)
    hosts = matrix.get("hosts")
    tools = {"ssh": "ssh", "rsync": "rsync"}
    port = defaults["base_port"]

    def attempt(exp, n, t, round_ms):
        """Runs the repetitions at one round length, stopping at the first
        that does not keep up."""
        nonlocal port
        e = {**exp, "round_ms": round_ms}
        for rep in range(exp.get("reps", defaults["reps"])):
            run.run_once(binary, e, n, t, rep, out / f"r{round_ms}", defaults, port, hosts, tools)
            port += n
            if port > 60000:
                port = defaults["base_port"]
            ok, why = sustained(out / f"r{round_ms}" / exp["name"] / f"n{n}-t{t}" / f"rep{rep}", n)
            if not ok:
                print(f"  {round_ms} ms: not sustained (rep {rep}: {why})", flush=True)
                return False
        print(f"  {round_ms} ms: sustained", flush=True)
        return True

    results = []
    for exp in matrix["experiment"]:
        if exp.get("mode", "net") != "net" or (args.only and exp["name"] != args.only):
            continue
        for n, t in sizes:
            if [n, t] not in [list(s) for s in exp["sizes"]]:
                continue
            print(f"{exp['name']} n={n} t={t}", flush=True)
            tried = []
            failed, first = None, None
            for round_ms in ladder:
                ok = attempt(exp, n, t, round_ms)
                tried.append((round_ms, ok))
                if ok:
                    first = round_ms
                    break
                failed = round_ms
            minimum = first
            if first is not None and failed is not None:
                mid = (failed + first) // 2
                if mid not in (failed, first):
                    ok = attempt(exp, n, t, mid)
                    tried.append((mid, ok))
                    if ok:
                        minimum = mid
            results.append({
                "experiment": exp["name"], "n": n, "t": t,
                "tried": " ".join(f"{ms}:{'ok' if ok else 'late'}" for ms, ok in tried),
                "minimum_ms": "" if minimum is None else minimum,
            })
            print(f"  minimum: {minimum if minimum is not None else 'none on the ladder'}", flush=True)

    out.mkdir(parents=True, exist_ok=True)
    with open(out / "minimums.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["experiment", "n", "t", "minimum_ms", "tried"])
        w.writeheader()
        w.writerows(results)
    lines = ["| experiment | n | t | minimum round | tried (ms) |", "| --- | --- | --- | --- | --- |"]
    for r in results:
        minimum = f"{r['minimum_ms']} ms" if r["minimum_ms"] != "" else f"over {ladder[-1]} ms"
        lines.append(f"| {r['experiment']} | {r['n']} | {r['t']} | {minimum} | {r['tried']} |")
    (out / "minimums.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
