#!/usr/bin/env python3
"""Runs honest-majority synchronous protocols from the Apollo artefact
(libchatter-rs: Apollo and Sync HotStuff) on loopback, one block of n inputs
each, so that their time to commit can sit next to polaris deciding IC on n
inputs, and polaris itself on loopback for the same byte count.

    python3 eval/honest_majority.py --chatter <libchatter-rs checkout> \\
        --polaris target/release/polaris \\
        --out eval/results/honest --sizes 8 16 32 --delta-ms 500 --reps 3

Every process is honest and f = (n - 1) / 2. The synchrony bound Delta is
set to polaris's round length. One client submits n transactions of
`--payload` bytes in one window, the nodes are configured with blocks of n
transactions, and the run ends when the client reports the block committed.
Per run, `run.json` records the client's mean latency per transaction, the
wall time from the client's start to that report, the CPU time of every node,
and the bytes that crossed the loopback interface (all nodes and the client,
TLS included), read from /sys/class/net/lo. Nothing else may use loopback
while this runs.

polaris runs as `polaris local` (every node in one process over TCP on
loopback, all honest, t = n/2 and t = 3n/4, rounds of Delta): `run.json`
records the loopback bytes and the decision round; its time to decision is
the round schedule, (round + 1) Delta plus the last round's processing,
which the network runs of the main harness measure.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

PROTOCOLS = {
    # Apollo's `-s` mode multicasts every proposal to the client, which
    # applies Apollo's commit rule itself (a block commits once f later
    # rounds are proposed on top of it) and reports the latency to that
    # commit; without it, nodes notify the client only after committing,
    # which never happens when the whole load fits in one block. Sync
    # HotStuff always multicasts committed blocks to clients.
    "apollo": ["-s"],
    "synchs": [],
}
CLK_TCK = os.sysconf("SC_CLK_TCK")


def lo_bytes():
    return int(Path("/sys/class/net/lo/statistics/tx_bytes").read_text())


def cpu_ms(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) * 1000 / CLK_TCK


def run_once(chatter, proto, n, delta, payload, d, port):
    f = (n - 1) // 2
    rel = chatter / "target" / "release"
    d.mkdir(parents=True, exist_ok=True)
    cli_port = port + 100
    subprocess.run([
        str(rel / "genconfig"), "-n", str(n), "-f", str(f), "-d", str(delta),
        "--blocksize", str(n), "--base_port", str(port),
        "--client_base_port", str(cli_port), "--payload", str(payload),
        "--target", str(d),
    ], check=True, stdout=subprocess.DEVNULL)
    (d / "ip_file").write_text("".join(f"127.0.0.1:{port + i}\n" for i in range(n)))
    (d / "cli_ip_file").write_text("".join(f"127.0.0.1:{cli_port + i}\n" for i in range(n)))

    boot = 5 + max(n, 3)
    nodes = []
    for i in range(n):
        log = open(d / f"node-{i}.log", "w")
        nodes.append(subprocess.Popen([
            str(rel / f"node-{proto}"), "-c", str(d / f"nodes-{i}.json"),
            "-i", str(d / "ip_file"), "--sleep", str(boot), "--delta", str(delta),
            *PROTOCOLS[proto],
        ], stdout=log, stderr=subprocess.STDOUT))
    time.sleep(boot)
    txs = n
    cpu0 = [cpu_ms(p.pid) for p in nodes]
    lo0 = lo_bytes()
    started = time.time()
    client_log = d / "client.log"
    with open(client_log, "w") as log:
        client = subprocess.Popen([
            str(rel / f"client-{proto}"), "-c", str(d / "client.json"),
            "-i", str(d / "cli_ip_file"), "-m", str(txs), "-w", str(txs),
        ], stdout=log, stderr=subprocess.STDOUT)
    latency = throughput = None
    while time.time() < started + 120:
        text = client_log.read_text()
        if m := re.search(r"DP\[Latency\]: ([0-9.]+)", text):
            latency = float(m.group(1))
        if m := re.search(r"DP\[Throughput\]: ([0-9.]+)", text):
            throughput = float(m.group(1))
        if latency is not None and throughput is not None:
            break
        time.sleep(0.05)
    wall = time.time() - started
    lo1 = lo_bytes()
    cpu1 = [cpu_ms(p.pid) for p in nodes]
    client.kill()
    for p in nodes:
        p.send_signal(signal.SIGKILL)
        p.wait()
    client.wait()
    result = {
        "protocol": proto, "n": n, "f": f, "delta_ms": delta, "payload": payload,
        "ok": latency is not None, "txs": txs,
        "latency_ms": latency, "throughput": throughput, "wall_s": round(wall, 3),
        "node_cpu_ms": [round(b - a, 1) for a, b in zip(cpu0, cpu1)],
        "loopback_bytes": lo1 - lo0,
    }
    (d / "run.json").write_text(json.dumps(result, indent=2))
    print(f"{proto:<7} n={n:<3} f={f:<3} latency={latency} ms wall={wall:.2f} s "
          f"lo={(lo1 - lo0) / 1e6:.2f} MB", flush=True)
    return result


# polaris over each broadcast, with t = n/2 and with a dishonest majority,
# t = 3n/4 (the fraction of n that may be Byzantine).
POLARIS = {
    "polaris-ds": (["--broadcast", "dolev-strong"], 1 / 2),
    "polaris-wxsd-agg": (["--broadcast", "wxsd", "--aggregate-votes"], 1 / 2),
    "polaris-ds-q": (["--broadcast", "dolev-strong"], 3 / 4),
    "polaris-wxsd-agg-q": (["--broadcast", "wxsd", "--aggregate-votes"], 3 / 4),
}


def run_polaris(binary, proto, n, delta, d):
    d.mkdir(parents=True, exist_ok=True)
    flags, fraction = POLARIS[proto]
    t = int(n * fraction)
    lo0 = lo_bytes()
    started = time.time()
    code = subprocess.run([
        str(binary), "local", "--n", str(n), "--t", str(t),
        "--round-ms", str(delta), "--protocol", "ic", *flags,
        "--max-rounds", "400", "--out", str(d / "runs"),
    ], stdout=open(d / "local.log", "w"), stderr=subprocess.STDOUT).returncode
    wall = time.time() - started
    lo1 = lo_bytes()
    rounds = []
    for f in sorted((d / "runs").glob("node-*.metrics.jsonl")):
        summary = json.loads(f.read_text().splitlines()[-1])
        rounds.append(summary["decision_round"])
    result = {
        "protocol": proto, "n": n, "t": t, "delta_ms": delta, "ok": code == 0,
        "decision_round": max(rounds) if rounds else None,
        "wall_s": round(wall, 3), "loopback_bytes": lo1 - lo0,
    }
    (d / "run.json").write_text(json.dumps(result, indent=2))
    print(f"{proto:<16} n={n:<3} round={result['decision_round']} "
          f"lo={(lo1 - lo0) / 1e6:.2f} MB", flush=True)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chatter", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--sizes", type=int, nargs="+", default=[8, 16, 32])
    ap.add_argument("--polaris", type=Path, help="the polaris binary; runs polaris too")
    ap.add_argument("--polaris-variants", nargs="*", default=list(POLARIS))
    ap.add_argument("--protocols", nargs="*", default=list(PROTOCOLS))
    ap.add_argument("--delta-ms", type=int, default=500)
    ap.add_argument("--payload", type=int, default=16)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--first-rep", type=int, default=0, help="skip the repetitions before this one")
    args = ap.parse_args()
    port = 21000
    for proto in args.protocols:
        for n in args.sizes:
            for rep in range(args.first_rep, args.reps):
                d = args.out / proto / f"n{n}" / f"rep{rep}"
                run_once(args.chatter.resolve(), proto, n, args.delta_ms, args.payload, d, port)
                port += 200
                time.sleep(1)
    if args.polaris:
        for proto in args.polaris_variants:
            for n in args.sizes:
                for rep in range(args.first_rep, args.reps):
                    d = args.out / proto / f"n{n}" / f"rep{rep}"
                    run_polaris(args.polaris.resolve(), proto, n, args.delta_ms, d)


if __name__ == "__main__":
    main()
