#!/usr/bin/env python3
"""Tests the multi-host path of eval/run.py on this machine: two "hosts",
127.0.0.1 and localhost, each with its own home directory, reached through
stand-ins for ssh and rsync that map `user@host:path` to that directory.
Runs the signed echo and the compiler over Dolev-Strong and checks that
every run succeeds and its results come back.

    python3 eval/test_hosts.py [--binary target/release/polaris]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SSH = """#!/bin/bash
while [[ "$1" == -o ]]; do shift 2; done
h="${1#*@}"; shift
HOME="$HOMES/$h" bash -c "$*"
"""

RSYNC = """#!/usr/bin/env python3
import fnmatch, os, shutil, sys
args = sys.argv[1:]
inc = [a.split("=", 1)[1] for a in args if a.startswith("--include=")]
paths = [a for a in args if not a.startswith("-")]
def local(p):
    if "@" in p and ":" in p:
        target, path = p.split(":", 1)
        return os.path.join(os.environ["HOMES"], target.split("@", 1)[1], path)
    return p
src, dst = local(paths[0]), local(paths[1])
os.makedirs(dst, exist_ok=True)
for name in os.listdir(src):
    if inc and not any(fnmatch.fnmatch(name, g) for g in inc):
        continue
    s, d = os.path.join(src, name), os.path.join(dst, name)
    if os.path.isdir(s):
        shutil.copytree(s, d, dirs_exist_ok=True)
    else:
        shutil.copy2(s, d)
"""

MATRIX = """
[defaults]
round_ms = 300
reps = 1
start_in_s = 3
base_port = 9100

[hosts]
list = ["test@127.0.0.1", "test@localhost"]
workdir = "polaris-eval"
binary = "polaris-eval/polaris"

[[experiment]]
name = "echo"
protocol = "echo"
sizes = [[4, 1]]

[[experiment]]
name = "ic"
protocol = "ic"
broadcast = "dolev-strong"
sizes = [[6, 3]]
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="target/release/polaris")
    binary = Path(ap.parse_args().binary).resolve()
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        homes = tmp / "homes"
        for host in ("127.0.0.1", "localhost"):
            (homes / host / "polaris-eval").mkdir(parents=True)
            shutil.copy2(binary, homes / host / "polaris-eval" / "polaris")
        for name, body in (("ssh", SSH), ("rsync", RSYNC)):
            (tmp / name).write_text(body)
            (tmp / name).chmod(0o755)
        (tmp / "matrix.toml").write_text(MATRIX)
        env = dict(os.environ, HOMES=str(homes))
        r = subprocess.run([
            sys.executable, str(here / "run.py"), str(tmp / "matrix.toml"),
            "--binary", str(binary), "--out", str(tmp / "out"),
            "--ssh", str(tmp / "ssh"), "--rsync", str(tmp / "rsync"),
        ], env=env, capture_output=True, text=True)
        print(r.stdout, end="")
        if r.returncode != 0:
            sys.exit(f"run.py failed:\n{r.stderr}")
        for exp, n in (("echo", 4), ("ic", 6)):
            run = tmp / "out" / exp / f"n{n}-t{1 if exp == 'echo' else 3}" / "rep0"
            assert json.loads((run / "run.json").read_text())["ok"], f"{exp}: run not ok"
            outputs = sorted((run / "runs").glob("node-*.metrics.jsonl"))
            assert len(outputs) == n, f"{exp}: {len(outputs)} of {n} nodes came back"
    print("multi-host path ok")


if __name__ == "__main__":
    main()
