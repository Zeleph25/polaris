#!/usr/bin/env python3
"""Checks the hosts of an experiment file before a multi-host run: that
each one answers over ssh without a password prompt, has rsync, has the
polaris binary at the configured path with the same version as the local
one, and has a clock within a few milliseconds of this machine's.

    python3 eval/check_hosts.py eval/hosts.toml [--binary target/release/polaris]

The clock offset is estimated from one ssh round trip (the remote time
against the midpoint of the local times around it), so it carries up to
half that round trip of error; the report shows both. Ports between hosts
are not checked here: the smoke experiments of eval/hosts.toml do that.
"""

import argparse
import subprocess
import sys
import time
import tomllib
from pathlib import Path


def ssh(target, command, timeout=20):
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target, command],
        capture_output=True, text=True, timeout=timeout,
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("matrix")
    ap.add_argument("--binary", default="target/release/polaris")
    args = ap.parse_args()

    hosts = tomllib.loads(Path(args.matrix).read_text()).get("hosts")
    if not hosts:
        sys.exit(f"{args.matrix} has no [hosts] table")
    rbin = hosts.get("binary", "polaris-eval/polaris")
    if not rbin.startswith("/"):
        rbin = f"~/{rbin}"
    local = subprocess.run([args.binary, "--version"], capture_output=True, text=True).stdout.strip()

    problems = 0
    for target in hosts["list"]:
        try:
            r = ssh(target, f"command -v rsync >/dev/null && echo rsync-ok; {rbin} --version")
        except subprocess.TimeoutExpired:
            print(f"{target}: ssh timed out")
            problems += 1
            continue
        if r.returncode != 0 and "rsync-ok" not in r.stdout:
            print(f"{target}: ssh failed: {r.stderr.strip()}")
            problems += 1
            continue
        notes = []
        if "rsync-ok" not in r.stdout:
            notes.append("rsync missing")
        version = r.stdout.replace("rsync-ok", "").strip()
        if not version:
            notes.append(f"no binary at {rbin}")
        elif version != local:
            notes.append(f"binary is {version!r}, local is {local!r}")

        before = time.time()
        r = ssh(target, "date +%s.%N")
        after = time.time()
        rtt_ms = (after - before) * 1000
        try:
            offset_ms = (float(r.stdout.strip()) - (before + after) / 2) * 1000
            clock = f"clock offset {offset_ms:+.1f} ms (+- {rtt_ms / 2:.1f})"
            if abs(offset_ms) > 20 + rtt_ms / 2:
                notes.append("clock far off; enable chrony or ntp")
        except ValueError:
            clock = "clock unread"
            notes.append("date failed")
        problems += bool(notes)
        print(f"{target}: {clock}" + (f"; {'; '.join(notes)}" if notes else "; ok"))
    if problems:
        sys.exit(f"{problems} host(s) need attention")


if __name__ == "__main__":
    main()
