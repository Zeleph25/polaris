#!/usr/bin/env python3
"""Writes a copy of an experiment file for the Hetzner servers: their
addresses as the [hosts] list, or no [hosts] table for a single server, on
which every node process then runs. On a single server nothing is copied
before a run, so its nodes start 10 s after their configs are written
instead of the file's start_in_s, which leaves room for copies over ssh.

    python3 eval/hetzner/hosts.py eval/hosts.toml <ip> [<ip>...]
"""

import re
import sys
from pathlib import Path


def main():
    text = Path(sys.argv[1]).read_text()
    ips = sys.argv[2:]
    text = re.sub(r"(?ms)^\[hosts\]\n.*?(?=^\[)", "", text)
    if len(ips) == 1:
        text = re.sub(r"(?m)^start_in_s = \d+$", "start_in_s = 10", text)
    if len(ips) > 1:
        listed = ", ".join(f'"root@{ip}"' for ip in ips)
        text += (f'\n[hosts]\nlist = [{listed}]\nworkdir = "polaris-eval"\n'
                 f'binary = "/root/polaris/target/release/polaris"\n')
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
