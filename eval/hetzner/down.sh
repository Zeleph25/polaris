#!/bin/bash
# Deletes every server that eval/hetzner/up.sh created (label role=polaris)
# and forgets their host keys, since Hetzner hands the addresses to later
# servers. The ssh key stays in the project for the next time.
set -euo pipefail
KNOWN=~/.ssh/polaris-hetzner-known
for name in $(hcloud server list -l role=polaris -o noheader -o columns=name); do
  ip=$(hcloud server ip "$name")
  echo "deleting $name ($ip)"
  hcloud server delete "$name" >/dev/null
  ssh-keygen -R "$ip" -f "$KNOWN" >/dev/null 2>&1 || true
done
