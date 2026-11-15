#!/bin/bash
# Creates the polaris servers on Hetzner Cloud, waits until polaris is built
# on all of them, and sets up the first one as the controller.
#
#   eval/hetzner/up.sh single          # one 48-core server, every node on it
#   eval/hetzner/up.sh regions         # 8 servers, 2 in each of 4 regions
#   eval/hetzner/up.sh single-shared   # one 16-core shared server (cpx62)
#   eval/hetzner/up.sh regions-shared  # 8 shared 8-core servers, 4 regions
#
# Needs the hcloud CLI with a project token (`hcloud context create polaris`).
# The shared variants fit the limits of a new account, which allow few
# dedicated cores. TYPE= overrides the server type of every server. Run
# eval/hetzner/down.sh when done: servers bill by the hour.
set -euo pipefail
cd "$(dirname "$0")/../.."

KEY=~/.ssh/polaris-hetzner
KNOWN=~/.ssh/polaris-hetzner-known
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN")

# One server type per location; the shared types differ by location.
case "${1:-}" in
  single)         LOCATIONS=(nbg1); TYPES=(ccx63) ;;
  regions)        LOCATIONS=(nbg1 nbg1 ash ash hil hil sin sin); TYPES=(ccx33 ccx33 ccx33 ccx33 ccx33 ccx33 ccx33 ccx33) ;;
  single-shared)  LOCATIONS=(nbg1); TYPES=(cpx62) ;;
  regions-shared) LOCATIONS=(nbg1 nbg1 ash ash hil hil sin sin); TYPES=(cpx42 cpx42 cpx41 cpx41 cpx41 cpx41 cpx42 cpx42) ;;
  *) echo "usage: $0 single|regions|single-shared|regions-shared" >&2; exit 2 ;;
esac

# A key for these servers only: the controller gets a copy to reach the others.
[ -f "$KEY" ] || ssh-keygen -t ed25519 -N "" -C polaris-hetzner -f "$KEY" >/dev/null
hcloud ssh-key describe polaris >/dev/null 2>&1 \
  || hcloud ssh-key create --name polaris --public-key-from-file "$KEY.pub" >/dev/null

names=()
for i in "${!LOCATIONS[@]}"; do
  name="polaris-$((i + 1))"
  names+=("$name")
  type="${TYPE:-${TYPES[$i]}}"
  echo "creating $name ($type in ${LOCATIONS[$i]})"
  hcloud server create --name "$name" --type "$type" --image ubuntu-24.04 \
    --location "${LOCATIONS[$i]}" --ssh-key polaris --label role=polaris \
    --user-data-from-file eval/hetzner/cloud-init.yaml >/dev/null
done

ips=()
for name in "${names[@]}"; do ips+=("$(hcloud server ip "$name")"); done
# Hetzner reuses addresses, and ssh refuses a new server whose address it
# knows with another key: forget whatever an earlier server left.
for ip in "${ips[@]}"; do ssh-keygen -R "$ip" -f "$KNOWN" >/dev/null 2>&1 || true; done

echo "waiting for the builds (about 5 minutes)"
for ip in "${ips[@]}"; do
  start=$SECONDS
  # Fails while the server boots (connection refused) and while it builds
  # (no marker yet); a refused host key or 20 minutes without a marker stop
  # the wait with ssh's last message.
  until err=$("${SSH[@]}" -o ConnectTimeout=5 "root@$ip" \
      'test -e /root/polaris-ready || test -e /root/polaris-failed' 2>&1); do
    case "$err" in
      *"Host key verification failed"*)
        printf 'ssh refuses %s:\n%s\nThe servers are still running: eval/hetzner/down.sh deletes them.\n' \
          "$ip" "$err" >&2
        exit 1 ;;
    esac
    if (( SECONDS - start > 1200 )); then
      printf '%s not ready after 20 minutes; ssh said: %s\nThe servers are still running: eval/hetzner/down.sh deletes them.\n' \
        "$ip" "${err:-nothing (no marker yet)}" >&2
      exit 1
    fi
    sleep 15
  done
  if "${SSH[@]}" "root@$ip" test -e /root/polaris-failed; then
    echo "build failed on $ip; see /root/build.log there" >&2
    exit 1
  fi
  echo "  $ip ready"
done

# The experiment file: the servers as hosts, or none for a single server.
python3 eval/hetzner/hosts.py eval/hosts.toml "${ips[@]}" > eval/hosts.hetzner.toml
ctl="${ips[0]}"
scp -i "$KEY" -o UserKnownHostsFile="$KNOWN" \
  "$KEY" "root@$ctl:.ssh/id_ed25519" >/dev/null
scp -i "$KEY" -o UserKnownHostsFile="$KNOWN" \
  eval/hosts.hetzner.toml "root@$ctl:polaris/eval/hosts.hetzner.toml" >/dev/null
# Let the controller reach every server, itself included, without prompts.
"${SSH[@]}" "root@$ctl" "for ip in ${ips[*]}; do ssh-keyscan -H \$ip >> ~/.ssh/known_hosts 2>/dev/null; done"

# Results go to a directory named after the server type, so that runs on
# another machine never overwrite these.
out="hetzner-${TYPE:-${TYPES[0]}}"
opts="-i $KEY -o UserKnownHostsFile=$KNOWN"

cat <<MSG

Ready. On the controller:

  ssh $opts root@$ctl
  tmux new -s polaris
  cd polaris
MSG
if [ "${#ips[@]}" -gt 1 ]; then
  echo "  python3 eval/check_hosts.py eval/hosts.hetzner.toml"
fi
cat <<MSG
  python3 eval/run.py eval/hosts.hetzner.toml --only smoke-echo --out eval/results/$out
  python3 eval/round_search.py eval/hosts.hetzner.toml --sizes 64:32,64:48 --out eval/results/$out/search
  python3 eval/run.py eval/hosts.hetzner.toml --round-ms-from eval/results/$out/search/minimums.csv --out eval/results/$out
  python3 eval/aggregate.py eval/results/$out

Then, back on this machine, copy the results back as one archive (the
per-message transcripts are left out: they are large and no table uses
them), unpack it into eval/results/$out (rename an older one first) and
delete the servers:

  ssh $opts root@$ctl "cd polaris/eval/results && tar czf ~/$out.tgz --exclude='*.transcript.jsonl' $out"
  scp $opts root@$ctl:$out.tgz eval/results/
  (cd eval/results && tar xzf $out.tgz)
  eval/hetzner/down.sh
MSG
