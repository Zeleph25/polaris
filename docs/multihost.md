# Running across several machines

The network runs of the README put every node on one machine, so they
measure processing but not latency. This page sets up the same runs across
real machines. One machine, the *controller*, holds the repository and
drives everything over ssh; the *hosts* run the nodes. The controller can
be your laptop or one of the hosts.

## What the hosts need

- **Machines.** 4 to 8 Linux machines, x86_64 or arm64, Ubuntu 22.04 or
  24.04 or similar, 4 cores and 4 GB of memory each. With 8 hosts and
  n = 64, each host runs 8 nodes; n parallel WXSD at n = 64 is the heaviest
  run. Lab machines, a cluster allocation or cloud VMs all work.
- **One user** on every host, reachable from the controller with an ssh key
  and no password prompt (`ssh user@host true` must return at once).
- **Addresses the hosts use to reach each other.** The names in the
  `[hosts]` list (the part after `@`) become the peer addresses, so they
  must resolve and route from every host. On a cloud network, use the
  private IPs: `user@10.0.0.5`.
- **Open ports.** TCP 7000 to 60000 between the hosts. The launcher gives
  every run a fresh range of n ports, starting at 7000 and wrapping at
  60000. The controller only needs ssh.
- **Synchronized clocks.** Round 0 starts at a wall-clock time written into
  every node's config, so the hosts' clocks must agree to well within a
  round. Install chrony (`sudo apt install chrony`) and check that
  `chronyc tracking` reports a system time offset of a few milliseconds.
- **rsync** on every host and on the controller.

### Firewall and cloud rules

On hosts that use ufw:

```
sudo ufw allow from 10.0.0.0/24 to any port 7000:60000 proto tcp
```

with the hosts' subnet in place of `10.0.0.0/24`. On a cloud provider, add
the same range to the security group or firewall rule that covers the VMs,
with the group itself as the source.

## Build the binary

Build polaris on one host (the hosts share an architecture) from the same
commit as the controller's checkout:

```
curl https://sh.rustup.rs -sSf | sh -s -- -y
source ~/.cargo/env
git clone https://github.com/Zeleph25/polaris.git && cd polaris
cargo build --release
```

Then copy `target/release/polaris` to `~/polaris-eval/polaris` on every
host (`scp`, or `rsync` from the host that built it). The controller also
needs a binary for its own platform, since it writes the configs with
`polaris genconfig`: on the controller, `cargo build --release` in the
same checkout. Both must come from the same commit; `check_hosts.py`
compares the version strings, which only change with the crate version.

## Fill in and check the hosts

In `eval/hosts.toml`, replace the `[hosts]` list with the ssh targets:

```toml
[hosts]
list = ["adam@10.0.0.5", "adam@10.0.0.6", "adam@10.0.0.7", "adam@10.0.0.8"]
workdir = "polaris-eval"
binary = "polaris-eval/polaris"
```

Then, from the repository on the controller:

```
python3 eval/check_hosts.py eval/hosts.toml
```

For each host, it checks ssh, rsync, the binary and its version, and the
clock offset against the controller. Fix anything it reports before going
on.

## Smoke runs, then the matrix

```
python3 eval/run.py eval/hosts.toml --only smoke-echo --out eval/results/hosts
python3 eval/run.py eval/hosts.toml --only smoke-ic --out eval/results/hosts
python3 eval/aggregate.py eval/results/hosts
```

Both must report `ok` and agreement, with 0 late messages.
- A node that never connects means a closed port or an address that does
  not route; its log, copied back next to the run, names the missing peers.
- A warning that the start time has already passed means the controller's
  clock, or a host's, is off, or that `start_in_s` (30 s) is too short for
  the copies.

Then run everything:

```
python3 eval/run.py eval/hosts.toml --out eval/results/hosts
python3 eval/aggregate.py eval/results/hosts
```

Each run takes about 30 s to start, plus its rounds at 500 ms, so the 72
runs of the file take about an hour and a half. `--only m-ic-ds` runs one
experiment. Send back the `eval/results/hosts` directory, or at least the
`summary.csv` and `summary.md` that `aggregate.py` writes there.

## On Hetzner Cloud

`eval/hetzner/` creates the servers, builds polaris on each one from
GitHub (so the repository must be public and `main` pushed), writes the
experiment file and deletes the servers afterwards. Hetzner Cloud opens
every port by default and Ubuntu keeps the clocks synchronized with
chrony, so there is nothing else to set up.

Once, on your laptop:

```
brew install hcloud                       # or the release binary from GitHub
hcloud context create polaris             # paste an API token: Hetzner Console,
                                          # your project, Security, API tokens,
                                          # with Read & Write
```

Then, from the repository:

```
eval/hetzner/up.sh single      # one CCX63: 48 dedicated cores, about EUR 1.2/hour
eval/hetzner/up.sh regions     # 8 CCX33 in Nuremberg, Ashburn, Hillsboro and
                               # Singapore: about EUR 1.5/hour for all 8
```

`up.sh` takes about five minutes, mostly the builds, and ends by
printing the commands to run on the first server, which is the
controller. Hetzner reuses addresses, so `up.sh` forgets any host key an
earlier server left for them (and `down.sh` those of the servers it
deletes); if ssh still refuses a server, or a build gives no sign of
life for 20 minutes, `up.sh` stops with ssh's message instead of
waiting. Results go to `eval/results/hetzner-<type>`, after the server
type. Run the printed commands inside `tmux`, or start the long one with
`nohup ... &`, so that the runs go on if your laptop sleeps or the
connection drops. `up.sh` also prints how to copy the results back as
one archive, without the per-message transcripts, which are large (1.6
GB for the matrix) and used by no table.
When the results are copied back:

```
eval/hetzner/down.sh           # deletes every polaris server
```

Servers bill by the hour until they are deleted, even idle ones; the
Hetzner Console lists anything left.

A new account may create only a few dedicated cores ("dedicated core limit
exceeded"). The Limits tab of the project's overview in the Hetzner Console
shows the limits, and its Request change button asks for more (handled by
hand, during business hours). Until then, `single-shared` (one 16-core
cpx62) and `regions-shared` (8-core cpx41 or cpx42, depending on the
location) use shared cores: rounds, bytes and signatures are the same,
timings are noisier.

On the single server, the 64 nodes of n = 64 share 48 cores. polaris
needs little of them, but n parallel WXSD at n = 64 may not finish its
rounds in 500 ms; if its runs report late messages, rerun that experiment
with `round_ms = 1000` or 2000 in its table.

## Latency

Hosts in one data center are a LAN, with well under a millisecond between
them. To measure polaris under wide-area latency, there are two ways:

- **Hosts in several regions.** For example, two VMs in each of four
  regions, with the round raised to hold the slowest one-way delay plus
  the work of a round: 500 ms is enough within a continent. Keep the order
  of the `[hosts]` list mixed across regions, so that each region holds
  nodes of every index.
- **Added delay on a LAN.** On every host, with its network interface in
  place of `eth0`:

  ```
  sudo tc qdisc add dev eth0 root netem delay 25ms      # 50 ms round trip
  sudo tc qdisc del dev eth0 root                        # to remove it
  ```

  This adds the delay to every packet the host sends, ssh included.

Whatever the setup, a run with late messages has rounds that are too short.
Raise `round_ms` in `[defaults]` until none arrive late: a late message
breaks the synchrony that every protocol here assumes.

## Notes

- Every run generates fresh keys. All the nodes' secret keys are copied to
  every host, which is fine for throwaway keys and nothing else.
- The launcher leaves each run's files in `~/polaris-eval/` on the hosts.
  Remove that directory between campaigns.
- The hosts run only honest nodes. Attacks are measured in the simulator,
  where rounds, bytes and signatures do not depend on the machine.
- `eval/test_hosts.py` runs the launcher's multi-host path on one machine,
  with two stand-in hosts, to check changes to the launcher itself.
