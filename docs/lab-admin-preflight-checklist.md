# Administrator checklist for the isolated live SDN lab

The current preflight is blocked because the application user cannot inspect the active system OVS
database. Do not run the Mininet topology, Ryu controller, validation runner, traffic generators, or
mitigation until every item below has been reviewed.

## Read-only host inspection

Run these on the intended lab host and retain the output for review:

```bash
sudo ovs-vsctl show
sudo ovs-vsctl list-br
ip -brief link
ss -ltnp | grep -E ':(6653)\b' || true
```

Identify each bridge and port owner. Do not stop the shared OVS service, remove bridges, alter
interfaces, change firewall rules, or detach ports as part of this checklist. If a bridge contains a
physical, Wi-Fi, VM, Docker, management, or otherwise unexplained interface, this host is not cleared
for the lab.

## Required isolation evidence

- Use a dedicated authorized lab machine/VM or a separately managed OVS instance whose bridge and
  port scope is under the operator's control.
- Verify the Stage 2 topology creates only `h1`, `h2`, `h3`, and `s1`, uses no host uplink, and points
  Ryu at `127.0.0.1:6653`.
- Confirm no pre-existing `s1` bridge, no listener on TCP 6653, and no unrelated OVS bridge that the
  Mininet process could affect.
- Confirm Ryu 4.34, Mininet, OVS, OpenFlow 1.3, Python dependency availability, and bounded runner
  cleanup requirements on the intended privileged interpreter.
- Ensure `var/runtime/ryu-status.json` can be atomically written by the Ryu process and read by the
  unprivileged API. The file contains only controller/datapath IDs, epochs, PID, version, and health
  timestamps; do not store credentials or packet data there.
- Decide and document an approved maximum-gap value and collection protocol before treating windows
  as eligible data. The code's 30-second default is an engineering default, not a research result.

After this review, run the read-only gate in the intended environment:

```bash
sudo .venv/bin/python scripts/preflight_stage7_lab.py --ack-isolated-lab
```

Proceed only if it exits `0` and reports `PASS`. An explicit acknowledgment does not override any
failed check. The next authorized command is a fresh, benign-only collection using
`scripts/run_stage7_rule_counter_validation.py` with a new output directory. Re-audit its telemetry
and require source-verified complete pairs before considering any attack-labeled data. Attack
experiments require their own bounded target/rate/duration review and must remain within the isolated
topology. Mitigation requires a separate enforcement/verification/rollback approval and remains
disabled in this application.
