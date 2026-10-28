# Stage 7 Packet-Observation Configuration Manifest

## Purpose and boundary

The repeatability harness now records the experiment's **requested** mirror
configuration separately from OVS/Mininet/collector state read back at run
time. A run is allowed to proceed to reachability/workload traffic only after
the readback manifest passes its configuration gate. This is configuration
auditing, not packet observation, detection, or a network experiment.

This document defines the manifest emitted by a future authorized harness
run. No packet experiment was run to validate it in this task. The manifest
contains configuration and interface metadata only; it must never contain
packet bytes or payloads.

## Artifact location and schema

The runner writes one `configuration-manifest.json` into each run directory
under the selected `experiments/stage7-telemetry/` output directory. The file
is written after the topology, collector veth/namespace, and requested Mirror
row exist, but **before the harness sends reachability probes or starts the
scenario workload**.

The JSON Schema for the run artifact is
[`configuration-manifest.schema.json`](../../experiments/stage7-telemetry/packet-observation-repeatability-2026-10-09/configuration-manifest.schema.json).
It is stored beside the preserved B1 campaign directory because the
`experiments/stage7-telemetry/` parent is root-owned and not writable by the
unprivileged implementation process. No realized-state sample manifest was
created: there was no live topology to read, and inventing one would be
misleading. Future root-run harness invocations write actual manifests into
their individual run directories.

Top-level schema version 1:

```json
{
  "schema_version": 1,
  "record_type": "packet_observation_configuration_manifest",
  "experiment_id": "unique run ID",
  "captured_at": "UTC timestamp",
  "requested": {},
  "realized": {},
  "preflight": {
    "passed": false,
    "checks": [
      {"name": "check name", "passed": false,
       "expected": "requested value", "observed": "read-back value"}
    ]
  }
}
```

`requested` records the intended bridge, expected bridge-port set, Mirror
name, source selector and intended host, destination selector, VLAN selectors,
`select_all`, filter, output port/VLAN, snaplen, collector namespace and both
veth interface names. It also lists which Mirror values the runner explicitly
sets and which values it expects from the OVSDB schema defaults. That
distinction prevents a default expectation from being presented as a command
argument.

`realized` is populated only from readback. It contains:

- bridge name, UUID, Port UUIDs, and Mirror UUID references;
- each bridge Port name/UUID and its Interface UUIDs;
- each bridge Interface name/UUID/type/MAC/MAC-in-use/OpenFlow port number;
- all Mirror rows attached to the test bridge, including UUID, name, source
  and destination port references, VLAN selectors, `select_all`, filter,
  output port/VLAN, snaplen, statistics, and external IDs;
- readable source/destination/output port names alongside Mirror UUID
  references;
- the observed Mininet host interface and linked switch interface for h1,
  h2, and h3, correlated to OVS Port/Interface UUIDs and OpenFlow port numbers;
- collector namespace name/inode, host-side output interface state,
  namespace-side interface name/ifindex/MAC/state, IPv4 and IPv6 addresses,
  and separate IPv4 and IPv6 route tables.

The runner reads selected OVSDB columns with `ovs-vsctl --format=json list`
and normalizes OVSDB UUID, set, map, and optional-scalar encodings. It obtains
host-to-switch association from the active Mininet `Link` endpoints and then
joins the switch interface to the OVS Interface and Port rows. It does not
infer h1/h2/h3 mapping from a port name alone.

If readback fails, the runner writes a manifest with `realized: null` and a
failed `realized_configuration_readback` check. It then stops before the
reachability checks and scenario workload. It does not copy requested values
into `realized` to make the gate pass.

## Preflight gate

The pure preflight evaluates and records each check independently:

1. the expected bridge exists;
2. exactly one requested Mirror is attached to that bridge;
3. there is no additional Mirror on that bridge;
4. realized source and destination selections agree with the request;
5. the realized source port maps through the actual Mininet link to the
   intended host (currently the requested B1 design is h2 / `s1-eth2`);
6. output port and snaplen match the request;
7. the realized default/optional Mirror fields agree with the declared
   expected defaults;
8. the Mirror output Port contains only the expected host-side collector
   interface;
9. the collector interface is in the expected namespace;
10. the test bridge has only the expected Mininet, local bridge, and collector
    ports, with no unexpected observation output interface.

Any failed check stops the run. The failed manifest remains available for
audit, and cleanup runs through the existing `finally` path. This gate checks
configuration state; it cannot prove snaplen behavior or packet-path
behavior without a separately authorized experiment.

The collector namespace record reports IPv4 and IPv6 addresses/routes
separately. Empty IPv4 routes do not imply IPv6 isolation, and even an empty
IPv6 route list is only a snapshot of configured routes, not proof against
all kernel-level or privileged paths.

## Timing and traffic boundary

Ryu and the Mininet topology must be started before the actual OVSDB and link
state can be read. Link activation may cause operating-system or control-plane
traffic independently of the harness workload. The guarantee added here is
that the harness does not issue its explicit reachability probes or start the
scenario workload until the requested-versus-realized configuration manifest
has been persisted and passed. The manifest is not a claim that no background
frames can exist before that point.

The collector is started only after the configuration preflight passes. The
manifest is saved before collector evidence and scenario artifacts, allowing
the audit chain to be read as:

```text
requested configuration → independently read-back configuration → preflight
→ explicit reachability/workload traffic → collector metadata
```

## Validation status

The parser, manifest builder, and preflight comparisons have unit tests,
including mismatched source port, wrong snaplen, extra mirror, wrong collector
output, and readback failure. Static validation does not create a bridge,
namespace, interface, Mirror row, or traffic. The live readback path remains
unverified until a future separately authorized run records a manifest.

No detector, classifier, model inference, risk decision, mitigation, packet
capture, or payload collection is part of this manifest feature. Packet
observation remains unfrozen; this work does not authorize another experiment
or unfreeze the detector boundary.

## Stage 7H.1 privileged configuration-readback validation

### Read-only startup-path review

The repeatability runner has no configuration-only CLI mode. Its current
`_run_one()` path starts the Ryu controller, calls `create_network()` (which
builds and starts Mininet/OVS and configures the bridge), creates the collector
namespace and veth, adds the host veth to the bridge, and creates the requested
Mirror. It then calls `_write_configuration_manifest()` and evaluates the
preflight. The explicit reachability pings and scenario workload occur after
that preflight, but topology/controller setup itself is not demonstrated to
be traffic-free: the preserved B1 Ryu log contains PacketIn/forwarding events
during the setup/reachability interval. Therefore this task did not launch the
runner or start Mininet to obtain a manifest. No claim is made that topology
startup could be performed without packets.

### Privilege boundary and result

A narrowly scoped, noninteractive, read-only OVSDB query was attempted:

```text
sudo -n ovs-vsctl --format=json --columns=_uuid,name,ports,mirrors list Bridge
sudo -n ovs-vsctl --format=json --columns=_uuid,name,select_all,select_src_port,select_dst_port,select_vlan,filter,output_port,output_vlan,snaplen,statistics,external_ids list Mirror
```

Both commands stopped at sudo with `sudo: a password is required`; neither
reached `ovs-vsctl` and neither read the OVSDB socket. The earlier direct
unprivileged OVSDB query was also denied access to
`/var/run/openvswitch/db.sock`. No password prompt, privilege escalation, or
permission change was attempted. The exact available boundary is therefore:
the current process cannot read OVSDB, and noninteractive sudo is not
authorized. No actual Mirror row was read or recorded.

No configuration manifest was created. There is no live Mininet bridge,
collector namespace, or Mirror row available from the old B1 artifacts to
record. In particular, this task does not substitute the requested
`select_src_port`, output port, or snaplen into a realized section. The
h1/h2/h3 mapping, collector addresses/routes, and actual Mirror UUID/fields
remain unverified for a live configuration.

### Preflight outcome

The pure preflight is covered by unit tests for matching state, wrong source
selection, wrong snaplen, wrong host-to-port mapping, unexpected mirrors,
wrong collector output, and unavailable readback. A failed comparison returns
`passed: false`, and `_run_one()` raises before its explicit reachability and
scenario workload paths. The live gate has not been exercised against OVS.
Its position is after topology and Mirror setup, so it does not prevent
background/control-plane traffic that may arise during infrastructure
startup. It does prevent the harness's later explicit probes/workload when a
readback comparison fails.

### Validation and status

Targeted tests passed: 27 passed; the two privileged system tests were skipped
by default. Ruff passed. Targeted mypy passed for the changed harness/config
and test files. Repository-wide mypy retains the unchanged error at
`networking/ryu/stage2_controller.py:373` concerning an optional
`PacketEvidenceBudget`.

No live configuration readback succeeded, so no realized-state fields are
reported as validated. No network state changed, no traffic or packets were
generated, and no raw packet data or capture was created. Packet observation
remains unfrozen. A future configuration-only validation still requires an
already-authorized narrow read-only OVSDB access path and an initialization
method whose traffic behavior is understood; this task did not add a sudo
rule, alter permissions, create a Mirror, or start that infrastructure.

## Stage 7H.2 standalone read-only auditor

### Behavior

`scripts/audit_stage7_packet_observation_config.py` is a standalone inventory
command. It does not import or invoke the repeatability runner, Mininet
topology startup, Ryu startup, collector setup, Mirror creation, traffic
generators, or reachability checks. Its commands are limited to read-only
`ovs-vsctl --format=json ... list` requests and `ip` namespace, link,
address, and route queries. It never invokes `sudo` or requests credentials.

The auditor records each command, return code, state, and sanitized error.
OVSDB rows are resolved through returned UUID references; requested settings,
when supplied, remain separate from observed state. `NOT_PRESENT`,
`NOT_ACCESSIBLE`, `NOT_APPLICABLE`, and `UNAVAILABLE` remain distinct.
`AUDIT_COMPLETE` means the required live state was verified;
`CONFIGURATION_MISMATCH` means readable state conflicts with an explicit
request; `AUDIT_INCOMPLETE` means a required read or live mapping is
inaccessible/unavailable. Non-complete results have no realized-state
manifest, and the CLI exits nonzero.

The auditor does not infer Mininet host-to-switch mappings from interface
names. A direct mapping requires a currently running topology source; this
standalone auditor does not start one. Collector state is queried only when
its namespace already exists. A successful configuration inventory would
not validate packet truncation, packet delivery, coverage, or forwarding.

### Tests and live invocation

Unit tests cover bridge/port/interface and Mirror UUID resolution, absent
Mirror, OVSDB permission denial, missing collector namespace/interface,
unavailable Mininet mapping, requested/observed mismatch, nonzero incomplete
exit, no manifest output when required readback fails, and the read-only
command boundary. These tests validate mocked behavior only; they do not
establish live OVS access.

One unprivileged live invocation was performed on 2026-10-13:

```text
.venv/bin/python scripts/audit_stage7_packet_observation_config.py
```

It returned exit code 2 (`AUDIT_INCOMPLETE`). The four read-only OVSDB table
requests (`Bridge`, `Port`, `Interface`, and `Mirror`) each exited with code 1
and the sanitized error `permission denied accessing the requested state`.
No OVSDB rows were observed. The `s7collector` namespace was observed as
`NOT_PRESENT`. No requested configuration was supplied, so Mininet mapping
was `NOT_APPLICABLE`; no host-to-port mapping was claimed. The manifest was
null and no manifest file was created.

This live result validates fail-closed handling of the permission boundary
only. It does not validate parsing against live OVSDB rows, collector
addresses/routes, or Mininet host mappings. No privilege escalation was
attempted. No services, topology, or network objects were started or changed;
no packets, packet bytes, or captures were created. Packet observation
remains unfrozen, and detector implementation remains blocked.

Final validation for H.2: the focused auditor/configuration tests passed
(14); the full suite passed (217 passed, 2 privileged tests skipped); Ruff
passed; targeted mypy passed for the four changed Python files. The 24 files
listed in the Stage 5A raw inventory and all 7 Stage 5D prepared files
matched their recorded SHA-256 values. The Stage 5F JSON/Markdown and Stage 7
JSON/Markdown protocol hashes also remained unchanged. These checks do not
change the live-readback limitation above.
