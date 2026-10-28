# Stage 2 SDN Control-Plane Architecture

## Purpose and boundary

Stage 2 validates a small local SDN control plane. It provides Mininet topology creation, Open vSwitch integration, an OpenFlow 1.3 Ryu controller, basic observation, and one reversible explicitly enabled forwarding test rule.

It does not implement intrusion detection, anomaly detection, ML, GraphSAGE, SHAP, GNNExplainer, risk scoring, automatic mitigation, quarantine, traffic blocking, dashboard UI, hardware integration, or external-network activity.

## Local topology

    h1 (client)      10.0.0.1 / 02:00:00:00:00:01
         \
          s1 (Open vSwitch, OpenFlow 1.3) ---- h3 (server) 10.0.0.3 / 02:00:00:00:00:03
         /
    h2 (test host)   10.0.0.2 / 02:00:00:00:00:02

The topology is local to Mininet. It has no Internet-facing links. s1 uses OpenFlow13 and connects to an external Ryu controller at 127.0.0.1:6653 by default. Configuration is read from SDN_STAGE2_* environment variables.

## Components and ownership

| Component | Location | Responsibility |
| --- | --- | --- |
| Topology adapter | networking/mininet/stage2_topology.py | Defines and starts the deterministic Mininet/OVS topology. |
| Controller adapter | networking/ryu/stage2_controller.py | Accepts OpenFlow 1.3 switches, handles features and packet-in events, observes port/flow statistics, and manages the explicit test rule. |
| Controller configuration | networking/ryu/config.py | Reads controller observation and test-rule settings. |
| Validation harness | networking/ryu/validate_stage2.py | Root-required local integration validation; starts only the components it stops. |
| Shared contracts | src/sdn_defense/ | Remain independent of Mininet and Ryu. |

## Ryu and OVS relationship

Ryu runs as the OpenFlow controller; OVS is the virtual switch. On switch features, Ryu installs a table-miss rule that sends unmatched frames to the controller. It supplies basic L2 learning so local hosts can communicate, requests port descriptions and flow statistics, and writes structured log records containing UTC timestamp, datapath ID, event type, ports where relevant, and flow counters where relevant.

The controller stores only basic in-memory MAC-to-port learning state. It has no detection or mitigation policy.

## Explicit reversible test rule

Only when SDN_STAGE2_INSTALL_TEST_RULE=true, Ryu installs one OpenFlow 1.3 rule:

- match: IPv4 TCP 10.0.0.1 to 10.0.0.3, destination port 18080;
- action: output to port 3, which is h3 in this fixed topology;
- priority: 100;
- cookie: 0x534432;
- expiry: configurable idle timeout, default 120 seconds;
- reason: explicit_stage2_h1_to_h3_tcp_test.

This is a test-only forwarding rule. It is enabled explicitly, has a finite idle timeout, and is removed by the controller during clean shutdown. It does not block, rate-limit, quarantine, or classify traffic.

## Fedora prerequisites

Install system packages (the Fedora package query used for this stage found OVS and Mininet; it did not find a python3-ryu RPM):

    sudo dnf install openvswitch mininet python3-pip
    sudo systemctl enable --now openvswitch

Install repository development tools in a Python environment (the system Python must provide Mininet imports for the root-required test):

    python3.11 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e '.[dev]'

Install Ryu into a separate Python 3.11 environment using [the reproducible Ryu runtime setup](ryu-runtime-setup.md):

    scripts/setup_ryu_stage2.sh
    scripts/setup_ryu_stage2.sh --check

The isolated setup uses Ryu 4.34 from upstream commit `d6cda4f427ff8de82b94c58aa826824a106014c2`, without modifying upstream source. PyPI installation fails because the legacy setup hook calls the removed `setuptools.command.easy_install.get_script_args` API. The exact build/runtime dependency pins, `.pth` import mechanism, and launcher are recorded in `scripts/`. Eventlet emits a known deprecation warning.

Verify the local control-plane dependencies:

    command -v mn ovs-vsctl ovs-ofctl
    sudo systemctl is-active openvswitch
    ovs-vsctl --version
    mn --version
    .venv-ryu/bin/ryu-manager --version
Mininet and Ryu run in separate environments here: the root-run system Python imports Fedora's Mininet package, while the controller executable comes from .venv-ryu. The validation harness accepts the controller executable through SDN_STAGE2_RYU_MANAGER or --ryu-manager.

    /usr/bin/python3 -c 'import mininet; print("Mininet import available")'
    .venv-ryu/bin/python -c 'import ryu; print("Ryu import available")'

## Startup, verification, and shutdown

Terminal 1 starts Ryu with the test rule disabled:

    EVENTLET_NO_GREENDNS=yes .venv-ryu/bin/ryu-manager --ofp-tcp-listen-port 6653 networking/ryu/stage2_controller.py

Terminal 2 starts Mininet:

    sudo env PYTHONPATH="$PWD" /usr/bin/python3 -m networking.mininet.stage2_topology

From the Mininet CLI, verify local connectivity and bridge state:

    mininet> pingall
    mininet> sh ovs-vsctl list bridge s1
    mininet> sh ovs-vsctl br-exists s1
    mininet> sh ovs-vsctl get bridge s1 protocols
    mininet> sh ovs-vsctl get-controller s1
    mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
    mininet> exit

After exit, the topology process calls network.stop(). Stop Ryu with Ctrl+C. If a previous Mininet run was interrupted, clean only the local Mininet state before retrying:

    sudo mn -c

## Reproducible validation procedure

Run the root-required local validation only after prerequisites are active:

    RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
    sudo env \
      PATH="$PWD/.venv-ryu/bin:$PATH" \
      PYTHONPATH="$RYU_SOURCE_DIR:$PWD" \
      SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
      /usr/bin/python3 -m networking.ryu.validate_stage2 \
      --log-file /tmp/stage2-ryu.log

The harness starts Ryu with the explicit test rule enabled, starts Mininet, checks h1 to h3 reachability, sends a local TCP/18080 probe, verifies the rule and its packet counter in OVS, verifies Ryu feature and flow-statistics log events, then stops the network and controller. `sudo` must receive the controller executable and import paths; without them, the root process cannot import Ryu. The validated log is a temporary local artifact at `/tmp/stage2-ryu.log`.

Stage 2 passed on Fedora using Python 3.11, Mininet 2.3.1b4, Open vSwitch 3.6.2, and Ryu 4.34 from the pinned upstream commit. The OVS switch connected to Ryu using OpenFlow 1.3, and bidirectional h1↔h3 forwarding completed with 0% packet loss. This is infrastructure validation only, not a security or research result.

## Python 3 compatibility note

The normal PyPI setup hook failure is the reason for the pinned source-based runtime. The upstream source remains unmodified; dependency compatibility is handled in `.venv-ryu`. The Stage 2 integration harness has been executed successfully in the Fedora environment described above. This controller foundation does not implement attacks, detection, ML, automatic mitigation, dashboard, or hardware behavior.
