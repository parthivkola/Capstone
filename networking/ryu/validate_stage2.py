"""Root-required Stage 2 local-control-plane validation script.

It starts Ryu, creates the deterministic Mininet topology, validates local forwarding,
checks the explicit reversible TCP/18080 test rule, and stops everything it starts.
It must run only on an isolated development host with Mininet and OVS installed.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import sys
from argparse import ArgumentParser
from pathlib import Path
from subprocess import DEVNULL, STDOUT, Popen, run
from tempfile import NamedTemporaryFile
from time import monotonic, sleep
from typing import Any, NoReturn

from networking.mininet.config import TopologyConfig

REQUIRED_COMMANDS = ("mn", "ovs-vsctl", "ovs-ofctl")
TEST_RULE_COOKIE = "534432"
TEST_TCP_PORT = 18080


def fail(message: str) -> NoReturn:
    """End validation with an actionable prerequisite or assertion failure."""

    raise RuntimeError(message)


def verify_prerequisites(ryu_manager: str) -> None:
    """Validate that this is an authorised local Mininet/OVS environment."""

    if os.geteuid() != 0:
        fail("Stage 2 validation requires root: run with sudo in an isolated local environment.")
    missing = [command for command in REQUIRED_COMMANDS if shutil.which(command) is None]
    if shutil.which(ryu_manager) is None:
        missing.append(ryu_manager)
    if missing:
        fail(f"Missing required commands: {', '.join(missing)}")
    service = run(
        ["systemctl", "is-active", "--quiet", "openvswitch"],
        check=False,
        stdout=DEVNULL,
        stderr=DEVNULL,
    )
    if service.returncode != 0:
        fail(
            "openvswitch service is not active; start it with: "
            "sudo systemctl enable --now openvswitch"
        )


def wait_for_controller(host: str, port: int, timeout_seconds: float) -> None:
    """Wait until the locally started Ryu listener accepts a TCP connection."""

    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            sleep(0.25)
    fail(f"Ryu did not listen on {host}:{port} within {timeout_seconds} seconds")


def run_host_tcp_test(network: Any) -> None:
    """Send one explicit local h1-to-h3 TCP/18080 request through the test rule."""

    h1 = network.get("h1")
    h3 = network.get("h3")
    server_program = (
        "import socket; "
        "server=socket.socket(); server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
        "server.bind(('10.0.0.3', 18080)); server.listen(1); "
        "connection,_=server.accept(); connection.recv(16); connection.sendall(b'ok'); "
        "connection.close(); server.close()"
    )
    server = h3.popen(["python3", "-c", server_program])
    sleep(0.5)
    client_program = (
        "import socket; "
        "client=socket.create_connection(('10.0.0.3', 18080), timeout=3); "
        "client.sendall(b'probe'); response=client.recv(2); client.close(); "
        "assert response == b'ok'"
    )
    client_status = h1.cmd(f"python3 -c {client_program!r}").strip()
    server.wait(timeout=5)
    if client_status:
        fail(f"Explicit TCP test flow failed: {client_status}")


def bridge_flow_dump() -> str:
    """Return the OpenFlow 1.3 flow dump for the isolated s1 bridge."""

    result = run(
        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"Unable to dump s1 flows: {result.stderr.strip()}")
    return result.stdout


def verify_test_rule_effect(flow_dump: str) -> None:
    """Verify that OVS retained and counted the explicit test-rule traffic."""

    matching_lines = [
        line
        for line in flow_dump.splitlines()
        if re.search(rf"cookie=0x0*{TEST_RULE_COOKIE}\b", line)
        and f"tp_dst={TEST_TCP_PORT}" in line
    ]
    if len(matching_lines) != 1:
        fail("Expected exactly one explicit Stage 2 TCP/18080 rule in s1.")
    packet_count = re.search(r"n_packets=(\d+)", matching_lines[0])
    if packet_count is None or int(packet_count.group(1)) < 1:
        fail("The explicit Stage 2 test rule did not observe any packets.")


def verify_test_rule_removed(flow_dump: str) -> None:
    """Require that the explicit rule was deleted during graceful controller stop."""

    if re.search(rf"cookie=0x0*{TEST_RULE_COOKIE}\b", flow_dump):
        fail("The explicit Stage 2 test rule remained installed after controller shutdown.")


def verify_controller_log(log_path: Path) -> None:
    """Require Ryu evidence of switch features and flow-statistics observation."""

    content = log_path.read_text(encoding="utf-8")
    required_events = (
        "switch_features_received",
        "flow_statistics_reply",
        "explicit_test_rule_removed",
    )
    missing = [event for event in required_events if event not in content]
    if missing:
        fail(f"Ryu log did not contain required events: {', '.join(missing)}")


def main() -> None:
    """Execute the local-only Stage 2 control-plane validation sequence."""

    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--controller-host", default="127.0.0.1")
    parser.add_argument("--controller-port", default=6653, type=int)
    parser.add_argument("--log-file", type=Path)
    parser.add_argument(
        "--ryu-manager",
        default=os.environ.get("SDN_STAGE2_RYU_MANAGER", "ryu-manager"),
    )
    arguments = parser.parse_args()
    verify_prerequisites(arguments.ryu_manager)

    log_file = arguments.log_file
    temporary_log: Any | None = None
    if log_file is None:
        with NamedTemporaryFile(prefix="stage2-ryu-", suffix=".log", delete=False) as stream:
            temporary_log = stream.name
        log_file = Path(temporary_log)

    environment = {
        **os.environ,
        "SDN_STAGE2_INSTALL_TEST_RULE": "true",
        "SDN_STAGE2_MONITOR_INTERVAL_SECONDS": "1.0",
        "SDN_STAGE2_TEST_RULE_EGRESS_PORT": "3",
        "PYTHONPATH": os.pathsep.join(
            filter(
                None,
                (
                    str(Path(__file__).resolve().parents[2]),
                    os.environ.get("PYTHONPATH", ""),
                ),
            )
        ),
    }
    log_stream = log_file.open("w", encoding="utf-8")
    controller = Popen(
        [
            arguments.ryu_manager,
            "--ofp-tcp-listen-port",
            str(arguments.controller_port),
            "networking/ryu/stage2_controller.py",
        ],
        env=environment,
        stdout=log_stream,
        stderr=STDOUT,
        text=True,
    )
    network: Any | None = None
    try:
        wait_for_controller(arguments.controller_host, arguments.controller_port, 15)
        from networking.mininet.stage2_topology import create_network

        network = create_network(
            TopologyConfig(
                controller_host=arguments.controller_host,
                controller_port=arguments.controller_port,
            )
        )
        if network.ping([network.get("h1"), network.get("h3")]) != 0:
            fail("h1 and h3 could not communicate through s1.")
        run_host_tcp_test(network)
        sleep(2)
        verify_test_rule_effect(bridge_flow_dump())
        controller.send_signal(2)  # SIGINT follows the same graceful path as Ctrl+C.
        controller.wait(timeout=10)
        verify_test_rule_removed(bridge_flow_dump())
    finally:
        if network is not None:
            network.stop()
        if controller.poll() is None:
            controller.terminate()
            try:
                controller.wait(timeout=10)
            except TimeoutError:
                controller.kill()
                controller.wait(timeout=5)
        log_stream.close()

    verify_controller_log(log_file)
    print(f"Stage 2 validation passed. Ryu structured log: {log_file}")
    if temporary_log is not None:
        print("The log is temporary; rerun with --log-file to retain it.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"Stage 2 validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
