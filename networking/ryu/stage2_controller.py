"""Stage 2 OpenFlow 1.3 observation controller.

The app provides basic learning-switch forwarding, switch/port/flow observation, and
one optional explicit test rule. It implements no intrusion detection, risk scoring,
automatic mitigation, or attack behaviour.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime
from typing import Any

from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib.packet import arp, ether_types, ethernet, ipv4, packet, tcp, udp
from ryu.ofproto import ofproto_v1_3

from networking.ryu.config import ControllerConfig
from networking.ryu.packet_evidence import PacketEvidenceBudget, PacketEvidencePolicy
from networking.ryu.structured_events import (
    MonotonicUtcClock,
    flow_statistics_log_details,
    run_start_timestamp,
    stage2_event,
)
from src.sdn_defense.controller_status import ControllerStatusPublisher
from src.sdn_defense.telemetry import (
    OBSERVATION_PROVENANCE_VERSION,
    CounterDeltaEngine,
    ObservationType,
    TelemetryObservation,
    TelemetryScope,
    flow_snapshot_from_observation,
    read_experiment_context,
)
from src.sdn_defense.telemetry_io import (
    DatapathEpoch,
    DatapathEpochTracker,
    MultipartFlowStatsAssembler,
    TelemetryJsonlRecorder,
)


class Stage2Controller(app_manager.RyuApp):
    """Ryu adapter for the controlled Stage 2 topology."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialise observation state without enabling the test rule by default."""

        super().__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.config = ControllerConfig.from_environment()
        self.config.validate()
        self._event_clock = MonotonicUtcClock()
        self._run_context_lock = threading.RLock()
        self.datapaths: dict[int, Any] = {}
        self._datapath_epochs = DatapathEpochTracker()
        self._status_publisher = ControllerStatusPublisher(self.config.status_file)
        self._recorded_epoch_ids: set[str] = set()
        self.mac_to_port: dict[int, dict[str, int]] = {}
        self._multipart = MultipartFlowStatsAssembler()
        self._counter_deltas = CounterDeltaEngine(
            maximum_gap_seconds=self.config.maximum_feature_gap_seconds
        )
        self._active_run_id: str | None = None
        self._active_run_metadata: dict[str, object] | None = None
        self._packet_evidence_policy = PacketEvidencePolicy(
            max_observations_per_second=self.config.packet_evidence_max_per_second,
            max_observations_per_run=self.config.packet_evidence_max_per_run,
        )
        self._packet_evidence_budget = (
            PacketEvidenceBudget(self._packet_evidence_policy)
            if self.config.packet_evidence_enabled
            else None
        )
        self._packet_evidence_datapaths: set[int] = set()
        self._recorder = (
            TelemetryJsonlRecorder(self.config.telemetry_jsonl, source_version="ryu-stage2-v1")
            if self.config.telemetry_jsonl is not None
            else None
        )
        self._run_recorder: TelemetryJsonlRecorder | None = None
        self._monitor_thread = hub.spawn(self._monitor)
        self._publish_controller_status()
        self._log("controller_started", openflow_version="1.3")

    def _log(self, event_type: str, datapath_id: int | None = None, **details: Any) -> None:
        """Write one parseable structured controller event."""

        self.logger.info(
            "stage2_event=%s",
            json.dumps(stage2_event(event_type, datapath_id, **details), sort_keys=True),
        )

    def _observe_datapath_connection(self, datapath: Any, *, source: str) -> DatapathEpoch:
        """Create or retrieve an epoch from an observed Ryu connection object."""

        self._current_run_id()
        now = self._event_clock.now()
        result = self._datapath_epochs.connect(
            datapath.id,
            datapath,
            observed_at=now,
            observed_monotonic_ns=time.monotonic_ns(),
        )
        if result.replaced_epoch is not None:
            old_epoch = result.replaced_epoch
            self.mac_to_port.pop(datapath.id, None)
            self._packet_evidence_datapaths.discard(datapath.id)
            for incomplete in self._multipart.disconnect(
                datapath.id,
                reason="datapath_replaced_before_disconnect",
                terminal_state="AMBIGUOUS",
            ):
                self._write_record("incomplete_collection", timestamp=now.isoformat(), **incomplete)
            self._write_connection_epoch_boundary(
                state="ambiguous",
                datapath_id=datapath.id,
                epoch=old_epoch,
                timestamp=now,
                source="replacement_observed",
            )
            for window in self._counter_deltas.datapath_disconnected(
                f"{datapath.id:016x}", observed_at=now, collector_monotonic_ns=time.monotonic_ns()
            ):
                self._write_record("observation_window", observation_window=window.to_dict())
        if result.replaced_epoch is None and self._datapaths_epoch_already_recorded(result.epoch):
            return result.epoch
        epoch_state = "connected" if result.epoch.state == "ACTIVE" else "ambiguous"
        self._write_connection_epoch_boundary(
            state=epoch_state,
            datapath_id=datapath.id,
            epoch=result.epoch,
            timestamp=now,
            source=(
                source
                if epoch_state == "connected"
                else "reused_datapath_object_ambiguous_lifecycle"
            ),
        )
        self._publish_controller_status()
        return result.epoch

    def _publish_controller_status(self) -> None:
        """Publish only active datapaths observed in the current Ryu connection epoch."""

        active: list[dict[str, str]] = []
        for datapath_id, datapath in tuple(self.datapaths.items()):
            epoch = self._datapath_epochs.active_epoch(datapath_id)
            if epoch is None or self._datapath_epochs.epoch_for_connection(
                datapath_id, datapath
            ) != epoch:
                continue
            active.append({"datapath_id": f"{datapath_id:016x}", "epoch_id": epoch.epoch_id})
        try:
            self._status_publisher.publish(
                controller_instance_id=self._datapath_epochs.controller_instance_id,
                datapaths=active,
                openflow_version="1.3",
            )
        except OSError as error:
            self.logger.warning("controller status publication failed: %s", type(error).__name__)

    def _datapaths_epoch_already_recorded(self, epoch: DatapathEpoch) -> bool:
        return epoch.epoch_id in self._recorded_epoch_ids

    def _write_connection_epoch_boundary(
        self,
        *,
        state: str,
        datapath_id: int | None,
        epoch: DatapathEpoch | None,
        timestamp: datetime,
        source: str,
        affected_epoch_ids: list[str] | None = None,
    ) -> None:
        fields: dict[str, object] = {
            "timestamp": timestamp.isoformat(),
            "datapath_id": None if datapath_id is None else f"{datapath_id:016x}",
            "datapath_epoch_id": None if epoch is None else epoch.epoch_id,
            "epoch_sequence": None if epoch is None else epoch.sequence,
            "controller_instance_id": self._datapath_epochs.controller_instance_id,
            "state": state,
            "lifecycle_source": source,
            "run_id": self._current_run_id(),
        }
        if affected_epoch_ids is not None:
            fields["affected_epoch_ids"] = affected_epoch_ids
        if epoch is not None:
            fields["connected_at"] = epoch.connected_at.isoformat()
            fields["connected_monotonic_ns"] = epoch.connected_monotonic_ns
            if state == "connected":
                self._recorded_epoch_ids.add(epoch.epoch_id)
        self._log(
            "connection_epoch_boundary",
            datapath_id,
            datapath_epoch_id=None if epoch is None else epoch.epoch_id,
            epoch_sequence=None if epoch is None else epoch.sequence,
            controller_instance_id=self._datapath_epochs.controller_instance_id,
            state=state,
            lifecycle_source=source,
            affected_epoch_ids=affected_epoch_ids,
        )
        self._write_record("connection_boundary", **fields)

    @handler.set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def datapath_state_change_handler(self, event: Any) -> None:
        """Track connected and disconnected OpenFlow datapaths."""

        datapath = event.datapath
        if event.state == MAIN_DISPATCHER:
            self._observe_datapath_connection(datapath, source="ryu_main_dispatcher")
            self.datapaths[datapath.id] = datapath
            self._publish_controller_status()
            self._log("datapath_connected", datapath.id, address=str(datapath.address))
        elif event.state == DEAD_DISPATCHER:
            self._current_run_id()
            now = self._event_clock.now()
            datapath_id = getattr(datapath, "id", None)
            if datapath_id is None:
                # Unknown disconnect invalidates every active connection/collection.
                invalidated_epochs = self._datapath_epochs.invalidate_all()
                for incomplete in self._multipart.invalidate_all(
                    reason="unidentified_disconnect_invalidated_active_collection"
                ):
                    self._write_record(
                        "incomplete_collection", timestamp=now.isoformat(), **incomplete
                    )
                for current_id, _datapath in tuple(self.datapaths.items()):
                    for window in self._counter_deltas.datapath_disconnected(
                        f"{current_id:016x}",
                        observed_at=now,
                        collector_monotonic_ns=time.monotonic_ns(),
                    ):
                        self._write_record(
                            "observation_window", observation_window=window.to_dict()
                        )
                self.datapaths.clear()
                self.mac_to_port.clear()
                self._packet_evidence_datapaths.clear()
                self._log("datapath_disconnected", reason="datapath_id_unavailable")
                self._write_connection_epoch_boundary(
                    state="ambiguous_global_disconnect",
                    datapath_id=None,
                    epoch=None,
                    timestamp=now,
                    source="ryu_dead_dispatcher_without_datapath_id",
                    affected_epoch_ids=[epoch.epoch_id for epoch in invalidated_epochs],
                )
                self._publish_controller_status()
                return
            closed_epoch = self._datapath_epochs.disconnect(datapath_id, datapath)
            active_epoch = self._datapath_epochs.active_epoch(datapath_id)
            if (
                closed_epoch is not None
                and active_epoch is not None
                and active_epoch.epoch_id != closed_epoch.epoch_id
            ):
                affected = self._multipart.invalidate_epoch(
                    datapath_id,
                    closed_epoch.epoch_id,
                    reason="stale_connection_disconnect",
                )
            else:
                affected = self._multipart.disconnect(datapath_id)
            for incomplete in affected:
                self._write_record("incomplete_collection", timestamp=now.isoformat(), **incomplete)
            if active_epoch is None:
                for window in self._counter_deltas.datapath_disconnected(
                    f"{datapath_id:016x}",
                    observed_at=now,
                    collector_monotonic_ns=time.monotonic_ns(),
                ):
                    self._write_record("observation_window", observation_window=window.to_dict())
            if self.datapaths.get(datapath_id) is datapath:
                self.datapaths.pop(datapath_id, None)
                self.mac_to_port.pop(datapath_id, None)
                self._packet_evidence_datapaths.discard(datapath_id)
            self._log("datapath_disconnected", datapath_id)
            self._write_connection_epoch_boundary(
                state="disconnected"
                if closed_epoch is not None and closed_epoch.state == "CLOSED"
                else "ambiguous",
                datapath_id=datapath_id,
                epoch=closed_epoch,
                timestamp=now,
                source="ryu_dead_dispatcher",
            )
            self._publish_controller_status()

    @handler.set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, event: Any) -> None:
        """Install table-miss forwarding and request initial switch observations."""

        datapath = event.msg.datapath
        self._observe_datapath_connection(datapath, source="ryu_switch_features")
        self.datapaths[datapath.id] = datapath
        self._publish_controller_status()
        self.mac_to_port.setdefault(datapath.id, {})
        self._install_table_miss(datapath)
        self._request_port_descriptions(datapath)
        self._request_flow_statistics(datapath)
        if self.config.packet_evidence_enabled:
            self._install_packet_evidence_rules(datapath)
        self._log("switch_features_received", datapath.id)

        if self.config.install_explicit_test_rule:
            self.install_explicit_test_rule(datapath)

    def _install_table_miss(self, datapath: Any) -> None:
        """Send unmatched packets to this controller for basic learning forwarding."""

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            actions=actions,
            reason="table_miss_to_controller",
        )

    def _add_flow(
        self,
        datapath: Any,
        priority: int,
        match: Any,
        actions: list[Any],
        reason: str,
        cookie: int = 0,
        idle_timeout: int = 0,
    ) -> None:
        """Install a forwarding rule and record its explicit controller reason."""

        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        request = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            priority=priority,
            idle_timeout=idle_timeout,
            match=match,
            instructions=instructions,
        )
        datapath.send_msg(request)
        self._log(
            "flow_rule_installed",
            datapath.id,
            reason=reason,
            priority=priority,
            cookie=f"0x{cookie:x}",
            idle_timeout_seconds=idle_timeout,
        )

    def install_explicit_test_rule(self, datapath: Any) -> None:
        """Install the reversible h1-to-h3 TCP/18080 forwarding test rule.

        The rule is enabled only by SDN_STAGE2_INSTALL_TEST_RULE=true. It does not
        classify, block, quarantine, or rate-limit traffic.
        """

        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.config.test_rule_source_ip,
            ipv4_dst=self.config.test_rule_destination_ip,
            ip_proto=6,
            tcp_dst=self.config.test_rule_tcp_port,
        )
        actions = [parser.OFPActionOutput(self.config.test_rule_egress_port)]
        self._add_flow(
            datapath=datapath,
            priority=self.config.test_rule_priority,
            match=match,
            actions=actions,
            reason="explicit_stage2_h1_to_h3_tcp_test",
            cookie=self.config.test_rule_cookie,
            idle_timeout=self.config.test_rule_idle_timeout_seconds,
        )

    def remove_explicit_test_rule(self, datapath: Any) -> None:
        """Remove the explicit test rule by cookie and exact match."""

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=self.config.test_rule_source_ip,
            ipv4_dst=self.config.test_rule_destination_ip,
            ip_proto=6,
            tcp_dst=self.config.test_rule_tcp_port,
        )
        request = parser.OFPFlowMod(
            datapath=datapath,
            cookie=self.config.test_rule_cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=0,
            command=ofproto.OFPFC_DELETE_STRICT,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=self.config.test_rule_priority,
            match=match,
        )
        datapath.send_msg(request)
        self._log(
            "explicit_test_rule_removed",
            datapath.id,
            cookie=f"0x{self.config.test_rule_cookie:x}",
        )

    def _install_packet_evidence_rules(self, datapath: Any) -> None:
        """Copy fixed-scope TCP headers while outputting originals to h3."""

        if datapath.id in self._packet_evidence_datapaths:
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        policy = self._packet_evidence_policy
        for destination_port in policy.destination_ports:
            match = parser.OFPMatch(
                in_port=policy.ingress_port,
                eth_type=0x0800,
                ip_proto=6,
                ipv4_src=policy.source_ip,
                ipv4_dst=policy.destination_ip,
                tcp_dst=destination_port,
            )
            actions = [
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, policy.controller_copy_max_bytes),
                parser.OFPActionOutput(policy.egress_port),
            ]
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            request = parser.OFPFlowMod(
                datapath=datapath,
                cookie=policy.flow_cookie,
                table_id=0,
                command=ofproto.OFPFC_ADD,
                idle_timeout=0,
                hard_timeout=policy.flow_hard_timeout_seconds,
                priority=policy.flow_priority,
                flags=0,
                match=match,
                instructions=instructions,
            )
            datapath.send_msg(request)
            self._log(
                "packet_evidence_rule_submitted",
                datapath.id,
                cookie=f"0x{policy.flow_cookie:x}",
                source_ip=policy.source_ip,
                destination_ip=policy.destination_ip,
                destination_port=destination_port,
                ingress_port=policy.ingress_port,
                egress_port=policy.egress_port,
                controller_copy_max_bytes=policy.controller_copy_max_bytes,
                hard_timeout_seconds=policy.flow_hard_timeout_seconds,
            )
        self._packet_evidence_datapaths.add(datapath.id)

    def _remove_packet_evidence_rules(self, datapath: Any) -> None:
        """Delete only rules carrying the packet-evidence cookie."""

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        request = parser.OFPFlowMod(
            datapath=datapath,
            cookie=self._packet_evidence_policy.flow_cookie,
            cookie_mask=0xFFFFFFFFFFFFFFFF,
            table_id=0,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(request)
        self._packet_evidence_datapaths.discard(datapath.id)
        self._log(
            "packet_evidence_rules_delete_submitted",
            datapath.id,
            cookie=f"0x{self._packet_evidence_policy.flow_cookie:x}",
        )

    @handler.set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event: Any) -> None:
        """Perform basic L2 learning only for unmatched local topology traffic."""

        message = event.msg
        datapath = message.datapath
        run_id = self._current_run_id()
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        ingress_port = message.match["in_port"]
        frame = packet.Packet(message.data)
        header = frame.get_protocol(ethernet.ethernet)
        if header is None or header.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        is_packet_evidence_copy = (
            self.config.packet_evidence_enabled
            and int(getattr(message, "reason", -1)) == ofproto.OFPR_ACTION
            and int(getattr(message, "cookie", -1)) == self._packet_evidence_policy.flow_cookie
        )
        if is_packet_evidence_copy:
            # The OpenFlow action list already copied this frame to Ryu and sent
            # the original to the fixed h3 port. Learn the source for return-path
            # forwarding, but never send a second packet from this PacketIn.
            self.mac_to_port.setdefault(datapath.id, {})[header.src] = ingress_port
            observed_at = self._event_clock.now()
            collector_monotonic_ns = time.monotonic_ns()
            budget = self._packet_evidence_budget
            accepted = budget is not None and budget.offer(run_id, collector_monotonic_ns)
            if accepted and budget is not None and self.config.record_packetin_telemetry:
                self._record_packet_observation(
                    frame,
                    datapath.id,
                    ingress_port,
                    header,
                    collector_monotonic_ns,
                    run_id,
                    source="ryu_openflow_bounded_packet_copy",
                    additional_payload={
                        "evidence_mode": "bounded_openflow_packet_copy",
                        "sampling_policy": "arrival_order_rolling_1s_and_run_caps",
                        "sampling_sequence": budget.accepted_count,
                        "copied_byte_count": len(message.data),
                        "original_byte_count": int(
                            getattr(message, "total_len", len(message.data))
                        ),
                        "packet_truncated": int(getattr(message, "total_len", len(message.data)))
                        > len(message.data),
                        "controller_copy_max_bytes": (
                            self._packet_evidence_policy.controller_copy_max_bytes
                        ),
                    },
                    observed_at=observed_at,
                )
            self._log(
                "packet_evidence_copy_processed",
                datapath.id,
                run_id=run_id,
                accepted=bool(accepted),
                cookie=f"0x{self._packet_evidence_policy.flow_cookie:x}",
                forwarded_by_openflow=True,
                packet_out_sent=False,
            )
            return

        table = self.mac_to_port.setdefault(datapath.id, {})
        table[header.src] = ingress_port
        egress_port = table.get(header.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(egress_port)]

        # PacketIn is a limited controller-visible sample, not a complete packet
        # capture. Telemetry failures must never change the forwarding path.
        if self.config.record_packetin_telemetry:
            try:
                self._record_packet_observation(
                    frame,
                    datapath.id,
                    ingress_port,
                    header,
                    time.monotonic_ns(),
                    run_id,
                )
            except Exception as error:  # Keep raw telemetry best-effort and non-disruptive.
                self._log(
                    "telemetry_observation_failed",
                    datapath.id,
                    error_type=type(error).__name__,
                )

        if egress_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=ingress_port, eth_dst=header.dst)
            self._add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                reason="basic_l2_learning",
            )

        data = None if message.buffer_id != ofproto.OFP_NO_BUFFER else message.data
        packet_out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=message.buffer_id,
            in_port=ingress_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(packet_out)
        self._log(
            "packet_in_forwarded",
            datapath.id,
            ingress_port=ingress_port,
            egress_port=egress_port,
            source_mac=header.src,
            destination_mac=header.dst,
        )

    @handler.set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_description_reply_handler(self, event: Any) -> None:
        """Log observed port details in structured form."""

        run_id = self._current_run_id()
        for port in event.msg.body:
            observed_at = self._event_clock.now()
            observation = TelemetryObservation.create(
                observation_id=str(uuid.uuid4()),
                observation_type=ObservationType.PORT_DESCRIPTION,
                observed_at=observed_at,
                source="ryu_openflow_port_description",
                scope=TelemetryScope(datapath_id=f"{event.msg.datapath.id:016x}"),
                payload={
                    "port_no": int(port.port_no),
                    "name": port.name.decode(errors="replace"),
                    "state": int(port.state),
                    "config": int(port.config),
                },
                provenance_version=OBSERVATION_PROVENANCE_VERSION,
                collector_monotonic_ns=time.monotonic_ns(),
                run_id=run_id,
            )
            self._log(
                "telemetry_observation", event.msg.datapath.id, observation=observation.to_dict()
            )
            self._write_record("telemetry_observation", observation=observation.to_dict())
            self._log(
                "port_description",
                event.msg.datapath.id,
                port_no=port.port_no,
                name=port.name.decode(errors="replace"),
                state=port.state,
                config=port.config,
            )

    @handler.set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_statistics_reply_handler(self, event: Any) -> None:
        """Assemble all multipart parts before publishing a coherent snapshot."""

        self._current_run_id()
        datapath_id = event.msg.datapath.id
        epoch = self._datapath_epochs.epoch_for_connection(datapath_id, event.msg.datapath)
        received_at = self._event_clock.now()
        received_monotonic_ns = time.monotonic_ns()
        more = bool(event.msg.flags & event.msg.datapath.ofproto.OFPMPF_REPLY_MORE)
        raw_records = [
            self._stat_observation(datapath_id, stat, received_at, received_monotonic_ns)
            for stat in event.msg.body
        ]
        if epoch is None or epoch.state != "ACTIVE":
            self._log(
                "flow_collection_rejected",
                datapath_id,
                xid=event.msg.xid,
                reason="reply_connection_epoch_missing_or_inactive",
            )
            self._write_record(
                "incomplete_collection",
                timestamp=received_at.isoformat(),
                collection_id=(
                    None
                    if epoch is None
                    else f"{epoch.epoch_id}:{datapath_id:016x}:{event.msg.xid:08x}"
                ),
                datapath_id=f"{datapath_id:016x}",
                datapath_epoch_id=None if epoch is None else epoch.epoch_id,
                xid=event.msg.xid,
                complete=False,
                terminal_state="AMBIGUOUS",
                reason="reply_connection_epoch_missing_or_inactive",
            )
            return
        try:
            collection = self._multipart.add_part(
                datapath_id=datapath_id,
                xid=event.msg.xid,
                datapath_epoch_id=epoch.epoch_id,
                records=raw_records,
                more=more,
                received_at=received_at,
                received_monotonic_ns=received_monotonic_ns,
            )
        except TimeoutError as error:
            collection_id = f"{epoch.epoch_id}:{datapath_id:016x}:{event.msg.xid:08x}"
            self._write_record(
                "incomplete_collection",
                timestamp=received_at.isoformat(),
                collection_id=collection_id,
                datapath_id=f"{datapath_id:016x}",
                datapath_epoch_id=epoch.epoch_id,
                xid=event.msg.xid,
                complete=False,
                terminal_state="TIMED_OUT",
                reason=str(error),
            )
            return
        except (KeyError, ValueError) as error:
            self._log("flow_collection_rejected", datapath_id, xid=event.msg.xid, reason=str(error))
            self._write_record(
                "incomplete_collection",
                timestamp=received_at.isoformat(),
                collection_id=f"{epoch.epoch_id}:{datapath_id:016x}:{event.msg.xid:08x}",
                datapath_id=f"{datapath_id:016x}",
                datapath_epoch_id=epoch.epoch_id,
                xid=event.msg.xid,
                complete=False,
                terminal_state="INCOMPLETE",
                reason="unmatched_or_invalid_multipart_part",
            )
            return
        if collection is None:
            return

        active_run_id = self._current_run_id()
        if collection.run_id != active_run_id:
            self._write_record(
                "incomplete_collection",
                timestamp=collection.completed_at.isoformat(),
                collection_id=collection.collection_id,
                datapath_id=f"{datapath_id:016x}",
                xid=collection.xid,
                run_id=collection.run_id,
                complete=False,
                terminal_state="CANCELLED",
                datapath_epoch_id=collection.datapath_epoch_id,
                reason="run_boundary_before_collection_completion",
                partial_record_count=len(collection.records),
            )
            return

        self._write_record(
            "flow_collection",
            timestamp=collection.completed_at.isoformat(),
            collection_id=collection.collection_id,
            datapath_id=f"{datapath_id:016x}",
            xid=collection.xid,
            complete=True,
            terminal_state="COMPLETE",
            datapath_epoch_id=collection.datapath_epoch_id,
            part_count=collection.parts_received,
            record_count=len(collection.records),
            run_id=collection.run_id,
            started_at=collection.started_at.isoformat(),
            completed_at=collection.completed_at.isoformat(),
            started_monotonic_ns=collection.started_monotonic_ns,
            completed_monotonic_ns=collection.completed_monotonic_ns,
            elapsed_seconds=(collection.completed_monotonic_ns - collection.started_monotonic_ns)
            / 1e9,
        )
        self._log(
            "flow_collection_complete",
            datapath_id,
            collection_id=collection.collection_id,
            datapath_epoch_id=collection.datapath_epoch_id,
            xid=collection.xid,
            part_count=collection.parts_received,
            record_count=len(collection.records),
            run_id=collection.run_id,
        )
        snapshots = []
        for raw in collection.records:
            raw["run_id"] = collection.run_id
            # A coherent collection is timestamped at completion; part receipt times
            # are not individual switch sampling timestamps.
            raw["timestamp"] = collection.completed_at.isoformat()
            raw["collector_monotonic_ns"] = collection.completed_monotonic_ns
            raw["collection_id"] = collection.collection_id
            raw["datapath_epoch_id"] = collection.datapath_epoch_id
            snapshot = flow_snapshot_from_observation(
                raw,
                run_id=collection.run_id,
                collection_id=collection.collection_id,
                datapath_epoch_id=collection.datapath_epoch_id,
            )
            snapshots.append(snapshot)
            self._log(
                "flow_statistics",
                datapath_id,
                **flow_statistics_log_details(raw),
            )
            self._write_record(
                "flow_snapshot",
                timestamp=raw["timestamp"],
                run_id=collection.run_id,
                collection_id=collection.collection_id,
                datapath_epoch_id=collection.datapath_epoch_id,
                flow_record=snapshot.record.to_dict(),
                collector_monotonic_ns=collection.completed_monotonic_ns,
            )
        self._process_complete_collection(collection, snapshots)

    def _record_packet_observation(
        self,
        frame: Any,
        datapath_id: int,
        ingress_port: int,
        ethernet_header: Any,
        collector_monotonic_ns: int,
        run_id: str | None,
        *,
        source: str = "ryu_packet_in",
        additional_payload: dict[str, str | int | float | bool | None] | None = None,
        observed_at: datetime | None = None,
    ) -> None:
        """Emit parsed fields from one PacketIn without interpreting its meaning."""

        payload: dict[str, str | int | float | bool | None] = {
            "eth_type": int(ethernet_header.ethertype),
            "src_mac": str(ethernet_header.src).lower(),
            "dst_mac": str(ethernet_header.dst).lower(),
        }
        selectors: dict[str, str | int] = {
            "in_port": ingress_port,
            "src_mac": str(ethernet_header.src).lower(),
            "dst_mac": str(ethernet_header.dst).lower(),
        }
        obs_type = ObservationType.ETHERNET_PACKET_IN
        arp_header = frame.get_protocol(arp.arp)
        ip_header = frame.get_protocol(ipv4.ipv4)
        tcp_header = frame.get_protocol(tcp.tcp)
        udp_header = frame.get_protocol(udp.udp)
        if arp_header is not None:
            obs_type = ObservationType.ARP_PACKET_IN
            payload.update(
                {
                    "arp_opcode": int(arp_header.opcode),
                    "arp_src_ip": str(arp_header.src_ip),
                    "arp_dst_ip": str(arp_header.dst_ip),
                    "arp_src_mac": str(arp_header.src_mac).lower(),
                    "arp_dst_mac": str(arp_header.dst_mac).lower(),
                }
            )
            selectors["src_ip"] = str(arp_header.src_ip)
            selectors["dst_ip"] = str(arp_header.dst_ip)
        elif ip_header is not None:
            payload.update(
                {
                    "ip_protocol": int(ip_header.proto),
                    "src_ip": str(ip_header.src),
                    "dst_ip": str(ip_header.dst),
                    "ip_ttl": int(ip_header.ttl),
                }
            )
            selectors.update(
                {
                    "src_ip": str(ip_header.src),
                    "dst_ip": str(ip_header.dst),
                    "ip_protocol": int(ip_header.proto),
                }
            )
            if tcp_header is not None:
                obs_type = ObservationType.TCP_PACKET_IN
                payload.update(
                    {
                        "src_port": int(tcp_header.src_port),
                        "dst_port": int(tcp_header.dst_port),
                        "tcp_bits": int(tcp_header.bits),
                    }
                )
                selectors.update(
                    {"src_port": int(tcp_header.src_port), "dst_port": int(tcp_header.dst_port)}
                )
            elif udp_header is not None:
                obs_type = ObservationType.UDP_PACKET_IN
                payload.update(
                    {"src_port": int(udp_header.src_port), "dst_port": int(udp_header.dst_port)}
                )
                selectors.update(
                    {"src_port": int(udp_header.src_port), "dst_port": int(udp_header.dst_port)}
                )
            else:
                obs_type = ObservationType.IPV4_PACKET_IN
        if additional_payload:
            payload.update(additional_payload)
        observation = TelemetryObservation.create(
            observation_id=str(uuid.uuid4()),
            observation_type=obs_type,
            observed_at=observed_at or self._event_clock.now(),
            source=source,
            scope=TelemetryScope.from_mapping(f"{datapath_id:016x}", selectors),
            payload=payload,
            provenance_version=OBSERVATION_PROVENANCE_VERSION,
            collector_monotonic_ns=collector_monotonic_ns,
            run_id=run_id,
        )
        self._log("telemetry_observation", datapath_id, observation=observation.to_dict())
        self._write_record("telemetry_observation", observation=observation.to_dict())

    def _request_port_descriptions(self, datapath: Any) -> None:
        """Request port descriptions from one datapath."""

        request = datapath.ofproto_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(request)

    def _request_flow_statistics(self, datapath: Any) -> None:
        """Request basic flow statistics from one datapath."""

        # Run-context transition and request emission form one event transaction.
        # Without this lock, a callback could write a new run boundary after a
        # poll has captured its run ID/time but before that request is appended.
        with self._run_context_lock:
            self._request_flow_statistics_locked(datapath)

    def _request_flow_statistics_locked(self, datapath: Any) -> None:
        """Request flow stats while holding the run-context event lock."""

        epoch = self._datapath_epochs.active_epoch(datapath.id)
        if (
            epoch is None
            or self._datapath_epochs.epoch_for_connection(datapath.id, datapath) != epoch
        ):
            self._write_record(
                "incomplete_collection",
                timestamp=self._event_clock.now().isoformat(),
                datapath_id=f"{datapath.id:016x}",
                datapath_epoch_id=None if epoch is None else epoch.epoch_id,
                complete=False,
                terminal_state="AMBIGUOUS",
                reason="statistics_request_without_active_connection_epoch",
            )
            return
        request = datapath.ofproto_parser.OFPFlowStatsRequest(datapath)
        datapath.set_xid(request)
        run_id = self._current_run_id()
        # Emit a run-start boundary before timestamping this request so appended
        # events remain monotonic for replay validation.
        started_at = self._event_clock.now()
        started_monotonic_ns = time.monotonic_ns()
        collection_id = self._multipart.start(
            datapath_id=datapath.id,
            xid=request.xid,
            started_at=started_at,
            started_monotonic_ns=started_monotonic_ns,
            datapath_epoch_id=epoch.epoch_id,
            run_id=run_id,
        )
        self._write_record(
            "flow_collection",
            timestamp=started_at.isoformat(),
            collection_id=collection_id,
            datapath_id=f"{datapath.id:016x}",
            datapath_epoch_id=epoch.epoch_id,
            xid=request.xid,
            state="requested",
            run_id=run_id,
            started_at=started_at.isoformat(),
            started_monotonic_ns=started_monotonic_ns,
        )
        self._log(
            "flow_collection_requested",
            datapath.id,
            collection_id=collection_id,
            datapath_epoch_id=epoch.epoch_id,
            xid=request.xid,
            run_id=run_id,
        )
        datapath.send_msg(request)

    def _monitor(self) -> None:
        """Request flow statistics at the configured observation interval."""

        while True:
            for incomplete in self._multipart.expire(time.monotonic_ns()):
                self._write_record(
                    "incomplete_collection",
                    timestamp=self._event_clock.now().isoformat(),
                    **incomplete,
                )
            for datapath in tuple(self.datapaths.values()):
                active = self._datapath_epochs.active_epoch(datapath.id)
                if (
                    active is not None
                    and self._datapath_epochs.epoch_for_connection(datapath.id, datapath) == active
                ):
                    self._request_flow_statistics(datapath)
            self._publish_controller_status()
            hub.sleep(self.config.monitor_interval_seconds)

    def close(self) -> None:
        """Remove an enabled explicit test rule before controller shutdown."""

        if self.config.install_explicit_test_rule:
            for datapath in tuple(self.datapaths.values()):
                self.remove_explicit_test_rule(datapath)
        self._current_run_id()
        if self._packet_evidence_budget is not None and self._packet_evidence_budget.run_id:
            self._finish_packet_evidence_run(self._event_clock.now())
        for datapath in tuple(self.datapaths.values()):
            if datapath.id in self._packet_evidence_datapaths:
                self._remove_packet_evidence_rules(datapath)
        now = self._event_clock.now()
        for incomplete in self._multipart.invalidate_all(
            reason="controller_shutdown", terminal_state="CANCELLED"
        ):
            self._write_record("incomplete_collection", timestamp=now.isoformat(), **incomplete)
        for epoch in self._datapath_epochs.invalidate_all():
            self._write_connection_epoch_boundary(
                state="ambiguous",
                datapath_id=epoch.datapath_id,
                epoch=epoch,
                timestamp=now,
                source="controller_shutdown",
            )
        self.datapaths.clear()
        self._publish_controller_status()
        self._log("controller_stopped")
        if self._recorder is not None:
            self._recorder.close()
        if self._run_recorder is not None:
            self._run_recorder.close()
            self._run_recorder = None
        super().close()

    def _current_run_id(self) -> str | None:
        with self._run_context_lock:
            return self._current_run_id_locked()

    def _current_run_id_locked(self) -> str | None:
        """Read and record run transitions while holding the context lock."""

        try:
            context = read_experiment_context(self.config.observation_context_file)
        except ValueError as error:
            self._log("experiment_context_invalid", reason=str(error))
            context = None
        run_id = (
            str(context["run_id"])
            if context is not None and context.get("active") is True
            else None
        )
        metadata = context if run_id is not None else None
        if run_id != self._active_run_id:
            timestamp = self._event_clock.now().isoformat()
            for incomplete in self._multipart.cancel_for_run_change(run_id):
                self._write_record("incomplete_collection", timestamp=timestamp, **incomplete)
            if self._active_run_id is not None:
                boundary_time = datetime.fromisoformat(timestamp)
                self._finish_packet_evidence_run(boundary_time)
                self._write_record(
                    "run_boundary",
                    timestamp=timestamp,
                    run_id=self._active_run_id,
                    state="ended",
                    metadata=self._active_run_metadata,
                )
                if self._run_recorder is not None:
                    self._run_recorder.close()
                    self._run_recorder = None
            if run_id is not None and metadata is not None:
                if self.config.run_telemetry_directory is not None:
                    # Run IDs are UUIDs in the Stage 7 orchestration contract;
                    # restrict file names here rather than trusting context text.
                    if not re.fullmatch(r"[0-9a-fA-F-]{36}", run_id):
                        raise ValueError("run ID is not a canonical UUID")
                    self.config.run_telemetry_directory.mkdir(parents=True, exist_ok=True)
                    self._run_recorder = TelemetryJsonlRecorder(
                        self.config.run_telemetry_directory / f"telemetry-{run_id}.jsonl",
                        source_version="ryu-stage2-run-scoped-v1",
                    )
                started_at = run_start_timestamp(metadata, timestamp)
                self._write_record(
                    "run_metadata", timestamp=started_at, run_id=run_id, metadata=metadata
                )
                self._write_record(
                    "run_boundary", timestamp=started_at, run_id=run_id, state="started"
                )
            self._active_run_id = run_id
            self._active_run_metadata = metadata
            if run_id is not None and self._packet_evidence_budget is not None:
                self._packet_evidence_budget.begin_run(run_id)
        return run_id

    def _finish_packet_evidence_run(self, ended_at: datetime) -> None:
        budget = self._packet_evidence_budget
        if budget is None or budget.run_id is None:
            return
        timestamp = ended_at.isoformat()
        summary = budget.finish_run(budget.run_id, ended_at=timestamp)
        self._write_record("packet_evidence_coverage", timestamp=timestamp, **summary)

    def _write_record(self, record_type: str, **fields: object) -> None:
        if self._recorder is not None:
            if record_type == "incomplete_collection" and "terminal_monotonic_ns" not in fields:
                fields["terminal_monotonic_ns"] = time.monotonic_ns()
            self._recorder.write(record_type, **fields)
        if self._run_recorder is not None:
            run_fields = dict(fields)
            if record_type == "incomplete_collection" and "terminal_monotonic_ns" not in run_fields:
                run_fields["terminal_monotonic_ns"] = time.monotonic_ns()
            self._run_recorder.write(record_type, **run_fields)

    def _process_complete_collection(self, collection: Any, snapshots: list[Any]) -> None:
        active_rule_ids: list[str] = []
        identity_resolution_complete = True
        for snapshot in snapshots:
            try:
                window = self._counter_deltas.observe(snapshot)
            except ValueError as error:
                identity_resolution_complete = False
                self._log(
                    "flow_delta_unavailable",
                    collection.datapath_id,
                    record_id=snapshot.record.record_id,
                    reason=str(error),
                )
                continue
            active_rule_ids.append(window.rule_identity.identity_id)
            self._write_record("observation_window", observation_window=window.to_dict())
        if identity_resolution_complete:
            for window in self._counter_deltas.close_missing(
                f"{collection.datapath_id:016x}",
                active_rule_ids,
                snapshot_complete=True,
                observed_at=collection.completed_at,
                collector_monotonic_ns=collection.completed_monotonic_ns,
            ):
                self._write_record("observation_window", observation_window=window.to_dict())

    @staticmethod
    def _stat_observation(
        datapath_id: int, stat: Any, observed_at: datetime, monotonic_ns: int
    ) -> dict[str, object]:
        return {
            "event_type": "flow_statistics",
            "timestamp": observed_at.isoformat(),
            "datapath_id": f"{datapath_id:016x}",
            "table_id": stat.table_id,
            "priority": stat.priority,
            "cookie": f"0x{stat.cookie:x}",
            "packet_count": stat.packet_count,
            "byte_count": stat.byte_count,
            "duration_seconds": stat.duration_sec,
            "match": str(stat.match),
            "collector_monotonic_ns": monotonic_ns,
        }
