"""Loopback-only Ryu gateway for explicitly submitted Stage 7 test actions.

This app exposes no detection or policy logic. Its small newline-delimited JSON
socket accepts typed action records from the local test orchestrator and reports
only adapter submission status. Independent OVS polling establishes confirmation.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any

from ryu.base import app_manager
from ryu.controller import handler, ofp_event
from ryu.controller.handler import DEAD_DISPATCHER, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from networking.ryu.mitigation_adapter import RyuAdapterConfig, RyuOpenFlowMitigationAdapter
from networking.ryu.stage7_events import datapath_state_event
from src.sdn_defense.contracts import (
    ActionType,
    MitigationAction,
    MitigationScope,
    RollbackState,
    ScopeKind,
)

MAX_REQUEST_BYTES = 65536


class Stage7MitigationGateway(app_manager.RyuApp):
    """Ryu datapath bridge for controlled local enforcement verification only."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.logger.setLevel(logging.INFO)
        self.datapaths: dict[int, Any] = {}
        port = int(os.environ.get("SDN_STAGE7_GATEWAY_PORT", "16654"))
        if not 1 <= port <= 65535:
            raise ValueError("SDN_STAGE7_GATEWAY_PORT must be a valid TCP port")
        verified = os.environ.get("SDN_STAGE7_FLOW_MOD_VERIFIED", "false").lower() == "true"
        self.adapter = RyuOpenFlowMitigationAdapter(
            self.datapaths,
            RyuAdapterConfig(
                table_id=0,
                priority=40000,
                flow_mod_support_verified=verified,
                cookie_namespace="stage7-live-test",
            ),
        )
        self._server = hub.listen(("127.0.0.1", port))
        self._server_thread = hub.spawn(self._serve)
        self.logger.info(
            "stage7_gateway_started=%s",
            json.dumps({"bind": "127.0.0.1", "port": port, "flow_mod_enabled": verified}),
        )

    @handler.set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def datapath_state_change_handler(self, event: Any) -> None:
        datapath = event.datapath
        if event.state == MAIN_DISPATCHER:
            if datapath.id is not None:
                self.datapaths[datapath.id] = datapath
            self.logger.info(
                "stage7_datapath_connected=%s",
                json.dumps(datapath_state_event("connected", datapath.id), sort_keys=True),
            )
        elif event.state == DEAD_DISPATCHER:
            if datapath.id is not None:
                self.datapaths.pop(datapath.id, None)
            self.logger.info(
                "stage7_datapath_disconnected=%s",
                json.dumps(datapath_state_event("disconnected", datapath.id), sort_keys=True),
            )

    def _serve(self) -> None:
        while True:
            connection, _address = self._server.accept()
            hub.spawn(self._handle_connection, connection)

    def _handle_connection(self, connection: Any) -> None:
        try:
            connection.settimeout(2.0)
            payload = bytearray()
            while len(payload) <= MAX_REQUEST_BYTES and b"\n" not in payload:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_REQUEST_BYTES or b"\n" not in payload:
                raise ValueError("request must be one bounded JSON line")
            request = json.loads(bytes(payload).split(b"\n", 1)[0])
            response = self._dispatch(request)
        except Exception as error:
            response = {"status": "REJECTED", "reason": str(error)}
        try:
            connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")
        finally:
            connection.close()

    def _dispatch(self, request: object) -> dict[str, object]:
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
        command = request.get("command")
        if command == "apply":
            action = self._action_from_payload(request.get("action"))
            result = self.adapter.apply(action)
        elif command == "rollback":
            action_id = request.get("action_id")
            if not isinstance(action_id, str) or not action_id:
                raise ValueError("rollback requires action_id")
            result = self.adapter.rollback(action_id)
        else:
            raise ValueError("unsupported gateway command")
        response: dict[str, object] = {
            "action_id": result.action_id,
            "status": result.status.value,
            "reason": result.reason,
            "rule_cookie": result.rule_cookie,
        }
        self.logger.info("stage7_adapter_result=%s", json.dumps(response, sort_keys=True))
        return response

    @staticmethod
    def _action_from_payload(payload: object) -> MitigationAction:
        if not isinstance(payload, dict):
            raise ValueError("apply requires an action object")
        scope_payload = payload.get("scope")
        if not isinstance(scope_payload, dict):
            raise ValueError("action requires an exact scope")
        selectors = scope_payload.get("selectors")
        if not isinstance(selectors, dict) or any(
            not isinstance(key, str) or not isinstance(value, (str, int))
            for key, value in selectors.items()
        ):
            raise ValueError("scope selectors must be string/integer values")
        return MitigationAction(
            action_id=str(payload["action_id"]),
            action=ActionType(str(payload["action"])),
            scope=MitigationScope.from_mapping(ScopeKind(str(scope_payload["kind"])), selectors),
            created_at=datetime.fromisoformat(str(payload["created_at"])),
            expires_at=datetime.fromisoformat(str(payload["expires_at"])),
            ttl_seconds=int(payload["ttl_seconds"]),
            reason=str(payload["reason"]),
            evidence_refs=tuple(str(item) for item in payload["evidence_refs"]),
            policy_version=str(payload["policy_version"]),
            decision_id=str(payload["decision_id"]),
            extension_count=int(payload.get("extension_count", 0)),
            rollback_state=RollbackState(str(payload.get("rollback_state", "PROPOSED"))),
        )
