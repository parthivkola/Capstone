"""Local loopback client for the isolated Stage 7 Ryu action gateway."""

from __future__ import annotations

import json
import socket
from typing import Any

from src.sdn_defense.contracts import (
    ActionType,
    AdapterCapabilities,
    AdapterResult,
    AdapterStatus,
    MitigationAction,
    ScopeKind,
)


class SocketRyuMitigationAdapter:
    """Submit actions to a loopback Ryu app; SUCCESS means SUBMITTED only."""

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 16654,
        flow_mod_support_verified: bool = False,
        timeout_seconds: float = 2.0,
    ) -> None:
        if host not in ("127.0.0.1", "::1"):
            raise ValueError("Stage 7 action gateway must use loopback")
        if not 1 <= port <= 65535 or timeout_seconds <= 0:
            raise ValueError("invalid gateway port or timeout")
        self.host = host
        self.port = port
        self.timeout_seconds = timeout_seconds
        self._flow_verified = flow_mod_support_verified

    @property
    def capabilities(self) -> AdapterCapabilities:
        if not self._flow_verified:
            return AdapterCapabilities(((ActionType.MONITOR, tuple(ScopeKind)),))
        scopes = (ScopeKind.FLOW, ScopeKind.TUPLE, ScopeKind.HOST)
        return AdapterCapabilities(
            (
                (ActionType.MONITOR, tuple(ScopeKind)),
                (ActionType.BLOCK, scopes),
                (ActionType.QUARANTINE, scopes),
            ),
            unsupported_selectors=("host_id", "scenario_id", "fixture_id"),
        )

    def apply(self, action: MitigationAction) -> AdapterResult:
        return self._request({"command": "apply", "action": _action_payload(action)})

    def rollback(self, action_id: str) -> AdapterResult:
        return self._request({"command": "rollback", "action_id": action_id})

    def _request(self, request: dict[str, Any]) -> AdapterResult:
        try:
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout_seconds
            ) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.sendall(json.dumps(request, sort_keys=True).encode() + b"\n")
                response = bytearray()
                while b"\n" not in response and len(response) < 65536:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            if len(response) >= 65536 or b"\n" not in response:
                raise RuntimeError("Ryu gateway response is missing or oversized")
            payload = json.loads(bytes(response).split(b"\n", 1)[0])
            if not isinstance(payload, dict):
                raise RuntimeError("Ryu gateway returned a non-object response")
            return AdapterResult(
                action_id=str(payload.get("action_id", request.get("action_id", "unknown"))),
                status=AdapterStatus(str(payload["status"])),
                reason=str(payload["reason"]),
                rule_cookie=(
                    int(payload["rule_cookie"]) if payload.get("rule_cookie") is not None else None
                ),
            )
        except (OSError, KeyError, TypeError, ValueError, RuntimeError) as error:
            action_id = str(request.get("action_id", "gateway-request"))
            action_payload = request.get("action")
            if isinstance(action_payload, dict):
                action_id = str(action_payload.get("action_id", action_id))
            return AdapterResult(action_id, AdapterStatus.FAILED, f"gateway failure: {error}")


def _action_payload(action: MitigationAction) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "action": action.action.value,
        "scope": {
            "kind": action.scope.kind.value,
            "selectors": dict(action.scope.selectors),
        },
        "created_at": action.created_at.isoformat(),
        "expires_at": action.expires_at.isoformat(),
        "ttl_seconds": action.ttl_seconds,
        "reason": action.reason,
        "evidence_refs": list(action.evidence_refs),
        "policy_version": action.policy_version,
        "decision_id": action.decision_id,
        "extension_count": action.extension_count,
        "rollback_state": action.rollback_state.value,
    }
