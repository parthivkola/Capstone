"""Isolated OpenFlow 1.3 mitigation adapter foundation for Stage 7.

This module is deliberately not imported by the Stage 2 controller. It uses the
Ryu datapath/parser surface through an adapter boundary, so ordinary unit tests do
not require Ryu, OVS, root privileges, or a live switch.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from src.sdn_defense.contracts import (
    ActionType,
    AdapterCapabilities,
    AdapterResult,
    AdapterStatus,
    DefenseAuditEvent,
    MitigationAction,
    MitigationScope,
    RollbackState,
    ScopeKind,
)


@dataclass(frozen=True, slots=True)
class RyuAdapterConfig:
    """Explicit OpenFlow settings; unverified capabilities default to disabled."""

    table_id: int
    priority: int
    flow_mod_support_verified: bool = False
    cookie_namespace: str = "stage7"

    def __post_init__(self) -> None:
        if not 0 <= self.table_id <= 255:
            raise ValueError("table_id must be within the OpenFlow table range")
        if not 1 <= self.priority <= 65535:
            raise ValueError("priority must be a non-zero OpenFlow priority")
        if not self.cookie_namespace:
            raise ValueError("cookie namespace must be non-empty")


@dataclass(frozen=True, slots=True)
class _InstalledRule:
    datapath: Any
    cookie: int
    priority: int
    match: Any
    action: MitigationAction


class RyuOpenFlowMitigationAdapter:
    """Apply exact-scope drop rules and remove only rules owned by action IDs.

    Rate limiting is intentionally UNSUPPORTED: no meter has been verified and
    the protocol does not freeze a rate/burst value. No action is sent by creating
    this adapter; callers must explicitly invoke ``apply``.
    """

    def __init__(
        self,
        datapaths: Mapping[int, Any],
        config: RyuAdapterConfig,
        *,
        clock: Callable[[], datetime] | None = None,
        audit_sink: Callable[[DefenseAuditEvent], None] | None = None,
    ) -> None:
        self._datapaths = datapaths
        self._config = config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._audit_sink = audit_sink
        self._installed: dict[str, _InstalledRule] = {}
        self._cookies: dict[int, str] = {}
        self._audit_events: list[DefenseAuditEvent] = []

    @property
    def capabilities(self) -> AdapterCapabilities:
        if not self._config.flow_mod_support_verified:
            return AdapterCapabilities(((ActionType.MONITOR, tuple(ScopeKind)),))
        scopes = (ScopeKind.FLOW, ScopeKind.TUPLE, ScopeKind.HOST)
        return AdapterCapabilities(
            (
                (ActionType.MONITOR, tuple(ScopeKind)),
                (ActionType.QUARANTINE, scopes),
                (ActionType.BLOCK, scopes),
            ),
            unsupported_selectors=("host_id", "scenario_id", "fixture_id"),
        )

    @property
    def audit_events(self) -> tuple[DefenseAuditEvent, ...]:
        """Structured events retained for the lifetime of this adapter instance."""

        return tuple(self._audit_events)

    def apply(self, action: MitigationAction) -> AdapterResult:
        """Install one hard-timeout flow rule, or explicitly reject it."""

        if action.action is ActionType.RATE_LIMIT:
            return self._finish(
                action,
                AdapterStatus.UNSUPPORTED,
                "OpenFlow meter capability is unavailable",
                "action_unsupported",
            )
        if action.action not in (ActionType.BLOCK, ActionType.QUARANTINE):
            return self._finish(
                action,
                AdapterStatus.UNSUPPORTED,
                "action is not implemented by this adapter",
                "action_unsupported",
            )
        if not self._config.flow_mod_support_verified:
            return self._finish(
                action,
                AdapterStatus.UNSUPPORTED,
                "flow-mod capability is unverified",
                "action_unsupported",
            )
        if action.rollback_state is not RollbackState.PROPOSED:
            return self._finish(
                action, AdapterStatus.REJECTED, "action is not in PROPOSED state", "action_rejected"
            )
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None or now >= action.expires_at:
            return self._finish(
                action,
                AdapterStatus.REJECTED,
                "action is expired or adapter clock is naive",
                "action_rejected",
            )
        if action.action_id in self._installed:
            return self._finish(
                action, AdapterStatus.REJECTED, "action ID is already installed", "action_rejected"
            )
        try:
            datapath, match = self._resolve(action.scope)
            cookie = self._cookie(action.action_id)
            owner = self._cookies.get(cookie)
            if owner is not None and owner != action.action_id:
                return self._finish(
                    action, AdapterStatus.FAILED, "action cookie collision", "action_failed"
                )
            parser = datapath.ofproto_parser
            request = parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie,
                command=datapath.ofproto.OFPFC_ADD,
                table_id=self._config.table_id,
                hard_timeout=action.ttl_seconds,
                idle_timeout=0,
                priority=self._config.priority,
                match=match,
                instructions=[],  # Empty instruction list is an exact-match drop rule.
            )
            datapath.send_msg(request)
            active_action = replace(action, rollback_state=RollbackState.ACTIVE)
            self._installed[action.action_id] = _InstalledRule(
                datapath, cookie, self._config.priority, match, active_action
            )
            self._cookies[cookie] = action.action_id
            return self._finish(
                active_action,
                AdapterStatus.SUCCESS,
                "exact-scope OpenFlow drop rule submitted",
                "action_applied",
                rule_cookie=cookie,
            )
        except (KeyError, ValueError, TypeError, AttributeError) as error:
            return self._finish(action, AdapterStatus.UNSUPPORTED, str(error), "action_rejected")
        except Exception as error:  # adapter boundary converts switch errors to FAILED
            return self._finish(
                action, AdapterStatus.FAILED, f"OpenFlow send failed: {error}", "action_failed"
            )

    def rollback(self, action_id: str) -> AdapterResult:
        """Delete only the strict match/cookie installed for this action ID."""

        rule = self._installed.get(action_id)
        if rule is None:
            return AdapterResult(
                action_id, AdapterStatus.REJECTED, "no rule is registered for action ID"
            )
        try:
            datapath = rule.datapath
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            request = parser.OFPFlowMod(
                datapath=datapath,
                cookie=rule.cookie,
                cookie_mask=0xFFFFFFFFFFFFFFFF,
                command=ofproto.OFPFC_DELETE_STRICT,
                table_id=self._config.table_id,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=rule.priority,
                match=rule.match,
            )
            datapath.send_msg(request)
            del self._installed[action_id]
            self._cookies.pop(rule.cookie, None)
            result = AdapterResult(
                action_id, AdapterStatus.SUCCESS, "exact action rule delete submitted", rule.cookie
            )
            self._audit_action(
                replace(rule.action, rollback_state=RollbackState.ROLLED_BACK),
                result,
                "rollback_submitted",
            )
            return result
        except Exception as error:
            result = AdapterResult(
                action_id, AdapterStatus.FAILED, f"exact rollback failed: {error}", rule.cookie
            )
            self._audit_action(rule.action, result, "rollback_failed")
            return result

    def _resolve(self, scope: MitigationScope) -> tuple[Any, Any]:
        selectors = dict(scope.selectors)
        if scope.kind is ScopeKind.SCENARIO_FIXTURE or set(selectors).intersection(
            {"host_id", "scenario_id", "fixture_id"}
        ):
            raise ValueError("scope is not representable as an exact OpenFlow match")
        datapath_value = selectors.pop("datapath_id", None)
        if datapath_value is None:
            raise ValueError("scope is missing datapath_id")
        datapath_id = (
            int(str(datapath_value), 16) if isinstance(datapath_value, str) else datapath_value
        )
        datapath = self._datapaths.get(datapath_id)
        if datapath is None:
            raise KeyError("scope datapath is not connected")
        match_fields: dict[str, str | int] = {}
        ip_versions: set[int] = set()
        for key, value in selectors.items():
            if key in ("src_ip", "dst_ip"):
                address = ipaddress.ip_address(str(value))
                ip_versions.add(address.version)
                match_fields[
                    "ipv4_src"
                    if key == "src_ip" and address.version == 4
                    else "ipv6_src"
                    if key == "src_ip"
                    else "ipv4_dst"
                    if address.version == 4
                    else "ipv6_dst"
                ] = str(address)
            elif key in ("src_mac", "dst_mac", "in_port"):
                match_fields[{"src_mac": "eth_src", "dst_mac": "eth_dst"}.get(key, key)] = value
            elif key == "ip_protocol":
                match_fields["ip_proto"] = value
            elif key in ("src_port", "dst_port"):
                protocol = selectors.get("ip_protocol")
                if protocol not in (6, 17):
                    raise ValueError("transport ports require TCP or UDP protocol")
                prefix = "tcp" if protocol == 6 else "udp"
                match_fields[f"{prefix}_{'src' if key == 'src_port' else 'dst'}"] = value
            else:
                raise ValueError(f"unsupported OpenFlow selector: {key}")
        if len(ip_versions) > 1:
            raise ValueError("mixed IPv4/IPv6 endpoints are unsupported")
        if ip_versions == {4}:
            match_fields["eth_type"] = 0x0800
        elif ip_versions == {6}:
            match_fields["eth_type"] = 0x86DD
        if not match_fields:
            raise ValueError("scope has no OpenFlow match fields")
        return datapath, datapath.ofproto_parser.OFPMatch(**match_fields)

    def _cookie(self, action_id: str) -> int:
        digest = hashlib.sha256(f"{self._config.cookie_namespace}:{action_id}".encode()).digest()
        return int.from_bytes(digest[:8], byteorder="big", signed=False)

    def _finish(
        self,
        action: MitigationAction,
        status: AdapterStatus,
        reason: str,
        event_type: str,
        *,
        rule_cookie: int | None = None,
    ) -> AdapterResult:
        timestamp = self._clock()
        event = DefenseAuditEvent(
            event_id=hashlib.sha256(
                f"{action.action_id}:{event_type}:{timestamp.isoformat()}".encode()
            ).hexdigest(),
            timestamp=timestamp,
            event_type=event_type,
            decision_id=action.decision_id,
            action_id=action.action_id,
            action=action.action,
            scope=action.scope,
            reason=reason,
            policy_version=action.policy_version,
            adapter_status=status,
            ttl_seconds=action.ttl_seconds,
            rollback_state=action.rollback_state,
            rule_cookie=rule_cookie,
        )
        self._audit_events.append(event)
        if self._audit_sink is not None:
            try:
                self._audit_sink(event)
            except Exception as error:
                failure_event = replace(
                    event,
                    event_id=hashlib.sha256(
                        f"{event.event_id}:audit-sink-failed".encode()
                    ).hexdigest(),
                    event_type="audit_sink_failed",
                    reason=f"audit sink failed; in-memory event retained: {error}",
                    adapter_status=AdapterStatus.FAILED,
                )
                self._audit_events.append(failure_event)
        return AdapterResult(action.action_id, status, reason, rule_cookie)

    def _audit_action(
        self, action: MitigationAction, result: AdapterResult, event_type: str
    ) -> None:
        self._finish(
            action,
            result.status,
            result.reason,
            event_type,
            rule_cookie=result.rule_cookie,
        )
