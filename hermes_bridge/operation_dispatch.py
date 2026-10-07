"""RPC operation dispatch for the HermLink adapter.

The relay adapter owns connection and frame delivery.  This module owns the
RPC policy: operation lookup, idempotency, and stable error mapping.  Handler
implementations stay on the adapter for now because they need its injected
Hermes REST/local-WS state; this seam keeps that transport-facing state out of
the dispatch loop and gives the operation surface one testable entry point.
"""

import asyncio
import json
import logging
import urllib.error
from typing import Any, Awaitable, Callable, Dict, Optional


logger = logging.getLogger(__name__)

_RPC_DEDUP_WINDOW_S = 30.0


class _RpcError(Exception):
    """Validation failure inside an RPC handler."""


class _LocalRpcError(Exception):
    """JSON-RPC error from Hermes' local /api/ws door."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = int(code)
        self.message = message


def _http_error_detail(exc: urllib.error.HTTPError) -> str:
    """Extract FastAPI's human-readable detail from an HTTP error."""
    try:
        body = exc.read()
        data = json.loads(body.decode())
        detail = data.get("detail") if isinstance(data, dict) else None
        if detail:
            return str(detail)
    except Exception:
        pass
    return str(exc)


class OperationDispatcher:
    """Dispatch one decoded ``rpc.request`` payload to an adapter host.

    The host is deliberately a narrow runtime dependency rather than a base
    class.  Production uses ``HermesBridgeAdapter``; tests use a small fake
    host that provides the same handler/response callbacks.
    """

    _HANDLER_NAMES = {
        "sessions.messages": "_rpc_sessions_messages",
        "sessions.fork": "_rpc_sessions_fork",
        "sessions.list": "_rpc_sessions_list",
        "sessions.active": "_rpc_sessions_active",
        "sessions.create": "_rpc_sessions_create",
        "sessions.switch": "_rpc_sessions_switch",
        "sessions.delete": "_rpc_sessions_delete",
        "sessions.search": "_rpc_sessions_search",
        "sessions.export": "_rpc_sessions_export",
        "skills.toggle": "_rpc_skills_toggle",
        "skills.content": "_rpc_skills_content",
        "skills.hub.search": "_rpc_skills_hub_search",
        "skills.hub.install": "_rpc_skills_hub_install",
        "skills.hub.uninstall": "_rpc_skills_hub_uninstall",
        "agent.status": "_rpc_agent_status",
        "agent.set_model": "_rpc_agent_set_model",
        "usage.get": "_rpc_usage_get",
        "cron.notes": "_rpc_cron_notes",
        "cron.notes.capabilities": "_rpc_cron_notes_capabilities",
        "cron.notes.set": "_rpc_cron_notes_set",
        "cron.notes.delete": "_rpc_cron_notes_delete",
        "cron.create": "_rpc_cron_create",
        "cron.capabilities": "_rpc_cron_capabilities",
        "cron.edit": "_rpc_cron_edit",
        "cron.delete": "_rpc_cron_delete",
        "cron.runs": "_rpc_cron_runs",
        "cron.profiles": "_rpc_cron_profiles",
        "runs.start": "_rpc_runs_start",
        "runs.stop": "_rpc_runs_stop",
        "approval.resolve": "_rpc_approval_resolve",
        "connector.capabilities": "_rpc_connector_capabilities",
        "connector.health": "_rpc_connector_health",
        "connector.test": "_rpc_connector_test",
        "connector.reconnect": "_rpc_connector_reconnect",
        "approvals.list": "_rpc_approvals_list",
        "memory.list": "_rpc_memory_list",
        "memory.delete": "_rpc_memory_delete",
        "memory.pending": "_rpc_memory_pending",
        "memory.approve": "_rpc_memory_approve",
        "memory.reject": "_rpc_memory_reject",
        "skills.pending": "_rpc_skills_pending",
        "skills.approve": "_rpc_skills_pending_approve",
        "skills.reject": "_rpc_skills_pending_reject",
        "skills.diff": "_rpc_skills_pending_diff",
        "chat.stop": "_rpc_chat_stop",
        "bots.list": "_rpc_bots_list",
        "bots.capabilities": "_rpc_bots_capabilities",
        "bots.activity.snapshot": "_rpc_bots_activity_snapshot",
        "bots.notify.get": "_rpc_bots_notify_get",
        "bots.notify.set": "_rpc_bots_notify_set",
        "bots.open": "_rpc_bots_open",
        "bots.send": "_rpc_bots_send",
        "bots.stop": "_rpc_bots_stop",
        "bots.close": "_rpc_bots_close",
        "bots.history": "_rpc_bots_history",
        "bots.subagents.list": "_rpc_bots_subagents_list",
        "bots.subagents.tail": "_rpc_bots_subagents_tail",
        "bots.subagents.steer": "_rpc_bots_subagents_steer",
        "bots.subagents.interrupt": "_rpc_bots_subagents_interrupt",
        "rooms.capabilities": "_rpc_rooms_capabilities",
        "rooms.list": "_rpc_rooms_list",
        "rooms.create": "_rpc_rooms_create",
        "rooms.open": "_rpc_rooms_open",
        "rooms.send": "_rpc_rooms_send",
        "rooms.log": "_rpc_rooms_log",
        "rooms.stop": "_rpc_rooms_stop",
        "rooms.approve": "_rpc_rooms_approve",
        "rooms.close": "_rpc_rooms_close",
    }

    def __init__(self, host: Any):
        self._host = host
        self._seen_rpc_ids: Dict[str, float] = {}

    async def dispatch(self, payload: Dict[str, Any]) -> None:
        rpc = payload.get("rpc") or {}
        rpc_id = rpc.get("id", "")
        method = rpc.get("method", "")
        params = rpc.get("params") or {}

        if self._is_duplicate(rpc_id):
            logger.debug("[hermes_bridge] rpc %s duplicate — skipping (dedup)", rpc_id)
            return

        handler = self._handler(method)
        if handler is None:
            await self._host._send_rpc_response(rpc_id, ok=False, error="method_not_found")
            return

        try:
            data = await handler(params)
            await self._host._send_rpc_response(rpc_id, ok=True, data=data)
        except _RpcError as exc:
            await self._host._send_rpc_response(rpc_id, ok=False, error=str(exc))
        except urllib.error.HTTPError as exc:
            logger.warning("[hermes_bridge] rpc %s failed: HTTP %d", method, exc.code)
            error = "hermes_auth_failed" if exc.code in (401, 403) else _http_error_detail(exc)
            await self._host._send_rpc_response(rpc_id, ok=False, error=error)
        except Exception as exc:
            logger.warning(
                "[hermes_bridge] rpc %s failed: %s — %s", method, type(exc).__name__, exc
            )
            error = self._classify_error(exc)
            await self._host._send_rpc_response(rpc_id, ok=False, error=error)

    def _is_duplicate(self, rpc_id: Any) -> bool:
        if not rpc_id:
            return False
        loop = asyncio.get_event_loop()
        now = loop.time()
        duplicate = rpc_id in self._seen_rpc_ids
        self._seen_rpc_ids[rpc_id] = now
        cutoff = now - _RPC_DEDUP_WINDOW_S
        self._seen_rpc_ids = {
            key: received_at
            for key, received_at in self._seen_rpc_ids.items()
            if received_at >= cutoff
        }
        return duplicate

    def _handler(self, method: str) -> Optional[Callable[[Dict[str, Any]], Awaitable[Any]]]:
        host = self._host
        direct_name = self._HANDLER_NAMES.get(method)
        if direct_name:
            return getattr(host, direct_name, None)

        simple = {
            "skills.list": lambda p: host._api.get("/api/skills"),
            "skills.hub.update": lambda p: host._api.post("/api/skills/hub/update", body={}),
            "model.options": lambda p: host._api.get("/api/model/options"),
            "cron.list": lambda p: host._rpc_cron_list(p),
            "cron.pause": lambda p: host._rpc_cron_action(p, "pause"),
            "cron.resume": lambda p: host._rpc_cron_action(p, "resume"),
            "cron.trigger": lambda p: host._rpc_cron_action(p, "trigger"),
        }.get(method)
        return simple

    @staticmethod
    def _classify_error(exc: Exception) -> str:
        err_str = str(exc).lower()
        if "refused" in err_str or "no hermes api port reachable" in err_str or "timed out" in err_str:
            return "hermes_offline"
        if "401" in err_str or "unauthorized" in err_str or "auth" in err_str:
            return "hermes_auth_failed"
        return "hermes_api_unavailable"
