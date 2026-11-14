"""kanban.op laptop executor — sealed RPC receiver (PRD_Inbox_Kanban.md §2.1/§4).

GitLab #156. Phone ops that reach the bridge have already been admitted by the
sealed-frame path: ``adapter._read_frame`` decrypts with ``crypto.open`` (PSK,
nonce-replay dedup) before anything is classified, so a handler only ever sees
the decrypted ``rpc.request`` body, and an unauthorized or tampered frame never
reaches this module. What this module owns is the op contract:

* params are validated exactly like ``lib/kanban-wire.ts`` ``validateOpBody``
  (v/kind envelope, op_id / idempotency_key / client_seq shape, default-deny
  op allowlist with a named ``admin_op_rejected`` code),
* each op runs once: a persistent writer-side ledger keyed by ``op_id``
  replays the recorded ack without re-invoking the board tool, and a mutation
  whose earlier execution never settled is answered with a terminal
  ``kanban_outcome_unknown`` ack instead of a silent re-execution (create is
  non-idempotent, PRD §2.1.5),
* execution calls Hermes' own registered ``kanban_<name>`` tool handler
  directly (``DirectKanbanExecutor``) — the same code an agent's tool call
  runs, minus the model — and the handler's structured JSON result decides the
  ack,
* acks mirror ``lib/kanban-wire.ts`` Ack bodies with a mandatory ``op_id``
  echo and are delivered in order: this receiver holds one asyncio lock so
  execution and acks are strictly serialized per adapter.

Timeouts: the receiver answers within ``DEFAULT_EXECUTOR_TIMEOUT_S``, which
stays below the relay's synchronous RPC bound (``RPC_REPLY_TIMEOUT_MS`` in
``app/api/relay/message+api.ts``) so the phone hears the laptop's answer rather
than a relay 504. An op still running at that bound raises
``KanbanOpExecutionTimeout`` (adapter: ``executor_timeout`` rpc error, which the
phone's queue retries), but the execution keeps running and settles the ledger
when it lands. A retry of the same op_id waits for that execution instead of
re-running it or calling it unknown, so a slow-but-successful op is reported
as the success it was. Only an execution that ends ambiguously stays
``pending``: the same op_id replayed later gets ``kanban_outcome_unknown`` for
mutations and a fresh execution for read-only ops.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from . import bot_notify

logger = logging.getLogger(__name__)

# Mirror of lib/kanban-wire.ts KANBAN_OPS (keep in sync; that file is the
# contract). User-facing kanban tools with the ``kanban_`` prefix stripped;
# attach (base64 bytes) and internal hooks stay off the wire.
KANBAN_OPS: Tuple[str, ...] = (
    "list",
    "show",
    "create",
    "comment",
    "complete",
    "block",
    "unblock",
    "request_review",
    "request_changes",
    "link",
    "heartbeat",
    "attach_url",
    "attachments",
    "schedule",
    "update",
)
_OP_SET = frozenset(KANBAN_OPS)

# Ops that only read the board: an unsettled earlier attempt of one of these
# may be re-executed. Everything else may mutate, so an unsettled attempt is
# answered with kanban_outcome_unknown (locked decision #3, issue #156).
READONLY_OPS = frozenset({"list", "show", "heartbeat", "attachments"})

_ACK_ROLE = "kanban.ack"
_MAX_ERROR_CHARS = 400
# How long one rpc request waits for its op (locked decision #2: bounded, never
# hangs the request). Must stay below the relay's RPC_REPLY_TIMEOUT_MS (12 s,
# app/api/relay/message+api.ts), itself below the phone's POST abort (15 s,
# lib/kanban-op-send.ts), so the laptop's answer always reaches the phone. A
# direct tool call settles in well under a second; an op that misses this bound
# keeps running and settles the ledger for the phone's retry.
DEFAULT_EXECUTOR_TIMEOUT_S = 8.0
_LEDGER_MAX_ENTRIES = 500


class KanbanOpTransportError(Exception):
    """The request body carries no usable op_id — reply as an rpc error."""


class KanbanOpExecutionTimeout(Exception):
    """The op did not settle within the receiver's bound — retryable."""


def _plain_object(value: Any) -> bool:
    return isinstance(value, dict)


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def is_admin_op(op: str) -> bool:
    """Admin surfaces stay desktop-only (lib/kanban-wire.ts isAdminOp)."""
    return (
        op.startswith("board_")
        or op.startswith("tenant_")
        or op.startswith("slug_")
        or "admin" in op
    )


def _validate_op_body(params: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Return None for a valid OpRequest body, else (code, message).

    Mirrors lib/kanban-wire.ts validateOpBody: envelope first, then field
    shapes, then the default-deny op allowlist with a named admin code.
    """
    if params.get("v") != 1:
        return ("malformed", "v must be 1")
    if params.get("kind") != "kanban.op":
        return ("malformed", 'kind must be "kanban.op"')
    if not _non_empty_string(params.get("op_id")):
        return ("malformed", "op_id must be a non-empty string")
    if not _non_empty_string(params.get("idempotency_key")):
        return ("malformed", "idempotency_key must be a non-empty string")
    client_seq = params.get("client_seq")
    if isinstance(client_seq, bool) or not isinstance(client_seq, int) or client_seq < 0:
        return ("malformed", "client_seq must be a non-negative integer")
    op = params.get("op")
    if not isinstance(op, str):
        return ("malformed", "op must be a string")
    if is_admin_op(op):
        return ("admin_op_rejected", f'admin op "{op}" is not available on the phone')
    if op not in _OP_SET:
        return ("unknown_op", f'unknown op "{op}"')
    if not _plain_object(params.get("args")):
        return ("malformed", "args must be a plain JSON object")
    return None


def op_card_id(args: Dict[str, Any]) -> Optional[str]:
    """The card id a kanban op targets, or None (lib/kanban-wire.ts opCardId)."""
    value = args.get("task_id")
    return value if _non_empty_string(value) else None


def ack_ok(op_id: str, version: int) -> Dict[str, Any]:
    """AckOk mirrored from lib/kanban-wire.ts (board/task ids ride the tool call)."""
    return {"v": 1, "kind": _ACK_ROLE, "op_id": op_id, "ok": True, "version": int(version)}


def ack_error(op_id: str, code: str, message: str) -> Dict[str, Any]:
    """AckError mirrored from lib/kanban-wire.ts (error kind + message)."""
    return {
        "v": 1,
        "kind": _ACK_ROLE,
        "op_id": op_id,
        "ok": False,
        "error": {"code": code, "message": str(message)[:_MAX_ERROR_CHARS]},
    }


def ledger_path(profile_id: str) -> str:
    """Bridge-local durable state, beside the other per-profile bridge state."""
    return os.path.join(bot_notify._STATE_DIR, f"kanban_op_ledger_{profile_id}.json")


class KanbanOpLedger:
    """Persistent op_id -> settled-ack store (writer-side, per bridge profile).

    Terminal records (``status`` ok/error) carry the exactly-delivered ack so
    a duplicate op replays it without invoking the board tool. ``pending``
    records mark an attempted-but-unsettled execution (crash, gateway loss,
    timeout) and are what mutation ops may never silently re-execute.
    """

    def __init__(self, path: str):
        self._path = path
        self._entries: Dict[str, Dict[str, Any]] = {}

    def load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if not isinstance(raw, dict):
                raise ValueError("expected an object")
        except (OSError, ValueError, json.JSONDecodeError):
            logger.debug("[hermes_bridge] kanban op ledger unavailable: %s", self._path)
            self._entries = {}
            return
        entries: Dict[str, Dict[str, Any]] = {}
        for op_id, entry in raw.items():
            if _non_empty_string(op_id) and _plain_object(entry) and entry.get("status") in (
                "pending",
                "ok",
                "error",
            ):
                entries[op_id] = entry
        self._entries = entries

    def save(self) -> None:
        if len(self._entries) > _LEDGER_MAX_ENTRIES:
            kept: Dict[str, Dict[str, Any]] = {}
            for op_id, entry in self._entries.items():
                if entry.get("status") == "pending":
                    kept[op_id] = entry
            for op_id, entry in self._entries.items():
                if entry.get("status") != "pending" and len(kept) < _LEDGER_MAX_ENTRIES:
                    kept.setdefault(op_id, entry)
            self._entries = kept
        target = self._path
        temporary = f"{target}.tmp"
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(self._entries, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except OSError as exc:
            logger.debug("[hermes_bridge] failed to persist kanban op ledger: %s", exc)
            try:
                os.unlink(temporary)
            except OSError:
                pass

    def get(self, op_id: str) -> Optional[Dict[str, Any]]:
        entry = self._entries.get(op_id)
        return dict(entry) if isinstance(entry, dict) else None

    @property
    def entries(self) -> Dict[str, Dict[str, Any]]:
        return self._entries

    def record_pending(self, op_id: str, op_name: str, task_id: Optional[str]) -> None:
        self._entries[op_id] = {
            "op": op_name,
            "task_id": task_id,
            "status": "pending",
            "ack": None,
            "settled_at": None,
        }
        self.save()

    def settle(self, op_id: str, ack: Dict[str, Any]) -> Dict[str, Any]:
        entry = self._entries.setdefault(
            op_id, {"op": None, "task_id": None, "status": "pending", "ack": None}
        )
        entry["status"] = "ok" if ack.get("ok") is True else "error"
        entry["ack"] = dict(ack)
        entry["settled_at"] = time.time()
        self.save()
        return entry


class KanbanOpReceiver:
    """Validates, dedupes, executes and acks one kanban.op RPC payload.

    ``executor`` is a seam: ``async execute(op) -> outcome`` with the outcome
    contract below. Production uses ``DirectKanbanExecutor``; tests inject a
    fake. ``version_fn`` reads the board snapshot (run off-thread when the
    receiver needs the ok ack version); ``on_mutated`` is the cheap
    snapshot-refresh tick the adapter provides so board state follows an ack
    fast.
    """

    def __init__(
        self,
        executor: Any,
        *,
        ledger: KanbanOpLedger,
        version_fn: Optional[Callable[[], Any]] = None,
        on_mutated: Optional[Callable[[], Awaitable[Any]]] = None,
        timeout_s: float = DEFAULT_EXECUTOR_TIMEOUT_S,
    ):
        self._executor = executor
        self._ledger = ledger
        self._version_fn = version_fn
        self._on_mutated = on_mutated
        self._timeout_s = timeout_s
        self._loaded = False
        self._lock = asyncio.Lock()
        # Executions whose rpc answer timed out but which are still running.
        self._inflight: Dict[str, "asyncio.Future[Dict[str, Any]]"] = {}

    async def handle(self, params: Dict[str, Any]) -> Dict[str, Any]:
        if not _plain_object(params):
            raise KanbanOpTransportError("malformed_request")
        if not self._loaded:
            self._ledger.load()
            self._loaded = True
        problem = _validate_op_body(params)
        op_id = params.get("op_id")
        if problem is not None:
            if _non_empty_string(op_id):
                return ack_error(str(op_id), problem[0], problem[1])
            raise KanbanOpTransportError(problem[0])
        # A body that passed _validate_op_body has a non-empty-string op_id.
        op_id = str(op_id)

        async with self._lock:
            replayed = self._ledger.get(op_id)
            if replayed and replayed.get("status") in ("ok", "error"):
                # Terminal record: replay the recorded ack without invoking
                # the board tool (tool-invoked-once acceptance).
                stored = replayed.get("ack")
                if isinstance(stored, dict):
                    return {str(key): value for key, value in stored.items()}
                return ack_error(op_id, "executor_failed", "unsettled ledger record")
            running = self._inflight.get(op_id)
            if running is not None and not running.done():
                # A retry of an op whose earlier answer timed out while it kept
                # running: wait for that execution's real outcome rather than
                # re-running it or calling it unknown.
                return await self._await_settled(op_id, running)
            if replayed and replayed.get("status") == "pending" and params.get("op") not in READONLY_OPS:
                return self._settle_outcome_unknown(op_id)

            # Strict order: a later op never overtakes one still running.
            await self._wait_for_inflight()
            op_name = params.get("op")
            task_id = op_card_id(params.get("args") or {})
            self._ledger.record_pending(op_id, op_name, task_id)
            execution = asyncio.ensure_future(self._execute_and_settle(op_id, dict(params)))
            self._inflight[op_id] = execution
            execution.add_done_callback(lambda done, key=op_id: self._forget(key, done))
            return await self._await_settled(op_id, execution)

    async def _await_settled(
        self, op_id: str, execution: "asyncio.Future[Dict[str, Any]]"
    ) -> Dict[str, Any]:
        """The execution's ack, or a retryable timeout while it keeps running."""
        try:
            return await asyncio.wait_for(asyncio.shield(execution), timeout=self._timeout_s)
        except asyncio.TimeoutError:
            logger.warning(
                "[hermes_bridge] kanban.op %s still running after %.1fs; its outcome "
                "settles the ledger for the retry",
                op_id,
                self._timeout_s,
            )
            raise KanbanOpExecutionTimeout() from None

    async def _wait_for_inflight(self) -> None:
        """Bounded wait for executions whose rpc answer already timed out."""
        for execution in list(self._inflight.values()):
            if execution.done():
                continue
            try:
                await asyncio.wait_for(asyncio.shield(execution), timeout=self._timeout_s)
            except asyncio.TimeoutError:
                # Nothing recorded for the new op yet: a plain retryable error.
                raise KanbanOpExecutionTimeout() from None
            except Exception:  # noqa: BLE001 — that op's own outcome is in the ledger
                pass

    def _forget(self, op_id: str, execution: "asyncio.Future[Dict[str, Any]]") -> None:
        if self._inflight.get(op_id) is execution:
            del self._inflight[op_id]
        # Retrieve a late failure nobody awaited, so asyncio does not log it.
        if not execution.cancelled():
            execution.exception()

    async def _execute_and_settle(self, op_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run one op to completion and record its ack (or leave it pending)."""
        try:
            outcome = await self._executor.execute(params)
        except Exception as exc:  # noqa: BLE001 — executor blew up mid-call
            logger.warning(
                "[hermes_bridge] kanban.op %s executor raised %s: %s",
                op_id,
                type(exc).__name__,
                exc,
            )
            # Outcome unknown: the ledger keeps it pending so a mutation is
            # never silently re-executed.
            raise KanbanOpExecutionTimeout() from None

        if not _plain_object(outcome):
            outcome = {"settled": False, "committed": True}

        entry = self._ledger.get(op_id)
        if outcome.get("settled"):
            if outcome.get("ok") is True:
                version = int(outcome.get("version") or 0) or await self.board_version()
                ack = ack_ok(op_id, version)
            else:
                ack = self._build_error_ack(op_id, outcome)
            self._ledger.settle(op_id, ack)
            await self._maybe_tick(entry)
            return ack

        if outcome.get("committed") is False:
            # Refused before any commit: provably nothing ran.
            ack = ack_error(
                op_id,
                str(outcome.get("code") or "executor_unavailable"),
                str(outcome.get("message") or "executor did not run the op"),
            )
            self._ledger.settle(op_id, ack)
            return ack

        # Ran but ambiguous: leave pending, transport-retryable error.
        logger.warning(
            "[hermes_bridge] kanban.op %s left unsettled (%s)",
            op_id,
            outcome.get("code") or "unknown",
        )
        raise KanbanOpExecutionTimeout()

    def _settle_outcome_unknown(self, op_id: str) -> Dict[str, Any]:
        ack = ack_error(
            op_id,
            "kanban_outcome_unknown",
            "an earlier execution of this op did not settle; it was not re-executed. "
            "Check the board state and decide the action again.",
        )
        self._ledger.settle(op_id, ack)
        return ack

    @staticmethod
    def _build_error_ack(op_id: str, outcome: Dict[str, Any]) -> Dict[str, Any]:
        code = str(outcome.get("code") or "executor_failed")
        if code not in ("tool_failed", "executor_failed", "executor_unavailable"):
            code = "executor_failed"
        return ack_error(op_id, code, str(outcome.get("message") or "executor failed"))

    async def _maybe_tick(self, entry: Optional[Dict[str, Any]]) -> None:
        """Cheap snapshot refresh after a settled mutating op (touched the board)."""
        if self._on_mutated is None or not isinstance(entry, dict):
            return
        if entry.get("op") in READONLY_OPS or entry.get("op") is None:
            return
        try:
            await self._on_mutated()
        except Exception as exc:
            logger.debug("[hermes_bridge] kanban snapshot tick after op failed: %s", exc)

    async def board_version(self, default: int = 0) -> int:
        """Fresh board version (read-only kanban.db read), or ``default``."""
        if self._version_fn is None:
            return default
        try:
            snapshot = await asyncio.to_thread(self._version_fn)
        except FileNotFoundError:
            return default
        except Exception as exc:
            logger.debug("[hermes_bridge] kanban board version unavailable: %s", exc)
            return default
        if isinstance(snapshot, dict) and isinstance(snapshot.get("version"), int):
            return snapshot["version"]
        return default


class DirectKanbanExecutor:
    """Real seam: the op runs through Hermes' own registered kanban tool.

    ``tools.registry.registry.dispatch("kanban_<op>", args)`` is the code path
    an agent's tool call takes (argument checks, board resolution, author
    identity from the gateway's profile), without a model in the loop: no
    executor session, no prompt, no receipt to reverse-engineer. The handlers
    are synchronous SQLite work, so the call runs off the event loop and
    settles in well under a second.
    """

    async def execute(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Run ``op``; map the tool's JSON result onto the outcome contract.

        ``{"settled": bool, "committed": bool|None, "ok": bool, "code": str,
        "message": str}`` — settled outcomes become ledger-replayed acks;
        committed-False means provably nothing ran; an unreadable result stays
        pending and surfaces as a retryable transport error.
        """
        tool = f"kanban_{op.get('op')}"
        args = dict(op.get("args") or {})
        raw = await asyncio.to_thread(_dispatch_kanban_tool, tool, args)
        if raw is None:
            return {
                "settled": False,
                "committed": False,
                "code": "executor_unavailable",
                "message": "this Hermes has no kanban tools to run the op",
            }
        return classify_tool_result(raw)


def _dispatch_kanban_tool(tool: str, args: Dict[str, Any]) -> Optional[Any]:
    """``registry.dispatch`` for one kanban tool; None when the host lacks it.

    Private Hermes surface (see PRIVATE_IMPORTS.md), imported lazily: importing
    ``tools.kanban_tools`` registers the ``kanban_*`` handlers.
    """
    try:
        import tools.kanban_tools  # noqa: F401
        from tools.registry import registry
    except Exception as exc:  # noqa: BLE001 — any import failure means "unavailable"
        _warn_private_import("tools.kanban_tools / tools.registry", exc)
        return None
    dispatch = getattr(registry, "dispatch", None)
    if not callable(dispatch):
        _warn_private_import("tools.registry.dispatch", AttributeError("dispatch"))
        return None
    return dispatch(tool, args)


def classify_tool_result(raw: Any) -> Dict[str, Any]:
    """Kanban tool result -> outcome. Handlers answer JSON: ``{"error": ...}``
    (``tool_error``, nothing changed) or a success object."""
    payload: Any = raw
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = None
    if not _plain_object(payload):
        return {
            "settled": False,
            "committed": True,
            "code": "executor_failed",
            "message": "unreadable kanban tool result",
        }
    error = payload.get("error")
    if error:
        return _failed("tool_failed", str(error))
    return {"settled": True, "committed": True, "ok": True, "code": None, "message": ""}


def _failed(code: str, message: str) -> Dict[str, Any]:
    return {"settled": True, "committed": True, "ok": False, "code": code, "message": message}


def _warn_private_import(module: str, exc: Exception) -> None:
    try:
        from .adapter import _warn_private_import_once

        _warn_private_import_once(module, exc)
    except Exception:
        logger.debug("[hermes_bridge] private Hermes helper %s unavailable", module)
