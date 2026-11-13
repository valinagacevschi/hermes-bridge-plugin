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
* execution is one deterministic single-turn prompt to a dedicated executor
  session on the adapter's own gateway profile (``prompt.submit`` ->
  ``prompt.receipt`` include_result), with the code — not the model —
  authoritative: the receipt must contain a ``tool_use`` for the mandated
  ``kanban_<name>`` tool with exactly the sent args, and the final response
  must not report a failure,
* acks mirror ``lib/kanban-wire.ts`` Ack bodies with a mandatory ``op_id``
  echo and are delivered in order: this receiver holds one asyncio lock so
  execution and acks are strictly serialized per adapter.

Timeouts and ambiguous submissions are transport-style errors, not acks: the
receiver raises ``KanbanOpExecutionTimeout``, which the adapter maps to an
``executor_timeout`` rpc error — a failure the phone's queue marks retryable
(a real ack or nothing, never a guessed success). The unsettled attempt stays
``pending`` in the ledger, so the same op_id replayed later gets
``kanban_outcome_unknown`` for mutations and a fresh execution for read-only
ops.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from . import bot_notify, local_owner

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

_EXECUTOR_TITLE = "kanban-executor"
_ACK_ROLE = "kanban.ack"
_MAX_ERROR_CHARS = 400
# Receiver-side bound for one executor turn. Bounded, never hangs the rpc
# request (locked decision #2). The phone's own rpc wait is far shorter; a
# turn that misses this bound stays pending and the op resolves per the
# ledger rules above.
DEFAULT_EXECUTOR_TIMEOUT_S = 90.0
# Interval between prompt.receipt polls.
_RECEIPT_POLL_S = 0.5
_LEDGER_MAX_ENTRIES = 500


class KanbanOpTransportError(Exception):
    """The request body carries no usable op_id — reply as an rpc error."""


class KanbanOpExecutionTimeout(Exception):
    """The executor turn did not settle within its bound — retryable."""


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
    contract below. Production uses ``GatewayKanbanExecutor``; tests inject a
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
            if replayed and replayed.get("status") == "pending" and params.get("op") not in READONLY_OPS:
                return self._settle_outcome_unknown(op_id)

            op_name = params.get("op")
            task_id = op_card_id(params.get("args") or {})
            self._ledger.record_pending(op_id, op_name, task_id)
            try:
                outcome = await asyncio.wait_for(
                    self._executor.execute(dict(params)), timeout=self._timeout_s
                )
            except asyncio.TimeoutError:
                # The gateway turn may still run; the ledger keeps it pending so
                # a mutation is never silently re-executed behind our back.
                logger.warning("[hermes_bridge] kanban.op %s executor turn timed out", op_id)
                raise KanbanOpExecutionTimeout() from None
            except Exception as exc:  # noqa: BLE001 — executor blew up mid-call
                logger.warning(
                    "[hermes_bridge] kanban.op %s executor raised %s: %s",
                    op_id,
                    type(exc).__name__,
                    exc,
                )
                # Outcome unknown — same conservative treatment as a timeout.
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

            # Submitted but ambiguous: leave pending, transport-retryable error
            # (same conservative semantics as the bounded-wait timeout above).
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


class GatewayKanbanExecutor:
    """Real seam: one deterministic single-turn prompt on the owner gateway.

    A dedicated ``kanban-executor`` session on the adapter's own gateway
    profile (``session.create`` with the title resolves-or-creates under the
    owner's lock). The prompt mandates exactly one tool call; verification of
    the committed receipt — not the model's word — decides the outcome.
    """

    def __init__(self, profile_id: str):
        self._profile_id = profile_id
        self._cached_executor_session: Optional[str] = None

    async def execute(self, op: Dict[str, Any]) -> Dict[str, Any]:
        """Run ``op``; classify the receipt into the outcome contract.

        ``{"settled": bool, "committed": bool|None, "ok": bool, "code": str,
        "message": str}`` — settled outcomes become ledger-replayed acks;
        committed-False means provably nothing ran; anything ambiguous stays
        pending and surfaces as a retryable transport error.
        """
        op_id = str(op.get("op_id") or "")
        op_name = str(op.get("op") or "")
        tool = f"kanban_{op_name}"
        args = op.get("args") or {}
        from_context: Optional[BaseException] = None
        try:
            async with local_owner.connect(None, _warn_private_import) as client:
                target = await self._ensure_executor_session(client)
                submission = local_owner.submission_id(self._profile_id, _EXECUTOR_TITLE, op_id)
                receipt = await local_owner.submit(
                    client, target, _executor_prompt(tool, args, op_id), submission,
                    _warn_private_import,
                )
                admission = receipt["admission_id"]
                while True:
                    receipt = await client.rpc(
                        "prompt.receipt",
                        session_id=target,
                        admission_id=admission,
                        include_result=True,
                    )
                    if isinstance(receipt, dict) and receipt.get("status") == "terminal":
                        break
                    await asyncio.sleep(_RECEIPT_POLL_S)
                return self._classify_receipt(receipt, tool, args)
        except local_owner.OwnerUnconfirmed as exc:
            from_context = exc
        except Exception as exc:  # noqa: BLE001 — classified by _committed_before_submit
            from_context = exc
        committed = self._committed_before_submit(from_context)
        logger.warning(
            "[hermes_bridge] kanban.op %s executor unavailable (%s, committed=%s)",
            op_id,
            type(from_context).__name__ if from_context else "?",
            committed,
        )
        return {
            "settled": False,
            "committed": committed,
            "code": "executor_unavailable",
            "message": f"kanban executor turn could not start: {_brief(from_context)}",
        }

    async def _ensure_executor_session(self, client: Any) -> str:
        """Resolve-or-create the dedicated session, then resume its runtime id."""
        stored: Optional[str] = None
        try:
            created = await client.rpc(
                "session.create", request_id=uuid.uuid4().hex, title=_EXECUTOR_TITLE
            )
            if isinstance(created, dict):
                stored = created.get("stored_session_id")
        except Exception:
            stored = self._cached_executor_session
        if not isinstance(stored, str) or not stored.strip():
            raise RuntimeError("no kanban-executor session on the owner gateway")
        attached = await client.rpc("session.resume", session_id=stored)
        target = attached.get("session_id") if isinstance(attached, dict) else None
        if not _non_empty_string(target):
            raise RuntimeError("session.resume returned no runtime session id")
        self._cached_executor_session = stored
        return target

    def _committed_before_submit(self, exc: Optional[BaseException]) -> bool:
        """False only for refusals the owner raised before the submit committed."""
        if exc is None:
            return False
        try:
            _, refused, rpc_error, *_ = local_owner._api(_warn_private_import)
        except Exception:
            return True
        if isinstance(exc, rpc_error):
            data = getattr(exc, "data", None)
            reason = data.get("reason") if isinstance(data, dict) else None
            if isinstance(reason, str) and reason in refused:
                return False
        return True

    def _classify_receipt(self, receipt: Dict[str, Any], tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        outcome = receipt.get("outcome")
        if outcome in ("cancelled", "steered", "unknown"):
            return _failed("executor_failed", f"executor turn ended {outcome} (unsettled)")
        result = receipt.get("result")
        if not _plain_object(result):
            return _failed("executor_failed", "executor receipt carried no result")
        error = result.get("error") or result.get("failed")
        if error:
            return _failed("tool_failed", str(error))
        if not _find_mandated_tool_call(result.get("messages"), tool, args):
            return _failed(
                "executor_failed",
                f"executor turn did not call {tool} with the mandated arguments",
            )
        final = str(result.get("final_response") or "").strip()
        if final.lower().startswith("failed"):
            reason = final.split(":", 1)[1].strip() if ":" in final else ""
            return _failed("tool_failed", reason or "executor tool reported failure")
        return {"settled": True, "committed": True, "ok": True, "code": None, "message": ""}


def _failed(code: str, message: str) -> Dict[str, Any]:
    return {"settled": True, "committed": True, "ok": False, "code": code, "message": message}


def _brief(exc: Optional[BaseException]) -> str:
    return (
        f"{type(exc).__name__}: {str(exc)[:_MAX_ERROR_CHARS]}"
        if exc is not None
        else "unknown error"
    )


def _executor_prompt(tool: str, args: Dict[str, Any], op_id: str) -> str:
    return (
        f'Kanban op {op_id}. Reply with only "ok" or "failed: <error>" after you:\n'
        f"call tool {tool} EXACTLY once with EXACTLY these arguments (JSON): "
        f"{json.dumps(args, separators=(',', ':'))}\n"
        "Do not call any other tool and do not ask questions."
    )


def _json_args(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except ValueError:
            return raw
    return raw


def _find_mandated_tool_call(messages: Any, tool: str, args: Dict[str, Any]) -> bool:
    """Whether the turn's history contains the mandated tool_use with these args.

    Accepts both the OpenAI-ish ``tool_calls`` history rows and content-block
    ``tool_use`` entries, so a host-side shape change degrades to a negative
    ack instead of a false positive.
    """
    if not isinstance(messages, list):
        return False
    for message in messages:
        if not isinstance(message, dict):
            continue
        for call in message.get("tool_calls") or []:
            fn = call.get("function") if isinstance(call, dict) else None
            if (
                isinstance(fn, dict)
                and fn.get("name") == tool
                and _json_args(fn.get("arguments")) == args
            ):
                return True
        blocks = message.get("content")
        if not isinstance(blocks, list):
            continue
        for block in blocks:
            if (
                isinstance(block, dict)
                and block.get("type") == "tool_use"
                and block.get("name") == tool
                and block.get("input") == args
            ):
                return True
    return False


def _warn_private_import(module: str, exc: Exception) -> None:
    try:
        from .adapter import _warn_private_import_once

        _warn_private_import_once(module, exc)
    except Exception:
        logger.debug("[hermes_bridge] private Hermes helper %s unavailable", module)
