# Queued-admission steer/replace for laptop-owned sessions (#150).
# Surfaces owner pending rows on session.control.read; forwards verbs to the
# canonical owner without raising the private-import count.

"""Steer or replace a still-queued admission on a laptop-owned session.

Owners list ``controls`` on pending rows (``prompt.steer_queued`` /
``prompt.replace_queued``). Phone-native ``hermes_bridge`` sessions never get
those verbs; only local-owned sessions the phone continues through
``local_owner`` do. Older hosts without ``controls`` / the verbs degrade to
today's behaviour (empty list / mapped refusals).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, Dict, List, Optional

from . import local_owner
from .operation_dispatch import _RpcError
from .session_continue import is_local_owned_session

logger = logging.getLogger(__name__)

STEER_REFUSALS = frozenset({
    "admission_started",
    "session_idle",
    "steer_unavailable",
    "unsupported_control",
    "not_found",
})
REPLACE_REFUSALS = frozenset({
    "admission_started",
    "admission_conflict",
    "queue_full",
    "unsupported_control",
    "not_found",
})
_CONTROL_VERBS = frozenset({"steer", "replace"})


def project_pending(pending: Any) -> List[Dict[str, Any]]:
    """Project owner pending rows to the phone shape (admission_id, text, controls)."""
    out: List[Dict[str, Any]] = []
    if not isinstance(pending, list):
        return out
    for row in pending:
        if not isinstance(row, dict):
            continue
        admission_id = row.get("admission_id")
        text = row.get("text")
        if not isinstance(admission_id, str) or not admission_id:
            continue
        if not isinstance(text, str):
            continue
        status = row.get("status")
        # Queued rows plus steers still bound to the running turn (started + steering).
        if status != "queued" and not (status == "started" and row.get("steering") is True):
            continue
        controls_raw = row.get("controls")
        controls: List[str] = []
        if isinstance(controls_raw, list):
            controls = [c for c in controls_raw if isinstance(c, str) and c in _CONTROL_VERBS]
        item: Dict[str, Any] = {
            "admission_id": admission_id,
            "text": text,
            "controls": controls,
        }
        input_id = row.get("input_id")
        if isinstance(input_id, str) and input_id:
            item["input_id"] = input_id
        out.append(item)
    return out


async def read_queued(host: Any, session_id: str, profile: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    """Pending admissions for a local-owned session, or None when not applicable.

    None means the caller should omit ``queued`` (phone-native / non-local). An
    empty list means the owner answered and currently has none.
    """
    if not is_local_owned_session(session_id):
        return None
    try:
        async with host._connect_local_owner(profile) as client:
            snap = await client.rpc(
                "session.resume", session_id=session_id, omit_messages=True
            )
    except Exception as exc:
        logger.debug(
            "[hermes_bridge] queued admissions unavailable for %s: %s",
            session_id,
            type(exc).__name__,
        )
        return []
    if not isinstance(snap, dict):
        return []
    return project_pending(snap.get("pending"))


def _owner_refusal(exc: Exception, refusals: frozenset) -> str:
    """Map a GatewayRPCError (or lookalike) to a stable refusal code."""
    reason = str(exc)
    data = getattr(exc, "data", None)
    if isinstance(data, dict):
        named = data.get("reason")
        if isinstance(named, str) and named:
            reason = named
    if reason in refusals:
        return reason
    return "unsupported_control" if reason == "method_not_found" else "owner_unavailable"


async def steer(host: Any, p: Dict[str, Any]) -> Any:
    """Forward ``prompt.steer_queued`` for a laptop-owned session."""
    session_id = p.get("id")
    admission_id = p.get("admission_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise _RpcError("missing_session_id")
    if not isinstance(admission_id, str) or not admission_id.strip():
        raise _RpcError("not_found")
    if not is_local_owned_session(session_id):
        raise _RpcError("unsupported_control")
    profile = await host._resolve_core_profile(p.get("core_profile"))
    try:
        async with host._connect_local_owner(profile) as client:
            attached = await client.rpc(
                "session.resume", session_id=session_id, omit_messages=True
            )
            target = attached.get("session_id") if isinstance(attached, dict) else None
            if not isinstance(target, str) or not target:
                raise _RpcError("not_found")
            return await client.rpc(
                "prompt.steer_queued",
                session_id=target,
                admission_id=admission_id.strip(),
            )
    except _RpcError:
        raise
    except Exception as exc:
        raise _RpcError(_owner_refusal(exc, STEER_REFUSALS)) from exc


async def replace(host: Any, p: Dict[str, Any]) -> Any:
    """Forward ``prompt.replace_queued`` for a laptop-owned session."""
    session_id = p.get("id")
    admission_id = p.get("admission_id")
    text = p.get("text")
    if not isinstance(session_id, str) or not session_id.strip():
        raise _RpcError("missing_session_id")
    if not isinstance(admission_id, str) or not admission_id.strip():
        raise _RpcError("not_found")
    if not isinstance(text, str) or not text.strip():
        raise _RpcError("not_found")
    if not is_local_owned_session(session_id):
        raise _RpcError("unsupported_control")
    profile = await host._resolve_core_profile(p.get("core_profile"))
    # Idempotent for the same edit of the same admission (owner binds on submission_id).
    digest = hashlib.sha256(text.strip().encode()).hexdigest()[:24]
    request_id = local_owner.submission_id(
        host._profile_id, session_id, f"replace:{admission_id.strip()}:{digest}"
    )
    try:
        async with host._connect_local_owner(profile) as client:
            attached = await client.rpc(
                "session.resume", session_id=session_id, omit_messages=True
            )
            target = attached.get("session_id") if isinstance(attached, dict) else None
            if not isinstance(target, str) or not target:
                raise _RpcError("not_found")
            receipt = await client.rpc(
                "prompt.replace_queued",
                session_id=target,
                admission_id=admission_id.strip(),
                submission_id=request_id,
                text=text.strip(),
            )
            # Replacement retires the original watcher; follow the new admission
            # without submitting again (gateway/session_queued_controls.py).
            ready = asyncio.Event()
            payload = {"session_id": session_id, "msg_id": receipt["admission_id"], "content": text.strip()}
            tasks = getattr(host, "_local_owner_tasks", None)
            if tasks is None:
                tasks = host._local_owner_tasks = {}
            if request_id not in tasks:
                tasks[request_id] = asyncio.create_task(
                    host._run_local_owner(payload, profile, request_id, ready, receipt)
                )
            return receipt
    except _RpcError:
        raise
    except Exception as exc:
        raise _RpcError(_owner_refusal(exc, REPLACE_REFUSALS)) from exc
