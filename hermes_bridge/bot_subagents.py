# Bot delegated-child inspection: opaque refs, capability probe, list/tail RPCs.
# Extracted from adapter.py so bot-chat state and phone projection stay cohesive
# instead of growing the adapter further.

"""Opaque Bot-child refs and bots.subagents.* handlers."""

from __future__ import annotations

import secrets
from typing import Any, Dict, Optional, Tuple

from .operation_dispatch import _LocalRpcError, _RpcError

TAIL_LIMIT_BYTES = 16 * 1024
_PROBE_SESSION = "hermlink-capability-probe"
_PROBE_CHILD = "hermlink-capability-probe-child"


def invalidate_refs(refs: Dict[str, Dict[str, Any]], token: str) -> None:
    for ref, target in list(refs.items()):
        if target.get("chat") == token:
            refs.pop(ref, None)


def unavailable_reason(exc: Exception) -> str:
    if isinstance(exc, _LocalRpcError):
        if exc.code == -32601:
            return "unsupported"
        if exc.code == 4001:
            return "owner_unavailable"
    if isinstance(exc, _RpcError) and str(exc) in ("offline", "hermes_offline"):
        return "offline"
    return "unavailable"


def cap_tail_text(text: str, truncated: bool) -> Tuple[str, bool]:
    """Bound tail to Hermes' 16 KiB UTF-8 window so runtimes cannot overrun."""
    encoded = text.encode("utf-8")
    if len(encoded) <= TAIL_LIMIT_BYTES:
        return text, truncated
    return encoded[-TAIL_LIMIT_BYTES:].decode("utf-8", errors="ignore"), True


def _method_supported(exc: Exception) -> Optional[bool]:
    """True if the method exists, False if missing, None if transport blocked."""
    if isinstance(exc, _LocalRpcError):
        return exc.code != -32601
    if isinstance(exc, _RpcError):
        return None
    return None


def local_method_available(method: str) -> Optional[bool]:
    """Read the loaded Hermes contract catalog without sending a control RPC."""
    try:
        from tui_gateway.contracts import METHODS
    except Exception:
        return None
    return method in METHODS


async def ensure_capabilities(host: Any) -> Dict[str, Any]:
    """Probe reads and inspect control contracts once per adapter lifetime."""
    cached = getattr(host, "_subagent_caps", None)
    if cached is not None:
        return cached

    list_available = False
    list_reason: Optional[str] = "unavailable"
    try:
        await host._local_rpc("subagent.list", {"session_id": _PROBE_SESSION})
        list_available = True
        list_reason = None
    except (_LocalRpcError, _RpcError) as exc:
        supported = _method_supported(exc)
        if supported is True:
            list_available = True
            list_reason = None
        elif supported is False:
            list_reason = "unsupported"
        else:
            list_reason = unavailable_reason(exc)

    tail_available = False
    tail_reason: Optional[str] = "unavailable"
    if list_available:
        try:
            await host._local_rpc(
                "subagent.tail",
                {"session_id": _PROBE_SESSION, "subagent_id": _PROBE_CHILD},
            )
            tail_available = True
            tail_reason = None
        except (_LocalRpcError, _RpcError) as exc:
            supported = _method_supported(exc)
            if supported is True:
                tail_available = True
                tail_reason = None
            elif supported is False:
                tail_reason = "unsupported"
            else:
                tail_reason = unavailable_reason(exc)
    else:
        tail_reason = list_reason

    controls = {}
    for action, method in (
        ("steer", "subagent.steer"),
        ("interrupt", "subagent.interrupt"),
    ):
        supported = local_method_available(method)
        controls[action] = {
            "available": supported is True,
            "reason": None
            if supported is True
            else "unsupported"
            if supported is False
            else "unavailable",
        }

    result = {
        "available": list_available,
        "reason": list_reason,
        "tail": {"available": tail_available, "reason": tail_reason},
        "controls": controls,
    }
    host._subagent_caps = result
    return result


async def resume_bot_for_subagents(host: Any, token: str) -> Dict[str, Any]:
    host._require_bots_enabled()
    chat = host._bot_chats.get(token)
    if chat is None:
        raise _RpcError("chat_expired")
    await host._require_bot_profile(str(chat.get("name") or ""))
    snapshot = await host._resume_bot_chat(str(chat["name"]), str(chat["stored_id"]))
    runtime = str(snapshot.get("session_id") or "").strip()
    if not runtime:
        raise _RpcError("chat_expired")
    if runtime != chat.get("runtime_handle"):
        invalidate_refs(host._subagent_refs, token)
        chat["runtime_handle"] = runtime
    host._touch_bot_chat(chat)
    return chat


def _mint_children(
    refs: Dict[str, Dict[str, Any]],
    token: str,
    runtime_handle: str,
    rows: Any,
) -> list:
    children = []
    if not isinstance(rows, list):
        return children
    for row in rows:
        if not isinstance(row, dict) or not row.get("subagent_id"):
            continue
        ref = secrets.token_urlsafe(24)
        refs[ref] = {
            "chat": token,
            "runtime_handle": runtime_handle,
            "subagent_id": str(row["subagent_id"]),
        }
        children.append(
            {
                "ref": ref,
                "goal": str(row.get("goal") or ""),
                "status": str(row.get("status") or "unknown"),
                "accepting_steer": row.get("accepting_steer") is True,
                "started_at": row.get("started_at"),
                "tool_count": row.get("tool_count"),
                "last_tool": row.get("last_tool"),
            }
        )
    return children


async def list_children(host: Any, p: Dict[str, Any]) -> Any:
    """List only children attached to this live Bot runtime session."""
    token = str(p.get("chat") or "").strip()
    if not token:
        raise _RpcError("chat_expired")
    chat = await resume_bot_for_subagents(host, token)
    invalidate_refs(host._subagent_refs, token)
    caps = await ensure_capabilities(host)
    tail = caps["tail"]
    if not caps["available"]:
        return {
            "available": False,
            "reason": caps["reason"],
            "tail_available": False,
            "tail_reason": caps["reason"],
            "subagents": [],
        }
    try:
        snapshot = await host._local_rpc(
            "subagent.list", {"session_id": chat["runtime_handle"]}
        )
    except (_LocalRpcError, _RpcError) as exc:
        reason = unavailable_reason(exc)
        return {
            "available": False,
            "reason": reason,
            "tail_available": False,
            "tail_reason": reason,
            "subagents": [],
        }
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("subagents"), list):
        return {
            "available": False,
            "reason": "unavailable",
            "tail_available": False,
            "tail_reason": "unavailable",
            "subagents": [],
        }
    children = _mint_children(
        host._subagent_refs, token, chat["runtime_handle"], snapshot["subagents"]
    )
    return {
        "available": True,
        "reason": None,
        "tail_available": tail["available"] is True,
        "tail_reason": tail["reason"],
        "subagents": children,
        "controls": caps.get("controls", {}),
    }


async def tail_child(host: Any, p: Dict[str, Any]) -> Any:
    """Read a bounded upstream tail using a ref from this Bot's latest list."""
    token = str(p.get("chat") or "").strip()
    ref = str(p.get("child") or "").strip()
    unavailable = {
        "available": False,
        "reason": "child_unavailable",
        "text": "",
        "truncated": False,
    }
    if not token or not ref:
        return unavailable
    target = host._subagent_refs.get(ref)
    if not target or target.get("chat") != token:
        return unavailable
    chat = await resume_bot_for_subagents(host, token)
    if target.get("runtime_handle") != chat.get("runtime_handle"):
        invalidate_refs(host._subagent_refs, token)
        return unavailable
    try:
        result = await host._local_rpc(
            "subagent.tail",
            {
                "session_id": target["runtime_handle"],
                "subagent_id": target["subagent_id"],
            },
        )
    except (_LocalRpcError, _RpcError) as exc:
        return {**unavailable, "reason": unavailable_reason(exc)}
    if not isinstance(result, dict):
        return unavailable
    available = result.get("available") is True
    text = str(result.get("text") or "") if available else ""
    truncated = bool(result.get("truncated")) if available else False
    if available:
        text, truncated = cap_tail_text(text, truncated)
    return {
        "available": available,
        "reason": None if available else "output_unavailable",
        "text": text,
        "truncated": truncated,
    }


async def mutate_child(host: Any, p: Dict[str, Any], action: str) -> Dict[str, Any]:
    """Mutate only a child ref from the current Bot list and live runtime owner."""
    token = str(p.get("chat") or "").strip()
    ref = str(p.get("child") or "").strip()
    unavailable = {"status": "unavailable", "reason": "child_unavailable"}
    if not token or not ref:
        return unavailable
    target = host._subagent_refs.get(ref)
    if not target or target.get("chat") != token:
        return unavailable
    chat = await resume_bot_for_subagents(host, token)
    if target.get("runtime_handle") != chat.get("runtime_handle"):
        invalidate_refs(host._subagent_refs, token)
        return unavailable
    method = "subagent.steer" if action == "steer" else "subagent.interrupt"
    params = {
        "session_id": target["runtime_handle"],
        "subagent_id": target["subagent_id"],
    }
    if action == "steer":
        text = p.get("text")
        if not isinstance(text, str) or not text.strip():
            return {"status": "rejected", "reason": "text_required"}
        params["text"] = text.strip()
    try:
        result = await host._local_rpc(method, params)
    except (_LocalRpcError, _RpcError) as exc:
        return {"status": "unavailable", "reason": unavailable_reason(exc)}
    if not isinstance(result, dict):
        return {"status": "unavailable", "reason": "unavailable"}
    if action == "steer":
        outcome = result.get("status")
        if outcome not in ("queued", "applied", "missed", "rejected"):
            outcome = "unavailable"
    else:
        found = result.get("found")
        outcome = "interrupted" if found is True else "finished" if found is False else "unavailable"
    reason = None if outcome not in ("unavailable", "rejected") else "child_unavailable"
    return {"status": outcome, "reason": reason}


async def steer_child(host: Any, p: Dict[str, Any]) -> Dict[str, Any]:
    return await mutate_child(host, p, "steer")


async def interrupt_child(host: Any, p: Dict[str, Any]) -> Dict[str, Any]:
    return await mutate_child(host, p, "interrupt")
