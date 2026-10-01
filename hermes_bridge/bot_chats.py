# Forever-chat bots.*; #84 J: require_bot_profile via bots_policy (no host duck).
"""Phone-facing bots.* forever-chat over Hermes session.* + REST history."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import urllib.error
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

from . import bot_subagents
from .bots_policy import require_bot_profile, require_bots_enabled
from .operation_dispatch import _LocalRpcError, _RpcError

logger = logging.getLogger(__name__)

# Canonical forever-chat identity. Title is exact; do not fuzzy-match.
_BOT_CHAT_TITLE = "Bot Chat"
_BOT_KICKOFF = "Hey, tell me about yourself!"
_BOT_HISTORY_LIMIT = 50
_BOT_POLL_FAST_S = 1.0
_BOT_POLL_IDLE_S = 5.0
_BOT_IDLE_TIMEOUT_S = 300.0
# session.resume / prompt.submit: "session_id required" / "session not found".
_STALE_SESSION_CODES = frozenset({4006, 4007})

def _is_stale_session(exc: BaseException) -> bool:
    return isinstance(exc, _LocalRpcError) and exc.code in _STALE_SESSION_CODES

def _message_text(row: Dict[str, Any]) -> str:
    display = row.get("display_content")
    if isinstance(display, str) and display.strip():
        return display.strip()
    content = row.get("content")
    if content is None:
        content = row.get("text") or row.get("api_content") or ""
    if isinstance(content, list):
        parts: List[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text")
                if isinstance(text, str) and part.get("type") in (None, "text"):
                    parts.append(text)
        return "".join(parts).strip()
    return str(content).strip()

def _message_ts_ms(row: Dict[str, Any]) -> int:
    raw = row.get("timestamp") or row.get("created_at") or 0
    try:
        n = float(raw)
    except (TypeError, ValueError):
        return 0
    if n > 1e12:
        return int(n)
    return int(n * 1000)

def _display_reasoning(row: Dict[str, Any]) -> Optional[str]:
    """Plain reasoning text the phone can show. Skips redacted signature blobs."""
    parts: List[str] = []

    def add(value: Any) -> None:
        if not isinstance(value, str):
            return
        text = value.strip()
        if text and text not in parts:
            parts.append(text)

    add(row.get("reasoning"))
    add(row.get("reasoning_content"))
    details = row.get("reasoning_details")
    if isinstance(details, list):
        for detail in details:
            if not isinstance(detail, dict) or detail.get("type") == "redacted_thinking":
                continue
            for key in ("summary", "thinking", "content", "text"):
                if isinstance(detail.get(key), str) and str(detail.get(key)).strip():
                    add(detail.get(key))
                    break
    return "\n\n".join(parts) if parts else None

def _project_bot_messages(rows: Any, chat: str) -> List[Dict[str, Any]]:
    """Project REST message rows down to what the phone renders.

    The REST payload is much richer (tool_calls, opaque reasoning_details, …).
    Shipping that over the relay would be a large multiple of the text.
    Displayable reasoning summaries are the exception: the phone collapses them.
    """
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        role = str(row.get("role") or "").strip()
        if role not in ("user", "assistant"):
            continue
        if row.get("display_kind") == "hidden":
            continue
        text = _message_text(row)
        reasoning = _display_reasoning(row) if role == "assistant" else None
        row_id = row.get("id") if row.get("id") is not None else row.get("row_id")
        if row_id is None or row_id == "":
            continue
        projected: Dict[str, Any] = {
            "id": str(row_id),
            "session_id": chat,
            "role": role,
            "content": text,
            "sealed_frame": None,
            "ts": _message_ts_ms(row),
            "is_error": 1 if row.get("error") else 0,
            "attachments": None,
            "is_gap": 0,
            "controls": None,
            "ack_state": None,
        }
        if reasoning:
            projected["reasoning"] = reasoning
        out.append(projected)
    return out

async def lookup_chat(host, name: str) -> Optional[str]:
    """Registry lookup by exact title. Returns the stored id, or None."""
    try:
        listed = await host._local_rpc(
            "session.list",
            {
                "profile": name,
                "title": _BOT_CHAT_TITLE,
                "include_hidden": True,
            },
        )
    except _LocalRpcError as exc:
        raise _RpcError("bots_unavailable") from exc
    sessions = listed.get("sessions") if isinstance(listed, dict) else None
    if not isinstance(sessions, list) or not sessions:
        return None
    first = sessions[0] if isinstance(sessions[0], dict) else {}
    stored = first.get("id") or first.get("resolved_id")
    return str(stored) if stored else None

async def resume_chat(host, name: str, stored_id: str) -> Dict[str, Any]:
    """session.resume request uses the STORED id; response session_id is runtime."""
    try:
        snap = await host._local_rpc(
            "session.resume",
            {
                "session_id": stored_id,
                "profile": name,
                "omit_messages": True,
            },
        )
    except _LocalRpcError as exc:
        if _is_stale_session(exc):
            raise _RpcError("chat_expired") from exc
        raise _RpcError("bots_unavailable") from exc
    if not isinstance(snap, dict):
        raise _RpcError("bots_unavailable")
    return snap

async def fetch_history(
    host, stored_id: str, name: str, chat: str, offset: int, limit: int
) -> Dict[str, Any]:
    # Omitting profile returns 404, not the default laptop's rows.
    # Do not "fix" this by defaulting the param.
    qs = urlencode(
        {
            "profile": name,
            "limit": str(limit),
            "offset": str(offset),
            "order": "latest",
            "include_compacted": "true",
        }
    )
    path = f"/api/sessions/{quote(stored_id, safe='')}/messages?{qs}"
    try:
        raw = await host._api.get(path)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise _RpcError("chat_expired") from exc
        raise
    rows = raw.get("messages") if isinstance(raw, dict) else []
    pagination = raw.get("pagination") if isinstance(raw, dict) else {}
    if not isinstance(pagination, dict):
        pagination = {}
    messages = _project_bot_messages(rows, chat)
    returned = int(pagination.get("returned") or len(messages))
    return {
        "messages": messages,
        "pagination": {
            "limit": int(pagination.get("limit") or limit),
            "offset": int(pagination.get("offset") or offset),
            "returned": returned,
            "has_more": returned >= limit,
        },
    }

def mint_token() -> str:
    return secrets.token_urlsafe(18)

def touch_chat(host, chat: Dict[str, Any]) -> None:
    chat["last_activity"] = time.monotonic()

def start_poll(host, token: str) -> None:
    tasks = getattr(host, "_bot_poll_tasks", None)
    if tasks is None:
        host._bot_poll_tasks = {}
        tasks = host._bot_poll_tasks
    existing = tasks.get(token)
    if existing is not None and not existing.done():
        return
    tasks[token] = asyncio.ensure_future(poll_loop(host, token))

async def stop_poll(host, token: str) -> None:
    task = getattr(host, "_bot_poll_tasks", {}).pop(token, None)
    if task is None:
        return
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass

async def expire_chat(host, token: str) -> None:
    getattr(host, "_bot_chats", {}).pop(token, None)
    bot_subagents.invalidate_refs(getattr(host, "_subagent_refs", {}), token)
    await stop_poll(host, token)

async def reresolve_chat(host, chat: Dict[str, Any]) -> None:
    """Silent re-resolve: registry lookup → resume. At most once per op."""
    stored = await lookup_chat(host, str(chat["name"]))
    if not stored:
        raise _RpcError("chat_expired")
    chat["stored_id"] = stored
    snap = await resume_chat(host, str(chat["name"]), stored)
    runtime = str(snap.get("session_id") or "").strip()
    if not runtime:
        raise _RpcError("chat_expired")
    chat["runtime_handle"] = runtime

async def prompt_chat(host, chat: Dict[str, Any], text: str) -> None:
    """prompt.submit uses the RUNTIME handle. One silent re-resolve on stale."""
    try:
        await host._local_rpc(
            "prompt.submit",
            {"session_id": chat["runtime_handle"], "text": text},
        )
        return
    except _LocalRpcError as exc:
        if not _is_stale_session(exc):
            raise _RpcError("bots_unavailable") from exc
    await reresolve_chat(host, chat)
    try:
        await host._local_rpc(
            "prompt.submit",
            {"session_id": chat["runtime_handle"], "text": text},
        )
    except _LocalRpcError as exc:
        raise _RpcError("chat_expired") from exc

def adopt_inflight_run(host, chat: Dict[str, Any], snap: Dict[str, Any]) -> Optional[str]:
    running = bool(snap.get("running"))
    inflight = snap.get("inflight") if isinstance(snap.get("inflight"), dict) else {}
    streaming = bool(inflight.get("streaming")) if inflight else False
    if running or streaming:
        if not chat.get("run_id"):
            chat["run_id"] = str(uuid.uuid4())
        chat["was_running"] = True
        chat["last_text"] = str((inflight or {}).get("assistant") or "")
        return str(chat["run_id"])
    return chat.get("run_id") if chat.get("was_running") else None

async def poll_loop(host, token: str) -> None:
    """Poll session.resume. Fast while in flight; slow when idle; stop after idle timeout."""
    try:
        while True:
            chat = getattr(host, "_bot_chats", {}).get(token)
            if chat is None:
                return
            idle_s = getattr(host, "_bot_idle_timeout_s", _BOT_IDLE_TIMEOUT_S)
            if time.monotonic() - float(chat.get("last_activity") or 0) > idle_s:
                await expire_chat(host, token)
                return
            try:
                snap = await resume_chat(host, str(chat["name"]), str(chat["stored_id"]))
            except _RpcError:
                await asyncio.sleep(getattr(host, "_bot_poll_idle_s", _BOT_POLL_IDLE_S))
                continue
            runtime = str(snap.get("session_id") or "").strip()
            if runtime:
                chat["runtime_handle"] = runtime
            inflight = snap.get("inflight") if isinstance(snap.get("inflight"), dict) else {}
            text = str((inflight or {}).get("assistant") or "")
            running = bool(snap.get("running") or (inflight or {}).get("streaming"))
            if chat.get("suppress_running_until_idle"):
                if running:
                    await asyncio.sleep(getattr(host, "_bot_poll_fast_s", _BOT_POLL_FAST_S))
                    continue
                chat["suppress_running_until_idle"] = False
            run_id = str(chat.get("run_id") or "")
            if running:
                if not run_id:
                    run_id = str(uuid.uuid4())
                    chat["run_id"] = run_id
                if text != chat.get("last_text"):
                    chat["last_text"] = text
                    await host._send_run_event(run_id, "message.delta", {"text": text}, done=False)
                chat["was_running"] = True
                delay = getattr(host, "_bot_poll_fast_s", _BOT_POLL_FAST_S)
            else:
                if run_id and chat.get("was_running"):
                    await host._send_run_event(
                        run_id, "message.complete", {"text": text}, done=True
                    )
                    chat["was_running"] = False
                    chat["last_text"] = text
                delay = getattr(host, "_bot_poll_idle_s", _BOT_POLL_IDLE_S)
            await asyncio.sleep(delay)
    except asyncio.CancelledError:
        return

async def open_chat(host, p: Dict[str, Any]) -> Any:
    name = str(p.get("name") or "").strip()
    if not name:
        raise _RpcError("bot_gone")
    row = await require_bot_profile(host, name)
    logger.info("[hermes_bridge] bots.open name=%s", name)

    stored_id = await lookup_chat(host, name)
    minted = False
    snap: Dict[str, Any] = {}
    runtime_handle = ""
    if stored_id:
        snap = await resume_chat(host, name, stored_id)
        runtime_handle = str(snap.get("session_id") or "").strip()
    else:
        # Adopt-before-mint already ran (lookup empty). Create-then-prompt
        # is one uninterrupted sequence — a live-but-unprompted session
        # is invisible to session.resume (§4.4).
        try:
            created = await host._local_rpc(
                "session.create",
                {
                    "profile": name,
                    "title": _BOT_CHAT_TITLE,
                    "hidden": True,
                },
            )
        except _LocalRpcError as exc:
            raise _RpcError("bots_unavailable") from exc
        if not isinstance(created, dict):
            raise _RpcError("bots_unavailable")
        # create response: session_id = runtime, stored_session_id = stored.
        runtime_handle = str(created.get("session_id") or "").strip()
        stored_id = str(created.get("stored_session_id") or "").strip()
        if not runtime_handle or not stored_id:
            raise _RpcError("bots_unavailable")
        minted = True
        try:
            await host._local_rpc(
                "prompt.submit",
                {"session_id": runtime_handle, "text": _BOT_KICKOFF},
            )
        except _LocalRpcError as exc:
            raise _RpcError("bots_unavailable") from exc
        snap = {
            "session_id": runtime_handle,
            "running": True,
            "inflight": {"user": _BOT_KICKOFF, "assistant": "", "streaming": True},
        }

    if not runtime_handle or not stored_id:
        raise _RpcError("bots_unavailable")

    token = mint_token()
    chats = getattr(host, "_bot_chats", None)
    if chats is None:
        host._bot_chats = {}
        chats = host._bot_chats
    record: Dict[str, Any] = {
        "name": name,
        "stored_id": stored_id,
        "runtime_handle": runtime_handle,
        "run_id": None,
        "last_activity": time.monotonic(),
        "last_text": "",
        "was_running": False,
    }
    run_id = adopt_inflight_run(host, record, snap)
    chats[token] = record
    start_poll(host, token)

    try:
        history = await fetch_history(
            host, stored_id, name, token, 0, _BOT_HISTORY_LIMIT
        )
    except _RpcError:
        if minted:
            history = {
                "messages": _project_bot_messages(
                    [
                        {
                            "id": "kickoff",
                            "role": "user",
                            "content": _BOT_KICKOFF,
                            "timestamp": time.time(),
                        }
                    ],
                    token,
                ),
                "pagination": {
                    "limit": _BOT_HISTORY_LIMIT,
                    "offset": 0,
                    "returned": 1,
                    "has_more": False,
                },
            }
        else:
            raise

    display = (row.get("display_name") or name) if isinstance(row, dict) else name
    return {
        "chat": token,
        "name": name,
        "display_name": display,
        "messages": history["messages"],
        "pagination": history["pagination"],
        "run_id": run_id,
        "running": bool(record.get("was_running")),
    }

async def send_message(host, p: Dict[str, Any]) -> Any:
    require_bots_enabled()
    token = str(p.get("chat") or "").strip()
    text = str(p.get("text") or "").strip()
    if not token:
        raise _RpcError("chat_expired")
    if not text:
        raise _RpcError("empty_text")
    chat = getattr(host, "_bot_chats", {}).get(token)
    if chat is None:
        raise _RpcError("chat_expired")
    logger.info("[hermes_bridge] bots.send name=%s", chat.get("name"))
    touch_chat(host, chat)
    await prompt_chat(host, chat, text)
    run_id = str(uuid.uuid4())
    chat["run_id"] = run_id
    chat["was_running"] = True
    chat["last_text"] = ""
    chat["suppress_running_until_idle"] = False
    start_poll(host, token)
    return {"run_id": run_id}

async def stop_chat(host, p: Dict[str, Any]) -> Any:
    """Interrupt only the Bot chat named by a live opaque token."""
    require_bots_enabled()
    token = str(p.get("chat") or "").strip()
    if not token:
        raise _RpcError("chat_expired")
    chat = getattr(host, "_bot_chats", {}).get(token)
    if chat is None:
        raise _RpcError("chat_expired")
    await require_bot_profile(host, str(chat.get("name") or ""))
    touch_chat(host, chat)

    recovered_stale_handle = False
    try:
        snapshot = await resume_chat(host, str(chat["name"]), str(chat["stored_id"]))
        runtime = str(snapshot.get("session_id") or "").strip()
        if not runtime:
            raise _RpcError("chat_expired")
        chat["runtime_handle"] = runtime
    except _RpcError as exc:
        if str(exc) == "chat_expired":
            await reresolve_chat(host, chat)
            recovered_stale_handle = True
            snapshot = {"running": True}
        else:
            raise

    run_id = str(chat.get("run_id") or "")
    inflight = snapshot.get("inflight") if isinstance(snapshot.get("inflight"), dict) else {}
    active = bool(snapshot.get("running") or inflight.get("streaming"))
    if not active:
        if run_id and chat.get("was_running"):
            final_text = str(inflight.get("assistant") or chat.get("last_text") or "")
            await host._send_run_event(
                run_id, "run.completed", {"text": final_text}, done=True
            )
        chat["was_running"] = False
        chat["run_id"] = None
        return {"stopped": False, "status": "already_finished"}

    try:
        outcome = await host._local_rpc(
            "session.interrupt", {"session_id": chat["runtime_handle"]}
        )
    except _LocalRpcError as exc:
        if not _is_stale_session(exc):
            raise _RpcError("bots_unavailable") from exc
        if recovered_stale_handle:
            raise _RpcError("chat_expired") from exc
        await reresolve_chat(host, chat)
        try:
            outcome = await host._local_rpc(
                "session.interrupt", {"session_id": chat["runtime_handle"]}
            )
        except _LocalRpcError as retry_exc:
            raise _RpcError("chat_expired") from retry_exc

    interrupted = isinstance(outcome, dict) and outcome.get("status") == "interrupted"
    if interrupted and run_id:
        final_text = str(inflight.get("assistant") or chat.get("last_text") or "")
        await host._send_run_event(
            run_id, "run.stopped", {"text": final_text}, done=True
        )
    elif run_id and chat.get("was_running"):
        final_text = str(inflight.get("assistant") or chat.get("last_text") or "")
        await host._send_run_event(
            run_id, "run.completed", {"text": final_text}, done=True
        )
    chat["was_running"] = False
    chat["run_id"] = None
    chat["last_text"] = ""
    chat["suppress_running_until_idle"] = interrupted
    return {
        "stopped": interrupted,
        "status": "stopped" if interrupted else "already_finished",
    }

async def close_chat(host, p: Dict[str, Any]) -> Any:
    token = str(p.get("chat") or "").strip()
    if token:
        await expire_chat(host, token)
    return {"closed": True}

async def history(host, p: Dict[str, Any]) -> Any:
    require_bots_enabled()
    token = str(p.get("chat") or "").strip()
    if not token:
        raise _RpcError("chat_expired")
    chat = getattr(host, "_bot_chats", {}).get(token)
    if chat is None:
        raise _RpcError("chat_expired")
    touch_chat(host, chat)
    try:
        offset = max(0, int(p.get("offset") or 0))
    except (TypeError, ValueError):
        offset = 0
    try:
        limit = int(p.get("limit") or _BOT_HISTORY_LIMIT)
    except (TypeError, ValueError):
        limit = _BOT_HISTORY_LIMIT
    limit = max(1, min(limit, 500))
    return await fetch_history(
        host, str(chat["stored_id"]), str(chat["name"]), token, offset, limit
    )

def clear_chats(host: Any) -> None:
    """Cancel poll tasks and drop opaque chat tokens (disconnect / Laptop switch)."""
    for task in list(getattr(host, "_bot_poll_tasks", {}).values()):
        task.cancel()
    if hasattr(host, "_bot_poll_tasks"):
        host._bot_poll_tasks.clear()
    if hasattr(host, "_bot_chats"):
        host._bot_chats.clear()

def chats_map(host: Any) -> Dict[str, Dict[str, Any]]:
    chats = getattr(host, "_bot_chats", None)
    if chats is None:
        host._bot_chats = {}
        chats = host._bot_chats
    return chats
