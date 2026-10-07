# Hosted Bot rooms: groups.* ops; #84 H: phone owns seq cursor (handle has no cursor).
"""Phone-facing rooms.* operations over Hermes hosted-room groups.* RPCs."""

from __future__ import annotations

import re
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Set

from .bots_policy import (
    bots_flag_enabled,
    fetch_profiles_snapshot,
    require_bots_enabled,
)
from .operation_dispatch import _LocalRpcError, _RpcError

_GROUPS_META_KEY = "hermes-bots-groups"
_DEFAULT_LOG_LIMIT = 50
_UNMENTIONED_DELIVERY = "all_members"
# Mirrors gateway.hosted_room_discussion._MENTION_RE — upstream recipient contract
# is @handle tokens inside message text (resolve_mentions).
_MENTION_RE = re.compile(r"@([A-Za-z0-9][A-Za-z0-9._:-]*)", re.IGNORECASE)
_RESERVED_HANDLES = frozenset({"all", "everyone"})
# Upstream Discussion resolve_mentions(..., default_all=True) — not a
# groups.capabilities field; phone must not invent a different policy.
_REQUIRED_METHODS = frozenset(
    {
        "groups.capabilities",
        "groups.list",
        "groups.create",
        "groups.state",
        "groups.send",
        "groups.log",
    }
)


def _control_cap(available: bool, reason: Optional[str] = None) -> Dict[str, Any]:
    return {"available": available, "reason": reason}


def _blocked(reason: str) -> Dict[str, Any]:
    return {
        "available": False,
        "reason": reason,
        "driver": False,
        "max_log_limit": 0,
        "unmentioned_delivery": _UNMENTIONED_DELIVERY,
        "methods": [],
        "stop": _control_cap(False, reason),
        "approve": _control_cap(False, reason),
    }


def _rooms_map(host: Any) -> Dict[str, Dict[str, Any]]:
    rooms = getattr(host, "_room_handles", None)
    if rooms is None:
        host._room_handles = {}
        rooms = host._room_handles
    return rooms


def clear_handles(host: Any) -> None:
    rooms = getattr(host, "_room_handles", None)
    if rooms is not None:
        rooms.clear()
    host._room_caps = None


async def _bot_profiles(host: Any) -> Dict[str, Dict[str, Any]]:
    """Bot roster map from one profiles.list (shared policy snapshot)."""
    snap = await fetch_profiles_snapshot(host, include_sessions=False)
    return snap.bots


def _project_member(raw: Dict[str, Any], available_profiles: Set[str]) -> Dict[str, Any]:
    profile = str(raw.get("profile") or "").strip()
    return {
        "member_id": str(raw.get("member_id") or "") or None,
        "profile": profile or None,
        "handle": str(raw.get("handle") or profile or "") or None,
        "display_name": str(raw.get("display_name") or raw.get("handle") or profile or "")
        or None,
        "available": bool(profile) and profile in available_profiles,
    }


def _project_room(raw: Dict[str, Any], available_profiles: Set[str]) -> Dict[str, Any]:
    members_raw = raw.get("members") if isinstance(raw.get("members"), list) else []
    return {
        "room_id": str(raw.get("room_id") or ""),
        "name": str(raw.get("name") or ""),
        "members": [
            _project_member(m, available_profiles)
            for m in members_raw
            if isinstance(m, dict)
        ],
        "latest_seq": int(raw.get("latest_seq") or 0),
        "authority_epoch": int(raw.get("authority_epoch") or 0),
        "supported": True,
        "updated_at": raw.get("updated_at"),
    }


def _project_event(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    kind = str(raw.get("kind") or "")
    payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    actor = raw.get("actor") if isinstance(raw.get("actor"), dict) else {}
    text = payload.get("text")
    if not isinstance(text, str):
        return None
    if kind == "message.user":
        role = "user"
        turn_id = None
    elif kind == "message.member":
        role = "assistant"
        turn_id = str(payload.get("turn_id") or "") or None
    else:
        return None
    return {
        "id": str(raw.get("event_id") or ""),
        "seq": int(raw.get("seq") or 0),
        "role": role,
        "author": {
            "kind": str(actor.get("kind") or ""),
            "id": str(actor.get("id") or ""),
        },
        "turn_id": turn_id,
        "content": text,
        "ts": float(raw.get("created_at") or 0),
        "thread_id": str(payload.get("thread_id") or "") or None,
    }



_APPROVAL_CHOICES = frozenset({"once", "deny"})


def _project_pending_approval(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict) or str(raw.get("kind") or "") != "approval":
        return None
    approval = raw.get("approval") if isinstance(raw.get("approval"), dict) else {}
    request_id = str(raw.get("request_id") or approval.get("request_id") or "").strip()
    task_id = str(raw.get("task_id") or "").strip()
    member_id = str(raw.get("member_id") or "").strip()
    if not request_id or not task_id or not member_id:
        return None
    choices_raw = approval.get("choices") if isinstance(approval.get("choices"), list) else []
    choices = [str(c) for c in choices_raw if str(c) in _APPROVAL_CHOICES]
    if not choices:
        choices = ["once", "deny"]
    return {
        "member_id": member_id,
        "task_id": task_id,
        "execution_generation": int(raw.get("execution_generation") or 0),
        "request_id": request_id,
        "command": str(approval.get("command") or ""),
        "description": str(approval.get("description") or ""),
        "choices": choices,
    }


def _project_driver_status(status: Any) -> Dict[str, Any]:
    if not isinstance(status, dict):
        return {"working": False, "pending_approvals": []}
    actions = status.get("pending_actions") if isinstance(status.get("pending_actions"), list) else []
    pending = []
    for action in actions:
        projected = _project_pending_approval(action) if isinstance(action, dict) else None
        if projected is not None:
            pending.append(projected)
    return {
        "working": bool(status.get("working")),
        "pending_approvals": pending,
    }


def _mirror_unsupported(default_row: Optional[Dict[str, Any]], hosted_ids: Set[str]) -> List[Dict[str, Any]]:
    if not isinstance(default_row, dict):
        return []
    ui_meta = default_row.get("ui_meta")
    if not isinstance(ui_meta, dict):
        return []
    snap = ui_meta.get(_GROUPS_META_KEY)
    if not isinstance(snap, dict):
        return []
    rooms = snap.get("rooms")
    if not isinstance(rooms, dict):
        return []
    unsupported: List[Dict[str, Any]] = []
    for key, room in rooms.items():
        if not isinstance(room, dict):
            continue
        room_id = str(room.get("roomId") or room.get("room_id") or "").strip()
        name = str(room.get("name") or key or "").strip() or key
        if not room_id:
            unsupported.append(
                {"room_id": None, "name": name, "reason": "desktop_mirror"}
            )
            continue
        if room_id in hosted_ids:
            continue
        unsupported.append(
            {"room_id": room_id, "name": name, "reason": "desktop_mirror"}
        )
    return unsupported


async def capabilities(host: Any, _params: Dict[str, Any]) -> Dict[str, Any]:
    cached = getattr(host, "_room_caps", None)
    if cached is not None:
        return cached
    if not bots_flag_enabled():
        host._room_caps = _blocked("bots_disabled")
        return host._room_caps
    try:
        await host._local_rpc("profiles.list", {"include_sessions": False})
    except _LocalRpcError as exc:
        host._room_caps = _blocked("bots_unavailable")
        return host._room_caps
    except _RpcError as exc:
        host._room_caps = _blocked(str(exc))
        return host._room_caps
    try:
        raw = await host._local_rpc("groups.capabilities", {})
    except _LocalRpcError as exc:
        reason = "rooms_unsupported" if exc.code == -32601 else "rooms_unavailable"
        host._room_caps = _blocked(reason)
        return host._room_caps
    except _RpcError as exc:
        host._room_caps = _blocked(str(exc))
        return host._room_caps
    if not isinstance(raw, dict):
        host._room_caps = _blocked("rooms_unavailable")
        return host._room_caps
    driver = bool(raw.get("driver"))
    methods = raw.get("methods") if isinstance(raw.get("methods"), list) else []
    method_names = {str(m) for m in methods}
    if not driver:
        result = {
            **_blocked("driver_unavailable"),
            "max_log_limit": int(raw.get("max_log_limit") or 0),
            "methods": [str(m) for m in methods],
        }
        host._room_caps = result
        return result
    if not _REQUIRED_METHODS.issubset(method_names):
        result = {
            **_blocked("rooms_unsupported"),
            "max_log_limit": int(raw.get("max_log_limit") or 0),
            "methods": [str(m) for m in methods],
        }
        host._room_caps = result
        return result
    stop_ok = "groups.stop" in method_names
    approve_ok = "groups.approve" in method_names
    result = {
        "available": True,
        "reason": None,
        "driver": True,
        "max_log_limit": int(raw.get("max_log_limit") or _DEFAULT_LOG_LIMIT),
        "unmentioned_delivery": _UNMENTIONED_DELIVERY,
        "methods": [str(m) for m in methods],
        "stop": _control_cap(True) if stop_ok else _control_cap(False, "stop_unsupported"),
        "approve": _control_cap(True) if approve_ok else _control_cap(False, "approve_unsupported"),
    }
    host._room_caps = result
    return result


async def _require_rooms(host: Any) -> Dict[str, Any]:
    caps = await capabilities(host, {})
    if not caps.get("available"):
        raise _RpcError(str(caps.get("reason") or "rooms_unavailable"))
    return caps


async def list_rooms(host: Any, _params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    await _require_rooms(host)
    # One profiles.list for bot roster + default-row mirror (was two RPCs).
    snap = await fetch_profiles_snapshot(host, include_sessions=False)
    available = set(snap.bots)
    try:
        listed = await host._local_rpc("groups.list", {})
    except _LocalRpcError as exc:
        raise _RpcError("rooms_unavailable") from exc
    rooms_raw = listed.get("rooms") if isinstance(listed, dict) else None
    if not isinstance(rooms_raw, list):
        rooms_raw = []
    rooms = [
        _project_room(r, available)
        for r in rooms_raw
        if isinstance(r, dict) and r.get("disbanded_at") is None
    ]
    hosted_ids = {r["room_id"] for r in rooms if r["room_id"]}
    return {
        "rooms": rooms,
        "unsupported": _mirror_unsupported(snap.default_row, hosted_ids),
    }


def _member_inputs(bots: Dict[str, Dict[str, Any]], names: List[str]) -> List[Dict[str, Any]]:
    members: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for raw_name in names:
        name = str(raw_name or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        row = bots.get(name)
        if row is None:
            raise _RpcError("member_unavailable")
        display = str(row.get("display_name") or name)
        members.append(
            {
                "member_id": f"m-{name}",
                "profile": name,
                "handle": name,
                "display_name": display,
            }
        )
    if len(members) < 1:
        raise _RpcError("member_unavailable")
    return members


async def create_room(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    await _require_rooms(host)
    name = str(params.get("name") or "").strip()
    if not name:
        raise _RpcError("invalid_room")
    member_names = params.get("members")
    if not isinstance(member_names, list):
        raise _RpcError("member_unavailable")
    bots = await _bot_profiles(host)
    members = _member_inputs(bots, [str(m) for m in member_names])
    room_id = str(params.get("room_id") or f"room-{uuid.uuid4().hex[:12]}")
    try:
        created = await host._local_rpc(
            "groups.create",
            {"room_id": room_id, "name": name, "members": members},
        )
    except _LocalRpcError as exc:
        raise _RpcError("rooms_unavailable") from exc
    room_raw = created.get("room") if isinstance(created, dict) else None
    if not isinstance(room_raw, dict):
        raise _RpcError("rooms_unavailable")
    return {"room": _project_room(room_raw, set(bots))}


async def _fetch_log(
    host: Any, room_id: str, *, since_seq: int, limit: int
) -> Dict[str, Any]:
    params: Dict[str, Any] = {"room_id": room_id, "limit": limit, "since_seq": since_seq}
    try:
        page = await host._local_rpc("groups.log", params)
    except _LocalRpcError as exc:
        raise _RpcError("rooms_unavailable") from exc
    if not isinstance(page, dict):
        raise _RpcError("rooms_unavailable")
    events = page.get("events") if isinstance(page.get("events"), list) else []
    messages = []
    for event in events:
        projected = _project_event(event)
        if projected is not None:
            messages.append(projected)
    return {
        "messages": messages,
        "cursor": int(page.get("cursor") or since_seq),
        "latest_seq": int(page.get("latest_seq") or 0),
        "has_more": bool(page.get("has_more")),
    }


async def _fetch_latest_page(
    host: Any, room_id: str, *, latest_seq: int, limit: int
) -> Dict[str, Any]:
    """Bounded tail of the authoritative log. ``has_more`` means older remain."""
    if latest_seq <= 0 or limit <= 0:
        return {"messages": [], "cursor": 0, "latest_seq": latest_seq, "has_more": False}
    start = max(0, latest_seq - limit)
    page = await _fetch_log(host, room_id, since_seq=start, limit=limit)
    # Byte budgets can stop short of latest_seq — walk forward, keep the tail.
    while page["has_more"] and page["cursor"] < latest_seq:
        more = await _fetch_log(host, room_id, since_seq=page["cursor"], limit=limit)
        if int(more["cursor"]) <= int(page["cursor"]):
            break
        merged = page["messages"] + more["messages"]
        page = {
            "messages": merged[-limit:] if len(merged) > limit else merged,
            "cursor": more["cursor"],
            "latest_seq": more["latest_seq"],
            "has_more": more["has_more"],
        }
    oldest = page["messages"][0]["seq"] if page["messages"] else 0
    return {
        "messages": page["messages"],
        "cursor": page["cursor"],
        "latest_seq": page["latest_seq"] or latest_seq,
        "has_more": oldest > 1,
    }


async def _fetch_older_page(
    host: Any, room_id: str, *, before_seq: int, limit: int
) -> Dict[str, Any]:
    """Bounded page of events strictly older than ``before_seq``."""
    if before_seq <= 1 or limit <= 0:
        return {"messages": [], "cursor": 0, "latest_seq": 0, "has_more": False}
    start = max(0, before_seq - 1 - limit)
    collected: List[Dict[str, Any]] = []
    seen_through = start
    latest_seq = 0
    cursor = start
    for _ in range(32):
        page = await _fetch_log(host, room_id, since_seq=seen_through, limit=limit)
        latest_seq = int(page.get("latest_seq") or latest_seq)
        cursor = int(page.get("cursor") or seen_through)
        for message in page["messages"]:
            if int(message["seq"]) < before_seq:
                collected.append(message)
        if cursor <= seen_through:
            break
        seen_through = cursor
        if seen_through >= before_seq - 1 or not page["has_more"]:
            break
    messages = collected[-limit:] if len(collected) > limit else collected
    oldest = int(messages[0]["seq"]) if messages else 0
    return {
        "messages": messages,
        "cursor": cursor,
        "latest_seq": latest_seq,
        "has_more": oldest > 1,
    }



async def _fetch_driver_status(host: Any, room_id: str) -> Dict[str, Any]:
    try:
        state = await host._local_rpc("groups.state", {"room_id": room_id})
    except _LocalRpcError:
        return _project_driver_status(None)
    status = state.get("driver_status") if isinstance(state, dict) else None
    return _project_driver_status(status)


def _mint_handle(host: Any, room_id: str, name: str) -> str:
    token = secrets.token_urlsafe(18)
    _rooms_map(host)[token] = {
        "room_id": room_id,
        "name": name,
        "opened_at": time.monotonic(),
    }
    return token


def _require_handle(host: Any, token: str) -> Dict[str, Any]:
    if not token:
        raise _RpcError("room_closed")
    room = _rooms_map(host).get(token)
    if room is None:
        raise _RpcError("room_closed")
    return room


async def open_room(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    caps = await _require_rooms(host)
    room_id = str(params.get("room_id") or "").strip()
    if not room_id:
        raise _RpcError("room_gone")
    bots = await _bot_profiles(host)
    try:
        state = await host._local_rpc("groups.state", {"room_id": room_id})
    except _LocalRpcError as exc:
        raise _RpcError("room_gone") from exc
    room_raw = state.get("room") if isinstance(state, dict) else None
    if not isinstance(room_raw, dict) or room_raw.get("disbanded_at") is not None:
        raise _RpcError("room_gone")
    limit = min(int(caps.get("max_log_limit") or _DEFAULT_LOG_LIMIT), _DEFAULT_LOG_LIMIT)
    latest_seq = int(room_raw.get("latest_seq") or 0)
    page = await _fetch_latest_page(host, room_id, latest_seq=latest_seq, limit=limit)
    driver = _project_driver_status(state.get("driver_status") if isinstance(state, dict) else None)
    projected = _project_room(room_raw, set(bots))
    handle = _mint_handle(host, room_id, projected["name"])
    return {
        "handle": handle,
        "room_id": projected["room_id"],
        "name": projected["name"],
        "members": projected["members"],
        "messages": page["messages"],
        "cursor": page["cursor"],
        "latest_seq": page["latest_seq"],
        "has_more": page["has_more"],
        "unmentioned_delivery": _UNMENTIONED_DELIVERY,
        "working": driver["working"],
        "pending_approvals": driver["pending_approvals"],
    }


def _mention_handles_in_text(text: str) -> List[str]:
    found: List[str] = []
    seen: Set[str] = set()
    for match in _MENTION_RE.finditer(text):
        handle = match.group(1)
        key = handle.casefold()
        if key in seen:
            continue
        seen.add(key)
        found.append(handle)
    return found


def _ensure_mention_text(text: str, handles: List[str]) -> str:
    existing = {h.casefold() for h in _mention_handles_in_text(text)}
    missing = [h for h in handles if h.casefold() not in existing]
    if not missing:
        return text
    prefix = " ".join(f"@{h}" for h in missing)
    body = text.strip()
    return f"{prefix} {body}".strip() if body else prefix


def _member_lookup_keys(member: Dict[str, Any]) -> Set[str]:
    keys: Set[str] = set()
    for field in ("member_id", "handle", "profile"):
        value = str(member.get(field) or "").strip()
        if value:
            keys.add(value.casefold())
    return keys


def _resolve_member_token(
    token: str, members: List[Dict[str, Any]]
) -> Dict[str, Any]:
    key = str(token or "").strip().casefold()
    if not key:
        raise _RpcError("recipient_unknown")
    matches = [m for m in members if key in _member_lookup_keys(m)]
    # De-dupe by member_id so handle+profile aliases on one row don't look ambiguous.
    by_id: Dict[str, Dict[str, Any]] = {}
    for match in matches:
        mid = str(match.get("member_id") or match.get("handle") or id(match))
        by_id[mid] = match
    unique = list(by_id.values())
    if not unique:
        raise _RpcError("recipient_unknown")
    if len(unique) > 1:
        raise _RpcError("recipient_ambiguous")
    return unique[0]


def _require_available(member: Dict[str, Any]) -> Dict[str, Any]:
    if not member.get("available"):
        raise _RpcError("recipient_unavailable")
    handle = str(member.get("handle") or member.get("profile") or "").strip()
    if not handle:
        raise _RpcError("recipient_unknown")
    return member


async def _live_room_members(host: Any, room_id: str) -> List[Dict[str, Any]]:
    bots = await _bot_profiles(host)
    try:
        state = await host._local_rpc("groups.state", {"room_id": room_id})
    except _LocalRpcError as exc:
        raise _RpcError("room_gone") from exc
    room_raw = state.get("room") if isinstance(state, dict) else None
    if not isinstance(room_raw, dict) or room_raw.get("disbanded_at") is not None:
        raise _RpcError("room_gone")
    projected = _project_room(room_raw, set(bots))
    return list(projected.get("members") or [])


def _resolve_send_text(
    text: str,
    recipients: Optional[List[Any]],
    members: List[Dict[str, Any]],
) -> str:
    """Sole @handle rewrite authority (#84 K) — phone sends draft text + member_ids only."""
    selected: List[Dict[str, Any]] = []
    if isinstance(recipients, list) and recipients:
        for raw in recipients:
            member = _require_available(_resolve_member_token(str(raw), members))
            selected.append(member)
    else:
        for handle in _mention_handles_in_text(text):
            if handle.casefold() in _RESERVED_HANDLES:
                continue
            member = _require_available(_resolve_member_token(handle, members))
            selected.append(member)
        if not selected:
            return text
    # Preserve first-seen order; drop duplicate member rows.
    handles: List[str] = []
    seen: Set[str] = set()
    for member in selected:
        handle = str(member.get("handle") or member.get("profile") or "").strip()
        key = handle.casefold()
        if not handle or key in seen:
            continue
        seen.add(key)
        handles.append(handle)
    resolved = _ensure_mention_text(text, handles)
    # Every @token in the final text must resolve — leftover free-typed unknowns
    # must not ride along with a structured recipient list.
    for handle in _mention_handles_in_text(resolved):
        if handle.casefold() in _RESERVED_HANDLES:
            continue
        _require_available(_resolve_member_token(handle, members))
    return resolved


async def send_message(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    await _require_rooms(host)
    handle = str(params.get("handle") or "").strip()
    text = str(params.get("text") or "").strip()
    if not text:
        raise _RpcError("empty_text")
    room = _require_handle(host, handle)
    recipients = params.get("recipients")
    text_handles = _mention_handles_in_text(text)
    has_member_mentions = any(h.casefold() not in _RESERVED_HANDLES for h in text_handles)
    # Unmentioned path: no recipients and no member @tokens → backend default_all.
    if (isinstance(recipients, list) and recipients) or has_member_mentions:
        members = await _live_room_members(host, str(room["room_id"]))
        text = _resolve_send_text(
            text, recipients if isinstance(recipients, list) else None, members
        )
    thread_id = str(params.get("thread_id") or f"thread-{uuid.uuid4().hex[:12]}")
    payload = {"text": text, "thread_id": thread_id}
    try:
        result = await host._local_rpc(
            "groups.send",
            {
                "room_id": room["room_id"],
                "event_id": f"evt-{uuid.uuid4().hex[:16]}",
                "payload": payload,
            },
        )
    except _LocalRpcError as exc:
        raise _RpcError("rooms_unavailable") from exc
    event = result.get("event") if isinstance(result, dict) else None
    projected = _project_event(event) if isinstance(event, dict) else None
    return {
        "accepted": bool(isinstance(result, dict) and result.get("accepted", True)),
        "event": projected,
        "thread_id": thread_id,
    }


async def read_log(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    caps = await _require_rooms(host)
    handle = str(params.get("handle") or "").strip()
    room = _require_handle(host, handle)
    limit = min(
        int(params.get("limit") or caps.get("max_log_limit") or _DEFAULT_LOG_LIMIT),
        int(caps.get("max_log_limit") or _DEFAULT_LOG_LIMIT),
    )
    before = params.get("before_seq")
    if before is not None:
        page = await _fetch_older_page(
            host, str(room["room_id"]), before_seq=int(before), limit=limit
        )
        return page
    since = params.get("since_seq")
    if since is None:
        # Phone is the sole catch-up owner (#84 H); do not invent a handle cursor.
        raise _RpcError("invalid_params")
    since_seq = int(since)
    page = await _fetch_log(host, str(room["room_id"]), since_seq=since_seq, limit=limit)
    driver = await _fetch_driver_status(host, str(room["room_id"]))
    page["working"] = driver["working"]
    page["pending_approvals"] = driver["pending_approvals"]
    return page


async def stop_room_work(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    handle = str(params.get("handle") or "").strip()
    room = _require_handle(host, handle)
    caps = await _require_rooms(host)
    stop_cap = caps.get("stop") if isinstance(caps.get("stop"), dict) else {}
    if not stop_cap.get("available"):
        raise _RpcError(str(stop_cap.get("reason") or "stop_unsupported"))
    cancel_id = str(params.get("cancel_id") or "mobile-stop").strip() or "mobile-stop"
    try:
        result = await host._local_rpc(
            "groups.stop",
            {"room_id": room["room_id"], "cancel_id": cancel_id},
        )
    except _LocalRpcError as exc:
        if exc.code == -32601:
            raise _RpcError("stop_unsupported") from exc
        raise _RpcError("rooms_unavailable") from exc
    cancelled = int(result.get("cancelled") or 0) if isinstance(result, dict) else 0
    stopped = cancelled > 0
    return {
        "stopped": stopped,
        "status": "stopped" if stopped else "already_finished",
        "cancelled": cancelled,
    }


async def approve_room(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    require_bots_enabled()
    handle = str(params.get("handle") or "").strip()
    room = _require_handle(host, handle)
    caps = await _require_rooms(host)
    approve_cap = caps.get("approve") if isinstance(caps.get("approve"), dict) else {}
    if not approve_cap.get("available"):
        raise _RpcError(str(approve_cap.get("reason") or "approve_unsupported"))
    member_id = str(params.get("member_id") or "").strip()
    task_id = str(params.get("task_id") or "").strip()
    request_id = str(params.get("request_id") or "").strip()
    choice = str(params.get("choice") or "").strip()
    try:
        execution_generation = int(params.get("execution_generation") or 0)
    except (TypeError, ValueError) as exc:
        raise _RpcError("approval_gone") from exc
    if not member_id or not task_id or not request_id:
        raise _RpcError("approval_gone")
    if choice not in _APPROVAL_CHOICES:
        raise _RpcError("approval_invalid_choice")
    driver = await _fetch_driver_status(host, str(room["room_id"]))
    match = next(
        (
            a
            for a in driver["pending_approvals"]
            if a["member_id"] == member_id
            and a["task_id"] == task_id
            and a["execution_generation"] == execution_generation
            and a["request_id"] == request_id
        ),
        None,
    )
    if match is None:
        raise _RpcError("approval_gone")
    try:
        result = await host._local_rpc(
            "groups.approve",
            {
                "room_id": room["room_id"],
                "member_id": member_id,
                "task_id": task_id,
                "execution_generation": execution_generation,
                "choice": choice,
                "request_id": request_id,
            },
        )
    except _LocalRpcError as exc:
        if exc.code == -32601:
            raise _RpcError("approve_unsupported") from exc
        message = str(getattr(exc, "message", "") or "")
        if "no longer pending" in message.lower():
            raise _RpcError("approval_gone") from exc
        raise _RpcError("rooms_unavailable") from exc
    if not isinstance(result, dict):
        raise _RpcError("rooms_unavailable")
    return {
        "approved": bool(result.get("approved", True)),
        "result": result.get("result") if isinstance(result.get("result"), dict) else {},
    }


async def close_room(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    handle = str(params.get("handle") or "").strip()
    if handle:
        _rooms_map(host).pop(handle, None)
    return {"ok": True}
