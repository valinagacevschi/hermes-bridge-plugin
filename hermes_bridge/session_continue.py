"""Map a phone chat onto its own Hermes gateway session.

The gateway session key includes source.thread_id. With no thread id, every
phone message shares one hermes_bridge row. A phone chat id becomes that
thread id, except for the legacy row that was created before threads existed:
sending into that row keeps its empty thread so the old transcript stays put.
"""

import datetime
import uuid
from typing import Any, Dict, List, Optional


def hermes_session_to_continue(payload: dict) -> Optional[str]:
    sid = payload.get("session_id")
    if not isinstance(sid, str):
        return None
    sid = sid.strip()
    if not sid or sid.startswith("agent:"):
        return None
    return sid


def new_bridge_chat_id() -> str:
    """Id the phone keeps. The gateway stores it as thread_id, not as the row id."""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]


def bridge_thread_id(session_id: Optional[str], sessions: List[dict]) -> Optional[str]:
    """Thread id to put on the gateway message, or None to keep the legacy row."""
    if not session_id:
        return None
    for row in sessions:
        if not isinstance(row, dict) or row.get("source") != "hermes_bridge":
            continue
        if row.get("id") == session_id:
            thread = row.get("thread_id")
            if isinstance(thread, str) and thread.strip():
                return thread.strip()
            return None
        if row.get("thread_id") == session_id:
            return session_id
    return session_id


def resolve_message_session_id(session_id: str, sessions: List[dict]) -> str:
    """History is stored under the gateway row id. The phone asks with the thread id."""
    for row in sessions:
        if not isinstance(row, dict) or row.get("source") != "hermes_bridge":
            continue
        if row.get("thread_id") == session_id and isinstance(row.get("id"), str) and row.get("id"):
            return row["id"]
    return session_id


def rewrite_listed_sessions(data: Any) -> Any:
    """Phone session ids are thread ids. Leave the legacy empty-thread row unchanged."""
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
        return data
    sessions: List[Any] = []
    for row in data["sessions"]:
        if not isinstance(row, dict):
            sessions.append(row)
            continue
        thread = row.get("thread_id")
        if row.get("source") == "hermes_bridge" and isinstance(thread, str) and thread.strip():
            row = dict(row)
            row["id"] = thread.strip()
        sessions.append(row)
    return {**data, "sessions": sessions}
