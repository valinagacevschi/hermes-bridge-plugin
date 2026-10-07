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
    foreign_ids = {
        row.get("id") for row in sessions
        if isinstance(row, dict) and row.get("source") != "hermes_bridge"
    }
    for row in sessions:
        if not isinstance(row, dict) or row.get("source") != "hermes_bridge":
            continue
        if row.get("id") == session_id:
            if row.get("forked_from") or row.get("thread_id") in foreign_ids:
                thread = row.get("thread_id")
                return thread.strip() if isinstance(thread, str) and thread.strip() else session_id
            thread = row.get("thread_id")
            if isinstance(thread, str) and thread.strip():
                return thread.strip()
            return None
        if row.get("thread_id") == session_id:
            return session_id
    return session_id


def resolve_message_session_id(session_id: str, sessions: List[dict]) -> str:
    """History is stored under the gateway row id. The phone asks with the thread id."""
    if any(isinstance(row, dict) and row.get("id") == session_id for row in sessions):
        return session_id
    for row in sessions:
        if not isinstance(row, dict) or row.get("source") != "hermes_bridge":
            continue
        if row.get("thread_id") == session_id and isinstance(row.get("id"), str) and row.get("id"):
            return row["id"]
    return session_id


def rewrite_listed_sessions(data: Any) -> Any:
    """Expose phone thread ids except legacy forks colliding with foreign sessions."""
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
        return data
    foreign_ids = {
        row.get("id") for row in data["sessions"]
        if isinstance(row, dict) and row.get("source") != "hermes_bridge"
    }
    sessions: List[Any] = []
    for row in data["sessions"]:
        if not isinstance(row, dict):
            sessions.append(row)
            continue
        if row.get("source") == "hermes_bridge":
            thread = row.get("thread_id")
            if isinstance(thread, str) and thread.strip():
                row = dict(row)
                if thread in foreign_ids:
                    row["forked_from"] = thread
                    row["title"] = f"↪ {row.get('title') or next((r.get('title') for r in data['sessions'] if isinstance(r, dict) and r.get('id') == thread), thread)}"
                else:
                    row["id"] = thread.strip()
        sessions.append(row)
    # Older gateway rows can otherwise resolve to the same phone id.
    seen = set()
    unique = []
    for row in sessions:
        if isinstance(row, dict) and row.get("id") in seen:
            continue
        if isinstance(row, dict):
            seen.add(row.get("id"))
        unique.append(row)
    return {**data, "sessions": unique}
