"""Map a phone chat onto its own Hermes gateway session.

The gateway session key includes source.thread_id. With no thread id, every
phone message shares one hermes_bridge row. A phone chat id becomes that
thread id, except for the legacy row that was created before threads existed:
sending into that row keeps its empty thread so the old transcript stays put.

Foreign (Telegram/CLI) sessions get a dedicated continuation thread
``cont_<foreign_id>`` so the routing key never collides with the foreign id;
the adapter then switch_session's that key onto the real foreign session row.
Exact foreign ids win over legacy forks whose thread_id equals the foreign id.

Laptop-app sessions are never bound or switched: that re-stamps their origin
and breaks the laptop's durable local receipt. Their sends go through the
canonical owner's session.resume / prompt.submit client API instead. A local-
id remains laptop-owned even after an earlier bad re-stamp.
"""

import datetime
import uuid
from typing import Any, Dict, List, Optional, Sequence


CONT_PREFIX = "cont_"
LOCAL_PLATFORM_ID_PREFIX = "local-"


def is_local_platform_id(session_id: Optional[str]) -> bool:
    """True for ids Hermes mints only for the laptop app's local platform."""
    return isinstance(session_id, str) and session_id.startswith(LOCAL_PLATFORM_ID_PREFIX)


def is_local_owned_session(session_id: Optional[str], row: Any = None) -> bool:
    """True when the phone must submit to the owner instead of binding it.

    Prefix ``local-`` is enough on its own. ``source == "local"`` covers a
    listed row whose id does not use that prefix. A continue that already
    re-stamped the row leaves source ``hermes_bridge`` and thread
    ``cont_<id>`` while the id stays ``local-…``; the prefix still matches.
    """
    if is_local_platform_id(session_id):
        return True
    if not isinstance(row, dict):
        return False
    row_id = row.get("id") if isinstance(row.get("id"), str) else None
    if session_id is not None and row_id is not None and row_id != session_id:
        return False
    if is_local_platform_id(row_id):
        return True
    return row.get("source") == "local"


def local_owned_continue_result(session_id: str) -> Dict[str, Any]:
    """Unavailable/old owner fallback: do not bind; the phone opens a copy."""
    return {
        "id": session_id,
        "continued": False,
        "fork": True,
        "reason": "local_owned",
    }


def _present_local_owned_row(row: dict) -> dict:
    """List a laptop session under source local, even after a bad re-stamp.

    Clearing ``cont_<id>`` keeps the phone from treating the row as a bridge
    continuation. The stored gateway row is not modified.
    """
    presented = dict(row)
    presented["source"] = "local"
    row_id = presented.get("id")
    if isinstance(row_id, str) and presented.get("thread_id") == continuation_thread_id(row_id):
        presented["thread_id"] = None
    return presented


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


def continuation_thread_id(foreign_id: str) -> str:
    """Deterministic bridge thread for continuing a non-bridge session."""
    return f"{CONT_PREFIX}{foreign_id}"


def is_continuation_thread(thread_id: Optional[str]) -> bool:
    return isinstance(thread_id, str) and thread_id.startswith(CONT_PREFIX) and len(thread_id) > len(CONT_PREFIX)


def phone_session_from_continuation_thread(thread_id: str) -> Optional[str]:
    """Recover the phone/foreign session id from ``cont_<id>`` after a restart."""
    if not is_continuation_thread(thread_id):
        return None
    return thread_id[len(CONT_PREFIX):]


def stamp_phone_session_id(thread_id: str, thread_phone_session: Dict[str, str]) -> str:
    """Frame stamp for a gateway thread: map hit, else derive from ``cont_`` prefix."""
    mapped = thread_phone_session.get(thread_id)
    if isinstance(mapped, str) and mapped:
        return mapped
    derived = phone_session_from_continuation_thread(thread_id)
    return derived if derived else thread_id


def bare_key_phone_session_from_payload(payload: dict) -> Optional[str]:
    """Phone chat that last drove the legacy bare DM key, or None if absent."""
    sid = payload.get("session_id")
    if not isinstance(sid, str):
        return None
    sid = sid.strip()
    return sid or None


def stamp_bare_key_session_id(remembered: Optional[str]) -> Optional[str]:
    """Outbound stamp for a bare-key reply: real phone session only, never Agent inbox."""
    if isinstance(remembered, str) and remembered and not remembered.startswith("agent:"):
        return remembered
    return None


def continuation_switch_target(
    current_session_id: str,
    listed_id: str,
    *,
    resolved_tip: Optional[str] = None,
    lineage_ids: Optional[Sequence[str]] = None,
) -> Optional[str]:
    """Return the session id to switch the bridge key onto, or None if already correct.

    When ``resolved_tip`` is available (``resolve_resume_session_id``), bind to that
    live tip. Never switch a key that already points at the tip back to an older
    lineage member. Without a tip resolver, only switch when the current id is
    outside the target's compression lineage.
    """
    lineage = [sid for sid in (lineage_ids or ()) if isinstance(sid, str) and sid]
    if resolved_tip:
        target = resolved_tip
        if current_session_id == target:
            return None
        if lineage and current_session_id in lineage:
            tip = lineage[-1]
            if current_session_id == tip:
                return None
            if target in lineage:
                try:
                    if lineage.index(current_session_id) > lineage.index(target):
                        return None
                except ValueError:
                    pass
        return target

    target = listed_id
    if current_session_id == target:
        return None
    if lineage and current_session_id in lineage:
        return None
    return target


def is_continued_row(row: Any) -> bool:
    """A foreign session the phone continued: core re-stamps its origin to the bridge."""
    return (
        isinstance(row, dict)
        and row.get("source") == "hermes_bridge"
        and isinstance(row.get("id"), str)
        and row.get("thread_id") == continuation_thread_id(row["id"])
    )


def _foreign_ids(sessions: List[Any]) -> set:
    return {
        row.get("id") for row in sessions
        if isinstance(row, dict) and (row.get("source") != "hermes_bridge" or is_continued_row(row))
    }


def bridge_thread_id(session_id: Optional[str], sessions: List[dict]) -> Optional[str]:
    """Thread id to put on the gateway message, or None to keep the legacy row.

    An exact non-bridge id always continues (``cont_<id>``), even when a legacy
    fork row also has ``thread_id == session_id``. Sends into the fork itself
    still use the fork's gateway row id (``row.id == session_id``).

    A laptop-app session returns None. Callers must use the owner client; this
    None is not the legacy bare key.
    """
    if not session_id:
        return None
    matched = next(
        (row for row in sessions if isinstance(row, dict) and row.get("id") == session_id),
        None,
    )
    if is_local_owned_session(session_id, matched):
        return None
    foreign_ids = _foreign_ids(sessions)
    # Exact foreign id wins over a legacy fork whose thread_id equals that id.
    if session_id in foreign_ids:
        return continuation_thread_id(session_id)
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
    """Expose phone thread ids except legacy forks colliding with foreign sessions.

    Continuation threads (``cont_*``) are short-lived empty bridge rows created
    by get_or_create before switch_session; hide them so the foreign id appears once.
    A laptop session already re-stamped to ``cont_<id>`` stays listed under its
    own id with source ``local``, so the phone submits to its owner.
    """
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
        return data
    foreign_ids = _foreign_ids(data["sessions"])
    sessions: List[Any] = []
    for row in data["sessions"]:
        if not isinstance(row, dict):
            sessions.append(row)
            continue
        row_id = row.get("id") if isinstance(row.get("id"), str) else None
        if is_local_owned_session(row_id, row):
            sessions.append(_present_local_owned_row(row))
            continue
        if is_continued_row(row):
            sessions.append(row)
            continue
        if row.get("source") == "hermes_bridge":
            thread = row.get("thread_id")
            if isinstance(thread, str) and thread.startswith(CONT_PREFIX):
                continue  # empty placeholder row from get_or_create before the switch
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
