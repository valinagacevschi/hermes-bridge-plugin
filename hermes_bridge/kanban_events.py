"""Board events -> phone Inbox (PRD_Inbox_Kanban.md §3).

Read-only poll of the laptop's ``~/.hermes/kanban.db``. Hermes core has no
event hook for kanban writes, so the adapter polls ``task_events`` (the same
kind of polling ``_poll_pending_writes`` already does for staged writes).

Every event becomes a normal unsolicited assistant send, which means it is
sealed, pushed live, and durably enqueued by ``adapter.send`` exactly like cron
output. The wire payload carries a ``kanban_event`` object; the phone files
those in its Inbox store instead of a chat session.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote

from . import bot_notify

logger = logging.getLogger(__name__)

DEFAULT_KANBAN_DB = os.path.join(os.path.expanduser("~"), ".hermes", "kanban.db")
MAX_EXCERPT_CHARS = 200
MAX_TITLE_CHARS = 200

# Event kinds this poll translates. Any other event still advances the cursor.
_REVIEW_REQUESTED = "review_requested"
_BLOCKED = "blocked"
_STATUS = "status"
_COMMENTED = "commented"


def kanban_db_path() -> str:
    """Dispatcher-pinned DB wins; the default board sits at the Hermes root."""
    return os.environ.get("HERMES_KANBAN_DB") or DEFAULT_KANBAN_DB


def state_path(profile_id: str) -> str:
    """Cursor lives beside the bridge's other runtime state (bot_notify)."""
    return os.path.join(bot_notify._STATE_DIR, f"kanban_events_{profile_id}.json")


def watch_profiles(config: Any, own_profile: Optional[str]) -> List[str]:
    """Profiles whose cards notify this phone.

    Unset -> the local core profile the gateway runs as (the adapter already
    knows it). Explicitly empty / invalid -> disabled.
    """
    extra = getattr(config, "extra", None)
    if not isinstance(extra, dict) or "kanban_watch_profiles" not in extra:
        return [own_profile] if own_profile else []
    raw = extra.get("kanban_watch_profiles")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    profiles: List[str] = []
    for value in raw:
        if isinstance(value, str) and value.strip() and value.strip() not in profiles:
            profiles.append(value.strip())
    return profiles


def load_cursor(path: str) -> Optional[int]:
    """Last processed ``task_events.id``; None means "never polled" (baseline)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        value = raw.get("cursor") if isinstance(raw, dict) else raw
        return int(value) if value is not None else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def save_cursor(path: str, cursor: int) -> None:
    target = path
    temporary = f"{target}.tmp"
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump({"cursor": int(cursor)}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        logger.debug("[hermes_bridge] failed to persist kanban cursor: %s", exc)
        try:
            os.unlink(temporary)
        except OSError:
            pass


def connect_readonly(path: str) -> sqlite3.Connection:
    """Open the board without ever taking a writer role on it."""
    conn = sqlite3.connect(f"file:{quote(path)}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _json_dict(raw: Any) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _first_line(value: Any, limit: int = MAX_EXCERPT_CHARS) -> Optional[str]:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None
    line = stripped.splitlines()[0].strip()
    return line[:limit] or None


def _comment_body(
    conn: sqlite3.Connection, task_id: str, created_at: int, author: Any
) -> Optional[str]:
    """Comment bodies are not in the event payload (only author + length)."""
    if isinstance(author, str) and author:
        row = conn.execute(
            "SELECT body FROM task_comments WHERE task_id = ? AND created_at = ? "
            "AND author = ? ORDER BY id DESC LIMIT 1",
            (task_id, created_at, author),
        ).fetchone()
        if row is not None:
            return row["body"]
    row = conn.execute(
        "SELECT body FROM task_comments WHERE task_id = ? AND created_at <= ? "
        "ORDER BY created_at DESC, id DESC LIMIT 1",
        (task_id, created_at),
    ).fetchone()
    return row["body"] if row is not None else None


def _translate(conn: sqlite3.Connection, row: sqlite3.Row) -> Optional[Dict[str, Any]]:
    """One task_events row -> wire event, or None when it is not a target kind."""
    payload = _json_dict(row["payload"])
    event_kind = row["event_kind"]
    actor: Any = payload.get("actor")

    if event_kind == _REVIEW_REQUESTED:
        kind = "review_requested"
        excerpt = payload.get("summary")
        actor = payload.get("implementer") or payload.get("reviewer")
    elif event_kind == _BLOCKED:
        kind = "blocked"
        excerpt = payload.get("reason")
    elif event_kind == _STATUS:
        status = payload.get("status")
        if status == "review":
            kind = "review"
            excerpt = payload.get("reason") or "entered review"
        elif status == "blocked":
            kind = "blocked"
            excerpt = payload.get("reason") or "blocked"
        else:
            return None
    elif event_kind == _COMMENTED:
        kind = "comment"
        # A comment event names its author; comment rows use `author` too.
        actor = payload.get("author")
        excerpt = _comment_body(conn, row["task_id"], int(row["created_at"] or 0), actor)
    else:
        return None

    task_id = str(row["task_id"])
    title = (row["title"] or task_id).strip()[:MAX_TITLE_CHARS]
    return {
        "event_id": f"{task_id}:{row['event_row_id']}:{kind}",
        "kind": kind,
        "task_id": task_id,
        "title": title,
        "excerpt": _first_line(excerpt),
        "actor": actor.strip() if isinstance(actor, str) and actor.strip() else None,
        "created_at": int(row["created_at"] or 0),
        # Internal routing label; adapter pops it before sealing the frame so
        # the wire payload keeps exactly the contracted keys.
        "assignee": row["assignee"],
    }


def collect_events(
    conn: sqlite3.Connection, cursor: int, watched: Sequence[str]
) -> Tuple[List[Dict[str, Any]], int]:
    """Translate rows after ``cursor`` for cards assigned to a watched profile."""
    watched_set = set(watched)
    rows = conn.execute(
        "SELECT e.id AS event_row_id, e.task_id, e.kind AS event_kind, e.payload, "
        "       e.created_at, t.title, t.assignee "
        "  FROM task_events e JOIN tasks t ON t.id = e.task_id "
        " WHERE e.id > ? ORDER BY e.id ASC",
        (int(cursor),),
    ).fetchall()
    events: List[Dict[str, Any]] = []
    new_cursor = int(cursor)
    for row in rows:
        new_cursor = max(new_cursor, int(row["event_row_id"]))
        assignee = row["assignee"]
        if not isinstance(assignee, str) or assignee not in watched_set:
            continue
        event = _translate(conn, row)
        if event is not None:
            events.append(event)
    return events, new_cursor


def poll(
    db_path: str, cursor: Optional[int], watched: Sequence[str]
) -> Optional[Tuple[List[Dict[str, Any]], int]]:
    """One read-only tick.

    Returns ``(events, new_cursor)``; ``None`` when the feature cannot run
    (missing DB / unreadable schema). First call (``cursor is None``)
    establishes a baseline so pre-existing history is not replayed as new.
    """
    if not watched:
        return [], int(cursor or 0)
    if not os.path.exists(db_path):
        return None
    try:
        conn = connect_readonly(db_path)
    except sqlite3.Error:
        return None
    try:
        if cursor is None:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) AS latest FROM task_events").fetchone()
            return [], int(row["latest"] or 0)
        return collect_events(conn, cursor, watched)
    except sqlite3.Error as exc:
        logger.debug("[hermes_bridge] kanban poll failed: %s", exc)
        return None
    finally:
        conn.close()


def event_content(event: Dict[str, Any]) -> str:
    """Human sentence shown as the Inbox row's title."""
    title = event.get("title") or event.get("task_id") or "Card"
    task_id = event.get("task_id") or ""
    kind = event.get("kind")
    if kind == "review":
        return f"Card {task_id}: {title} entered review"
    if kind == "blocked":
        return f"Card {task_id}: {title} is blocked"
    if kind == "review_requested":
        return f"Card {task_id}: review requested for {title}"
    if kind == "comment":
        return f"Card {task_id}: new comment on {title}"
    return f"Card {task_id}: {title}"
