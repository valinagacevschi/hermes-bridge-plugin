# Bot activity snapshot; #84 J: list_bots + lookup_chat via policy/chats (no host duck).
"""Durable Bot activity cursors from REST history — never session.resume."""

from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import quote, urlencode

from .bots_policy import list_bots
from .bot_chats import lookup_chat, _message_text, _message_ts_ms

# Bound recent completed turns per Bot so the phone can compute unread counts
# without shipping a full forever-chat transcript.
_ACTIVITY_HISTORY_LIMIT = 50


def project_completed_turns(rows: Any) -> List[Dict[str, Any]]:
    """Stable completed assistant-turn cursors from REST message rows.

    Partial/empty assistant rows and non-assistant roles are ignored. Duplicate
    ids (compaction lineage / repeated delivery) collapse to one cursor.
    Returned oldest → newest so a device read marker can count successors.
    """
    if not isinstance(rows, list):
        return []
    seen: set[str] = set()
    ordered: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("role") or "").strip() != "assistant":
            continue
        if row.get("display_kind") == "hidden":
            continue
        row_id = row.get("id") if row.get("id") is not None else row.get("row_id")
        if row_id is None or row_id == "":
            continue
        if not _message_text(row):
            continue
        cursor = str(row_id)
        if cursor in seen:
            continue
        seen.add(cursor)
        ordered.append({"cursor": cursor, "completed_at": _message_ts_ms(row)})
    ordered.sort(key=lambda item: (item["completed_at"], item["cursor"]))
    return ordered


async def _fetch_recent_messages(host: Any, stored_id: str, name: str) -> List[Any]:
    qs = urlencode(
        {
            "profile": name,
            "limit": str(_ACTIVITY_HISTORY_LIMIT),
            "offset": "0",
            "order": "latest",
            "include_compacted": "true",
        }
    )
    path = f"/api/sessions/{quote(stored_id, safe='')}/messages?{qs}"
    try:
        raw = await host._api.get(path)
    except Exception:
        # Missing chat or API gaps must not take over transport; degrade this Bot.
        return []
    rows = raw.get("messages") if isinstance(raw, dict) else []
    return rows if isinstance(rows, list) else []


async def activity_snapshot(host: Any, _params: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only activity snapshot for every bot-managed profile on this Laptop."""
    roster = await list_bots(host)
    bots: List[Dict[str, Any]] = []
    for row in roster:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        if not name:
            continue
        stored = await lookup_chat(host, name)
        if not stored:
            bots.append({"name": name, "cursor": None, "completed_at": None, "turns": []})
            continue
        messages = await _fetch_recent_messages(host, stored, name)
        turns = project_completed_turns(messages)
        latest = turns[-1] if turns else None
        bots.append(
            {
                "name": name,
                "cursor": latest["cursor"] if latest else None,
                "completed_at": latest["completed_at"] if latest else None,
                "turns": turns,
            }
        )
    return {"bots": bots, "generated_at": int(time.time() * 1000)}
