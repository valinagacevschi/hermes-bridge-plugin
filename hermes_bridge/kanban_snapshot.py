"""Serializer for the kanban.snapshot wire body (PRD_Inbox_Kanban.md §3/§4).

Reads the laptop's read-only ``~/.hermes/kanban.db`` and shapes it into the
exact body lib/kanban-wire.ts's ``validateSnapshotBody`` expects: 8 columns
in ``STATUSES`` order, and every ``card_ids`` entry present in ``cards``.

Versions are a monotonic watermark, not a gap-free sequence. ``card.version``
is the latest ``task_events.id`` for that task (0 if none); the board
``version`` is the latest ``task_events.id`` across all of ``task_events``
(0 if none). The phone's delta logic (lib/kanban-cache.ts) is written for
contiguous per-card versions; a snapshot's version only guarantees "newer
than before", not that every intermediate number was ever observed as its
own event — closing that gap is later work (kanban.events on the wire, not
the Inbox-only board-event watcher this module's sibling, kanban_events.py,
already emits).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Sequence

from .kanban_events import connect_readonly, kanban_db_path

BOARD = "default"

STATUSES: Sequence[str] = (
    "triage",
    "todo",
    "scheduled",
    "ready",
    "running",
    "blocked",
    "review",
    "done",
)
_STATUS_ORDER = {status: index for index, status in enumerate(STATUSES)}


def _comment_counts(conn, known_ids: set) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in conn.execute(
        "SELECT task_id, COUNT(*) AS n FROM task_comments GROUP BY task_id"
    ):
        if row["task_id"] in known_ids:
            counts[row["task_id"]] = int(row["n"])
    return counts


def _versions(conn, known_ids: set) -> tuple[Dict[str, int], int]:
    board_row = conn.execute("SELECT COALESCE(MAX(id), 0) AS v FROM task_events").fetchone()
    board_version = int(board_row["v"] or 0)
    card_versions: Dict[str, int] = {}
    for row in conn.execute("SELECT task_id, MAX(id) AS v FROM task_events GROUP BY task_id"):
        if row["task_id"] in known_ids:
            card_versions[row["task_id"]] = int(row["v"] or 0)
    return card_versions, board_version


def _links(conn, known_ids: set) -> tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    parents: Dict[str, List[str]] = {}
    children: Dict[str, List[str]] = {}
    for row in conn.execute("SELECT parent_id, child_id FROM task_links"):
        parent_id, child_id = row["parent_id"], row["child_id"]
        if parent_id not in known_ids or child_id not in known_ids:
            continue
        children.setdefault(parent_id, []).append(child_id)
        parents.setdefault(child_id, []).append(parent_id)
    for lst in parents.values():
        lst.sort()
    for lst in children.values():
        lst.sort()
    return parents, children


def build_snapshot(db_path: Optional[str] = None, board: str = BOARD) -> Dict[str, Any]:
    """Pure, read-only, deterministic: same DB contents => same return value.

    Raises ``FileNotFoundError`` when the board file does not exist — callers
    that poll (see adapter.py's kanban.snapshot emitter) treat that as "the
    feature cannot run yet", not a crash.
    """
    path = db_path or kanban_db_path()
    if not os.path.exists(path):
        raise FileNotFoundError(f"kanban db not found: {path}")

    conn = connect_readonly(path)
    try:
        rows = conn.execute(
            "SELECT id, title, status, assignee, COALESCE(priority, 0) AS priority, "
            "       created_at FROM tasks WHERE status != 'archived'"
        ).fetchall()
        known = [row for row in rows if row["status"] in _STATUS_ORDER]
        known_ids = {row["id"] for row in known}

        comment_counts = _comment_counts(conn, known_ids)
        card_versions, board_version = _versions(conn, known_ids)
        parents, children = _links(conn, known_ids)

        ordered = sorted(
            known,
            key=lambda row: (
                _STATUS_ORDER[row["status"]],
                -row["priority"],
                row["created_at"],
                row["id"],
            ),
        )

        columns: List[Dict[str, Any]] = [
            {"status": status, "card_ids": []} for status in STATUSES
        ]
        cards: List[Dict[str, Any]] = []
        for row in ordered:
            task_id = row["id"]
            columns[_STATUS_ORDER[row["status"]]]["card_ids"].append(task_id)
            cards.append(
                {
                    "id": task_id,
                    "title": row["title"] or "",
                    "status": row["status"],
                    "assignee": row["assignee"],
                    "priority": row["priority"],
                    "parents": parents.get(task_id, []),
                    "children": children.get(task_id, []),
                    "comment_count": comment_counts.get(task_id, 0),
                    "version": card_versions.get(task_id, 0),
                }
            )

        return {
            "v": 1,
            "kind": "kanban.snapshot",
            "board": board,
            "version": board_version,
            "columns": columns,
            "cards": cards,
        }
    finally:
        conn.close()


def snapshot_json(snapshot: Dict[str, Any]) -> str:
    """Stable encoding so the emitter can hash/compare it for change detection."""
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
