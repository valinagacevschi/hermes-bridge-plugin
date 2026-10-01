# Changes: Laptop-scoped Bot completion observer + encrypted destinations (#81).
"""Bounded Bot completion observation — read-only activity, no session.resume."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from .crypto import seal_blob

logger = logging.getLogger("hermes_bridge")

# Bound how often we re-read activity while opted in. Cheap REST history reads;
# must not approach live transport polling rates.
_NOTIFY_POLL_INTERVAL_S = 30.0

_STATE_DIR = os.path.join(os.path.expanduser("~"), ".hermes", "platforms", "hermes_bridge")


def _state_path(profile_id: str) -> str:
    return os.path.join(_STATE_DIR, f"bot_notify_{profile_id}.json")


def completion_event_id(bot_name: str, cursor: str) -> str:
    payload = f"bot_completion|{bot_name}|{cursor}".encode()
    return hashlib.sha256(payload).hexdigest()


def turns_after_cursor(
    turns: List[Dict[str, Any]],
    notified_cursor: Optional[str],
    notified_completed_at: Optional[int],
) -> List[Dict[str, Any]]:
    if not turns:
        return []
    if notified_cursor is None:
        return list(turns)
    index = next((i for i, turn in enumerate(turns) if turn.get("cursor") == notified_cursor), -1)
    if index >= 0:
        return turns[index + 1 :]
    if notified_completed_at is not None:
        return [t for t in turns if int(t.get("completed_at") or 0) > notified_completed_at]
    return []


def default_state() -> Dict[str, Any]:
    return {"enabled": False, "baseline_done": False, "notified": {}, "seen_event_ids": []}


def load_state(profile_id: str, path: Optional[str] = None) -> Dict[str, Any]:
    target = path or _state_path(profile_id)
    try:
        with open(target, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return default_state()
    if not isinstance(raw, dict):
        return default_state()
    notified = raw.get("notified") if isinstance(raw.get("notified"), dict) else {}
    seen = raw.get("seen_event_ids") if isinstance(raw.get("seen_event_ids"), list) else []
    return {
        "enabled": bool(raw.get("enabled")),
        "baseline_done": bool(raw.get("baseline_done")),
        "notified": {
            str(name): {
                "cursor": row.get("cursor") if isinstance(row, dict) else None,
                "completed_at": row.get("completed_at") if isinstance(row, dict) else None,
            }
            for name, row in notified.items()
            if isinstance(name, str) and name
        },
        "seen_event_ids": [str(item) for item in seen if isinstance(item, str)][-200:],
    }


def save_state(profile_id: str, state: Dict[str, Any], path: Optional[str] = None) -> None:
    target = path or _state_path(profile_id)
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        payload = {
            "enabled": bool(state.get("enabled")),
            "baseline_done": bool(state.get("baseline_done")),
            "notified": state.get("notified") if isinstance(state.get("notified"), dict) else {},
            "seen_event_ids": list(state.get("seen_event_ids") or [])[-200:],
        }
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(payload, handle)
    except OSError as exc:
        logger.warning("[hermes_bridge] failed to persist bot notify state: %s", exc)


def seal_destination(profile_id: str, psk: bytes, dest: Dict[str, Any]) -> str:
    plain = json.dumps(dest, separators=(",", ":"), sort_keys=True).encode()
    sealed = seal_blob(profile_id, plain, psk)
    return base64.b64encode(sealed).decode("ascii")


def build_destination(bot_name: str, cursor: str, completed_at: int) -> Dict[str, Any]:
    return {
        "v": 1,
        "kind": "bot",
        "bot": bot_name,
        "cursor": cursor,
        "completed_at": int(completed_at),
        "event_id": completion_event_id(bot_name, cursor),
    }


def establish_baseline(snapshot: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """Mark current activity as already seen — no historical alerts."""
    notified: Dict[str, Any] = {}
    bots = snapshot.get("bots") if isinstance(snapshot, dict) else None
    if isinstance(bots, list):
        for row in bots:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            if not name:
                continue
            turns = row.get("turns") if isinstance(row.get("turns"), list) else []
            latest = turns[-1] if turns else None
            if isinstance(latest, dict) and latest.get("cursor"):
                notified[name] = {
                    "cursor": str(latest["cursor"]),
                    "completed_at": int(latest.get("completed_at") or 0),
                }
            else:
                notified[name] = {"cursor": None, "completed_at": None}
    next_state = dict(state)
    next_state["enabled"] = True
    next_state["baseline_done"] = True
    next_state["notified"] = notified
    return next_state


def discover_completions(
    snapshot: Dict[str, Any], state: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Return new completions + updated notified cursors. Skips if not baselined."""
    if not state.get("enabled") or not state.get("baseline_done"):
        return [], state
    notified = dict(state.get("notified") or {})
    seen = list(state.get("seen_event_ids") or [])
    seen_set = set(seen)
    events: List[Dict[str, Any]] = []
    bots = snapshot.get("bots") if isinstance(snapshot, dict) else None
    if not isinstance(bots, list):
        return [], state
    for row in bots:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "")
        if not name:
            continue
        turns = [t for t in (row.get("turns") or []) if isinstance(t, dict) and t.get("cursor")]
        marker = notified.get(name) if isinstance(notified.get(name), dict) else {}
        fresh = turns_after_cursor(
            turns,
            marker.get("cursor") if isinstance(marker, dict) else None,
            marker.get("completed_at") if isinstance(marker, dict) else None,
        )
        for turn in fresh:
            cursor = str(turn["cursor"])
            completed_at = int(turn.get("completed_at") or 0)
            event_id = completion_event_id(name, cursor)
            if event_id in seen_set:
                continue
            dest = build_destination(name, cursor, completed_at)
            events.append({"bot": name, "dest": dest, "event_id": event_id})
            seen_set.add(event_id)
            seen.append(event_id)
        if turns:
            latest = turns[-1]
            notified[name] = {
                "cursor": str(latest["cursor"]),
                "completed_at": int(latest.get("completed_at") or 0),
            }
        elif name not in notified:
            notified[name] = {"cursor": None, "completed_at": None}
    next_state = dict(state)
    next_state["notified"] = notified
    next_state["seen_event_ids"] = seen[-200:]
    return events, next_state


async def get_preference(host: Any, _params: Dict[str, Any]) -> Dict[str, Any]:
    state = load_state(host._profile_id)
    return {"enabled": bool(state.get("enabled")), "baseline_done": bool(state.get("baseline_done"))}


async def set_preference(host: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    enabled = bool(params.get("enabled"))
    state = load_state(host._profile_id)
    if enabled and not state.get("enabled"):
        from . import bot_activity

        snapshot = await bot_activity.activity_snapshot(host, {})
        state = establish_baseline(snapshot, state)
        save_state(host._profile_id, state)
        host._ensure_bot_notify_observer()
        return {"enabled": True, "baseline_done": True}
    if not enabled:
        state["enabled"] = False
        save_state(host._profile_id, state)
        host._stop_bot_notify_observer()
        return {"enabled": False, "baseline_done": bool(state.get("baseline_done"))}
    return {"enabled": bool(state.get("enabled")), "baseline_done": bool(state.get("baseline_done"))}


async def observe_once(host: Any) -> int:
    """One observer tick. Returns number of lifecycle events emitted."""
    state = load_state(host._profile_id)
    if not state.get("enabled"):
        return 0
    from . import bot_activity

    snapshot = await bot_activity.activity_snapshot(host, {})
    if not state.get("baseline_done"):
        state = establish_baseline(snapshot, state)
        save_state(host._profile_id, state)
        return 0
    events, next_state = discover_completions(snapshot, state)
    if not events:
        if next_state != state:
            save_state(host._profile_id, next_state)
        return 0
    psk = host._psk
    if not psk:
        logger.warning("[hermes_bridge] bot notify skipped — missing PSK")
        return 0
    # Persist cursors/seen ids BEFORE emit so a crash after push cannot
    # re-alert the same completion (prefer at-most-once over duplicates).
    save_state(host._profile_id, next_state)
    emitted = 0
    for event in events:
        dest = event["dest"]
        try:
            sealed = seal_destination(host._profile_id, psk, dest)
            # Opaque routing only — never Bot names/content on the wire.
            await host._send_lifecycle_event(
                "bot.completed",
                data={"screen": "bot", "dest": sealed, "event_id": event["event_id"]},
            )
            emitted += 1
        except Exception as exc:
            logger.warning("[hermes_bridge] bot notify emit failed: %s", exc)
    return emitted


async def poll_completions(host: Any) -> None:
    """Background loop: discover Desktop/phone completions while opted in."""
    while getattr(host, "_should_run", False):
        state = load_state(host._profile_id)
        if not state.get("enabled"):
            return
        try:
            await observe_once(host)
        except Exception as exc:
            logger.warning("[hermes_bridge] bot notify tick failed: %s", exc)
        await _sleep(host, _NOTIFY_POLL_INTERVAL_S)


async def _sleep(host: Any, seconds: float) -> None:
    import asyncio

    end = time.monotonic() + seconds
    while getattr(host, "_should_run", False) and time.monotonic() < end:
        state = load_state(host._profile_id)
        if not state.get("enabled"):
            return
        await asyncio.sleep(min(1.0, end - time.monotonic()))
