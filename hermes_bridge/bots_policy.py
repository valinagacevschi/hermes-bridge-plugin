# Shared Bot enablement + profile authorization (#84 A/J).
# List/auth/projection live here so chats/activity/subagents do not host-duck them.
"""Bot policy predicates, roster projection, and one-shot profiles.list snapshots."""

from __future__ import annotations

import os
from typing import Any, Dict, List, NamedTuple, Optional

from .operation_dispatch import _LocalRpcError, _RpcError

_BOTS_ENABLED_TRUTHY = frozenset({"1", "true", "yes", "on"})


def bots_flag_enabled() -> bool:
    """Read HERMES_BRIDGE_BOTS_ENABLED (default on)."""
    raw = os.getenv("HERMES_BRIDGE_BOTS_ENABLED", "1")
    return str(raw).strip().lower() in _BOTS_ENABLED_TRUTHY


def is_bot_managed_row(row: Dict[str, Any]) -> bool:
    """Authorization/display predicate: bot-managed, non-default core-profile.

    There is no is_bot field. The marker is ui_meta['hermes-bots'], written
    by the desktop at bot creation. The default core-profile is excluded —
    normal chat already talks to it.
    """
    if row.get("is_default"):
        return False
    ui_meta = row.get("ui_meta")
    return isinstance(ui_meta, dict) and "hermes-bots" in ui_meta


def require_bots_enabled() -> None:
    if not bots_flag_enabled():
        raise _RpcError("bots_disabled")


def blocked_bot_capabilities(reason: str) -> Dict[str, Any]:
    blocked = {"available": False, "reason": reason}
    return {
        "stop": dict(blocked),
        "activity": dict(blocked),
        "notify": dict(blocked),
        "subagents": {
            **blocked,
            "tail": dict(blocked),
            "controls": {"steer": dict(blocked), "interrupt": dict(blocked)},
        },
    }


def project_bot_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Phone-facing roster row. Shape/color ride along from ui_meta; photos do not."""
    ui_meta = row.get("ui_meta") if isinstance(row.get("ui_meta"), dict) else {}
    bots_meta = ui_meta.get("hermes-bots") if isinstance(ui_meta, dict) else None
    if not isinstance(bots_meta, dict):
        bots_meta = {}
    canon = row.get("canonical_session")
    if not isinstance(canon, dict):
        canon = None
    display = row.get("display_name") or bots_meta.get("title") or row.get("name") or ""
    description = row.get("description") or bots_meta.get("description") or None
    return {
        "name": row.get("name") or "",
        "display_name": display,
        "model": row.get("model") or None,
        "description": description or None,
        "has_avatar": bool(row.get("has_avatar")),
        "canonical_session": (
            {
                "preview": canon.get("preview") or None,
                "last_active": canon.get("last_active"),
            }
            if canon
            else None
        ),
        "shape": bots_meta.get("shape") or None,
        "color": bots_meta.get("color") or None,
    }


class ProfilesSnapshot(NamedTuple):
    """One profiles.list parse: bot roster map + optional default row."""

    bots: Dict[str, Dict[str, Any]]
    default_row: Optional[Dict[str, Any]]


def parse_profiles_snapshot(result: Dict[str, Any]) -> ProfilesSnapshot:
    rows = result.get("profiles") or []
    if not isinstance(rows, list):
        rows = []
    bots: Dict[str, Dict[str, Any]] = {}
    default_row: Optional[Dict[str, Any]] = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        if default_row is None and (row.get("is_default") or row.get("name") == "default"):
            default_row = row
        if is_bot_managed_row(row):
            name = str(row.get("name") or "").strip()
            if name:
                bots[name] = row
    return ProfilesSnapshot(bots=bots, default_row=default_row)


async def fetch_profiles_snapshot(
    host: Any, *, include_sessions: bool = False
) -> ProfilesSnapshot:
    """Single profiles.list → bot map + default row. Raises bots_unavailable."""
    try:
        result = await host._local_rpc(
            "profiles.list", {"include_sessions": include_sessions}
        )
    except _LocalRpcError as exc:
        raise _RpcError("bots_unavailable") from exc
    if not isinstance(result, dict) or not result.get("bot_mode_protocol"):
        raise _RpcError("bots_unavailable")
    return parse_profiles_snapshot(result)


async def list_bots(host: Any) -> List[Dict[str, Any]]:
    """Projected roster of bot-managed core-profiles on this laptop."""
    require_bots_enabled()
    snap = await fetch_profiles_snapshot(host, include_sessions=True)
    return [project_bot_row(row) for row in snap.bots.values()]


async def require_bot_profile(host: Any, name: str) -> Dict[str, Any]:
    """Re-validate the name. Authorization boundary, not a display filter.

    Unknown name ⇒ bot_gone, never a fallback to the default core-profile.
    """
    require_bots_enabled()
    snap = await fetch_profiles_snapshot(host, include_sessions=True)
    row = snap.bots.get(name)
    if row is None:
        raise _RpcError("bot_gone")
    return row
