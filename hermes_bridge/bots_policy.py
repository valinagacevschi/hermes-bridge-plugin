# Shared Bot enablement + profile authorization (#84 A/J).
# List/auth/projection live here so chats/activity/subagents do not host-duck them.
"""Bot policy predicates, roster projection, and one-shot profiles.list snapshots.

The roster snapshot is the served door's answer PLUS the gateway's own served
bot rows (#159): the door can answer from a narrower profile root than the
gateway's (a headless `serve` enumerating its CLI home, for example), and a
served door must never hide bot profiles this gateway serves.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional

from .operation_dispatch import _LocalRpcError, _RpcError

logger = logging.getLogger(__name__)

_BOTS_ENABLED_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Avatar asset extensions the served door's roster checks (methods_profiles).
_AVATAR_EXTS = ("png", "jpg", "jpeg", "webp")


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


def _profiles_registry() -> Any:
    """Hermes' profile registry module, or None on an older core.

    Lazy + guarded (see PRIVATE_IMPORTS.md §hermes_cli.profiles): the import
    is the single validator-counted site; every symbol is duck-typed so a
    host that moved a helper degrades to the door's own answer. The module is
    re-read off ``sys.modules`` after the import — ``import a.b as c`` binds
    the parent package's cached attribute, which a sys.modules-patched fixture
    never replaces.
    """
    try:
        import hermes_cli.profiles  # noqa: F401

        return sys.modules.get("hermes_cli.profiles")
    except Exception:
        return None


def _profile_registry_row(name: str) -> Optional[Dict[str, Any]]:
    """A profiles.list-shaped row for one named profile from the registry.

    Reads the profile's ``profile.yaml`` — the same machine-written file the
    served door (and the Desktop's ui_meta CAS writer, which records the
    ``hermes-bots`` marker at bot creation) resolves. A profile whose yaml
    carries no marker is not a bot and is never synthesized. Never raises.
    """
    if not name or name == "default":
        return None
    reg = _profiles_registry()
    if reg is None:
        return None
    get_profile_dir = getattr(reg, "get_profile_dir", None)
    load_yaml_dict = getattr(reg, "_load_yaml_dict", None)
    if not callable(get_profile_dir) or not callable(load_yaml_dict):
        return None
    try:
        home = Path(str(get_profile_dir(name)))
    except Exception:
        return None
    try:
        data = load_yaml_dict(home / "profile.yaml")
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    ui_meta = data.get("ui_meta")
    if not isinstance(ui_meta, dict) or "hermes-bots" not in ui_meta:
        return None
    # Marker present. Fill the presentation fields the way the door's own
    # handler does: read_profile_meta is the host's parsed view (never raises).
    read_meta = getattr(reg, "read_profile_meta", None)
    meta: Dict[str, Any] = {}
    if callable(read_meta):
        try:
            row_meta = read_meta(home)
            if isinstance(row_meta, dict):
                meta = row_meta
        except Exception:
            meta = {}
    bots_meta = ui_meta.get("hermes-bots")
    if not isinstance(bots_meta, dict):
        bots_meta = {}
    has_avatar = False
    try:
        has_avatar = any((home / "assets" / f"avatar.{ext}").is_file() for ext in _AVATAR_EXTS)
    except OSError:
        has_avatar = False
    display = (
        str(meta.get("display_name") or "")
        or str(bots_meta.get("title") or "")
        or name
    )
    description = str(meta.get("description") or "") or str(bots_meta.get("description") or "")
    return {
        "name": name,
        "is_default": False,
        "display_name": display,
        "model": None,
        "description": description,
        "has_avatar": has_avatar,
        # No session store read here: the door's profiles.list (or none) is the
        # session source. project_bot_row tolerates a null canonical_session.
        "canonical_session": None,
        "ui_meta": ui_meta,
    }


def _gateway_bot_rows_behind_the_door(
    host: Any, door_rows: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Registry rows for gateway-served bot profiles the door answer missed (#159).

    The served door may answer with a narrower profile root than this
    gateway's (a headless `serve` enumerating its CLI home while the Desktop
    owns the lead-* profiles). Only names THIS gateway serves are eligible —
    `_gateway_served_profiles` is [own] for standalone gateways, so the
    machine-global multiplex roster never leaks into an isolated rig. The door
    wins for any name it already lists; projection is strictly additive and
    never raises.
    """
    try:
        served = host._gateway_served_profiles()
    except Exception:
        served = []
    if not isinstance(served, (list, tuple, set)):
        return []
    door_names = {
        str(row.get("name") or "").strip() for row in door_rows if isinstance(row, dict)
    }
    rows: List[Dict[str, Any]] = []
    for raw in served:
        name = str(raw or "").strip()
        if not name or name == "default" or name in door_names:
            continue
        row = _profile_registry_row(name)
        if row is not None:
            rows.append(row)
    if rows:
        logger.debug(
            "[hermes_bridge] projected served bot profile(s) the door answer missed: %s",
            ",".join(sorted(str(r["name"]) for r in rows)),
        )
    return rows


class ProfilesSnapshot(NamedTuple):
    """One profiles.list parse: bot roster map + optional default row."""

    bots: Dict[str, Dict[str, Any]]
    default_row: Optional[Dict[str, Any]]
    rows: List[Dict[str, Any]]


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
    return ProfilesSnapshot(bots=bots, default_row=default_row, rows=[r for r in rows if isinstance(r, dict)])


async def fetch_profiles_snapshot(
    host: Any, *, include_sessions: bool = False
) -> ProfilesSnapshot:
    """Single profiles.list → bot map + default row. Raises bots_unavailable.

    The door's rows are authoritative for the names it answers; bot-managed
    names this gateway serves that the door omits are projected from the
    profile registry (#159), so a served door never hides a host bot roster.
    """
    try:
        result = await host._local_rpc(
            "profiles.list", {"include_sessions": include_sessions}
        )
    except _LocalRpcError as exc:
        raise _RpcError("bots_unavailable") from exc
    if not isinstance(result, dict) or not result.get("bot_mode_protocol"):
        raise _RpcError("bots_unavailable")
    rows = result.get("profiles")
    door_rows = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    projected = _gateway_bot_rows_behind_the_door(host, door_rows)
    snapshot_result: Dict[str, Any] = dict(result)
    if projected:
        snapshot_result["profiles"] = door_rows + projected
    return parse_profiles_snapshot(snapshot_result)


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
