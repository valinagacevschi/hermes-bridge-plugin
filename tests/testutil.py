"""
Shared test harness for HermesBridgeAdapter unit tests (test_rpc.py,
test_streaming.py, test_attachments.py): stubs the gateway base classes +
heavy deps and builds an adapter with all network I/O mocked.

Import this module BEFORE hermes_bridge.adapter — it inserts the repo root
on sys.path and stubs `websockets` + `gateway.platforms.base` +
`tools.write_approval`/`tools.memory_tool`/`tools.skill_manager_tool` in
sys.modules. Those are Hermes core — present in a real Hermes venv, absent
in this standalone repo/CI — so they're stubbed here (unlike the source
monorepo's copy of this file, which runs inside a real Hermes install and
only patches individual names).
"""

import dataclasses
import enum as _enum
import os
import sys
import time as _time
import types as _types
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

# Make the `hermes_bridge` package importable from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Stub heavy/absent deps before importing the adapter.
sys.modules.setdefault("websockets", MagicMock())
sys.modules.setdefault("websockets.exceptions", MagicMock())


@dataclasses.dataclass
class RealSendResult:
    """Real dataclass stand-in for gateway.platforms.base.SendResult — a
    MagicMock would return a fresh auto-mock from `.success`/`.message_id`
    regardless of constructor kwargs. adapter.py builds SendResult(...) by
    looking up the module-global name at CALL time (not at def time), so
    this must be bound directly into the gateway.platforms.base stub below —
    patching `hermes_bridge.adapter.SendResult` only for the duration of
    make_adapter() (as the source monorepo's copy of this file does, safe
    there because the real Hermes core class is already bound) would not
    stick for calls made after make_adapter() returns."""

    success: bool
    message_id: Optional[str] = None
    error: Optional[str] = None
    raw_response: Any = None
    retryable: bool = False


if "gateway.platforms.base" not in sys.modules:
    sys.modules.setdefault("gateway", MagicMock())
    sys.modules.setdefault("gateway.platforms", MagicMock())
    _gw_base = _types.ModuleType("gateway.platforms.base")

    class _StubBasePlatformAdapter:  # real class so the adapter can subclass it
        def __init__(self, *a, **kw):
            pass

        # Real Hermes core provides these (chat.stop routes through them).
        # Stubbed here only so `patch.object(adapter, "build_source"/
        # "handle_message", ...)` has an attribute to override per-test —
        # tests never rely on these no-op bodies actually running.
        def build_source(self, *a, **kw):
            return {}

        async def handle_message(self, *a, **kw):
            return None

    class _RealMessageEvent:
        """Real class stand-in for gateway.platforms.base.MessageEvent —
        same rationale as RealSendResult above: a MagicMock would return a
        fresh auto-mock from `.text`/`.message_type` etc. regardless of
        constructor kwargs, breaking test_attachments.py's _receive_loop
        attribute assertions.

        Kwargs are absorbed rather than declared: core's MessageEvent grows
        fields (message_id, ...), and a fixed dataclass signature turns each
        addition into a TypeError swallowed by the adapter's dispatch
        try/except, i.e. a test failure that names the wrong cause."""

        _DEFAULTS = {
            "text": "",
            "source": None,
            "media_urls": None,
            "media_types": None,
            "message_type": None,
        }

        def __init__(self, **kwargs):
            self.__dict__.update(self._DEFAULTS)
            self.__dict__.update(kwargs)

        def __repr__(self):
            fields = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
            return f"MessageEvent({fields})"

    class _ProcessingOutcome(_enum.Enum):
        """Real enum, not a MagicMock: adapter.py compares outcomes by
        identity (`outcome == ProcessingOutcome.SUCCESS`), and every attribute
        of a MagicMock compares equal to nothing in particular."""

        SUCCESS = "success"
        FAILURE = "failure"
        CANCELLED = "cancelled"

    _gw_base.BasePlatformAdapter = _StubBasePlatformAdapter
    _gw_base.SendResult = RealSendResult
    _gw_base.MessageEvent = _RealMessageEvent
    _gw_base.MessageType = MagicMock()
    _gw_base.Platform = MagicMock()
    _gw_base.ProcessingOutcome = _ProcessingOutcome
    sys.modules["gateway.platforms.base"] = _gw_base

# `tools.write_approval`/`tools.memory_tool`/`tools.skill_manager_tool` are
# Hermes-core modules backing the memory/skills write-approval RPCs
# (adapter.py imports them lazily, inside the RPC handler methods, via
# `from tools import write_approval as wa`). Absent outside a real Hermes
# install, so stub them here.
#
# `tools` itself MUST be a real (empty) module, not a MagicMock: `from tools
# import write_approval` resolves via `getattr(tools_module, "write_approval")`
# first, falling back to sys.modules["tools.write_approval"] only on
# AttributeError. A MagicMock parent never raises AttributeError — it hands
# back an unrelated auto-mock attribute instead of our stub submodule, and
# `patch("tools.write_approval.x", ...)` would then be patching a module
# nothing actually calls.
if "tools.write_approval" not in sys.modules:
    _tools_pkg = sys.modules.get("tools") or _types.ModuleType("tools")
    sys.modules.setdefault("tools", _tools_pkg)

    _wa = _types.ModuleType("tools.write_approval")
    _wa.MEMORY = "memory"
    _wa.SKILLS = "skills"
    _wa.list_pending = MagicMock(return_value=[])
    _wa.get_pending = MagicMock(return_value=None)
    _wa.discard_pending = MagicMock(return_value=False)
    _wa.skill_pending_diff = MagicMock(return_value="")
    _tools_pkg.write_approval = _wa
    sys.modules["tools.write_approval"] = _wa

    _memory_tool = _types.ModuleType("tools.memory_tool")
    _memory_tool.apply_memory_pending = MagicMock(return_value={"success": True})
    _memory_tool.load_on_disk_store = MagicMock()
    _tools_pkg.memory_tool = _memory_tool
    sys.modules["tools.memory_tool"] = _memory_tool

    _skill_tool = _types.ModuleType("tools.skill_manager_tool")
    _skill_tool.apply_skill_pending = MagicMock(return_value='{"success": true}')
    _tools_pkg.skill_manager_tool = _skill_tool
    sys.modules["tools.skill_manager_tool"] = _skill_tool

PSK = bytes(range(32))
PROFILE = "test-profile"


class StubBasePlatformAdapter:
    """Minimal real base class — HermesBridgeAdapter is constructed via
    __new__, so this __init__ is never actually invoked. A plain class (not a
    MagicMock instance) avoids dunder-assignment restrictions in newer
    unittest.mock versions when used as a base in `class X(Base):`.

    NOTE: patching ``adapter.BasePlatformAdapter`` to this class only affects
    code that reads that module-level name afterward — it does NOT rewire
    HermesBridgeAdapter's already-defined ``__bases__`` (that's fixed at
    class-creation time, when the FIRST import of hermes_bridge.adapter ran
    the `from gateway.platforms.base import BasePlatformAdapter` above,
    against the stub module installed at the top of this file). So
    genuinely-inherited methods HermesBridgeAdapter never overrides
    (``build_source``, ``handle_message``, ...) resolve to
    ``_StubBasePlatformAdapter`` (a no-op), not a real Hermes core
    implementation. Tests exercising a handler that calls one of those must
    patch it per-instance instead (see test_rpc.py TestChatStop) — this class
    only avoids the __init__-related dunder-assignment crash if __init__
    were ever invoked, which the __new__-based construction below
    deliberately avoids anyway."""


def make_adapter(psk: bytes = PSK, profile_id: str = PROFILE):
    """Return a HermesBridgeAdapter with all network I/O stubbed."""
    with (
        patch(
            "hermes_bridge.adapter.BasePlatformAdapter",
            StubBasePlatformAdapter,
        ),
        patch("hermes_bridge.adapter.load_psk", return_value=psk),
    ):
        from hermes_bridge.adapter import HermesBridgeAdapter

        adapter = HermesBridgeAdapter.__new__(HermesBridgeAdapter)
        # Every field below mirrors the monorepo's testutil.make_adapter. The
        # adapter is built via __new__ (no __init__, no network, no env), so a
        # field added there and missed here surfaces as a bare AttributeError
        # deep inside a handler. scripts/sync-from-expo-hermes.sh fails the
        # sync when the monorepo sets a field this file doesn't.
        adapter._ws = MagicMock()
        adapter._ws.send = AsyncMock()
        adapter._profile_id = profile_id
        adapter._psk = psk
        adapter._seen_rpc_ids = {}
        adapter._descriptor = None
        adapter._inbound_cursor = 0
        adapter._inbound_seen_seq = 0
        adapter._backlog_open = True
        adapter._ws_connected_at = _time.time()
        adapter._pending_prompts = {}
        adapter._stream_pending = set()
        adapter._hermes_session_tokens = {}
        adapter._hermes_api_port = None
        # Nothing spawned by _ensure_local_api in a test adapter.
        adapter._api_proc = None
        adapter._local_ws = None
        adapter._local_ws_lock = None
        adapter._local_ws_next_id = 1
        adapter._bots_enabled = None
        adapter._bot_chats = {}
        adapter._bot_poll_tasks = {}
        adapter._bot_idle_timeout_s = 300.0
        adapter._bot_poll_fast_s = 1.0
        adapter._bot_poll_idle_s = 5.0
    return adapter
