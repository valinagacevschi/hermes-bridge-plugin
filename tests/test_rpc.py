"""
Unit tests for HermesBridgeAdapter RPC dispatch — cron write methods + dedup.

Run from the repo root:
    python -m pytest tests/test_rpc.py
or with any Python ≥3.8 that has websockets + PyNaCl installed.
"""

import asyncio
import json
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Make the `hermes_bridge` package importable when running from the repo root.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Stub heavy deps before importing the adapter. `gateway.platforms.base` is
# Hermes core — present in a real Hermes venv, absent in standalone CI — so
# stub it (and websockets) so adapter.py's module-level imports resolve.
# BasePlatformAdapter must be a REAL class (HermesBridgeAdapter subclasses it);
# a MagicMock base breaks subclassing on Python 3.12. The others are only used
# inside methods (and re-patched per-test), so MagicMock stand-ins suffice.
import types as _types

sys.modules.setdefault("websockets", MagicMock())
sys.modules.setdefault("websockets.exceptions", MagicMock())
if "gateway.platforms.base" not in sys.modules:
    sys.modules.setdefault("gateway", MagicMock())
    sys.modules.setdefault("gateway.platforms", MagicMock())
    _gw_base = _types.ModuleType("gateway.platforms.base")

    class BasePlatformAdapter:  # real class so the adapter can subclass it
        def __init__(self, *a, **kw):
            pass

    _gw_base.BasePlatformAdapter = BasePlatformAdapter
    _gw_base.SendResult = MagicMock()
    _gw_base.MessageEvent = MagicMock()
    _gw_base.Platform = MagicMock()
    sys.modules["gateway.platforms.base"] = _gw_base


def _make_adapter():
    """Return a HermesBridgeAdapter with all network I/O stubbed."""
    # Stub the gateway base class. The adapter is built via __new__ below (which
    # skips __init__), so no constructor stub is needed — and setting __init__ on
    # a MagicMock is rejected on Python 3.12+.
    BasePlatformAdapter = MagicMock()

    psk_bytes = b"\x00" * 32

    with (
        patch("hermes_bridge.adapter.BasePlatformAdapter", BasePlatformAdapter),
        patch("hermes_bridge.adapter.load_psk", return_value=psk_bytes),
        patch("hermes_bridge.adapter.SendResult", MagicMock()),
        patch("hermes_bridge.adapter.MessageEvent", MagicMock()),
        patch("hermes_bridge.adapter.Platform", MagicMock()),
    ):
        from hermes_bridge.adapter import HermesBridgeAdapter

        adapter = HermesBridgeAdapter.__new__(HermesBridgeAdapter)
        adapter._ws = MagicMock()
        adapter._ws.send = AsyncMock()
        adapter._profile_id = "test-profile"
        adapter._psk = psk_bytes
        adapter._seen_rpc_ids = {}
    return adapter


def _rpc_payload(method, params=None, rpc_id="test-id-001"):
    return {
        "role": "rpc.request",
        "content": "",
        "rpc": {"id": rpc_id, "method": method, "params": params or {}},
    }


class TestCronWriteMethods(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()

    async def _run(self, method, params=None, rpc_id="rid-1"):
        """Run _handle_rpc and return the first sealed WS send call's decoded payload."""
        sent_frames = []

        async def capture_send(frame):
            sent_frames.append(frame)

        self.adapter._ws.send = capture_send

        hermes_response = {"status": "ok"}
        with patch.object(
            self.adapter, "_hermes_post", AsyncMock(return_value=hermes_response)
        ) as mock_post:
            await self.adapter._handle_rpc(
                _rpc_payload(method, params, rpc_id=rpc_id)
            )
        return sent_frames, mock_post

    async def test_cron_pause_calls_correct_path(self):
        frames, mock_post = await self._run("cron.pause", {"id": "job-abc"})
        mock_post.assert_called_once_with("/api/cron/jobs/job-abc/pause")
        assert len(frames) == 1

    async def test_cron_resume_calls_correct_path(self):
        frames, mock_post = await self._run("cron.resume", {"id": "job-xyz"})
        mock_post.assert_called_once_with("/api/cron/jobs/job-xyz/resume")
        assert len(frames) == 1

    async def test_cron_trigger_calls_correct_path(self):
        frames, mock_post = await self._run("cron.trigger", {"id": "job-123"})
        mock_post.assert_called_once_with("/api/cron/jobs/job-123/trigger")
        assert len(frames) == 1

    async def test_missing_job_id_returns_error(self):
        sent_frames = []

        async def capture_send(frame):
            sent_frames.append(frame)

        self.adapter._ws.send = capture_send

        with patch.object(self.adapter, "_hermes_post", AsyncMock()) as mock_post:
            await self.adapter._handle_rpc(_rpc_payload("cron.pause", {"id": ""}))

        mock_post.assert_not_called()
        # _send_rpc_response still sends a frame even on error
        assert len(sent_frames) == 1

    async def test_dedup_skips_duplicate_rpc_id(self):
        sent_frames = []

        async def capture_send(frame):
            sent_frames.append(frame)

        self.adapter._ws.send = capture_send

        with patch.object(
            self.adapter, "_hermes_post", AsyncMock(return_value={"ok": True})
        ) as mock_post:
            # First call — should be processed
            await self.adapter._handle_rpc(
                _rpc_payload("cron.trigger", {"id": "job-1"}, rpc_id="dup-id-001")
            )
            # Second call — same rpc.id — should be dropped
            await self.adapter._handle_rpc(
                _rpc_payload("cron.trigger", {"id": "job-1"}, rpc_id="dup-id-001")
            )

        mock_post.assert_called_once()  # only fired once despite two calls
        assert len(sent_frames) == 1

    async def test_different_rpc_ids_both_processed(self):
        sent_frames = []

        async def capture_send(frame):
            sent_frames.append(frame)

        self.adapter._ws.send = capture_send

        with patch.object(
            self.adapter, "_hermes_post", AsyncMock(return_value={"ok": True})
        ) as mock_post:
            await self.adapter._handle_rpc(
                _rpc_payload("cron.trigger", {"id": "job-1"}, rpc_id="id-A")
            )
            await self.adapter._handle_rpc(
                _rpc_payload("cron.trigger", {"id": "job-1"}, rpc_id="id-B")
            )

        assert mock_post.call_count == 2
        assert len(sent_frames) == 2


if __name__ == "__main__":
    unittest.main()
