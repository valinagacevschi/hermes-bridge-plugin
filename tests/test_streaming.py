"""
Unit tests for HermesBridgeAdapter streaming — send()'s expect_edits gate
+ edit_message().

Run from the repo root:
    python -m pytest tests/test_streaming.py
or with any Python ≥3.8 that has websockets + PyNaCl installed.
"""

import unittest
from unittest.mock import AsyncMock, patch

# Import testutil FIRST — it inserts the repo root on sys.path and stubs
# websockets/gateway.platforms.base before anything imports the adapter.
from testutil import PROFILE, PSK, make_adapter as _make_adapter

from hermes_bridge.crypto import open_frame


def _open(frame: str):
    payload = open_frame(PROFILE, "out", frame, PSK)
    assert payload is not None, "frame failed to decrypt"
    return payload


class TestSendExpectEdits(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()

    async def test_normal_send_enqueues_durably(self):
        """No expect_edits metadata — today's exact behavior, unchanged."""
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()) as mock_enqueue:
            result = await self.adapter.send("chat-1", "hello")

        self.assertTrue(result.success)
        self.assertIsNotNone(result.message_id)
        mock_enqueue.assert_called_once()
        payload = _open(sent_frames[0])
        self.assertEqual(payload["content"], "hello")
        self.assertNotIn("edit", payload)

    async def test_expect_edits_send_skips_durable_enqueue(self):
        """GatewayStreamConsumer's streaming-preview send() — must return a
        message_id (so the consumer knows we support editing) but must NOT
        durably enqueue the partial preview text."""
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()) as mock_enqueue:
            result = await self.adapter.send(
                "chat-1", "Hel", metadata={"expect_edits": True}
            )

        self.assertTrue(result.success)
        self.assertIsNotNone(result.message_id)
        mock_enqueue.assert_not_called()
        payload = _open(sent_frames[0])
        self.assertEqual(payload["content"], "Hel")

    async def test_unsolicited_send_still_enqueues(self):
        """Cron/scheduled-job sends never set expect_edits — unaffected."""
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()) as mock_enqueue:
            result = await self.adapter.send(
                "chat-1", "job done", metadata={"job_id": "abc"}
            )

        self.assertTrue(result.success)
        mock_enqueue.assert_called_once()
        payload = _open(sent_frames[0])
        self.assertTrue(payload["unsolicited"])


class TestEditMessage(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()

    async def test_intermediate_edit_is_live_only(self):
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()) as mock_enqueue:
            result = await self.adapter.edit_message("chat-1", "msg-abc", "Hello wor")

        self.assertTrue(result.success)
        self.assertEqual(result.message_id, "msg-abc")
        mock_enqueue.assert_not_called()
        payload = _open(sent_frames[0])
        self.assertEqual(payload["msg_id"], "msg-abc")
        self.assertTrue(payload["edit"])
        self.assertNotIn("final", payload)
        self.assertEqual(payload["content"], "Hello wor")

    async def test_finalize_edit_enqueues_durably(self):
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()) as mock_enqueue:
            result = await self.adapter.edit_message(
                "chat-1", "msg-abc", "Hello world!", finalize=True
            )

        self.assertTrue(result.success)
        mock_enqueue.assert_called_once_with("msg-abc", sent_frames[0])
        payload = _open(sent_frames[0])
        self.assertTrue(payload["edit"])
        self.assertTrue(payload["final"])
        self.assertEqual(payload["content"], "Hello world!")

    async def test_edit_content_replaces_not_appends(self):
        """Each edit call carries the FULL accumulated text — verifies the
        adapter doesn't try to diff/append (that's the gateway's job)."""
        sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: sent_frames.append(f))
        with patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
            await self.adapter.edit_message("chat-1", "msg-1", "Hi")
            await self.adapter.edit_message("chat-1", "msg-1", "Hi there")
            await self.adapter.edit_message("chat-1", "msg-1", "Hi there!", finalize=True)

        contents = [_open(f)["content"] for f in sent_frames]
        self.assertEqual(contents, ["Hi", "Hi there", "Hi there!"])

    async def test_edit_without_connection_fails(self):
        self.adapter._ws = None
        result = await self.adapter.edit_message("chat-1", "msg-1", "text")
        self.assertFalse(result.success)
        self.assertEqual(result.error, "not_connected")


if __name__ == "__main__":
    unittest.main()
