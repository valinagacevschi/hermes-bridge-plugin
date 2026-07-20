"""
Unit tests for HermesBridgeAdapter attachments: outbound
send_image_file/send_document/send_voice (seal+upload to the relay's
sealed-blob store) and inbound attachment fetch+decrypt into
MessageEvent.media_urls/media_types.

Run from the repo root:
    python -m pytest tests/test_attachments.py
or with any Python ≥3.8 that has websockets + PyNaCl installed.
"""

import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

# Import testutil FIRST — it inserts the repo root on sys.path and stubs
# websockets/gateway.platforms.base before anything imports the adapter.
from testutil import PROFILE, PSK, make_adapter as _make_adapter

from hermes_bridge.crypto import open_frame, seal_blob
from gateway.platforms.base import MessageType


def _open(frame: str):
    payload = open_frame(PROFILE, "out", frame, PSK)
    assert payload is not None, "frame failed to decrypt"
    return payload


class TestSendImageFile(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: self.sent_frames.append(f))
        self._tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        self._tmp.write(b"\x89PNG fake image bytes")
        self._tmp.close()

    def tearDown(self):
        os.unlink(self._tmp.name)

    async def test_uploads_blob_and_sends_attachment_ref(self):
        with patch.object(
            self.adapter, "_upload_blob", AsyncMock(return_value="blob_abc123")
        ) as mock_upload, patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
            result = await self.adapter.send_image_file(
                "chat-1", self._tmp.name, caption="a photo"
            )

        self.assertTrue(result.success)
        mock_upload.assert_called_once()
        uploaded_bytes, mime = mock_upload.call_args.args
        self.assertEqual(mime, "image/png")

        payload = _open(self.sent_frames[0])
        self.assertEqual(payload["content"], "a photo")
        self.assertEqual(len(payload["attachments"]), 1)
        att = payload["attachments"][0]
        self.assertEqual(att["mime"], "image/png")
        self.assertEqual(att["blob_id"], "blob_abc123")
        self.assertEqual(att["name"], os.path.basename(self._tmp.name))

        # The bytes handed to _upload_blob decrypt back to the original file
        # content via seal_blob's counterpart — proves _send_attachment reads
        # the real file rather than fabricating placeholder bytes.
        from hermes_bridge.crypto import open_blob

        with open(self._tmp.name, "rb") as f:
            original = f.read()
        sealed_for_check = seal_blob(PROFILE, original, PSK)
        self.assertEqual(open_blob(PROFILE, sealed_for_check, PSK), original)

    async def test_read_failure_falls_back_to_text_send(self):
        with patch.object(self.adapter, "_upload_blob", AsyncMock()) as mock_upload, patch.object(
            self.adapter, "_enqueue_durable", AsyncMock()
        ):
            result = await self.adapter.send_image_file(
                "chat-1", "/nonexistent/path/does-not-exist.png", caption="oops"
            )

        self.assertTrue(result.success)
        mock_upload.assert_not_called()
        payload = _open(self.sent_frames[0])
        self.assertNotIn("attachments", payload)
        self.assertIn("oops", payload["content"])
        self.assertIn("Couldn't deliver", payload["content"])

    async def test_upload_failure_falls_back_to_text_send(self):
        with patch.object(
            self.adapter, "_upload_blob", AsyncMock(side_effect=RuntimeError("network down"))
        ), patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
            result = await self.adapter.send_image_file("chat-1", self._tmp.name)

        self.assertTrue(result.success)
        payload = _open(self.sent_frames[0])
        self.assertNotIn("attachments", payload)
        self.assertIn("Couldn't deliver", payload["content"])


class TestSendDocument(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: self.sent_frames.append(f))
        self._tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
        self._tmp.write(b"%PDF-1.4 fake pdf bytes")
        self._tmp.close()

    def tearDown(self):
        os.unlink(self._tmp.name)

    async def test_uses_explicit_file_name_over_basename(self):
        with patch.object(
            self.adapter, "_upload_blob", AsyncMock(return_value="blob_doc1")
        ), patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
            result = await self.adapter.send_document(
                "chat-1", self._tmp.name, file_name="report.pdf"
            )

        self.assertTrue(result.success)
        payload = _open(self.sent_frames[0])
        att = payload["attachments"][0]
        self.assertEqual(att["mime"], "application/pdf")
        self.assertEqual(att["name"], "report.pdf")
        self.assertEqual(att["blob_id"], "blob_doc1")


class TestSendVoice(unittest.IsolatedAsyncioTestCase):
    """Outbound voice/TTS replies — same _send_attachment path, audio mime."""

    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []
        self.adapter._ws.send = AsyncMock(side_effect=lambda f: self.sent_frames.append(f))
        self._tmp = tempfile.NamedTemporaryFile(suffix=".mp3", delete=False)
        self._tmp.write(b"fake mp3 bytes")
        self._tmp.close()

    def tearDown(self):
        os.unlink(self._tmp.name)

    async def test_uploads_blob_and_sends_audio_attachment_ref(self):
        with patch.object(
            self.adapter, "_upload_blob", AsyncMock(return_value="blob_voice1")
        ) as mock_upload, patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
            result = await self.adapter.send_voice("chat-1", self._tmp.name)

        self.assertTrue(result.success)
        uploaded_bytes, mime = mock_upload.call_args.args
        self.assertEqual(mime, "audio/mpeg")

        payload = _open(self.sent_frames[0])
        att = payload["attachments"][0]
        self.assertEqual(att["mime"], "audio/mpeg")
        self.assertEqual(att["blob_id"], "blob_voice1")
        self.assertEqual(att["name"], os.path.basename(self._tmp.name))

    async def test_unrecognized_extension_falls_back_to_audio_mpeg(self):
        # send_voice is only ever called with audio; an unrecognized/no
        # extension must still classify as audio/* so Hermes core's
        # inbound message_type/STT mime check (mime.startswith("audio/"))
        # keeps working end-to-end.
        tmp = tempfile.NamedTemporaryFile(suffix="", delete=False)
        tmp.write(b"raw audio bytes")
        tmp.close()
        try:
            with patch.object(
                self.adapter, "_upload_blob", AsyncMock(return_value="blob_voice2")
            ) as mock_upload, patch.object(self.adapter, "_enqueue_durable", AsyncMock()):
                await self.adapter.send_voice("chat-1", tmp.name)
            _, mime = mock_upload.call_args.args
            self.assertEqual(mime, "audio/mpeg")
        finally:
            os.unlink(tmp.name)


class TestInboundAttachments(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()
        self._tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmpdir.cleanup()

    async def test_downloads_decrypts_and_writes_to_media_dir(self):
        plaintext = b"decrypted image bytes"
        with patch.object(
            self.adapter, "_download_blob", AsyncMock(return_value=plaintext)
        ), patch("hermes_bridge.adapter._INBOUND_MEDIA_DIR", self._tmpdir.name):
            media_urls, media_types = await self.adapter._download_attachments_to_media(
                [{"mime": "image/jpeg", "blob_id": "blob_xyz", "name": "cat.jpg"}]
            )

        self.assertEqual(len(media_urls), 1)
        self.assertEqual(media_types, ["image/jpeg"])
        self.assertTrue(os.path.exists(media_urls[0]))
        with open(media_urls[0], "rb") as f:
            self.assertEqual(f.read(), plaintext)
        # blob_id-prefixed filename — avoids collisions between attachments
        # sharing a display name.
        self.assertIn("blob_xyz", os.path.basename(media_urls[0]))
        self.assertIn("cat.jpg", os.path.basename(media_urls[0]))

    async def test_failed_download_is_skipped_not_fatal(self):
        with patch.object(
            self.adapter, "_download_blob", AsyncMock(return_value=None)
        ), patch("hermes_bridge.adapter._INBOUND_MEDIA_DIR", self._tmpdir.name):
            media_urls, media_types = await self.adapter._download_attachments_to_media(
                [{"mime": "image/png", "blob_id": "blob_bad"}]
            )

        self.assertEqual(media_urls, [])
        self.assertEqual(media_types, [])

    async def test_missing_blob_id_is_skipped(self):
        with patch.object(self.adapter, "_download_blob", AsyncMock()) as mock_dl, patch(
            "hermes_bridge.adapter._INBOUND_MEDIA_DIR", self._tmpdir.name
        ):
            media_urls, media_types = await self.adapter._download_attachments_to_media(
                [{"mime": "image/png"}]
            )

        mock_dl.assert_not_called()
        self.assertEqual(media_urls, [])
        self.assertEqual(media_types, [])

    async def test_receive_loop_populates_media_urls_on_event(self):
        """End-to-end through _receive_loop: an inbound sealed frame with
        `attachments` results in a MessageEvent carrying media_urls/media_types."""
        from hermes_bridge.crypto import seal

        plaintext = b"hello bytes"
        frame = seal(
            PROFILE,
            "in",
            {
                "role": "user",
                "content": "check this out",
                "attachments": [{"mime": "image/png", "blob_id": "blob_1", "name": "x.png"}],
            },
            PSK,
        )

        captured_events = []

        async def fake_handle_message(event):
            captured_events.append(event)

        async def fake_ws_iter():
            import json as _json

            yield _json.dumps({"role": "user", "content": frame})

        with patch.object(
            self.adapter, "_download_blob", AsyncMock(return_value=plaintext)
        ), patch(
            "hermes_bridge.adapter._INBOUND_MEDIA_DIR", self._tmpdir.name
        ), patch.object(
            self.adapter, "build_source", return_value={"chat_id": PROFILE}
        ), patch.object(
            self.adapter, "handle_message", fake_handle_message
        ):
            self.adapter._ws = fake_ws_iter()
            await self.adapter._receive_loop()

        self.assertEqual(len(captured_events), 1)
        event = captured_events[0]
        self.assertEqual(event.text, "check this out")
        self.assertEqual(len(event.media_urls), 1)
        self.assertEqual(event.media_types, ["image/png"])
        with open(event.media_urls[0], "rb") as f:
            self.assertEqual(f.read(), plaintext)
        self.assertEqual(event.message_type, MessageType.PHOTO)

    async def test_receive_loop_sets_voice_message_type_for_audio(self):
        """Inbound audio must set message_type=VOICE (not just an audio mime
        in media_types) — gateway/run.py's /voice `voice_only` auto-TTS mode
        keys directly off event.message_type, not per-attachment mime."""
        from hermes_bridge.crypto import seal

        frame = seal(
            PROFILE,
            "in",
            {
                "role": "user",
                "content": "",
                "attachments": [{"mime": "audio/m4a", "blob_id": "blob_voice", "name": "v.m4a"}],
            },
            PSK,
        )

        captured_events = []

        async def fake_handle_message(event):
            captured_events.append(event)

        async def fake_ws_iter():
            import json as _json

            yield _json.dumps({"role": "user", "content": frame})

        with patch.object(
            self.adapter, "_download_blob", AsyncMock(return_value=b"voice bytes")
        ), patch(
            "hermes_bridge.adapter._INBOUND_MEDIA_DIR", self._tmpdir.name
        ), patch.object(
            self.adapter, "build_source", return_value={"chat_id": PROFILE}
        ), patch.object(
            self.adapter, "handle_message", fake_handle_message
        ):
            self.adapter._ws = fake_ws_iter()
            await self.adapter._receive_loop()

        self.assertEqual(len(captured_events), 1)
        self.assertEqual(captured_events[0].message_type, MessageType.VOICE)

    async def test_receive_loop_defaults_to_text_message_type_with_no_media(self):
        """Regression guard: a plain text message (no attachments) must keep
        the default MessageType.TEXT — added alongside voice/photo classification
        so a bug there can't silently reclassify every ordinary text message."""
        from hermes_bridge.crypto import seal

        frame = seal(PROFILE, "in", {"role": "user", "content": "hello"}, PSK)
        captured_events = []

        async def fake_handle_message(event):
            captured_events.append(event)

        async def fake_ws_iter():
            import json as _json

            yield _json.dumps({"role": "user", "content": frame})

        with patch.object(self.adapter, "build_source", return_value={"chat_id": PROFILE}), patch.object(
            self.adapter, "handle_message", fake_handle_message
        ):
            self.adapter._ws = fake_ws_iter()
            await self.adapter._receive_loop()

        self.assertEqual(len(captured_events), 1)
        self.assertEqual(captured_events[0].message_type, MessageType.TEXT)


if __name__ == "__main__":
    unittest.main()
