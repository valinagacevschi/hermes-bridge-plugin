"""
Unit tests for HermesBridgeAdapter RPC dispatch — cron write methods,
dedup, chat.stop, and memory/skills write-approval.

Run from the repo root:
    python -m pytest tests/test_rpc.py
or with any Python ≥3.8 that has websockets + PyNaCl installed.
"""

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Import testutil FIRST — it inserts the repo root on sys.path and stubs
# websockets/gateway.platforms.base before anything imports the adapter.
from testutil import make_adapter as _make_adapter

from hermes_bridge.adapter import _diff_new_pending


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


def _http_error(status: int, detail: str):
    """Build a real urllib.error.HTTPError whose body is FastAPI's
    {"detail": "..."} shape, for testing _http_error_detail passthrough."""
    import io
    import urllib.error

    body = json.dumps({"detail": detail}).encode()
    return urllib.error.HTTPError(
        url="http://localhost:9119/api/cron/jobs",
        code=status,
        msg="Bad Request",
        hdrs=None,
        fp=io.BytesIO(body),
    )


class TestCronCreateEdit(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []

        async def capture_send(frame):
            self.sent_frames.append(frame)

        self.adapter._ws.send = capture_send

    async def test_create_missing_schedule_returns_error(self):
        with patch.object(self.adapter, "_hermes_post", AsyncMock()) as mock_post:
            await self.adapter._handle_rpc(_rpc_payload("cron.create", {"prompt": "hello"}))
        mock_post.assert_not_called()
        assert len(self.sent_frames) == 1

    async def test_create_calls_correct_path_with_body(self):
        with patch.object(
            self.adapter, "_hermes_post", AsyncMock(return_value={"id": "job-new"})
        ) as mock_post:
            await self.adapter._handle_rpc(
                _rpc_payload(
                    "cron.create",
                    {
                        "schedule": "every 2h",
                        "prompt": "check server status",
                        "name": "Health check",
                        "deliver": "origin",
                        "skills": ["blogwatcher"],
                    },
                )
            )
        mock_post.assert_called_once_with(
            "/api/cron/jobs",
            body={
                "schedule": "every 2h",
                "prompt": "check server status",
                "name": "Health check",
                "deliver": "origin",
                "skills": ["blogwatcher"],
            },
        )
        assert len(self.sent_frames) == 1

    async def test_create_schedule_parse_error_surfaces_detail(self):
        """Hermes core's HTTP 400 {"detail": "..."} must reach the RPC caller
        as the actual message — not the generic hermes_api_unavailable the
        catch-all below would otherwise produce for any non-401 HTTPError."""
        error = _http_error(400, "Could not parse schedule: 'whenever'")
        with patch.object(
            self.adapter, "_send_rpc_response", AsyncMock()
        ) as mock_response, patch.object(self.adapter, "_hermes_post", AsyncMock(side_effect=error)):
            await self.adapter._handle_rpc(
                _rpc_payload("cron.create", {"schedule": "whenever", "prompt": "x"})
            )
        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is False
        assert "Could not parse schedule" in call_kwargs["error"]

    async def test_edit_missing_job_id_returns_error(self):
        with patch.object(self.adapter, "_hermes_post", AsyncMock()) as mock_post:
            await self.adapter._handle_rpc(_rpc_payload("cron.edit", {"schedule": "1h"}))
        mock_post.assert_not_called()
        assert len(self.sent_frames) == 1

    async def test_edit_no_fields_returns_error(self):
        with patch.object(self.adapter, "_hermes_post", AsyncMock()) as mock_post:
            await self.adapter._handle_rpc(_rpc_payload("cron.edit", {"id": "job-1"}))
        mock_post.assert_not_called()
        assert len(self.sent_frames) == 1

    async def test_edit_sends_partial_updates_wrapped(self):
        with patch.object(
            self.adapter, "_hermes_post", AsyncMock(return_value={"id": "job-1"})
        ) as mock_post:
            await self.adapter._handle_rpc(
                _rpc_payload("cron.edit", {"id": "job-1", "schedule": "every 1h"})
            )
        mock_post.assert_called_once_with(
            "/api/cron/jobs/job-1",
            body={"updates": {"schedule": "every 1h"}},
            method="PUT",
        )
        assert len(self.sent_frames) == 1

    async def test_edit_schedule_parse_error_surfaces_detail(self):
        error = _http_error(400, "Could not parse schedule: 'nonsense'")
        with patch.object(
            self.adapter, "_send_rpc_response", AsyncMock()
        ) as mock_response, patch.object(self.adapter, "_hermes_post", AsyncMock(side_effect=error)):
            await self.adapter._handle_rpc(
                _rpc_payload("cron.edit", {"id": "job-1", "schedule": "nonsense"})
            )
        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is False
        assert "Could not parse schedule" in call_kwargs["error"]


class TestHermesRequestHttpError(unittest.IsolatedAsyncioTestCase):
    """_hermes_request must treat a non-401 HTTPError as authoritative: a live
    Hermes answered on that port. Probing further ports would bury the error
    under connection-refused noise (breaking detail passthrough) and replay a
    non-idempotent POST."""

    async def test_non_401_error_raises_immediately_without_probing_other_ports(self):
        import urllib.error

        adapter = _make_adapter()
        adapter._hermes_session_token = "cached-token"
        adapter._hermes_api_port = None

        attempted_urls = []

        def fake_urlopen(req, timeout=None):
            attempted_urls.append(req.full_url)
            raise _http_error(400, "Could not parse schedule: 'whenever'")

        with patch.object(adapter, "_ports_to_probe", return_value=[9119, 9120, 8642]), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                await adapter._hermes_request("/api/cron/jobs", method="POST", body={"schedule": "whenever"})

        assert len(attempted_urls) == 1, f"expected single attempt, got {attempted_urls}"
        assert ctx.exception.code == 400
        # The answering port is the working port — cache it.
        assert adapter._hermes_api_port == 9119


class TestChatStop(unittest.IsolatedAsyncioTestCase):
    """chat.stop has no adapter-side interrupt logic — it synthesizes "/stop"
    and routes it through handle_message(), the same dispatch path every
    normal incoming message takes, so Hermes core's central /stop command
    handler (gateway/slash_commands.py) does the actual interrupt."""

    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []

        async def capture_send(frame):
            self.sent_frames.append(frame)

        self.adapter._ws.send = capture_send

    async def test_stop_dispatches_slash_stop_via_handle_message(self):
        # build_source/handle_message are real BasePlatformAdapter methods
        # (never overridden by HermesBridgeAdapter) — patching the module-
        # level BasePlatformAdapter name doesn't rewire an already-defined
        # subclass's MRO, so they're stubbed per-instance here rather than
        # exercising the genuine Hermes-core implementation (which needs a
        # fully constructed adapter/session context this harness doesn't build).
        with patch.object(
            self.adapter, "build_source", return_value={"chat_id": "test-profile"}
        ), patch.object(self.adapter, "handle_message", AsyncMock()) as mock_handle:
            await self.adapter._handle_rpc(_rpc_payload("chat.stop", {}))

        mock_handle.assert_called_once()
        event = mock_handle.call_args.args[0]
        assert event.text == "/stop"
        assert len(self.sent_frames) == 1

    async def test_stop_acks_even_with_no_active_turn(self):
        """_handle_stop_command is documented safe to call with nothing
        running — handle_message() itself must not raise either way."""
        with patch.object(
            self.adapter, "build_source", return_value={"chat_id": "test-profile"}
        ), patch.object(self.adapter, "handle_message", AsyncMock()), patch.object(
            self.adapter, "_send_rpc_response", AsyncMock()
        ) as mock_response:
            await self.adapter._handle_rpc(_rpc_payload("chat.stop", {}))

        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is True
        assert call_kwargs["data"] == {"stopped": True}


class TestWriteApprovalRpc(unittest.IsolatedAsyncioTestCase):
    """memory.*/skills.* write-approval RPCs (streaming write-approval from
    the phone).

    These call tools.write_approval/tools.memory_tool/tools.skill_manager_tool
    directly rather than proxying to a REST endpoint — Hermes core has no HTTP
    surface for staged writes (no matching route in
    gateway/platforms/api_server.py or hermes_cli/web_server.py). The gateway's
    own /memory and /skills slash-command handlers call these same functions
    in-process (gateway/slash_commands.py), which is what this adapter mirrors.
    """

    def setUp(self):
        self.adapter = _make_adapter()
        self.sent_frames = []

        async def capture_send(frame):
            self.sent_frames.append(frame)

        self.adapter._ws.send = capture_send

    async def test_memory_pending_lists_records(self):
        records = [
            {
                "id": "m1",
                "subsystem": "memory",
                "summary": "likes tea",
                "origin": "foreground",
                "created_at": 111.0,
                "payload": {"content": "likes tea"},
            }
        ]
        with patch("tools.write_approval.list_pending", return_value=records):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.pending"))
        data = mock_response.call_args.kwargs["data"]
        assert data == [
            {"id": "m1", "summary": "likes tea", "origin": "foreground", "created_at": 111.0, "content": "likes tea"}
        ]

    async def test_pending_summary_omits_skill_content(self):
        """Skill payload content must not leak into the pending list — only
        memory (small, ~200 char entries) gets inline content; skills fetch
        full content on demand via skills.diff."""
        records = [
            {
                "id": "s1",
                "subsystem": "skills",
                "summary": "gist",
                "origin": "foreground",
                "created_at": 1.0,
                "payload": {"content": "huge skill body"},
            }
        ]
        with patch("tools.write_approval.list_pending", return_value=records):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.pending"))
        data = mock_response.call_args.kwargs["data"]
        assert data[0]["content"] is None
        assert "huge skill body" not in json.dumps(data)

    async def test_memory_approve_applies_and_discards(self):
        rec = {"id": "m1", "subsystem": "memory", "payload": {"action": "add", "target": "user", "content": "x"}}
        with patch("tools.write_approval.get_pending", return_value=rec), patch(
            "tools.write_approval.discard_pending", return_value=True
        ) as mock_discard, patch(
            "tools.memory_tool.load_on_disk_store", return_value=MagicMock()
        ), patch(
            "tools.memory_tool.apply_memory_pending", return_value={"success": True}
        ) as mock_apply:
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.approve", {"id": "m1"}))
        mock_apply.assert_called_once()
        mock_discard.assert_called_once_with("memory", "m1")
        assert mock_response.call_args.kwargs["ok"] is True

    async def test_memory_approve_failure_does_not_discard(self):
        """A failed replay (e.g. store write error) must NOT discard the
        pending record — otherwise the staged write is lost with nothing
        ever applied."""
        rec = {"id": "m1", "subsystem": "memory", "payload": {"action": "add"}}
        with patch("tools.write_approval.get_pending", return_value=rec), patch(
            "tools.write_approval.discard_pending"
        ) as mock_discard, patch(
            "tools.memory_tool.load_on_disk_store", return_value=MagicMock()
        ), patch(
            "tools.memory_tool.apply_memory_pending", return_value={"success": False, "error": "boom"}
        ):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.approve", {"id": "m1"}))
        mock_discard.assert_not_called()
        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is False
        assert "boom" in call_kwargs["error"]

    async def test_memory_approve_missing_pending_errors(self):
        with patch("tools.write_approval.get_pending", return_value=None):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.approve", {"id": "nope"}))
        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is False
        assert call_kwargs["error"] == "pending_not_found"

    async def test_memory_reject_discards(self):
        with patch("tools.write_approval.discard_pending", return_value=True) as mock_discard:
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.reject", {"id": "m1"}))
        mock_discard.assert_called_once_with("memory", "m1")
        assert mock_response.call_args.kwargs["ok"] is True

    async def test_memory_reject_missing_pending_errors(self):
        with patch("tools.write_approval.discard_pending", return_value=False):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("memory.reject", {"id": "nope"}))
        assert mock_response.call_args.kwargs["ok"] is False

    async def test_skills_approve_applies_and_discards(self):
        rec = {"id": "s1", "subsystem": "skills", "payload": {"action": "create", "name": "foo"}}
        with patch("tools.write_approval.get_pending", return_value=rec), patch(
            "tools.write_approval.discard_pending", return_value=True
        ) as mock_discard, patch(
            "tools.skill_manager_tool.apply_skill_pending",
            return_value=json.dumps({"success": True}),
        ) as mock_apply:
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.approve", {"id": "s1"}))
        mock_apply.assert_called_once()
        mock_discard.assert_called_once_with("skills", "s1")
        assert mock_response.call_args.kwargs["ok"] is True

    async def test_skills_approve_failure_does_not_discard(self):
        rec = {"id": "s1", "subsystem": "skills", "payload": {"action": "create", "name": "foo"}}
        with patch("tools.write_approval.get_pending", return_value=rec), patch(
            "tools.write_approval.discard_pending"
        ) as mock_discard, patch(
            "tools.skill_manager_tool.apply_skill_pending",
            return_value=json.dumps({"success": False, "error": "name exists"}),
        ):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.approve", {"id": "s1"}))
        mock_discard.assert_not_called()
        call_kwargs = mock_response.call_args.kwargs
        assert call_kwargs["ok"] is False
        assert "name exists" in call_kwargs["error"]

    async def test_skills_reject_discards(self):
        with patch("tools.write_approval.discard_pending", return_value=True) as mock_discard:
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.reject", {"id": "s1"}))
        mock_discard.assert_called_once_with("skills", "s1")
        assert mock_response.call_args.kwargs["ok"] is True

    async def test_skills_diff_returns_diff_text(self):
        rec = {"id": "s1", "subsystem": "skills", "payload": {"action": "create", "name": "foo", "content": "# Foo"}}
        with patch("tools.write_approval.get_pending", return_value=rec), patch(
            "tools.write_approval.skill_pending_diff", return_value="# Foo"
        ) as mock_diff:
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.diff", {"id": "s1"}))
        mock_diff.assert_called_once_with(rec)
        assert mock_response.call_args.kwargs["data"] == {"diff": "# Foo"}

    async def test_skills_diff_missing_pending_errors(self):
        with patch("tools.write_approval.get_pending", return_value=None):
            with patch.object(self.adapter, "_send_rpc_response", AsyncMock()) as mock_response:
                await self.adapter._handle_rpc(_rpc_payload("skills.diff", {"id": "nope"}))
        assert mock_response.call_args.kwargs["ok"] is False


class TestDiffNewPending(unittest.TestCase):
    """_diff_new_pending is the one genuinely novel piece of
    _poll_pending_writes — a plain sync function so it doesn't need an event
    loop to test."""

    def test_first_call_returns_everything_and_seeds(self):
        seen: set = set()
        rec = {"id": "m1"}
        new = _diff_new_pending([rec], "memory", seen)
        assert new == [rec]
        assert ("memory", "m1") in seen

    def test_second_call_with_same_record_returns_nothing(self):
        seen: set = set()
        rec = {"id": "m1"}
        _diff_new_pending([rec], "memory", seen)
        new = _diff_new_pending([rec], "memory", seen)
        assert new == []

    def test_second_call_with_additional_record_returns_only_the_new_one(self):
        seen: set = set()
        rec1 = {"id": "m1"}
        rec2 = {"id": "m2"}
        _diff_new_pending([rec1], "memory", seen)
        new = _diff_new_pending([rec1, rec2], "memory", seen)
        assert new == [rec2]

    def test_same_id_different_subsystem_is_distinct(self):
        seen: set = set()
        _diff_new_pending([{"id": "x"}], "memory", seen)
        new = _diff_new_pending([{"id": "x"}], "skills", seen)
        assert new == [{"id": "x"}]


class TestPollPendingWrites(unittest.IsolatedAsyncioTestCase):
    """The first successful tick must establish a baseline (no pushes) rather
    than treating every already-pending write as new — otherwise a failed
    startup seed would cause a push burst on the recovery tick."""

    def setUp(self):
        self.adapter = _make_adapter()

    async def _run_two_ticks(self, fake_list_pending):
        sleeps = {"n": 0}

        async def fake_sleep(_seconds):
            sleeps["n"] += 1
            if sleeps["n"] >= 2:
                self.adapter._should_run = False

        self.adapter._should_run = True
        with patch("tools.write_approval.list_pending", side_effect=fake_list_pending), patch.object(
            self.adapter, "_send_push_notification", AsyncMock()
        ) as mock_push, patch("asyncio.sleep", side_effect=fake_sleep):
            await self.adapter._poll_pending_writes()
        return mock_push

    async def test_first_tick_seeds_without_firing_then_detects_new_write(self):
        rec1 = {"id": "m1", "subsystem": "memory", "summary": "old"}
        rec2 = {"id": "m2", "subsystem": "memory", "summary": "brand new"}
        calls = {"n": 0}

        def fake_list_pending(subsystem):
            if subsystem != "memory":
                return []
            calls["n"] += 1
            return [rec1] if calls["n"] == 1 else [rec1, rec2]

        mock_push = await self._run_two_ticks(fake_list_pending)

        # rec1 was already pending on the very first tick — must never fire.
        # rec2 only appears on the second tick — must fire exactly once.
        assert mock_push.call_count == 1
        assert "brand new" in mock_push.call_args.kwargs["body"]

    async def test_seed_failure_does_not_cause_burst_on_recovery(self):
        """A transient error on the very first list_pending call must not
        leave `seen` empty in a way that makes the NEXT (successful) tick
        treat every already-pending write as new."""
        rec1 = {"id": "m1", "subsystem": "memory", "summary": "old"}
        calls = {"n": 0}

        def fake_list_pending(subsystem):
            if subsystem != "memory":
                return []
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("transient fs error")
            return [rec1]

        mock_push = await self._run_two_ticks(fake_list_pending)
        mock_push.assert_not_called()


if __name__ == "__main__":
    unittest.main()
