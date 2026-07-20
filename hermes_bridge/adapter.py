import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import random
import re
import threading
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

import websockets
from websockets.exceptions import ConnectionClosed

from gateway.platforms.base import BasePlatformAdapter, SendResult, MessageEvent, MessageType, Platform

from .crypto import load_psk, open_blob, open_frame, seal, seal_blob

logger = logging.getLogger(__name__)

PLATFORM = Platform('api_server')

# Reconnect backoff bounds (seconds). The relay rolls on every deploy and the
# WS can drop on any network blip — the supervisor loop reconnects forever.
_RECONNECT_INITIAL = 1.0
_RECONNECT_MAX = 30.0

# Hermes local REST API — well-known fallback ports.
# 9119 is the declared default; 9120/8642 are legacy guesses.
# In practice the dashboard uses --port 0 (OS-assigned) so these are often wrong.
# _discover_dashboard_ports() finds the real port via psutil before falling back here.
_HERMES_API_PORTS = [9119, 9120, 8642]
# Dedup window: retried RPC requests (same rpc.id) within this window are no-ops.
_RPC_DEDUP_WINDOW_S = 30.0


def _http_error_detail(exc: "urllib.error.HTTPError") -> str:
    """Extract FastAPI's ``{"detail": "..."}`` from an HTTPError body.

    Hermes's local dashboard API returns 400 with a human-readable ``detail``
    message for validation errors (e.g. an unparseable cron schedule string —
    ``hermes_cli/web_server.py`` ``_create_cron_job_sync``/``_update_cron_job_sync``).
    Falls back to the bare exception string if the body isn't the expected
    shape. Read the body at most once — HTTPError is a file-like object.
    """
    try:
        body = exc.read()
        data = json.loads(body.decode())
        detail = data.get("detail") if isinstance(data, dict) else None
        if detail:
            return str(detail)
    except Exception:
        pass
    return str(exc)


class _RpcError(Exception):
    """Validation failure inside an RPC handler — str(exc) is the wire error code."""


def _require(params: Dict[str, Any], key: str, error: str) -> str:
    """Return params[key] as a stripped non-empty string, or raise _RpcError(error)."""
    value = str(params.get(key, "")).strip()
    if not value:
        raise _RpcError(error)
    return value


# Hermes memory file — entries separated by "\n§\n"; ids are content hashes.
_MEMORY_PATH = os.path.join(os.path.expanduser("~"), ".hermes", "memories", "MEMORY.md")

# Local cache for decrypted inbound attachments (PRD_Features.md §2.3) — same
# "platforms/<name>/media" convention other adapters use for downloaded media
# (see gateway/platforms/whatsapp_cloud.py's _INBOUND_MEDIA_CACHE), just
# built directly since hermes_bridge has no legacy path to migrate from.
_INBOUND_MEDIA_DIR = os.path.join(
    os.path.expanduser("~"), ".hermes", "platforms", "hermes_bridge", "media"
)


def _memory_entry_id(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def _read_memory_entries() -> List[str]:
    """Return the non-empty entries of MEMORY.md. Raises FileNotFoundError."""
    with open(_MEMORY_PATH, "r", encoding="utf-8") as f:
        raw = f.read()
    return [e.strip() for e in raw.split("\n§\n") if e.strip()]


def _diff_new_pending(
    current: List[Dict[str, Any]], subsystem: str, seen: set
) -> List[Dict[str, Any]]:
    """Return records in `current` not yet present in `seen`, adding their
    (subsystem, id) keys to `seen` as a side effect either way. Pulled out of
    _poll_pending_writes as a plain sync function so the diff logic — the
    only genuinely novel part of that loop — is unit-testable without an
    event loop."""
    new_records = []
    for rec in current:
        key = (subsystem, rec.get("id", ""))
        if key in seen:
            continue
        seen.add(key)
        new_records.append(rec)
    return new_records


def _pending_summary(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Shape a tools.write_approval pending record for the mobile Approvals tab.

    Memory entries are small (~200 chars, per PRD_Features.md §2.7) so the
    full content is inlined for the phone's preview — no separate diff call
    needed. Skill payloads can be 10-100KB; omit content here and let the
    phone fetch it on demand via the skills.diff RPC (mirrors the gateway's
    own chat-bubble truncation in gateway/slash_commands.py
    _handle_skills_command — full content is never worth pushing over the
    wire until the user actually asks to see it).
    """
    payload = rec.get("payload") or {}
    return {
        "id": rec.get("id", ""),
        "summary": rec.get("summary", ""),
        "origin": rec.get("origin", "foreground"),
        "created_at": rec.get("created_at", 0),
        "content": payload.get("content") if rec.get("subsystem") == "memory" else None,
    }


def _discover_dashboard_ports() -> List[int]:
    """Return listening ports of running `hermes dashboard` processes via psutil.

    Priority:
      1. Main dashboard (no --profile flag) — matches this adapter's context.
      2. Any other dashboard processes (profile-specific) as fallbacks.

    Returns empty list if psutil is unavailable or no dashboard is running.
    """
    try:
        import psutil  # optional — available in the Hermes venv
    except ImportError:
        return []

    main_ports: List[int] = []
    profile_ports: List[int] = []
    try:
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmd: List[str] = proc.info.get("cmdline") or []
                cmd_str = " ".join(cmd)
                # Must be a hermes dashboard process (not a gateway/other subcommand).
                if "hermes" not in cmd_str or "dashboard" not in cmd_str:
                    continue
                is_profile = "--profile" in cmd_str
                for conn in proc.connections("inet"):
                    if conn.status == "LISTEN":
                        port = conn.laddr.port
                        if is_profile:
                            profile_ports.append(port)
                        else:
                            main_ports.append(port)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception as exc:
        logger.debug("[hermes_bridge] psutil discovery failed: %s", exc)
    return main_ports + profile_ports


class HermesBridgeAdapter(BasePlatformAdapter):
    """Connects Hermes Agent to the Hermes Bridge relay via outbound WebSocket.

    The adapter dials out to the relay — no inbound port needed, no NAT issues.
    Mobile sends messages via POST /api/relay/message → relay → this WS.
    Hermes responses go the other way: send() → WS → relay → SSE → mobile.

    Messages are E2E-encrypted with a profile-scoped symmetric PSK (XChaCha20-Poly1305).
    The relay only ever sees base64 ciphertext — never plaintext content.
    PSK must be generated via 'hermes gateway pair' and stored at ~/.hermes/psk.
    """

    def __init__(self, config):
        super().__init__(config, PLATFORM)
        self._ws = None
        self._run_task: Optional[asyncio.Task] = None
        self._should_run = False
        self._relay_url: str = os.getenv("HERMES_BRIDGE_RELAY_URL", "ws://localhost:8082")
        self._profile_id: str = os.getenv("HERMES_BRIDGE_PROFILE_ID", "")
        self._api_key: str = os.getenv("HERMES_BRIDGE_API_KEY", "")
        self._psk: bytes = load_psk()  # raises RuntimeError if absent — hard fail on startup
        # rpc.id → received_at (epoch); pruned lazily to prevent unbounded growth.
        self._seen_rpc_ids: Dict[str, float] = {}
        # run_id → asyncio.Task; cancelled on disconnect or runs.stop.
        self._active_run_tasks: Dict[str, asyncio.Task] = {}
        # Hermes dashboard session token — extracted from the SPA HTML on first
        # API call. Per-process ephemeral; refreshed when a request 401s.
        self._hermes_session_token: Optional[str] = None
        # Cached working port — avoids re-probing all 3 ports on every RPC call.
        self._hermes_api_port: Optional[int] = None
        # Background poll for newly staged memory/skill writes (PRD_Features.md
        # §2.7) — see _poll_pending_writes for why this is polling, not a push.
        self._approval_poll_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Abstract methods required by BasePlatformAdapter
    # ------------------------------------------------------------------

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        # Try once so startup reflects real state, then hand off to a supervisor
        # loop that reconnects with backoff for the gateway's lifetime.
        # ``is_reconnect`` is forwarded by the gateway's reconnection watcher;
        # this adapter runs its own supervisor loop so the flag is informational.
        self._should_run = True
        if is_reconnect and self._run_task is not None and not self._run_task.done():
            # Supervisor already owns reconnection — just report current state.
            return self._ws is not None
        ok = await self._connect_ws()
        self._run_task = asyncio.ensure_future(self._run_loop())
        if self._approval_poll_task is None or self._approval_poll_task.done():
            self._approval_poll_task = asyncio.ensure_future(self._poll_pending_writes())
        return ok

    async def _connect_ws(self) -> bool:
        url = f"{self._relay_url}/ws/hermes/{self._profile_id}"
        if self._api_key:
            url += f"?api_key={self._api_key}"
        try:
            # ping_interval keeps the connection alive through idle proxies and
            # surfaces a dead peer quickly so the supervisor can reconnect.
            self._ws = await websockets.connect(url, ping_interval=20, ping_timeout=20)
            self._running = True
            redacted = url.split("?")[0]  # strip query — don't leak api_key
            logger.info("[hermes_bridge] connected to relay: %s", redacted)
            return True
        except Exception as exc:
            logger.error("[hermes_bridge] connect failed: %s", exc)
            self._ws = None
            self._running = False
            return False

    async def _run_loop(self) -> None:
        """Supervisor: keep a live WS to the relay, reconnecting with backoff."""
        backoff = _RECONNECT_INITIAL
        while self._should_run:
            if self._ws is None:
                if not await self._connect_ws():
                    await asyncio.sleep(backoff * (0.8 + 0.4 * random.random()))
                    backoff = min(backoff * 2, _RECONNECT_MAX)
                    continue
                backoff = _RECONNECT_INITIAL
            # Consume until the connection drops, then loop to reconnect.
            await self._receive_loop()
            self._ws = None
            self._running = False
            if self._should_run:
                logger.info("[hermes_bridge] reconnecting to relay…")
                await asyncio.sleep(backoff * (0.8 + 0.4 * random.random()))
                backoff = min(backoff * 2, _RECONNECT_MAX)

    async def disconnect(self) -> None:
        self._should_run = False
        self._running = False
        for task in list(self._active_run_tasks.values()):
            task.cancel()
        self._active_run_tasks.clear()
        if self._run_task:
            self._run_task.cancel()
            try:
                await self._run_task
            except asyncio.CancelledError:
                pass
            self._run_task = None
        if self._approval_poll_task:
            self._approval_poll_task.cancel()
            try:
                await self._approval_poll_task
            except asyncio.CancelledError:
                pass
            self._approval_poll_task = None
        if self._ws:
            await self._ws.close()
            self._ws = None
        logger.info("[hermes_bridge] disconnected")

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None,
    ) -> SendResult:
        if not self._ws:
            return SendResult(success=False, error="not_connected", retryable=True)
        # Stable id shared by the live frame and the durable-inbox row — lets the
        # phone dedup the same message arriving via both paths (see
        # /api/relay/enqueue+api.ts, lib/pending-sync.ts).
        msg_id = str(uuid.uuid4())
        # Hermes core's DeliveryRouter (gateway/delivery.py) passes `job_id` in
        # metadata for cron/scheduled-job sends and omits it for interactive
        # replies (which instead carry thread/reply-routing keys, if any). No
        # dedicated "origin" flag exists upstream — job_id's presence is the
        # only reliable signal. The phone uses this to route the message to a
        # dedicated "Agent" inbox session instead of whatever chat is open.
        is_unsolicited = bool(metadata and "job_id" in metadata)
        # GatewayStreamConsumer tags the FIRST message of a streamed reply
        # with metadata["expect_edits"]=True (gateway/stream_consumer.py
        # _send_new_chunk) — it's a live preview that will be progressively
        # rewritten via edit_message() below, not a complete message worth
        # persisting yet. Skip durable enqueue for it; the terminal
        # edit_message(finalize=True) call durably enqueues the real content.
        # Returning message_id=msg_id here is what lets the stream consumer
        # discover we support editing at all (see edit_message()) — without
        # it, GatewayStreamConsumer treats us as edit-incapable and falls
        # back to sending the complete answer as a second, separate message.
        expect_edits = bool(metadata and metadata.get("expect_edits"))
        try:
            payload: Dict[str, Any] = {"role": "assistant", "content": content, "msg_id": msg_id}
            if is_unsolicited:
                payload["unsolicited"] = True
            if attachments:
                payload["attachments"] = attachments
            frame = seal(self._profile_id, "out", payload, self._psk)
            await self._ws.send(frame)
            result = SendResult(success=True, message_id=msg_id)
        except ConnectionClosed as exc:
            # Connection dropped — the supervisor loop will reconnect. Still
            # attempt durable enqueue below so the message isn't lost.
            result = SendResult(success=False, error=str(exc), retryable=True)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

        if expect_edits:
            return result

        # Durable enqueue + push, best-effort: the live frame (if it sent) already
        # reached a connected phone; this just makes the message recoverable for
        # an offline/closed one. Never called for `_send_run_event` streaming
        # frames — this is what makes send() the semantic authority on "a real
        # message worth persisting + notifying".
        await self._enqueue_durable(msg_id, frame)
        return result

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Progressively rewrite a streamed reply in place (PRD_Features.md §2.2).

        GatewayStreamConsumer calls this repeatedly with the FULL accumulated
        text so far (edit semantics — each call replaces, not appends) for the
        message ``send()`` started via the ``expect_edits`` preview above.
        ``finalize=True`` on the last call marks the reply complete.

        The phone recognizes an update to the same ``msg_id`` via the `edit`
        flag on the sealed frame (lib/crypto.ts MessagePayload) and renders it
        into the existing streaming-preview bubble instead of inserting a new
        message; `final` commits it like a normal reply once the stream ends.
        """
        if not self._ws:
            return SendResult(success=False, error="not_connected", retryable=True)
        try:
            payload: Dict[str, Any] = {
                "role": "assistant",
                "content": content,
                "msg_id": message_id,
                "edit": True,
            }
            if finalize:
                payload["final"] = True
            frame = seal(self._profile_id, "out", payload, self._psk)
            await self._ws.send(frame)
        except ConnectionClosed as exc:
            return SendResult(success=False, error=str(exc), retryable=True)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

        if finalize:
            # Terminal edit — this is the real content worth persisting/
            # recovering offline, same contract as send()'s non-streamed path.
            await self._enqueue_durable(message_id, frame)

        return SendResult(success=True, message_id=message_id)

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {
            "id": chat_id,
            "platform": "hermes_bridge",
            "profile_id": self._profile_id,
        }

    # ------------------------------------------------------------------
    # Outbound attachments (PRD_Features.md §2.3)
    #
    # image_path/file_path have already been validated + resolved by Hermes
    # core (BasePlatformAdapter.filter_media_delivery_paths /
    # filter_local_delivery_paths run in gateway/run.py before send_image_file
    # / send_document are ever called) — safe to read directly here.
    #
    # send_voice is implemented below (#38). send_video is NOT overridden —
    # no issue currently scopes video attachments; falls back to
    # BasePlatformAdapter's default "couldn't deliver" text notice.
    #
    # send_multiple_images needs no override: BasePlatformAdapter's default
    # implementation already routes `file://` URIs through send_image_file
    # per-item (gateway/platforms/base.py), so overriding send_image_file
    # alone covers both the single-file and batched-images delivery paths.
    # ------------------------------------------------------------------

    async def _send_attachment(
        self,
        chat_id: str,
        local_path: str,
        mime: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ) -> SendResult:
        """Shared outbound path: read the local file, seal it as a blob,
        upload to the relay's sealed-blob store, then send a normal chat
        frame carrying the attachment ref via send() — reusing its existing
        msg_id/durable-enqueue/frame-building logic rather than duplicating
        it (this is send() with an attachment, not a separate wire concept).
        """
        # Mirrors BasePlatformAdapter's own send_image_file/send_document
        # default fallback shape: caption PREPENDED to the notice, never
        # replacing it — an upload failure must still read as a failure.
        notice = "⚠️ Couldn't deliver the attachment."
        fallback_text = f"{caption}\n{notice}" if caption else notice
        try:
            with open(local_path, "rb") as f:
                plaintext = f.read()
        except OSError as exc:
            logger.warning("[hermes_bridge] attachment read failed for %s: %s", local_path, exc)
            return await self.send(chat_id=chat_id, content=fallback_text, reply_to=reply_to, metadata=metadata)

        sealed = seal_blob(self._profile_id, plaintext, self._psk)
        try:
            blob_id = await self._upload_blob(sealed, mime)
        except Exception as exc:
            logger.warning("[hermes_bridge] blob upload failed: %s", exc)
            return await self.send(chat_id=chat_id, content=fallback_text, reply_to=reply_to, metadata=metadata)

        attachment: Dict[str, Any] = {"mime": mime, "blob_id": blob_id}
        if name:
            attachment["name"] = name
        return await self.send(
            chat_id=chat_id,
            content=caption or "",
            reply_to=reply_to,
            metadata=metadata,
            attachments=[attachment],
        )

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        mime = mimetypes.guess_type(image_path)[0] or "application/octet-stream"
        return await self._send_attachment(
            chat_id,
            image_path,
            mime,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
            name=os.path.basename(image_path),
        )

    async def send_document(
        self,
        chat_id: str,
        file_path: str,
        caption: Optional[str] = None,
        file_name: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        mime = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
        return await self._send_attachment(
            chat_id,
            file_path,
            mime,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
            name=file_name or os.path.basename(file_path),
        )

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Outbound voice/TTS replies (#38) — same blob path as images/documents.

        Called both for explicit send_voice() invocations and, via
        BasePlatformAdapter.play_tts's default (send_voice fallback), for
        Hermes's auto-TTS voice replies (gateway/run.py _send_voice_reply,
        gated by the /voice on|off|tts mode — already built into Hermes
        core's central slash-command dispatch, no adapter-side toggle logic
        needed here).

        Fallback to "audio/mpeg" (not "application/octet-stream" like
        send_document) if the extension is unrecognized — send_voice is only
        ever called with audio, and Hermes core's inbound STT/message-type
        classification keys off the mime starting with "audio/".
        """
        mime = mimetypes.guess_type(audio_path)[0] or "audio/mpeg"
        return await self._send_attachment(
            chat_id,
            audio_path,
            mime,
            caption=caption,
            reply_to=reply_to,
            metadata=metadata,
            name=os.path.basename(audio_path),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        """Forward messages arriving from mobile to Hermes via handle_message()."""
        try:
            async for raw in self._ws:
                try:
                    text = raw if isinstance(raw, str) else raw.decode()
                    # The relay forwards JSON.stringify({role, content}) where content
                    # is the sealed base64 frame.  Fall back to treating the raw text
                    # as the bare frame for forward-compat.
                    try:
                        parsed_msg = json.loads(text)
                        frame = parsed_msg.get("content", text) if isinstance(parsed_msg, dict) else text
                    except (json.JSONDecodeError, TypeError):
                        frame = text
                    payload = open_frame(self._profile_id, "in", frame, self._psk)
                    if payload is None:
                        logger.warning("[hermes_bridge] dropped frame: decrypt/replay/timestamp check failed")
                        continue
                    if payload.get("role") == "rpc.request":
                        rpc = payload.get("rpc") or {}
                        logger.info("[hermes_bridge] rpc dispatch method=%s id=%s", rpc.get("method"), str(rpc.get("id", ""))[:8])
                        asyncio.ensure_future(self._handle_rpc(payload))
                        continue
                    media_urls: List[str] = []
                    media_types: List[str] = []
                    attachments = payload.get("attachments") or []
                    if attachments:
                        media_urls, media_types = await self._download_attachments_to_media(
                            attachments
                        )
                    # message_type: per-attachment media_types already drives
                    # image/audio/video/document classification everywhere
                    # else in Hermes core (_event_media_is_image/_is_audio/...
                    # check the mime first, message_type only as a fallback)
                    # — EXCEPT auto-TTS's voice_only mode, which keys directly
                    # off message_type == MessageType.VOICE
                    # (gateway/run.py _should_auto_voice_reply). Priority
                    # mirrors signal.py's real inbound classification: audio >
                    # image > video > else document.
                    message_type = MessageType.TEXT
                    if media_types:
                        if any(mt.startswith("audio/") for mt in media_types):
                            message_type = MessageType.VOICE
                        elif any(mt.startswith("image/") for mt in media_types):
                            message_type = MessageType.PHOTO
                        elif any(mt.startswith("video/") for mt in media_types):
                            message_type = MessageType.VIDEO
                        else:
                            message_type = MessageType.DOCUMENT
                    event = MessageEvent(
                        text=payload["content"],
                        source=self.build_source(
                            chat_id=self._profile_id,
                            user_id="mobile",
                        ),
                        media_urls=media_urls,
                        media_types=media_types,
                        message_type=message_type,
                    )
                    await self.handle_message(event)
                except Exception as exc:
                    logger.warning("[hermes_bridge] message dispatch error: %s", exc)
        except ConnectionClosed:
            logger.info("[hermes_bridge] relay connection closed")
        except Exception as exc:
            logger.error("[hermes_bridge] receive loop error: %s", exc)
        # Return to the supervisor (_run_loop), which reconnects with backoff.

    async def _handle_rpc(self, payload: Dict[str, Any]) -> None:
        """Dispatch an rpc.request frame via _RPC_HANDLERS and respond over WS."""
        rpc = payload.get("rpc") or {}
        rpc_id = rpc.get("id", "")
        method = rpc.get("method", "")
        params = rpc.get("params") or {}

        # Idempotency: drop retried requests with the same rpc.id within the dedup window.
        loop = asyncio.get_event_loop()
        now = loop.time()
        if rpc_id and rpc_id in self._seen_rpc_ids:
            logger.debug("[hermes_bridge] rpc %s duplicate — skipping (dedup)", rpc_id)
            return
        if rpc_id:
            self._seen_rpc_ids[rpc_id] = now
            cutoff = now - _RPC_DEDUP_WINDOW_S
            stale = [k for k, t in self._seen_rpc_ids.items() if t < cutoff]
            for k in stale:
                del self._seen_rpc_ids[k]

        handler = self._RPC_HANDLERS.get(method)
        if handler is None:
            await self._send_rpc_response(rpc_id, ok=False, error="method_not_found")
            return

        try:
            data = await handler(self, params)
            await self._send_rpc_response(rpc_id, ok=True, data=data)
        except _RpcError as exc:
            await self._send_rpc_response(rpc_id, ok=False, error=str(exc))
        except urllib.error.HTTPError as exc:
            # A live Hermes answered but rejected the request. 401/403 keep the
            # stable auth error code; anything else passes Hermes's own
            # human-readable {"detail": "..."} through (e.g. an unparseable
            # cron schedule from cron.create/cron.edit).
            logger.warning("[hermes_bridge] rpc %s failed: HTTP %d", method, exc.code)
            error = "hermes_auth_failed" if exc.code in (401, 403) else _http_error_detail(exc)
            await self._send_rpc_response(rpc_id, ok=False, error=error)
        except Exception as exc:
            logger.warning("[hermes_bridge] rpc %s failed: %s — %s", method, type(exc).__name__, exc)
            # Classify error so the client can distinguish "Hermes not running" from
            # "auth failed" vs a transient API error.
            err_str = str(exc).lower()
            if "refused" in err_str or "no hermes api port reachable" in err_str or "timed out" in err_str:
                error_code = "hermes_offline"
            elif "401" in err_str or "unauthorized" in err_str or "auth" in err_str:
                error_code = "hermes_auth_failed"
            else:
                error_code = "hermes_api_unavailable"
            await self._send_rpc_response(rpc_id, ok=False, error=error_code)

    # ------------------------------------------------------------------
    # RPC handlers — dispatched by _handle_rpc via _RPC_HANDLERS below.
    # Contract: take a params dict, return the response data. Raise
    # _RpcError("<code>") for validation failures; let HTTPError and
    # connection errors propagate — _handle_rpc classifies them uniformly.
    # ------------------------------------------------------------------

    async def _rpc_sessions_messages(self, p: Dict[str, Any]) -> Any:
        session_id = _require(p, "id", "missing_session_id")
        return await self._hermes_get(f"/api/sessions/{session_id}/messages")

    async def _rpc_sessions_switch(self, p: Dict[str, Any]) -> Any:
        # Hermes has no REST endpoint to switch active session context.
        # Navigation proceeds on the mobile side — just ack.
        return {"switched": True}

    async def _rpc_sessions_delete(self, p: Dict[str, Any]) -> Any:
        session_id = _require(p, "id", "missing_session_id")
        await self._hermes_request(f"/api/sessions/{session_id}", method="DELETE")
        return {"deleted": True}

    async def _rpc_sessions_search(self, p: Dict[str, Any]) -> Any:
        q = str(p.get("q", "")).strip()
        limit = int(p.get("limit", 20))
        return await self._hermes_get(f"/api/sessions/search?q={q}&limit={limit}")

    async def _rpc_sessions_export(self, p: Dict[str, Any]) -> Any:
        session_id = _require(p, "id", "missing_session_id")
        return await self._hermes_get(f"/api/sessions/{session_id}/export")

    async def _rpc_skills_toggle(self, p: Dict[str, Any]) -> Any:
        name = _require(p, "name", "missing_skill_name")
        body = {"name": name, "enabled": bool(p.get("enabled"))}
        return await self._hermes_post("/api/skills/toggle", body=body, method="PUT")

    async def _rpc_skills_content(self, p: Dict[str, Any]) -> Any:
        name = _require(p, "name", "missing_skill_name")
        return await self._hermes_get(f"/api/skills/content?name={name}")

    async def _rpc_skills_hub_search(self, p: Dict[str, Any]) -> Any:
        q = str(p.get("q", "")).strip()
        limit = int(p.get("limit", 20))
        source = str(p.get("source", "all")).strip() or "all"
        return await self._hermes_get(f"/api/skills/hub/search?q={q}&limit={limit}&source={source}")

    async def _rpc_skills_hub_install(self, p: Dict[str, Any]) -> Any:
        identifier = _require(p, "identifier", "missing_identifier")
        return await self._hermes_post("/api/skills/hub/install", body={"identifier": identifier})

    async def _rpc_skills_hub_uninstall(self, p: Dict[str, Any]) -> Any:
        name = _require(p, "name", "missing_skill_name")
        return await self._hermes_post("/api/skills/hub/uninstall", body={"name": name})

    async def _rpc_agent_status(self, p: Dict[str, Any]) -> Any:
        data = await self._hermes_get("/api/status")
        try:
            stats = await self._hermes_get("/api/system/stats")
            if isinstance(data, dict) and isinstance(stats, dict):
                data = {**data, **stats}
        except Exception:
            pass
        return data

    async def _rpc_agent_set_model(self, p: Dict[str, Any]) -> Any:
        model = _require(p, "model", "missing_model")
        scope = str(p.get("scope", "main")).strip() or "main"
        provider = str(p.get("provider", "")).strip()
        return await self._hermes_post(
            "/api/model/set", body={"scope": scope, "provider": provider, "model": model}
        )

    async def _rpc_usage_get(self, p: Dict[str, Any]) -> Any:
        days = p.get("days", 7)
        return await self._hermes_get(f"/api/analytics/usage?days={days}")

    async def _rpc_cron_action(self, p: Dict[str, Any], action: str) -> Any:
        job_id = _require(p, "id", "missing_job_id")
        return await self._hermes_post(f"/api/cron/jobs/{job_id}/{action}")

    async def _rpc_cron_create(self, p: Dict[str, Any]) -> Any:
        schedule = _require(p, "schedule", "missing_schedule")
        body: Dict[str, Any] = {"schedule": schedule}
        for key in ("prompt", "name", "deliver"):
            if p.get(key):
                body[key] = str(p[key])
        skills = p.get("skills")
        if skills:
            body["skills"] = skills if isinstance(skills, list) else [str(skills)]
        return await self._hermes_post("/api/cron/jobs", body=body)

    async def _rpc_cron_edit(self, p: Dict[str, Any]) -> Any:
        job_id = _require(p, "id", "missing_job_id")
        updates: Dict[str, Any] = {k: p[k] for k in ("schedule", "prompt", "name", "deliver") if k in p}
        if "skills" in p:
            skills = p.get("skills")
            updates["skills"] = skills if isinstance(skills, list) else ([str(skills)] if skills else [])
        if not updates:
            raise _RpcError("no_updates")
        return await self._hermes_post(f"/api/cron/jobs/{job_id}", body={"updates": updates}, method="PUT")

    async def _rpc_cron_runs(self, p: Dict[str, Any]) -> Any:
        job_id = _require(p, "job_id", "missing_job_id")
        limit = int(p.get("limit", 20))
        return await self._hermes_get(f"/api/cron/jobs/{job_id}/runs?limit={limit}")

    async def _rpc_runs_start(self, p: Dict[str, Any]) -> Any:
        run_data = await self._hermes_post("/v1/runs", body=p)
        run_id = str(run_data.get("run_id") or run_data.get("id") or "").strip()
        if not run_id:
            raise _RpcError("no_run_id_in_response")
        # The mobile client opens its profile stream before issuing runs.start
        # (lib/hermes-rpc.ts), so spawning the event relay before the rpc
        # response frame goes out cannot lose events.
        self._active_run_tasks[run_id] = asyncio.ensure_future(self._stream_run_events(run_id))
        return {"run_id": run_id}

    async def _rpc_runs_stop(self, p: Dict[str, Any]) -> Any:
        run_id = str(p.get("run_id", "")).strip()
        task = self._active_run_tasks.pop(run_id, None)
        if task:
            task.cancel()
        try:
            await self._hermes_post(f"/v1/runs/{run_id}/stop")
        except Exception:
            pass
        return {"stopped": True}

    async def _rpc_approval_resolve(self, p: Dict[str, Any]) -> Any:
        run_id = str(p.get("run_id", "")).strip()
        approval_id = str(p.get("approval_id", "")).strip()
        if not run_id or not approval_id:
            raise _RpcError("missing_run_id_or_approval_id")
        decision = str(p.get("decision", "approve")).strip()
        return await self._hermes_post(f"/v1/runs/{run_id}/approval/{approval_id}/{decision}")

    async def _rpc_memory_list(self, p: Dict[str, Any]) -> Any:
        try:
            entries = _read_memory_entries()
        except FileNotFoundError:
            return []
        return [{"id": _memory_entry_id(e), "content": e} for e in entries]

    async def _rpc_memory_delete(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        try:
            entries = _read_memory_entries()
        except FileNotFoundError:
            raise _RpcError("memory_file_not_found")
        kept = [e for e in entries if _memory_entry_id(e) != entry_id]
        with open(_MEMORY_PATH, "w", encoding="utf-8") as f:
            f.write("\n§\n".join(kept))
        return {"deleted": True}

    # ------------------------------------------------------------------
    # Write-approval RPCs (PRD_Features.md §2.7). Distinct from memory.list/
    # memory.delete above (that pair edits the committed MEMORY.md directly).
    # These operate on Hermes's *staged* write-approval queue.
    #
    # No REST endpoint exists for this on Hermes core (unlike cron/model/etc,
    # which proxy to the dashboard API) — write-approval is only exposed via
    # in-process functions (tools.write_approval, tools.memory_tool,
    # tools.skill_manager_tool) that the gateway's own /memory and /skills
    # slash-command handlers call directly (gateway/slash_commands.py
    # _handle_memory_command/_handle_skills_command). Since this adapter runs
    # in the same process as the gateway (it already imports
    # gateway.platforms.base directly), we call the same functions rather
    # than inventing an HTTP proxy for something that has no HTTP surface.
    # ------------------------------------------------------------------

    async def _rpc_memory_pending(self, p: Dict[str, Any]) -> Any:
        from tools import write_approval as wa
        return [_pending_summary(r) for r in wa.list_pending(wa.MEMORY)]

    async def _rpc_memory_approve(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        from tools import write_approval as wa
        from tools.memory_tool import apply_memory_pending, load_on_disk_store

        rec = wa.get_pending(wa.MEMORY, entry_id)
        if not rec:
            raise _RpcError("pending_not_found")
        # No live agent in this process — build a fresh on-disk store the
        # same way the gateway's own /memory approve handler does, so the
        # applied write honors the same configured char limits.
        store = load_on_disk_store()
        result = apply_memory_pending(rec.get("payload", {}), store)
        if not result.get("success"):
            raise _RpcError(str(result.get("error") or "apply_failed"))
        wa.discard_pending(wa.MEMORY, entry_id)
        return {"approved": True}

    async def _rpc_memory_reject(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        from tools import write_approval as wa
        if not wa.discard_pending(wa.MEMORY, entry_id):
            raise _RpcError("pending_not_found")
        return {"rejected": True}

    async def _rpc_skills_pending(self, p: Dict[str, Any]) -> Any:
        from tools import write_approval as wa
        return [_pending_summary(r) for r in wa.list_pending(wa.SKILLS)]

    async def _rpc_skills_pending_approve(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        from tools import write_approval as wa
        from tools.skill_manager_tool import apply_skill_pending

        rec = wa.get_pending(wa.SKILLS, entry_id)
        if not rec:
            raise _RpcError("pending_not_found")
        result = json.loads(apply_skill_pending(rec.get("payload", {})))
        if not result.get("success"):
            raise _RpcError(str(result.get("error") or "apply_failed"))
        wa.discard_pending(wa.SKILLS, entry_id)
        return {"approved": True}

    async def _rpc_skills_pending_reject(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        from tools import write_approval as wa
        if not wa.discard_pending(wa.SKILLS, entry_id):
            raise _RpcError("pending_not_found")
        return {"rejected": True}

    async def _rpc_skills_pending_diff(self, p: Dict[str, Any]) -> Any:
        entry_id = _require(p, "id", "missing_id")
        from tools import write_approval as wa
        rec = wa.get_pending(wa.SKILLS, entry_id)
        if not rec:
            raise _RpcError("pending_not_found")
        return {"diff": wa.skill_pending_diff(rec)}

    async def _rpc_chat_stop(self, p: Dict[str, Any]) -> Any:
        """Abort the in-flight chat turn (PRD_Features.md §2.6).

        No adapter-side interrupt plumbing needed: Hermes core already
        handles ``/stop`` centrally (gateway/slash_commands.py
        _handle_stop_command, reached via the same command dispatch every
        platform's incoming text goes through) — it looks up the run by
        session key, interrupts it, and force-clears the session lock, safe
        to call even with no active run. Synthesizing "/stop" and routing it
        through handle_message() (the exact path _receive_loop uses for
        every normal incoming message) gets all of that for free.
        """
        event = MessageEvent(
            text="/stop",
            source=self.build_source(chat_id=self._profile_id, user_id="mobile"),
        )
        await self.handle_message(event)
        return {"stopped": True}

    # method name → handler(self, params). Plain functions (dict values don't
    # bind), so _handle_rpc calls handler(self, params) explicitly.
    _RPC_HANDLERS: Dict[str, Any] = {
        "sessions.list": lambda self, p: self._hermes_get("/api/sessions"),
        "sessions.messages": _rpc_sessions_messages,
        "sessions.switch": _rpc_sessions_switch,
        "sessions.delete": _rpc_sessions_delete,
        "sessions.search": _rpc_sessions_search,
        "sessions.export": _rpc_sessions_export,
        "skills.list": lambda self, p: self._hermes_get("/api/skills"),
        "skills.toggle": _rpc_skills_toggle,
        "skills.content": _rpc_skills_content,
        "skills.hub.search": _rpc_skills_hub_search,
        "skills.hub.install": _rpc_skills_hub_install,
        "skills.hub.uninstall": _rpc_skills_hub_uninstall,
        "skills.hub.update": lambda self, p: self._hermes_post("/api/skills/hub/update", body={}),
        "agent.status": _rpc_agent_status,
        "agent.set_model": _rpc_agent_set_model,
        "usage.get": _rpc_usage_get,
        "model.options": lambda self, p: self._hermes_get("/api/model/options"),
        "cron.list": lambda self, p: self._hermes_get("/api/cron/jobs"),
        "cron.pause": lambda self, p: self._rpc_cron_action(p, "pause"),
        "cron.resume": lambda self, p: self._rpc_cron_action(p, "resume"),
        "cron.trigger": lambda self, p: self._rpc_cron_action(p, "trigger"),
        "cron.create": _rpc_cron_create,
        "cron.edit": _rpc_cron_edit,
        "cron.runs": _rpc_cron_runs,
        "runs.start": _rpc_runs_start,
        "runs.stop": _rpc_runs_stop,
        "approval.resolve": _rpc_approval_resolve,
        "approvals.list": lambda self, p: self._hermes_get("/v1/approvals"),
        "memory.list": _rpc_memory_list,
        "memory.delete": _rpc_memory_delete,
        "memory.pending": _rpc_memory_pending,
        "memory.approve": _rpc_memory_approve,
        "memory.reject": _rpc_memory_reject,
        "skills.pending": _rpc_skills_pending,
        "skills.approve": _rpc_skills_pending_approve,
        "skills.reject": _rpc_skills_pending_reject,
        "skills.diff": _rpc_skills_pending_diff,
        "chat.stop": _rpc_chat_stop,
    }

    def _fetch_session_token(self, port: int) -> Optional[str]:
        """Extract the Hermes dashboard session token from the SPA HTML.

        Tries multiple patterns to handle different Hermes versions:
          - 0.16+:  SESSION_TOKEN__="<token>"
          - older:  SESSION_TOKEN__ = "<token>"  (spaces around =)
          - JSON:   "sessionToken":"<token>"
        """
        try:
            with urllib.request.urlopen(f"http://localhost:{port}/", timeout=5) as r:
                html = r.read().decode()
            for pat in [
                r'SESSION_TOKEN__\s*=\s*["\']([^"\']+)["\']',
                r'"sessionToken"\s*:\s*"([^"]+)"',
                r"'sessionToken'\s*:\s*'([^']+)'",
            ]:
                m = re.search(pat, html)
                if m:
                    return m.group(1)
            logger.debug("[hermes_bridge] session token not found in Hermes HTML on port %d", port)
            return None
        except Exception as exc:
            logger.debug("[hermes_bridge] _fetch_session_token port %d: %s", port, exc)
            return None

    async def _ensure_hermes_token(self, port: int) -> Optional[str]:
        """Return cached token or bootstrap from env var / SPA HTML.

        Priority:
          1. In-process cache (set once per gateway lifetime, cleared on 401)
          2. HERMES_SESSION_TOKEN env var (manual override — useful when HTML
             extraction fails on a Hermes version that changed the token format)
          3. Scrape from Hermes dashboard HTML
        """
        if self._hermes_session_token:
            return self._hermes_session_token
        env_token = os.getenv("HERMES_SESSION_TOKEN")
        if env_token:
            self._hermes_session_token = env_token
            return env_token
        loop = asyncio.get_event_loop()
        token = await loop.run_in_executor(None, self._fetch_session_token, port)
        if token:
            self._hermes_session_token = token
        return token

    def _ports_to_probe(self) -> List[int]:
        """Return ports to try in priority order.

        1. Cached known-good port (fast path, avoids re-probing).
        2. Live psutil discovery (handles --port 0 / auto-assigned ports).
        3. Static fallback list (well-known defaults).
        """
        if self._hermes_api_port is not None:
            # Cached port first; keep others as fallback for Hermes restart.
            discovered = _discover_dashboard_ports()
            rest = [p for p in (discovered + _HERMES_API_PORTS) if p != self._hermes_api_port]
            # Deduplicate while preserving order.
            seen = {self._hermes_api_port}
            deduped_rest = []
            for p in rest:
                if p not in seen:
                    seen.add(p)
                    deduped_rest.append(p)
            return [self._hermes_api_port] + deduped_rest

        discovered = _discover_dashboard_ports()
        combined = discovered + [p for p in _HERMES_API_PORTS if p not in discovered]
        return combined if combined else _HERMES_API_PORTS

    async def _hermes_request(
        self,
        path: str,
        method: str = "GET",
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Shared GET/POST/PUT helper: port-probe with cache, 401 token refresh."""
        loop = asyncio.get_event_loop()
        body_bytes = (json.dumps(body).encode() if body is not None else b"{}") if method != "GET" else None
        last_exc: Optional[Exception] = None

        for port in self._ports_to_probe():
            url = f"http://localhost:{port}{path}"
            token = await self._ensure_hermes_token(port)

            def _do(u=url, t=token, m=method, b=body_bytes):
                headers: Dict[str, str] = {}
                if t:
                    headers["X-Hermes-Session-Token"] = t
                if b is not None:
                    headers["Content-Type"] = "application/json"
                    headers["Content-Length"] = str(len(b))
                req = urllib.request.Request(u, method=m, data=b, headers=headers)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    raw = resp.read()
                    return json.loads(raw.decode()) if raw else {"ok": True}

            try:
                result = await loop.run_in_executor(None, _do)
                # Cache this port so future calls skip the probe loop.
                self._hermes_api_port = port
                return result
            except urllib.error.HTTPError as exc:
                if exc.code != 401:
                    # A live Hermes answered — this IS the working port; the
                    # request itself was rejected (validation 4xx / server
                    # 5xx). Do NOT keep probing: other ports would just refuse
                    # the connection and bury this error (losing e.g. a cron
                    # schedule-parse 400 detail), and re-sending a POST to
                    # them would replay a non-idempotent request.
                    self._hermes_api_port = port
                    raise
                # 401: token stale — clear and retry once with a freshly extracted token.
                self._hermes_session_token = None
                fresh = await self._ensure_hermes_token(port)
                if fresh and fresh != token:
                    try:
                        def _retry(u=url, t=fresh, m=method, b=body_bytes):
                            headers: Dict[str, str] = {"X-Hermes-Session-Token": t}
                            if b is not None:
                                headers["Content-Type"] = "application/json"
                                headers["Content-Length"] = str(len(b))
                            req = urllib.request.Request(u, method=m, data=b, headers=headers)
                            with urllib.request.urlopen(req, timeout=5) as r:
                                raw = r.read()
                                return json.loads(raw.decode()) if raw else {"ok": True}
                        result = await loop.run_in_executor(None, _retry)
                        self._hermes_api_port = port
                        return result
                    except Exception as e2:
                        last_exc = e2
                else:
                    # Token extraction itself is failing — no point retrying other ports
                    # for auth; but still try them in case one allows unauthenticated access.
                    logger.warning(
                        "[hermes_bridge] 401 from port %d and token re-extraction failed — "
                        "Hermes may require auth but SESSION_TOKEN__ is not in the HTML. "
                        "Check Hermes version or set HERMES_SESSION_TOKEN env var.",
                        port,
                    )
                    last_exc = exc
            except Exception as exc:
                last_exc = exc
                # Clear port cache on connection-level errors.
                if port == self._hermes_api_port:
                    self._hermes_api_port = None

        raise last_exc or RuntimeError("no hermes api port reachable")

    async def _hermes_get(self, path: str) -> Any:
        """GET from Hermes local REST API."""
        return await self._hermes_request(path, method="GET")

    async def _hermes_post(
        self, path: str, body: Optional[Dict[str, Any]] = None, method: str = "POST"
    ) -> Any:
        """POST/PUT to Hermes local REST API."""
        return await self._hermes_request(path, method=method, body=body)

    async def _send_push_notification(
        self, title: str, body: str, data: Optional[Dict[str, Any]] = None
    ) -> None:
        """POST to relay /api/notify — relay publishes to hermes:<id>:notify → push.ts delivers."""
        relay_http = self._relay_url.replace("ws://", "http://").replace("wss://", "https://")
        url = f"{relay_http}/api/notify"
        payload = json.dumps({"title": title, "body": body, "data": data or {}}).encode()
        loop = asyncio.get_event_loop()
        try:
            def _post(u=url, b=payload, k=self._api_key):
                req = urllib.request.Request(
                    u,
                    method="POST",
                    data=b,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {k}",
                        "Content-Length": str(len(b)),
                    },
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
            await loop.run_in_executor(None, _post)
        except Exception as exc:
            logger.warning("[hermes_bridge] push notification failed: %s", exc)

    _APPROVAL_POLL_INTERVAL_S = 30

    async def _poll_pending_writes(self) -> None:
        """Push-notify on newly staged memory/skill writes (PRD_Features.md §2.7).

        Unlike run-scoped tool approvals (an ``approval.request`` event on the
        live /v1/runs SSE stream — see _stream_run_events), Hermes core has no
        event/callback when ``tools.write_approval.stage_write()`` runs — it's
        a synchronous file write with no notification hook, confirmed by
        reading tools/write_approval.py, tools/memory_tool.py and
        tools/skill_manager_tool.py. This matters most for background_review-
        origin writes (the self-improvement fork that runs after a turn with
        no live chat to reply into) — polling the pending dirs is the only way
        to surface those. Interval is a plain constant, not configurable: this
        is a small file-glob check, cheap enough to just always run.

        ``seeded`` guards against a startup false-positive burst: until the
        first successful read of both pending dirs, a tick only *establishes*
        the baseline (adds ids to ``seen``) rather than firing pushes for
        them — otherwise a transient failure on the real startup seed would
        leave ``seen`` empty, and the next successful tick would treat every
        already-pending write as "new" and fire a push per item.
        """
        from tools import write_approval as wa

        seen: set = set()
        seeded = False

        while self._should_run:
            try:
                for subsystem in (wa.MEMORY, wa.SKILLS):
                    new_records = _diff_new_pending(wa.list_pending(subsystem), subsystem, seen)
                    if not seeded:
                        continue  # this tick only establishes the baseline
                    for rec in new_records:
                        label = "memory" if subsystem == wa.MEMORY else "skill"
                        asyncio.ensure_future(
                            self._send_push_notification(
                                title=f"New {label} write staged",
                                body=str(rec.get("summary", ""))[:200] or "Review in Approvals.",
                                data={"screen": "agent", "tab": "approvals"},
                            )
                        )
                seeded = True
            except Exception as exc:
                logger.warning("[hermes_bridge] pending-write poll failed: %s", exc)
            # Seed attempt failed — retry almost immediately rather than
            # waiting out a full interval with an unestablished baseline.
            await asyncio.sleep(self._APPROVAL_POLL_INTERVAL_S if seeded else 1)

    async def _upload_blob(self, sealed: bytes, mime: str) -> str:
        """POST sealed bytes to the relay's sealed-blob store
        (app/api/relay/blob+api.ts, PRD_Features.md §2.3). Raises on any
        failure — callers fall back to a text-only send()."""
        from urllib.parse import quote as _quote

        relay_http = self._relay_url.replace("ws://", "http://").replace("wss://", "https://")
        url = f"{relay_http}/api/relay/blob?profile_id={_quote(self._profile_id)}&mime={_quote(mime)}"
        loop = asyncio.get_event_loop()

        def _post(u=url, b=sealed, k=self._api_key):
            req = urllib.request.Request(
                u,
                method="POST",
                data=b,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Authorization": f"Bearer {k}",
                    "Content-Length": str(len(b)),
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())

        result = await loop.run_in_executor(None, _post)
        blob_id = result.get("blob_id") if isinstance(result, dict) else None
        if not blob_id:
            raise RuntimeError("blob upload response missing blob_id")
        return blob_id

    async def _download_blob(self, blob_id: str) -> Optional[bytes]:
        """GET + decrypt a sealed blob (app/api/relay/blob/[id]+api.ts,
        PRD_Features.md §2.3). None on any fetch/auth/decrypt failure —
        callers skip that one attachment rather than failing the whole
        message."""
        relay_http = self._relay_url.replace("ws://", "http://").replace("wss://", "https://")
        url = f"{relay_http}/api/relay/blob/{blob_id}"
        loop = asyncio.get_event_loop()

        def _get(u=url, k=self._api_key):
            req = urllib.request.Request(u, headers={"Authorization": f"Bearer {k}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read()

        try:
            sealed = await loop.run_in_executor(None, _get)
        except Exception as exc:
            logger.warning("[hermes_bridge] blob download failed for %s: %s", blob_id, exc)
            return None
        return open_blob(self._profile_id, sealed, self._psk)

    async def _download_attachments_to_media(
        self, attachments: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[str]]:
        """Fetch + decrypt each inbound attachment blob and write it to a
        local cache file, returning (media_urls, media_types) — the same
        parallel-array contract MessageEvent expects and every other
        adapter's inbound media handling produces (see
        gateway/platforms/whatsapp_cloud.py's _download_media_to_cache). A
        blob that fails to fetch/decrypt is silently skipped — Hermes core
        still sees the message text, just without that one attachment.
        """
        media_urls: List[str] = []
        media_types: List[str] = []
        for att in attachments:
            blob_id = str(att.get("blob_id", "")).strip()
            if not blob_id:
                continue
            mime = str(att.get("mime") or "application/octet-stream")
            plaintext = await self._download_blob(blob_id)
            if plaintext is None:
                logger.warning("[hermes_bridge] failed to fetch/decrypt attachment blob %s", blob_id)
                continue
            ext = mimetypes.guess_extension(mime.split(";")[0].strip()) or ".bin"
            name = str(att.get("name") or f"{blob_id}{ext}")
            # blob_id-prefixed filename avoids collisions between attachments
            # that share a display name (mirrors lib/attachments.ts's
            # writeAttachmentToCache on the mobile side).
            out_path = os.path.join(_INBOUND_MEDIA_DIR, f"{blob_id}_{name}")
            try:
                os.makedirs(_INBOUND_MEDIA_DIR, exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(plaintext)
            except OSError as exc:
                logger.warning("[hermes_bridge] failed to write attachment to disk: %s", exc)
                continue
            media_urls.append(out_path)
            media_types.append(mime)
        return media_urls, media_types

    async def _enqueue_durable(self, msg_id: str, sealed_frame: str) -> None:
        """POST to relay /api/relay/enqueue — persists the sealed frame so it
        survives the phone being offline/closed, and triggers a generic push.
        Mirrors _send_push_notification's urllib+executor pattern. Best-effort:
        the live WS send already reached a connected phone, so a failure here
        just means a closed phone won't catch up — log and move on."""
        relay_http = self._relay_url.replace("ws://", "http://").replace("wss://", "https://")
        url = f"{relay_http}/api/relay/enqueue"
        payload = json.dumps({"msg_id": msg_id, "sealed_frame": sealed_frame}).encode()
        loop = asyncio.get_event_loop()
        try:
            def _post(u=url, b=payload, k=self._api_key):
                req = urllib.request.Request(
                    u,
                    method="POST",
                    data=b,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {k}",
                        "Content-Length": str(len(b)),
                    },
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    resp.read()
            await loop.run_in_executor(None, _post)
        except Exception as exc:
            logger.warning("[hermes_bridge] durable enqueue failed: %s", exc)

    async def _send_run_event(self, run_id: str, event_type: str, data: Any, done: bool) -> None:
        if not self._ws:
            return
        rpc_payload: Dict[str, Any] = {"id": run_id, "event": event_type, "data": data, "done": done}
        frame = seal(
            self._profile_id,
            "out",
            {"role": "run.event", "content": "", "rpc": rpc_payload},
            self._psk,
        )
        try:
            await self._ws.send(frame)
        except ConnectionClosed as exc:
            logger.warning("[hermes_bridge] run event send failed: %s", exc)

    async def _stream_run_events(self, run_id: str) -> None:
        """Subscribe to Hermes SSE stream for run_id, relay events to mobile via :out."""
        loop = asyncio.get_event_loop()
        q: asyncio.Queue = asyncio.Queue()
        # Token is typically already cached by the preceding runs.start POST.
        # Resolve it before spawning the thread so the thread stays synchronous.
        probe_port = self._hermes_api_port or _HERMES_API_PORTS[0]
        session_token = await self._ensure_hermes_token(probe_port)

        def _sse_thread(port: int) -> None:
            url = f"http://localhost:{port}/v1/runs/{run_id}/events"
            try:
                headers: Dict[str, str] = {"Accept": "text/event-stream"}
                if session_token:
                    headers["X-Hermes-Session-Token"] = session_token
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=300) as resp:
                    current: Dict[str, Any] = {}
                    for raw_line in resp:
                        line = raw_line.decode("utf-8").rstrip("\r\n")
                        if line.startswith("event:"):
                            current["event"] = line[6:].strip()
                        elif line.startswith("data:"):
                            ds = line[5:].strip()
                            try:
                                current["data"] = json.loads(ds)
                            except Exception:
                                current["data"] = ds
                        elif line == "" and current:
                            asyncio.run_coroutine_threadsafe(q.put(("event", current.copy())), loop)
                            current = {}
                asyncio.run_coroutine_threadsafe(q.put(("done", None)), loop)
            except Exception as exc:
                asyncio.run_coroutine_threadsafe(q.put(("error", str(exc))), loop)

        # Use cached working port; fall back to first default if none known yet.
        sse_port = self._hermes_api_port or _HERMES_API_PORTS[0]
        t = threading.Thread(target=_sse_thread, args=(sse_port,), daemon=True)
        t.start()
        started = True

        if not started:
            await self._send_run_event(run_id, "run.error", {"message": "no hermes port reachable"}, done=True)
            self._active_run_tasks.pop(run_id, None)
            return

        _TERMINAL_EVENTS = {"run.completed", "run.error", "run.stopped", "run.failed"}

        try:
            while True:
                kind, data = await q.get()
                if kind == "done":
                    await self._send_run_event(run_id, "run.completed", {}, done=True)
                    asyncio.ensure_future(
                        self._send_push_notification(
                            title="Run complete",
                            body="Agent run finished.",
                            data={"screen": "agent", "tab": "runs", "run_id": run_id},
                        )
                    )
                    break
                elif kind == "error":
                    await self._send_run_event(run_id, "run.error", {"message": str(data)}, done=True)
                    asyncio.ensure_future(
                        self._send_push_notification(
                            title="Run failed",
                            body=str(data),
                            data={"screen": "agent", "tab": "runs", "run_id": run_id},
                        )
                    )
                    break
                elif kind == "event":
                    event_type = data.get("event", "unknown")
                    event_data = data.get("data", {})
                    is_terminal = event_type in _TERMINAL_EVENTS
                    # approval.request — notify immediately so user can act.
                    if event_type == "approval.request":
                        asyncio.ensure_future(
                            self._send_push_notification(
                                title="Approval required",
                                body=str(event_data.get("description", "Agent needs your approval.")),
                                data={"screen": "agent", "tab": "approvals", "run_id": run_id},
                            )
                        )
                    await self._send_run_event(run_id, event_type, event_data, done=is_terminal)
                    if is_terminal:
                        break
        except asyncio.CancelledError:
            await self._send_run_event(run_id, "run.stopped", {}, done=True)
        finally:
            self._active_run_tasks.pop(run_id, None)

    async def _send_rpc_response(
        self,
        rpc_id: str,
        ok: bool,
        data: Any = None,
        error: Optional[str] = None,
    ) -> None:
        if not self._ws:
            logger.warning("[hermes_bridge] rpc response dropped — ws not connected")
            return
        rpc_payload: Dict[str, Any] = {"id": rpc_id, "ok": ok}
        if ok:
            rpc_payload["data"] = data
        else:
            rpc_payload["error"] = error
        frame = seal(
            self._profile_id,
            "out",
            {"role": "rpc.response", "content": "", "rpc": rpc_payload},
            self._psk,
        )
        # Synchronous RPC: tag the response with a plaintext correlation id so the
        # relay can match it to the waiting POST and return it in the HTTP body —
        # instead of broadcasting over the lossy :out stream. The sealed frame
        # (and PSK content) stay encrypted; only the opaque rpc id is exposed.
        envelope = json.dumps({"type": "rpc", "rpc_id": rpc_id, "frame": frame})
        try:
            await self._ws.send(envelope)
        except ConnectionClosed as exc:
            logger.warning("[hermes_bridge] rpc response send failed: %s", exc)


# ------------------------------------------------------------------
# Registration
# ------------------------------------------------------------------

def _check_requirements() -> bool:
    return bool(
        os.getenv("HERMES_BRIDGE_RELAY_URL") and os.getenv("HERMES_BRIDGE_PROFILE_ID")
    )


def register(ctx) -> None:
    ctx.register_platform(
        name="hermes_bridge",
        label="Hermes Bridge",
        adapter_factory=lambda config: HermesBridgeAdapter(config),
        check_fn=_check_requirements,
        required_env=["HERMES_BRIDGE_RELAY_URL", "HERMES_BRIDGE_PROFILE_ID"],
        install_hint="pip install websockets pynacl",
        emoji="📱",
        allowed_users_env="HERMES_BRIDGE_ALLOWED_USERS",
        allow_all_env="HERMES_BRIDGE_ALLOW_ALL",
    )
