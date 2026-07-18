import asyncio
import hashlib
import json
import logging
import os
import random
import re
import threading
import urllib.request
import uuid
from typing import Any, Dict, List, Optional

import websockets
from websockets.exceptions import ConnectionClosed

from gateway.platforms.base import BasePlatformAdapter, SendResult, MessageEvent, Platform

from .crypto import load_psk, open_frame, seal

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
        try:
            payload: Dict[str, Any] = {"role": "assistant", "content": content, "msg_id": msg_id}
            if is_unsolicited:
                payload["unsolicited"] = True
            frame = seal(self._profile_id, "out", payload, self._psk)
            await self._ws.send(frame)
            result = SendResult(success=True)
        except ConnectionClosed as exc:
            # Connection dropped — the supervisor loop will reconnect. Still
            # attempt durable enqueue below so the message isn't lost.
            result = SendResult(success=False, error=str(exc), retryable=True)
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

        # Durable enqueue + push, best-effort: the live frame (if it sent) already
        # reached a connected phone; this just makes the message recoverable for
        # an offline/closed one. Never called for `_send_run_event` streaming
        # frames — this is what makes send() the semantic authority on "a real
        # message worth persisting + notifying".
        await self._enqueue_durable(msg_id, frame)
        return result

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {
            "id": chat_id,
            "platform": "hermes_bridge",
            "profile_id": self._profile_id,
        }

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
                    event = MessageEvent(
                        text=payload["content"],
                        source=self.build_source(
                            chat_id=self._profile_id,
                            user_id="mobile",
                        ),
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
        """Dispatch an rpc.request frame and send the response over WS."""
        rpc = payload.get("rpc") or {}
        rpc_id = rpc.get("id", "")
        method = rpc.get("method", "")

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

        try:
            if method == "sessions.list":
                data = await self._hermes_get("/api/sessions")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "sessions.messages":
                params = rpc.get("params") or {}
                session_id = str(params.get("id", "")).strip()
                if not session_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_session_id")
                    return
                data = await self._hermes_get(f"/api/sessions/{session_id}/messages")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "sessions.switch":
                # Hermes has no REST endpoint to switch active session context.
                # Navigation proceeds on the mobile side — just ack.
                await self._send_rpc_response(rpc_id, ok=True, data={"switched": True})
            elif method == "sessions.delete":
                params = rpc.get("params") or {}
                session_id = str(params.get("id", "")).strip()
                if not session_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_session_id")
                    return
                await self._hermes_request(f"/api/sessions/{session_id}", method="DELETE")
                await self._send_rpc_response(rpc_id, ok=True, data={"deleted": True})
            elif method == "skills.list":
                data = await self._hermes_get("/api/skills")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.toggle":
                params = rpc.get("params") or {}
                name = str(params.get("name", "")).strip()
                if not name:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_skill_name")
                    return
                enabled = bool(params.get("enabled"))
                data = await self._hermes_post(
                    "/api/skills/toggle", body={"name": name, "enabled": enabled}, method="PUT"
                )
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "cron.list":
                data = await self._hermes_get("/api/cron/jobs")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "agent.status":
                data = await self._hermes_get("/api/status")
                try:
                    stats = await self._hermes_get("/api/system/stats")
                    if isinstance(data, dict) and isinstance(stats, dict):
                        data = {**data, **stats}
                except Exception:
                    pass
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "usage.get":
                params = rpc.get("params") or {}
                days = params.get("days", 7)
                data = await self._hermes_get(f"/api/analytics/usage?days={days}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method in ("cron.pause", "cron.resume", "cron.trigger"):
                params = rpc.get("params") or {}
                job_id = str(params.get("id", "")).strip()
                if not job_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_job_id")
                    return
                action = method.split(".")[-1]  # pause | resume | trigger
                data = await self._hermes_post(f"/api/cron/jobs/{job_id}/{action}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "runs.start":
                params = rpc.get("params") or {}
                run_data = await self._hermes_post("/v1/runs", body=params)
                run_id = str(run_data.get("run_id") or run_data.get("id") or "").strip()
                if not run_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="no_run_id_in_response")
                    return
                await self._send_rpc_response(rpc_id, ok=True, data={"run_id": run_id})
                task = asyncio.ensure_future(self._stream_run_events(run_id))
                self._active_run_tasks[run_id] = task
            elif method == "runs.stop":
                params = rpc.get("params") or {}
                run_id = str(params.get("run_id", "")).strip()
                task = self._active_run_tasks.pop(run_id, None)
                if task:
                    task.cancel()
                try:
                    await self._hermes_post(f"/v1/runs/{run_id}/stop")
                except Exception:
                    pass
                await self._send_rpc_response(rpc_id, ok=True, data={"stopped": True})
            elif method == "approval.resolve":
                params = rpc.get("params") or {}
                run_id = str(params.get("run_id", "")).strip()
                approval_id = str(params.get("approval_id", "")).strip()
                decision = str(params.get("decision", "approve")).strip()
                if not run_id or not approval_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_run_id_or_approval_id")
                    return
                data = await self._hermes_post(f"/v1/runs/{run_id}/approval/{approval_id}/{decision}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "memory.list":
                mem_path = os.path.join(os.path.expanduser("~"), ".hermes", "memories", "MEMORY.md")
                memories = []
                try:
                    with open(mem_path, "r", encoding="utf-8") as f:
                        raw = f.read()
                    for entry in raw.split("\n§\n"):
                        content = entry.strip()
                        if content:
                            entry_id = hashlib.sha256(content.encode()).hexdigest()[:16]
                            memories.append({"id": entry_id, "content": content})
                except FileNotFoundError:
                    pass
                await self._send_rpc_response(rpc_id, ok=True, data=memories)
            elif method == "approvals.list":
                data = await self._hermes_get("/v1/approvals")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "memory.delete":
                params = rpc.get("params") or {}
                entry_id = str(params.get("id", "")).strip()
                if not entry_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_id")
                    return
                mem_path = os.path.join(os.path.expanduser("~"), ".hermes", "memories", "MEMORY.md")
                try:
                    with open(mem_path, "r", encoding="utf-8") as f:
                        raw = f.read()
                    entries = [e.strip() for e in raw.split("\n§\n") if e.strip()]
                    kept = [e for e in entries if hashlib.sha256(e.encode()).hexdigest()[:16] != entry_id]
                    with open(mem_path, "w", encoding="utf-8") as f:
                        f.write("\n§\n".join(kept))
                    await self._send_rpc_response(rpc_id, ok=True, data={"deleted": True})
                except FileNotFoundError:
                    await self._send_rpc_response(rpc_id, ok=False, error="memory_file_not_found")
            elif method == "model.options":
                data = await self._hermes_get("/api/model/options")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "agent.set_model":
                params = rpc.get("params") or {}
                scope = str(params.get("scope", "main")).strip() or "main"
                provider = str(params.get("provider", "")).strip()
                model = str(params.get("model", "")).strip()
                if not model:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_model")
                    return
                body = {"scope": scope, "provider": provider, "model": model}
                data = await self._hermes_post("/api/model/set", body=body)
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "sessions.search":
                params = rpc.get("params") or {}
                q = str(params.get("q", "")).strip()
                limit = int(params.get("limit", 20))
                data = await self._hermes_get(f"/api/sessions/search?q={q}&limit={limit}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "sessions.export":
                params = rpc.get("params") or {}
                session_id = str(params.get("id", "")).strip()
                if not session_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_session_id")
                    return
                data = await self._hermes_get(f"/api/sessions/{session_id}/export")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.content":
                params = rpc.get("params") or {}
                name = str(params.get("name", "")).strip()
                if not name:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_skill_name")
                    return
                data = await self._hermes_get(f"/api/skills/content?name={name}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.hub.search":
                params = rpc.get("params") or {}
                q = str(params.get("q", "")).strip()
                limit = int(params.get("limit", 20))
                source = str(params.get("source", "all")).strip() or "all"
                data = await self._hermes_get(
                    f"/api/skills/hub/search?q={q}&limit={limit}&source={source}"
                )
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.hub.install":
                params = rpc.get("params") or {}
                identifier = str(params.get("identifier", "")).strip()
                if not identifier:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_identifier")
                    return
                data = await self._hermes_post("/api/skills/hub/install", body={"identifier": identifier})
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.hub.uninstall":
                params = rpc.get("params") or {}
                name = str(params.get("name", "")).strip()
                if not name:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_skill_name")
                    return
                data = await self._hermes_post("/api/skills/hub/uninstall", body={"name": name})
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "skills.hub.update":
                data = await self._hermes_post("/api/skills/hub/update", body={})
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            elif method == "cron.runs":
                params = rpc.get("params") or {}
                job_id = str(params.get("job_id", "")).strip()
                if not job_id:
                    await self._send_rpc_response(rpc_id, ok=False, error="missing_job_id")
                    return
                limit = int(params.get("limit", 20))
                data = await self._hermes_get(f"/api/cron/jobs/{job_id}/runs?limit={limit}")
                await self._send_rpc_response(rpc_id, ok=True, data=data)
            else:
                await self._send_rpc_response(rpc_id, ok=False, error="method_not_found")
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
                if exc.code == 401:
                    # Token stale — clear and retry once with a freshly extracted token.
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
                else:
                    last_exc = exc
                # If we had a cached port and it returned a non-401 HTTP error, clear
                # the cache so the next call probes all ports again.
                if port == self._hermes_api_port and exc.code not in (401, 403):
                    self._hermes_api_port = None
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
