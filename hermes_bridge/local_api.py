"""Hermes' local REST API: where it listens, how to authenticate, how to start it.

Everything the app's Agent screen shows (sessions, skills, cron, runs, usage,
memory) is an RPC the adapter proxies to Hermes' own localhost HTTP API. That
API is not part of the gateway: it lives in the `hermes dashboard` /
`hermes serve` process, which the gateway neither starts nor supervises, and
Hermes ships no autostart setting for it (`dashboard.*` in
cli-config.yaml.example covers auth and OAuth only).

So talking to it needs four things — find the port, get a session token, make
the request, and make sure something is running at all — and all four were
previously inlined in adapter.py, where they had nothing to do with the relay
socket or the crypto around it. They live here instead, as one object with one
piece of state: the port that last answered.

Two localhost services are in play and neither serves the other's routes:

  * the dashboard (default 9119) serves ``/api/*`` — everything here
  * the api_server platform (8642) serves ``/v1/*`` — runs and run approvals

Hence two orderings: ``dashboard_candidates()`` for "is the Agent screen's API
up, and should I start one", and ``ports_to_probe()`` — candidates plus 8642 —
for requests, which may legitimately land on either.

Standard library only, plus psutil when the Hermes venv has it, so pair.py can
import the constants and the probe without dragging in `gateway`.
"""

import asyncio
import json
import logging
import os
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

#: Dashboard defaults, tried in order. `hermes dashboard --port 0` binds an
#: ephemeral port instead, which is what discover_dashboard_ports() is for.
DASHBOARD_PORTS = (9119, 9120)
#: The api_server platform's port — `/v1/runs` and run approvals only.
#:
#: Enabling that platform SHOULD be safe again (issue 62) — UNVERIFIED on a
#: live gateway. The adapter no longer squats on `Platform.API_SERVER`, so
#: core's own api_server platform can hold that value without one adapter
#: overwriting the other in the gateway's registry. That is read off the
#: registry code, not observed, and the last confident claim about this exact
#: config silently ate every reply. Flip it and send one message before
#: relying on it.
API_SERVER_PORT = 8642
SESSION_HEADER = "X-Hermes-Session-Token"
_REQUEST_TIMEOUT_S = 5
_CONNECT_TIMEOUT_S = 0.3
#: How often the supervisor re-checks that the API it started is still alive.
#: The dashboard is a plain process: it dies with its terminal, and a crash
#: would otherwise leave every Agent tab dead until the gateway restarted.
_SUPERVISE_INTERVAL_S = 30.0


def discover_dashboard_ports() -> List[int]:
    """Return listening ports of running dashboard/serve processes via psutil.

    Priority:
      1. Main dashboard (no --profile flag) — matches this adapter's context.
      2. Any other dashboard processes (profile-specific) as fallbacks.

    Returns empty list if psutil is unavailable or nothing is running.
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
                # `serve` counts as well as `dashboard`: it is the same backend
                # with the SPA switched off, it serves the same /api/* routes,
                # and it is what the Desktop app (and _ensure below) spawns.
                if "hermes" not in cmd_str:
                    continue
                if "dashboard" not in cmd_str and "serve" not in cmd_str:
                    continue
                is_profile = "--profile" in cmd_str
                # `Process.connections` is a deprecated shim for
                # `net_connections` in psutil 6+ (core pins 7.2.2) and is
                # slated for removal — when it goes, the AttributeError would
                # land in the outer catch and silently return no ports at all.
                list_conns = getattr(proc, "net_connections", None) or proc.connections
                for conn in list_conns("inet"):
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


def _dedupe(ports: List[int]) -> List[int]:
    seen = set()
    ordered = []
    for port in ports:
        if port not in seen:
            seen.add(port)
            ordered.append(port)
    return ordered


class LocalApi:
    """Hermes' localhost REST API, as seen from inside the gateway process."""

    def __init__(self) -> None:
        #: Port that last answered. Cached so a request skips the probe loop,
        #: cleared whenever that port stops behaving like the right service.
        self.port: Optional[int] = None
        #: Session tokens BY PORT: the dashboard mints one per process
        #: (`secrets.token_urlsafe(32)` in hermes_cli/web_server.py), so a
        #: token scraped from one is invalid on another — and
        #: discover_dashboard_ports() deliberately returns several.
        self._tokens: Dict[int, str] = {}
        #: The backend this object started, if it had to. None when an
        #: operator runs their own.
        self._proc: Optional[subprocess.Popen] = None
        self._supervisor: Optional[asyncio.Task] = None

    # ── where it listens ────────────────────────────────────────────────

    def dashboard_candidates(self) -> List[int]:
        """Ports that might serve ``/api/*``, in priority order.

        0. HERMES_BRIDGE_API_PORT — escape hatch for a dashboard psutil
           discovery cannot see (psutil missing, AccessDenied, or a command
           line that looks like neither `dashboard` nor `serve`). Without it,
           such a user gets `hermes_offline` on every Agent tab from a
           dashboard that is in fact running, with nothing to change.
        1. Cached known-good port (fast path, avoids re-probing).
        2. Live psutil discovery (handles --port 0 / auto-assigned ports).
        3. Static defaults.
        """
        override = os.getenv("HERMES_BRIDGE_API_PORT", "").strip()
        candidates: List[int] = [int(override)] if override.isdigit() else []
        if self.port is not None:
            candidates.append(self.port)
        return _dedupe(candidates + discover_dashboard_ports() + list(DASHBOARD_PORTS))

    def ports_to_probe(self) -> List[int]:
        """Candidates for a request — the dashboard's, plus api_server's."""
        return _dedupe(self.dashboard_candidates() + [API_SERVER_PORT])

    def listening(self) -> Optional[int]:
        """First dashboard port accepting a connection, or None. Blocking.

        Deliberately not ports_to_probe(): a listener on api_server's 8642
        serves `/v1/*` and none of the routes the Agent screen needs, so it
        must not read as "the API is up".
        """
        for port in self.dashboard_candidates():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=_CONNECT_TIMEOUT_S):
                    return port
            except OSError:
                continue
        return None

    # ── keeping one alive ───────────────────────────────────────────────

    async def start(self) -> None:
        """Ensure an API is up, then keep checking. Idempotent."""
        await self._ensure()
        if self._supervisor is None or self._supervisor.done():
            self._supervisor = asyncio.ensure_future(self._supervise())

    async def stop(self) -> None:
        """Stop supervising and terminate the backend we started, if any."""
        if self._supervisor is not None:
            self._supervisor.cancel()
            try:
                await self._supervisor
            except asyncio.CancelledError:
                pass
            self._supervisor = None
        # Only ever the backend WE spawned; an operator's own dashboard has no
        # handle here and is left alone. HERMES_PARENT_PID's watchdog is the
        # backstop if this path is skipped (hard kill, crash).
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
            self._proc = None

    async def _supervise(self) -> None:
        while True:
            await asyncio.sleep(_SUPERVISE_INTERVAL_S)
            await self._ensure()

    async def _ensure(self) -> None:
        """Start Hermes' headless backend when nothing serves ``/api/*``.

        Leaving this to the operator put the Agent screen one closed terminal
        away from broken: a hand-started dashboard dies with its shell or SSH
        session (observed as `rpc sessions.list failed: URLError — [Errno 61]
        Connection refused` hours after a working test).

        `serve` is the lean surface: identical `/api/*` routes with no SPA and
        no UI build, and its root still carries `__HERMES_SESSION_TOKEN__` for
        token() to scrape. Spawned with HERMES_PARENT_PID set, which arms
        Hermes' OWN parent-death watchdog
        (`web_server._start_parent_death_watchdog`) so the backend exits when
        this gateway does — no service file, no orphan.

        A no-op while something answers, so an operator's own dashboard keeps
        serving. `HERMES_BRIDGE_START_API=0` opts out entirely.
        """
        if os.getenv("HERMES_BRIDGE_START_API", "1").strip().lower() in ("0", "false", "no"):
            return
        if self._proc is not None and self._proc.poll() is None:
            return

        loop = asyncio.get_event_loop()
        live = await loop.run_in_executor(None, self.listening)
        if live is not None:
            logger.debug("[hermes_bridge] local API already on :%d — not starting one", live)
            return

        port = DASHBOARD_PORTS[0]
        log_path = Path(os.getenv("HERMES_HOME") or Path.home() / ".hermes") / "logs"
        log_path = log_path / "hermes-bridge-api.log"
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # The child dups this fd, so the parent closes its own copy as
            # soon as the spawn returns (or fails).
            with open(log_path, "a", buffering=1) as handle:
                self._proc = subprocess.Popen(  # noqa: S603
                    [
                        sys.executable,
                        "-m",
                        "hermes_cli.main",
                        "serve",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                    ],
                    stdout=handle,
                    stderr=subprocess.STDOUT,
                    env={**os.environ, "HERMES_PARENT_PID": str(os.getpid())},
                )
        except Exception as exc:
            # Not fatal: chat does not need this API, and the Agent screen's
            # own error names the fix. Never block the relay connection.
            logger.warning(
                "[hermes_bridge] could not start Hermes' local API (%s: %s) — the "
                "Agent screen will report hermes_offline until `hermes dashboard` runs",
                type(exc).__name__,
                exc,
            )
            self._proc = None
            return
        logger.info(
            "[hermes_bridge] started Hermes' local API for the Agent screen "
            "(hermes serve on :%d, pid %d) — log: %s",
            port,
            self._proc.pid,
            log_path,
        )

    # ── authenticating ──────────────────────────────────────────────────

    def _fetch_session_token(self, port: int) -> Optional[str]:
        """Extract the session token from the served HTML.

        Tries multiple patterns to handle different Hermes versions:
          - 0.16+:  SESSION_TOKEN__="<token>"
          - older:  SESSION_TOKEN__ = "<token>"  (spaces around =)
          - JSON:   "sessionToken":"<token>"
        """
        try:
            with urllib.request.urlopen(
                f"http://localhost:{port}/", timeout=_REQUEST_TIMEOUT_S
            ) as r:
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

    async def token(self, port: int) -> Optional[str]:
        """Cached token, or bootstrap one from the env var / served HTML.

        Priority:
          1. In-process cache (set once per gateway lifetime, cleared on 401)
          2. HERMES_SESSION_TOKEN env var (manual override — useful when HTML
             extraction fails on a Hermes version that changed the format)
          3. Scrape from the served HTML
        """
        cached = self._tokens.get(port)
        if cached:
            return cached
        env_token = os.getenv("HERMES_SESSION_TOKEN")
        if env_token:
            self._tokens[port] = env_token
            return env_token
        loop = asyncio.get_event_loop()
        token = await loop.run_in_executor(None, self._fetch_session_token, port)
        if token:
            self._tokens[port] = token
        return token

    # ── requesting ──────────────────────────────────────────────────────

    async def request(
        self,
        path: str,
        method: str = "GET",
        body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Call ``path`` on whichever port answers: probe, cache, 401 refresh."""
        loop = asyncio.get_event_loop()
        body_bytes = (
            (json.dumps(body).encode() if body is not None else b"{}")
            if method != "GET"
            else None
        )
        last_exc: Optional[Exception] = None

        for port in self.ports_to_probe():
            url = f"http://localhost:{port}{path}"
            token = await self.token(port)

            try:
                result = await loop.run_in_executor(
                    None, _send, url, token, method, body_bytes
                )
                # Cache this port so future calls skip the probe loop.
                self.port = port
                return result
            except urllib.error.HTTPError as exc:
                if exc.code not in (401, 404):
                    # A live Hermes answered — this IS the working port; the
                    # request itself was rejected (validation 4xx / server
                    # 5xx). Do NOT keep probing: other ports would just refuse
                    # the connection and bury this error (losing e.g. a cron
                    # schedule-parse 400 detail), and re-sending a POST to them
                    # would replay a non-idempotent request.
                    self.port = port
                    raise
                if exc.code == 404:
                    # 404 means SOMETHING is listening but it does not serve
                    # this route -- i.e. the wrong service, not a bad request.
                    # Treating it as proof of the working port is what pinned
                    # this adapter to the api_server platform on 8642 and made
                    # every Agent-tab RPC fail with a 404 that looked like a
                    # real answer (issue 64). Keep probing instead.
                    last_exc = exc
                    if port == self.port:
                        self.port = None
                    continue
                # 401: token stale — clear THIS port's token and retry once
                # with a freshly extracted one.
                self._tokens.pop(port, None)
                fresh = await self.token(port)
                if fresh and fresh != token:
                    try:
                        result = await loop.run_in_executor(
                            None, _send, url, fresh, method, body_bytes
                        )
                        self.port = port
                        return result
                    except Exception as e2:
                        last_exc = e2
                else:
                    # Token extraction itself is failing — no point retrying
                    # other ports for auth; but still try them in case one
                    # allows unauthenticated access.
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
                if port == self.port:
                    self.port = None

        raise last_exc or RuntimeError("no hermes api port reachable")

    async def get(self, path: str) -> Any:
        return await self.request(path, method="GET")

    async def post(
        self, path: str, body: Optional[Dict[str, Any]] = None, method: str = "POST"
    ) -> Any:
        return await self.request(path, method=method, body=body)


def _send(url: str, token: Optional[str], method: str, body: Optional[bytes]) -> Any:
    """One blocking HTTP call. Runs in an executor — never on the event loop."""
    headers: Dict[str, str] = {}
    if token:
        headers[SESSION_HEADER] = token
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    req = urllib.request.Request(url, method=method, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT_S) as resp:
        raw = resp.read()
        return json.loads(raw.decode()) if raw else {"ok": True}
