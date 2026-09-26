#!/usr/bin/env python3
"""Pair this laptop, and a phone, with the HermLink relay.

Run it once after installing the plugin:

    python3 ~/.hermes/plugins/hermes_bridge/pair.py
    python3 ~/.hermes/plugins/hermes_bridge/pair.py --verbose

First run provisions a self-serve profile + laptop API key, writes them to
``~/.hermes/.env``, authorizes the adapter's sender with Hermes, generates the
end-to-end PSK at ``~/.hermes/psk``, and prints a QR holding ``{token, psk}``. Later runs reuse that profile and mint a
fresh phone invite — run it again whenever an invite expires or a second phone
needs pairing.

Pass ``--verbose`` to print the complete provision response, credentials, PSK,
and exact QR payload for troubleshooting or manual entry. These values are
sensitive and are hidden by default.

The PSK never leaves this machine except through the QR you scan; the relay
never sees it.

Standard library only, plus ``qrcode`` for the terminal QR — declared in
plugin.yaml. Hermes 0.21+ prepares those dependencies after consent and
selects the managed environment through its launcher and bootstrap. Older
installs still keep them in the Hermes venv. This script re-execs onto
whichever of those is installed, so ``python3 pair.py`` works either way.
"""

import binascii
import json
import os
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# The port list belongs to local_api.py, which owns everything about Hermes'
# localhost API — importing it keeps this script from carrying a second copy
# that can drift. Both spellings are needed: pair.py is documented as a script
# (`python3 ~/.hermes/plugins/hermes_bridge/pair.py`, no package context) and
# imported as a package module by its tests.
try:
    from .local_api import DASHBOARD_PORTS
except ImportError:
    from local_api import DASHBOARD_PORTS

DEFAULT_RELAY = "https://herelay.appcenter.ro"
ENV_KEYS = (
    "HERMES_BRIDGE_RELAY_URL",
    "HERMES_BRIDGE_PROFILE_ID",
    "HERMES_BRIDGE_API_KEY",
    "HERMES_BRIDGE_ALLOWED_USERS",
    "HERMES_BRIDGE_HOME_CHANNEL",
    # Only ever set by hand — the escape hatch for a dashboard on a port the
    # adapter's psutil discovery cannot see. Read here so the readiness check
    # probes the same port the adapter will.
    "HERMES_BRIDGE_API_PORT",
)
# Every inbound frame reports this one synthetic user id (adapter.py's two
# build_source calls) — one phone or five, they are all "mobile".
ADAPTER_USER_ID = "mobile"
# Readiness severities. WARN exists because one check is genuinely advisory
# (the local REST API is started later, by the gateway) and reporting it as OK
# put a false "OK" in front of a missing thing to keep --check's exit code
# honest. Only FAIL votes on the exit code.
OK, WARN, FAIL = "OK", "WARN", "FAIL"
_REEXEC_FLAG = "HERMES_BRIDGE_PAIR_REEXEC"


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def read_env(env_file: Path) -> dict:
    """Parse ~/.hermes/.env well enough to find our three keys."""
    values = {}
    if not env_file.exists():
        return values
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() in ENV_KEYS:
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def to_ws(url: str) -> str:
    return url.replace("https:", "wss:", 1).replace("http:", "ws:", 1)


def to_http(url: str) -> str:
    return url.replace("wss:", "https:", 1).replace("ws:", "http:", 1)


def post(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:200]
        die(f"relay returned {exc.code}: {body}")
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        die(f"relay unreachable: {exc}")


def load_or_create_psk(psk_file: Path) -> str:
    """Return the 32-byte PSK as hex, creating it on first run."""
    if psk_file.exists():
        psk = psk_file.read_bytes()
        if len(psk) != 32:
            die(f"{psk_file} is {len(psk)} bytes, expected 32 — delete it to regenerate")
    else:
        psk = os.urandom(32)
        psk_file.write_bytes(psk)
        psk_file.chmod(0o600)
        print(f"Generated E2E PSK → {psk_file} (chmod 600)")
    return binascii.hexlify(psk).decode()


# Published by current Hermes installs. Bootstrap, not this script, selects
# the managed dependency environment — its directory changes between generations.
_LAUNCHER = Path("hermes-agent") / ".hermes" / "bin" / "hermes"
_LEGACY_PYTHON = Path("hermes-agent") / "venv" / "bin" / "python"
_BOOTSTRAP_MARKER = "import hermes_bootstrap;"
_MODERN_DEPS = "hermes plugins enable hermes_bridge — accept dependency preparation"
_LEGACY_PYNACL = '~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7"'
_LEGACY_QR = '~/.hermes/hermes-agent/venv/bin/pip install "qrcode>=7.4,<8"'


def _parse_runtime_command(stdout: str) -> Optional[list[str]]:
    """Take the JSON argv from ``hermes --print-runtime-command``."""
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if not stripped.startswith("["):
            continue
        try:
            command = json.loads(stripped)
        except json.JSONDecodeError:
            return None
        if isinstance(command, list) and command and all(isinstance(part, str) for part in command):
            return command
        return None
    return None


def _rewrite_bootstrap_entry(command: list[str], script: str) -> Optional[list[str]]:
    """Keep the launcher's bootstrap, then run this script instead of the CLI.

    The printed command imports ``hermes_bootstrap``, which activates the
    managed environment. Replacing only the entry point leaves that selection
    — and the caller's arguments — intact.

    ``runpy.run_path`` on a file does not put that file's directory on
    ``sys.path`` the way ``python3 pair.py`` does, so the sibling import of
    ``local_api`` would fail without the insert.
    """
    rewritten: list[str] = []
    replaced = False
    script_dir = os.path.dirname(script)
    for part in command:
        if not replaced and _BOOTSTRAP_MARKER in part:
            head, _, _tail = part.partition(_BOOTSTRAP_MARKER)
            part = (
                head
                + _BOOTSTRAP_MARKER
                + f" sys.path.insert(0, {script_dir!r});"
                + f" sys.argv = [{script!r}, *sys.argv[1:]];"
                + f" runpy.run_path({script!r}, run_name='__main__')"
            )
            replaced = True
        rewritten.append(part)
    if not replaced:
        return None
    return rewritten


def _modern_pair_command(hermes_home: Path) -> Optional[list[str]]:
    """Ask the installed launcher for a bootstrap command that runs this script.

    Returns None when this home has no published launcher, or the launcher
    predates ``--print-runtime-command``.
    """
    launcher = hermes_home / _LAUNCHER
    if not launcher.is_file() or not os.access(launcher, os.X_OK):
        return None
    script = os.path.abspath(__file__)
    try:
        completed = subprocess.run(
            [str(launcher), "--print-runtime-command", "--", *sys.argv[1:]],
            capture_output=True,
            text=True,
            timeout=15,
            env={**os.environ, "HERMES_HOME": str(hermes_home)},
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    command = _parse_runtime_command(completed.stdout)
    if command is None:
        return None
    return _rewrite_bootstrap_entry(command, script)


def _legacy_venv_command(hermes_home: Path) -> Optional[list[str]]:
    """Older supported installs keep plugin dependencies in hermes-agent/venv."""
    python = hermes_home / _LEGACY_PYTHON
    if not python.is_file():
        return None
    return [str(python), os.path.abspath(__file__), *sys.argv[1:]]


def reexec_under_hermes_python(hermes_home: Path) -> None:
    """Re-run this script under the interpreter that can import plugin dependencies.

    Current Hermes publishes a launcher whose bootstrap selects the managed
    dependency environment. That directory is not a stable path, so this asks
    the launcher (``--print-runtime-command``) rather than naming a generation.
    Homes without that launcher still fall back to ``hermes-agent/venv``.

    Two environments can share one Python binary through symlinks. Comparing
    ``Path.resolve()`` would treat them as the same environment and skip the
    relaunch, so the only loop brake is ``HERMES_BRIDGE_PAIR_REEXEC``.
    ``HERMES_HOME`` and the original arguments, including ``--check``, are
    passed through.
    """
    if os.environ.get(_REEXEC_FLAG):
        return
    for command in (_modern_pair_command(hermes_home), _legacy_venv_command(hermes_home)):
        if not command:
            continue
        os.environ["HERMES_HOME"] = str(hermes_home)
        os.environ[_REEXEC_FLAG] = "1"
        try:
            os.execv(command[0], command)
        except OSError:
            os.environ.pop(_REEXEC_FLAG, None)
            continue
        # execv replaces this process. A test double returns instead, and the
        # legacy candidate must not run after a successful handoff.
        return


def authorize_adapter_user(env_file: Path, env: dict) -> None:
    """Allowlist the adapter's user id for Hermes' authorization gate.

    Hermes default-denies a sender when no allowlist is configured for the
    platform (gateway/authz_mixin.py — fail-open is forbidden by its
    SECURITY.md), and answers the first message with "I don't recognize you
    yet" plus a pairing code for the owner to approve. That gate is redundant
    here and its failure mode is baffling: reaching this adapter at all means
    holding the laptop's api_key AND the PSK, and the phone that just scanned
    the QR was authorized by the person running this script.

    So write the allowlist entry that says so. Scoped to this platform's own
    env var, never GATEWAY_ALLOWED_USERS, and left alone if the operator has
    set their own value.
    """
    configured = env.get("HERMES_BRIDGE_ALLOWED_USERS", "")
    if configured:
        if ADAPTER_USER_ID not in [u.strip() for u in configured.split(",")]:
            print(
                f"warning: HERMES_BRIDGE_ALLOWED_USERS={configured} does not include "
                f"'{ADAPTER_USER_ID}' — Hermes will not recognize the phone. Add it, "
                "or approve the pairing code Hermes offers on the first message."
            )
        return
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write(f"HERMES_BRIDGE_ALLOWED_USERS={ADAPTER_USER_ID}\n")
    print(f"Authorized the bridge's sender in {env_file} (HERMES_BRIDGE_ALLOWED_USERS)")


def set_home_channel(env_file: Path, env: dict, profile_id: str) -> None:
    """Point Hermes' cron/notification delivery at this phone.

    A home channel is where Hermes sends cron results and cross-platform
    messages. Unset, it nags on the first message ("Type /sethome...") and
    `deliver=hermes_bridge` cron jobs have nowhere to go. There is nothing to
    choose here — a profile has exactly one chat and its id is the profile id
    — so set it rather than making the user answer a question with one
    possible answer. `/sethome` in the app still overrides it.
    """
    if env.get("HERMES_BRIDGE_HOME_CHANNEL"):
        return
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write(f"HERMES_BRIDGE_HOME_CHANNEL={profile_id}\n")
    print(f"Set this chat as the home channel for cron results and notifications")


def dashboard_port(env: dict) -> Optional[int]:
    """Return a localhost port that accepts a connection, or None.

    Chat only needs the gateway, but every Agent-tab screen (sessions, skills,
    cron, runs, usage, memory) is an RPC the adapter proxies to Hermes' local
    dashboard REST API — a SEPARATE process. The adapter starts one itself when
    nothing serves it (adapter.py `_ensure_local_api`), so this reports whether
    that has happened yet rather than asking the operator to do it.

    A TCP connect is all this can honestly check: the routes are session-token
    gated, and the token is scraped out of the dashboard's own HTML at request
    time. Something listening on a Hermes port is enough of a signal.
    """
    override = env.get("HERMES_BRIDGE_API_PORT", "").strip()
    ports = ([int(override)] if override.isdigit() else []) + list(DASHBOARD_PORTS)
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return port
        except OSError:
            continue
    return None


def readiness_report(hermes_home: Path, env: dict) -> list:
    """Check the things that only fail at first use, and say how to fix them.

    Every one of these was found by a user chatting to a freshly paired phone
    and getting silence, an unscannable payload, or a pairing code — none are
    visible to the plugin's tests, to `hermes plugins doctor`, or to the
    install-time security scan. Checking them here costs milliseconds and moves
    the discovery from "my agent is broken" to a line of terminal output.
    """
    checks: list[tuple[str, str, str]] = []

    try:
        import nacl  # noqa: F401,PLC0415

        checks.append((OK, "PyNaCl — messages can be encrypted", ""))
    except ImportError:
        checks.append((
            FAIL,
            "PyNaCl missing — the adapter will not load",
            f"{_MODERN_DEPS}; older installs: {_LEGACY_PYNACL}",
        ))

    try:
        import qrcode  # noqa: F401,PLC0415

        checks.append((OK, "qrcode — pairing QR renders", ""))
    except ImportError:
        checks.append((
            FAIL,
            "qrcode missing — pairing falls back to an unscannable payload",
            f"{_MODERN_DEPS}; older installs: {_LEGACY_QR}",
        ))

    if env.get("HERMES_BRIDGE_HOME_CHANNEL"):
        checks.append((OK, "home channel set — cron results reach the phone", ""))
    else:
        checks.append((
            FAIL,
            "no home channel — cron results have nowhere to go, and Hermes will ask",
            "re-run this script, or send /sethome from the app",
        ))

    # WARN, never FAIL: the gateway starts this itself (adapter.py's LocalApi),
    # so at the moment this script runs it is normally, correctly, absent.
    port = dashboard_port(env)
    checks.append(
        (OK, f"local REST API on :{port} — the Agent tab can load", "")
        if port
        else (
            WARN,
            "no local REST API yet — the gateway starts one for the Agent tab",
            "hermes gateway restart",
        )
    )

    allowed = [u.strip() for u in env.get("HERMES_BRIDGE_ALLOWED_USERS", "").split(",")]
    if ADAPTER_USER_ID in allowed:
        checks.append((OK, "sender allowlisted — Hermes will accept the phone", ""))
    else:
        checks.append((
            FAIL,
            "sender not allowlisted — Hermes answers the first message with a pairing code",
            f"echo HERMES_BRIDGE_ALLOWED_USERS={ADAPTER_USER_ID} >> {hermes_home}/.env",
        ))

    enabled = _plugin_enabled(hermes_home)
    if enabled is None:
        checks.append((WARN, "plugin enablement — not checked (no readable config.yaml)", ""))
    elif enabled:
        checks.append((OK, "plugin enabled in config.yaml", ""))
    else:
        checks.append((
            FAIL,
            "plugin not enabled — Hermes skips it silently at startup",
            "hermes plugins enable hermes_bridge",
        ))

    print()
    print("Readiness:")
    for status, label, fix in checks:
        print(f"  {status:<4} {label}")
        if fix:
            print(f"       fix: {fix}")
    return checks


def is_ready(checks: list) -> bool:
    """True when nothing FAILed. WARN lines are reported, never fatal."""
    return not any(status == FAIL for status, _, _ in checks)


def _plugin_enabled(hermes_home: Path) -> Optional[bool]:
    """Is this plugin in config.yaml's plugins.enabled? None = cannot tell.

    A user plugin that is installed but not listed there is skipped without a
    word at gateway startup — the quietest way this can be broken.

    Parsed by hand rather than with PyYAML: this script is stdlib-only so it
    runs under any interpreter, and the shape being read is a list of plain
    strings.
    # ponytail: handles the block and inline-list forms of plugins.enabled,
    # not anchors/multi-doc YAML; returns None (unknown, reported as
    # "not checked") rather than guessing if it cannot find the key.
    """
    config = hermes_home / "config.yaml"
    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    in_plugins = False
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            in_plugins = line.split(":", 1)[0].strip() == "plugins"
            continue
        if not in_plugins or line.strip().split(":", 1)[0].strip() != "enabled":
            continue

        _, _, inline = line.partition(":")
        inline = inline.strip()
        if inline.startswith("["):
            entries = inline.strip("[]").split(",")
        else:
            entries = []
            for follow in lines[i + 1:]:
                stripped = follow.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith("- "):
                    break
                entries.append(stripped[2:])
        return any(
            e.strip().strip("\"'").rsplit("/", 1)[-1] == "hermes_bridge" for e in entries
        )
    return None


def print_qr(payload: str) -> None:
    try:
        import qrcode  # noqa: PLC0415 — optional, absent on a bare Hermes install
    except ImportError:
        print("  No QR: `qrcode` is missing from the Hermes dependency environment.")
        print(f"  {_MODERN_DEPS}.")
        print(f"  Older installs: {_LEGACY_QR}")
        print(f"  payload (manual entry): {payload}")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def print_verbose_pairing_data(response: dict, profile_id: str, api_key: str,
                               psk_hex: str, payload: str) -> None:
    """Print every pairing value for troubleshooting and manual entry.

    These values are deliberately omitted from the normal output because the
    API key and PSK grant access to the paired bridge.  ``--verbose`` is an
    explicit opt-in for operators who need to inspect or recover the payload.
    """
    print("\nVerbose pairing data (sensitive — do not share):")
    print(f"  provision response: {json.dumps(response, sort_keys=True)}")
    print(f"  profile_id: {profile_id}")
    print(f"  api_key: {api_key}")
    print(f"  pairing code: {response.get('token')}")
    print(f"  psk: {psk_hex}")
    print(f"  payload: {payload}")


def main() -> None:
    hermes_home = Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
    if not hermes_home.is_dir():
        die(f"{hermes_home} not found — is Hermes installed?")
    reexec_under_hermes_python(hermes_home)
    verbose = "--verbose" in sys.argv[1:]
    env_file = hermes_home / ".env"
    env = read_env(env_file)

    # `pair.py --check` diagnoses an existing install without minting an
    # invite: same checks, no side effects, safe to tell a user to run.
    if "--check" in sys.argv[1:]:
        sys.exit(0 if is_ready(readiness_report(hermes_home, env)) else 1)

    relay_http = to_http(env.get("HERMES_BRIDGE_RELAY_URL") or DEFAULT_RELAY)
    if not env.get("HERMES_BRIDGE_RELAY_URL") and sys.stdin.isatty():
        answer = input(f"Relay URL [{relay_http}]: ").strip()
        if answer:
            relay_http = to_http(answer)

    profile_id = env.get("HERMES_BRIDGE_PROFILE_ID")
    api_key = env.get("HERMES_BRIDGE_API_KEY")
    repairing = bool(profile_id and api_key)

    if repairing:
        print(f"Minting a fresh phone invite for {profile_id} ...")
        response = post(f"{relay_http}/api/pair/provision", {"profile_id": profile_id})
    else:
        print(f"Provisioning a new profile via {relay_http} ...")
        response = post(f"{relay_http}/api/pair/provision", {})
        profile_id = response.get("profile_id")
        api_key = response.get("api_key")
        if not profile_id or not api_key:
            die(f"unexpected provision response: {response}")
        with env_file.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\nHERMES_BRIDGE_RELAY_URL={to_ws(relay_http)}"
                f"\nHERMES_BRIDGE_PROFILE_ID={profile_id}"
                f"\nHERMES_BRIDGE_API_KEY={api_key}\n"
            )
        print(f"Provisioned {profile_id} — credentials written to {env_file}")

    token = response.get("token")
    if not token:
        die(f"no invite token in response: {response}")

    authorize_adapter_user(env_file, env)
    set_home_channel(env_file, env, profile_id)
    psk_hex = load_or_create_psk(hermes_home / "psk")
    payload = json.dumps({"token": token, "psk": psk_hex}, separators=(",", ":"))

    if verbose:
        print_verbose_pairing_data(response, profile_id, api_key, psk_hex, payload)

    print()
    print(f"Pairing code: {token} — single use, expires {response.get('expires_at', 'in 1 hour')}")
    print("Open HermLink on your phone → Pair new device → scan:")
    print()
    print_qr(payload)
    print()
    print("The QR carries the invite AND the encryption key — keep it on screen only until scanned.")

    if is_ready(readiness_report(hermes_home, read_env(env_file))):
        print()
        print("All set. Apply it:  hermes gateway restart")
    else:
        print()
        print("Fix the FAIL lines above, then:  hermes gateway restart")


if __name__ == "__main__":
    main()
