#!/usr/bin/env python3
"""Pair this laptop, and a phone, with the Hermes Bridge relay.

Run it once after installing the plugin:

    python3 ~/.hermes/plugins/hermes_bridge/pair.py

First run provisions a self-serve profile + laptop API key, writes them to
``~/.hermes/.env``, authorizes the adapter's sender with Hermes, generates the
end-to-end PSK at ``~/.hermes/psk``, and prints a QR holding ``{token, psk}``. Later runs reuse that profile and mint a
fresh phone invite — run it again whenever an invite expires or a second phone
needs pairing.

The PSK never leaves this machine except through the QR you scan; the relay
never sees it.

Standard library only, plus ``qrcode`` for the terminal QR — declared in
plugin.yaml and installed per after-install.md. That lives in the Hermes venv,
so this script re-execs itself with the venv's interpreter: running it with any
python3 works.
"""

import binascii
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_RELAY = "https://herelay.appcenter.ro"
ENV_KEYS = (
    "HERMES_BRIDGE_RELAY_URL",
    "HERMES_BRIDGE_PROFILE_ID",
    "HERMES_BRIDGE_API_KEY",
    "HERMES_BRIDGE_ALLOWED_USERS",
)
# Every inbound frame reports this one synthetic user id (adapter.py's two
# build_source calls) — one phone or five, they are all "mobile".
ADAPTER_USER_ID = "mobile"
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


def reexec_under_hermes_python(hermes_home: Path) -> None:
    """Re-run this script with the Hermes venv's interpreter.

    ``qrcode`` is installed into ``~/.hermes/hermes-agent/venv`` — the only
    environment the plugin's dependencies live in. A plain ``python3 pair.py``
    uses the system interpreter, imports none of them, and degrades to an
    unscannable payload string *after* the user has correctly installed
    everything. Rather than make them remember a 50-character interpreter
    path, hand the script to the right python ourselves.

    Guarded by an env flag so a venv genuinely missing ``qrcode`` prints the
    install hint instead of exec-looping.
    """
    if os.environ.get(_REEXEC_FLAG):
        return
    venv_python = hermes_home / "hermes-agent" / "venv" / "bin" / "python"
    if not venv_python.exists():
        return
    try:
        if Path(sys.executable).resolve() == venv_python.resolve():
            return
    except OSError:
        return
    os.environ[_REEXEC_FLAG] = "1"
    os.execv(str(venv_python), [str(venv_python), os.path.abspath(__file__), *sys.argv[1:]])


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


def readiness_report(hermes_home: Path, env: dict) -> list:
    """Check the things that only fail at first use, and say how to fix them.

    Every one of these was found by a user chatting to a freshly paired phone
    and getting silence, an unscannable payload, or a pairing code — none are
    visible to the plugin's tests, to `hermes plugins doctor`, or to the
    install-time security scan. Checking them here costs milliseconds and moves
    the discovery from "my agent is broken" to a line of terminal output.
    """
    checks: list[tuple[bool, str, str]] = []

    try:
        import nacl  # noqa: F401,PLC0415

        checks.append((True, "PyNaCl — messages can be encrypted", ""))
    except ImportError:
        checks.append((
            False,
            "PyNaCl missing — the adapter will not load",
            '~/.hermes/hermes-agent/venv/bin/pip install "PyNaCl>=1.6,<1.7"',
        ))

    try:
        import qrcode  # noqa: F401,PLC0415

        checks.append((True, "qrcode — pairing QR renders", ""))
    except ImportError:
        checks.append((
            False,
            "qrcode missing — pairing falls back to an unscannable payload",
            '~/.hermes/hermes-agent/venv/bin/pip install "qrcode>=7.4,<8"',
        ))

    allowed = [u.strip() for u in env.get("HERMES_BRIDGE_ALLOWED_USERS", "").split(",")]
    if ADAPTER_USER_ID in allowed:
        checks.append((True, "sender allowlisted — Hermes will accept the phone", ""))
    else:
        checks.append((
            False,
            "sender not allowlisted — Hermes answers the first message with a pairing code",
            f"echo HERMES_BRIDGE_ALLOWED_USERS={ADAPTER_USER_ID} >> {hermes_home}/.env",
        ))

    enabled = _plugin_enabled(hermes_home)
    if enabled is None:
        checks.append((True, "plugin enablement — not checked (no readable config.yaml)", ""))
    elif enabled:
        checks.append((True, "plugin enabled in config.yaml", ""))
    else:
        checks.append((
            False,
            "plugin not enabled — Hermes skips it silently at startup",
            "hermes plugins enable hermes_bridge",
        ))

    print()
    print("Readiness:")
    for ok, label, fix in checks:
        print(f"  {'OK  ' if ok else 'FAIL'} {label}")
        if fix:
            print(f"       fix: {fix}")
    return checks


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
        print("  No QR: the `qrcode` package is missing from the Hermes venv.")
        print("  Install it, then re-run this script for a scannable code:")
        print('    ~/.hermes/hermes-agent/venv/bin/pip install "qrcode>=7.4,<8"')
        print(f"  payload (manual entry): {payload}")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    qr.print_ascii(invert=True)


def main() -> None:
    hermes_home = Path(os.getenv("HERMES_HOME", Path.home() / ".hermes"))
    if not hermes_home.is_dir():
        die(f"{hermes_home} not found — is Hermes installed?")
    reexec_under_hermes_python(hermes_home)
    env_file = hermes_home / ".env"
    env = read_env(env_file)

    # `pair.py --check` diagnoses an existing install without minting an
    # invite: same checks, no side effects, safe to tell a user to run.
    if "--check" in sys.argv[1:]:
        ready = all(ok for ok, _, _ in readiness_report(hermes_home, env))
        sys.exit(0 if ready else 1)

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
    psk_hex = load_or_create_psk(hermes_home / "psk")
    payload = json.dumps({"token": token, "psk": psk_hex}, separators=(",", ":"))

    print()
    print(f"Invite {token} — single use, expires {response.get('expires_at', 'in 1 hour')}")
    print("Open Hermes Bridge on your phone → Pair new device → scan:")
    print()
    print_qr(payload)
    print()
    print("The QR carries the invite AND the encryption key — keep it on screen only until scanned.")

    if all(ok for ok, _, _ in readiness_report(hermes_home, read_env(env_file))):
        print()
        print("All set. Apply it:  hermes gateway restart")
    else:
        print()
        print("Fix the FAIL lines above, then:  hermes gateway restart")


if __name__ == "__main__":
    main()
