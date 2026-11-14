"""``/pair``: mint a HermLink phone invite from inside Hermes.

The same steps as ``pair.py`` (``pair.mint_invite``), rendered for where the
command was typed:

* a local session (the classic CLI, or a CLI/TUI/Desktop session on the
  gateway) gets the pairing code, the terminal QR and the readiness report
  inline, like the script. ``/pair --verbose`` adds the script's sensitive
  dump, and only here;
* a messaging chat (Telegram, Discord, ...) gets the QR as a PNG, the code as
  text, and a one-line warning that the image is a secret. The PNG is written
  ``0600`` under Hermes' image cache, the only place the gateway delivers
  attachments from, and deleted after ``QR_TTL_SECONDS``.

Who may run it is Hermes' own decision: the gateway drops unauthorized senders
before any command runs, and a configured ``allow_admin_from`` gates plugin
commands like built-in ones. On top of that this refuses a chat that is not a
direct message (the QR would reach every member) and ``--verbose`` anywhere
but a local session.

The QR payload is ``{token, psk}``. It never enters an agent turn: a command's
reply goes straight to the chat and is not written to the session transcript,
which is why there is no agent tool for this and the bundled skill only points
the user at ``/pair``. Sending it through a third-party messenger still puts
the PSK on that service's servers — after-install.md spells out the trade-off.
"""

import logging
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from . import pair

logger = logging.getLogger(__name__)

COMMAND = "pair"
SKILL_NAME = "pair-phone"
SKILL_PATH = Path(__file__).resolve().parent / "skills" / SKILL_NAME / "SKILL.md"
# Long enough for the gateway to upload the image and the user to scan it.
QR_TTL_SECONDS = 300
_QR_PREFIX = "hermlink-pair-"
# The classic CLI dispatches with platform "cli"; a CLI/TUI/Desktop session
# served by the gateway arrives as Platform.LOCAL ("local").
_LOCAL_PLATFORMS = frozenset({"cli", "local"})
_DM_CHAT_TYPES = frozenset({"dm", "direct", "private"})
_FLAGS = frozenset({"--check", "--verbose"})

USAGE = "Usage: /pair [--check | --verbose]"
OLD_HOST = (
    "/pair needs Hermes 0.22.3 or newer: this Hermes does not tell a plugin command "
    "whether it was typed in the terminal or in a chat, and the QR is a secret. "
    "Run `python3 ~/.hermes/plugins/hermes_bridge/pair.py` in a terminal instead."
)
GROUP_REFUSED = (
    "/pair only runs in a direct message: the QR holds this laptop's encryption key, "
    "and everyone in this chat would see it."
)
VERBOSE_REFUSED = (
    "/pair --verbose prints the API key and the encryption key, so it only runs in the "
    "Hermes CLI on this laptop. Nothing was minted."
)
NO_QR_IN_CHAT = (
    "No QR image: `qrcode` is not installed in Hermes' environment ({fix}). The encryption "
    "key is never sent as text, so nothing was minted — fix that, or run /pair in the "
    "Hermes CLI on this laptop."
)
QR_SECRET_WARNING = (
    "⚠️ This QR holds the end-to-end encryption key. Treat it like a password: scan it now, "
    "then delete this message."
)


def register_pair_command(ctx) -> None:
    """Register ``/pair`` and the ``pair-phone`` skill where the host offers them.

    Both registrars exist on every supported Hermes, but a host or test double
    without them still loads the platform, and so does an install without the
    skill file.
    """
    register_command = getattr(ctx, "register_command", None)
    if callable(register_command):
        register_command(
            COMMAND,
            handle_pair,
            description="Pair a phone with HermLink: show the pairing code and QR",
            args_hint="[--check|--verbose]",
        )
    register_skill = getattr(ctx, "register_skill", None)
    if not SKILL_PATH.is_file():
        # The public mirror's sync copies only top-level files today, so a
        # published install can lack skills/; the command does not need it.
        logger.debug("[hermes_bridge] no %s; pair-phone skill not registered", SKILL_PATH)
    elif callable(register_skill):
        try:
            register_skill(
                SKILL_NAME,
                SKILL_PATH,
                description="Pair a phone with HermLink by pointing the user at /pair",
            )
        except (ValueError, OSError) as exc:  # missing file or a clashing name: the command still works
            logger.warning("[hermes_bridge] pair-phone skill not registered: %s", exc)


def handle_pair(raw_args: str = "", **context) -> str:
    """The ``/pair`` handler: ``fn(raw_args, *, platform, source, ...)``.

    Hermes 0.22.3+ passes the dispatch context (``platform``, ``source``) to
    handlers that accept it. Older hosts call ``fn(raw_args)`` only, and
    without ``platform`` there is no way to know a terminal from a group chat,
    so the command refuses rather than guess.
    """
    flags = raw_args.split()
    if any(flag not in _FLAGS for flag in flags):
        return USAGE
    platform = str(context.get("platform") or "")
    if not platform:
        return OLD_HOST
    local = platform in _LOCAL_PLATFORMS
    if not local:
        refusal = _chat_refusal(context.get("source"), flags)
        if refusal:
            return refusal

    hermes_home = pair.default_hermes_home()
    if "--check" in flags:
        checks = pair.readiness_checks(hermes_home, pair.read_env(hermes_home / ".env"))
        return "\n".join(["HermLink — " + ("ready" if pair.is_ready(checks) else "not ready"),
                          *pair.format_readiness(checks)])
    if not local and not pair.qr_available():
        return NO_QR_IN_CHAT.format(fix=pair._MODERN_DEPS)

    notes: list[str] = []
    try:
        invite = pair.mint_invite(hermes_home, log=notes.append)
    except pair.PairError as exc:
        # The full message can quote a relay response that carries the API key.
        return f"Pairing failed: {exc if local else exc.summary}"
    checks = pair.readiness_checks(hermes_home, pair.read_env(hermes_home / ".env"))
    if local:
        return render_local(invite, notes, checks, verbose="--verbose" in flags)
    return render_chat(invite, checks, qr_png_path(invite.payload))


def _chat_refusal(source, flags: list[str]) -> Optional[str]:
    if "--verbose" in flags:
        return VERBOSE_REFUSED
    chat_type = str(getattr(source, "chat_type", "") or "").lower()
    if chat_type not in _DM_CHAT_TYPES:
        return GROUP_REFUSED
    return None


def render_local(invite: pair.PairingInvite, notes: list[str], checks: list, *, verbose: bool) -> str:
    """The script's output, as one block of text for a local session."""
    lines = list(notes)
    if verbose:
        lines += pair.verbose_lines(invite.response, invite.profile_id, invite.api_key,
                                    invite.psk_hex, invite.payload)
    lines += [
        "",
        f"Pairing code: {invite.token} — single use, expires {invite.expires_at}",
        "Open HermLink on your phone → Pair new device → scan:",
        "",
    ]
    drawn = pair.qr_text(invite.payload)
    lines += [drawn] if drawn is not None else pair.qr_missing_lines(invite.payload)
    lines += [
        "",
        "The QR carries the invite AND the encryption key — keep it on screen only until scanned.",
        "",
        *pair.format_readiness(checks),
    ]
    restart = _restart_line(invite, checks)
    if restart:
        lines += ["", restart]
    return "\n".join(lines)


def render_chat(invite: pair.PairingInvite, checks: list, png: Optional[Path]) -> str:
    """Reply for a messaging chat: the QR attachment, the code, the warning — never the PSK as text.

    ``MEDIA:<path>`` is how a gateway reply carries an attachment; the adapter
    strips the tag and uploads the file as an image.
    """
    if png is None:
        lines = [
            f"HermLink pairing code: `{invite.token}` (single use, expires {invite.expires_at}).",
            "The QR image could not be drawn, and the encryption key is never sent as text. "
            "Run /pair in the Hermes CLI on this laptop to scan it there.",
        ]
    else:
        lines = [
            f"MEDIA:{png}",
            f"📱 HermLink pairing code: `{invite.token}` (single use, expires {invite.expires_at}).",
            "Open HermLink → Pair new device → scan this QR.",
            QR_SECRET_WARNING,
        ]
    failing = [label for status, label, _fix in checks if status == pair.FAIL]
    if failing:
        lines.append("Not ready yet: " + "; ".join(failing) + ". Run /pair --check for the fixes.")
    restart = _restart_line(invite, checks)
    if restart:
        lines.append(restart)
    return "\n".join(lines)


def _restart_line(invite: pair.PairingInvite, checks: list) -> Optional[str]:
    """A re-pair only mints an invite, which a running gateway needs no restart for."""
    if invite.provisioned:
        return "New laptop profile: restart the gateway to connect it — hermes gateway restart"
    if not pair.is_ready(checks):
        return "Fix the FAIL lines, then: hermes gateway restart"
    return None


def qr_dir() -> Path:
    """Hermes' image cache — a root the gateway delivers ``MEDIA:`` attachments from."""
    try:
        from hermes_constants import get_hermes_dir  # noqa: PLC0415 — public host API

        return Path(get_hermes_dir("cache/images", "image_cache"))
    except (ImportError, AttributeError, TypeError):
        return pair.default_hermes_home() / "cache" / "images"


def qr_png_path(payload: str) -> Optional[Path]:
    """Write the QR PNG and schedule its removal; None when it cannot be drawn."""
    directory = qr_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    sweep_stale_qr_files(directory)
    path = directory / f"{_QR_PREFIX}{secrets.token_hex(8)}.png"
    if not pair.write_qr_png(payload, path):
        return None
    timer = threading.Timer(QR_TTL_SECONDS, _remove, args=(path,))
    timer.daemon = True
    timer.start()
    return path


def sweep_stale_qr_files(directory: Path, now: Optional[float] = None) -> None:
    """Remove QR images a restart left behind (their timers died with the process)."""
    cutoff = (time.time() if now is None else now) - QR_TTL_SECONDS
    for stale in directory.glob(f"{_QR_PREFIX}*.png"):
        try:
            if stale.stat().st_mtime < cutoff:
                stale.unlink()
        except OSError:
            continue


def _remove(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.warning("[hermes_bridge] could not remove pairing QR %s", path)
