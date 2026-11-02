"""Client-only access to a local session's canonical owner. Never starts a gateway."""

import asyncio
import hashlib
from contextlib import asynccontextmanager
from pathlib import Path


class OwnerUnconfirmed(RuntimeError):
    """A submit may have committed. Never retry or fork this turn."""


def _api(warn):
    try:
        from tui_gateway.owner_forward import (
            connect_owner, discover_owner, _REFUSED_BEFORE_COMMIT,
        )
        from hermes_cli.gateway_client import GatewayRPCError
        return connect_owner, discover_owner, _REFUSED_BEFORE_COMMIT, GatewayRPCError
    except (ImportError, AttributeError) as exc:
        warn("tui_gateway.owner_forward / hermes_cli.gateway_client", exc)
        raise


@asynccontextmanager
async def connect(profile, warn):
    dial, discover, _, _ = _api(warn)
    try:
        from hermes_constants import get_hermes_home
        if profile:
            from hermes_cli.profiles import get_profile_dir
            home = Path(get_profile_dir(profile))
        else:
            home = Path(get_hermes_home())
    except (ImportError, AttributeError) as exc:
        warn("hermes_constants.get_hermes_home / hermes_cli.profiles.get_profile_dir", exc)
        raise
    endpoint = await asyncio.to_thread(discover, home)
    async with dial(home, endpoint) as client:
        description = await client.rpc("runtime.describe")
        if "durable-admission-v1" not in description.get("capabilities", []):
            raise RuntimeError("Owner has no durable client-submit API")
        yield client


def submission_id(profile_id, session_id, msg_id):
    # Profile and session scope keep independently generated phone ids apart.
    key = "\0".join((profile_id, session_id, msg_id))
    return "bridge-" + hashlib.sha256(key.encode()).hexdigest()


async def submit(client, target, text, request_id, warn):
    _, _, refused, rpc_error = _api(warn)
    try:
        receipt = await client.rpc("prompt.submit", session_id=target, text=text,
                                   submission_id=request_id)
    except Exception as exc:
        reason = exc.data.get("reason", str(exc)) if isinstance(exc, rpc_error) else None
        if isinstance(reason, str) and reason in refused:
            raise
        raise OwnerUnconfirmed("The Laptop did not confirm this turn. Check its transcript before sending again.") from exc
    if (not isinstance(receipt, dict) or not isinstance(receipt.get("admission_id"), str)
            or receipt.get("status") not in ("queued", "started", "terminal")):
        raise OwnerUnconfirmed("The Laptop did not confirm an admission. Check its transcript before sending again.")
    return receipt
