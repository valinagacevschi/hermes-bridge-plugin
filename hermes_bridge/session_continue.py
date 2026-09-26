"""Which inbound phone message continues a stored Hermes session.

The phone replicas Hermes sessions. A send names the stored session id.
The phone-only inbox (`agent:<profile>`) is not one of those sessions.
"""

from typing import Optional


def hermes_session_to_continue(payload: dict) -> Optional[str]:
    sid = payload.get("session_id")
    if not isinstance(sid, str):
        return None
    sid = sid.strip()
    if not sid or sid.startswith("agent:"):
        return None
    return sid
