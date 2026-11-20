"""Live MCP tool progress for a phone-continued Local chat turn (#153).

The owner publishes the turn's canonical execution frames to every attached
client, so the bridge's per-turn owner connection (``_run_local_owner``)
already receives them. Shapes, from the host (identical in v0.23.0/v0.23.1;
v0.21.0 has no ``tool.progress`` at all):

- frame: ``gateway/session_events.py:75-82`` ``SessionEvents.publish`` →
  ``{"params": {**stamp, "type", "session_id", "payload", "replay_epoch", "seq"}}``;
  the stamp is ``{authority_epoch, execution_generation, admission_id}``
  (``gateway/session_authority.py`` ``_stamp_claim``), and
  ``publish_execution`` fences it to the running generation.
- ``tool.start``: ``gateway/run_turn_progress.py`` ``_tool_lifecycle_payload``
  → ``{tool_id, name, context, tool_call_id, tool_name, args[, labels]}``,
  published before the tool runs (``agent/tool_executor.py``
  ``_begin_tool_execution`` precedes ``bound_tool_progress``).
- ``tool.progress``: ``gateway/local_viewer_events.py`` ``publish_progress`` →
  ``agent/tool_progress_relay.py`` ``tool_progress_payload`` →
  ``{tool_id, name, progress, total, percent, message}`` (percent/total None
  without a total). The relay already throttles to one frame per 0.5 s.
- ``tool.complete``: ``_tool_complete_payload`` → start fields + ``is_error``,
  ``result``.

Only progress-reporting tools reach the phone: ``tool.start`` is used to
admit a tool id, never forwarded (no args/results leave the turn), and a
tool that never reports progress produces no frame at all. Pure state — no
Hermes imports.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Optional, Set

MESSAGE_LIMIT = 300
NAME_LIMIT = 120
TOOL_LIMIT = 64


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def _text(value: Any, limit: int) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


class LocalTurnProgress:
    """One phone turn's progress relay state, bound to the owner admission.

    ``observe(params)`` takes one owner event's ``params`` already matched to
    the admission and returns the phone payload to send, or None. ``end()``
    returns the closing payload once, only if anything was forwarded.
    """

    def __init__(self, *, session_id: str, reply_to: str, turn_id: str, admission_id: str):
        self.session_id = session_id
        self.reply_to = reply_to
        self.turn_id = turn_id
        self.admission_id = admission_id
        self._generation: Any = None
        self._stream: Optional[str] = None
        self._started: Set[str] = set()
        self._reported: Set[str] = set()
        self._closed: Set[str] = set()
        self._seq = 0
        self._ended = False

    @property
    def forwarded(self) -> bool:
        return self._seq > 0

    def _same_execution(self, params: Dict[str, Any]) -> bool:
        if params.get("admission_id") != self.admission_id:
            return False
        generation = params.get("execution_generation")
        if generation is not None:
            if self._generation is None:
                self._generation = generation
            elif generation != self._generation:
                return False
        stream = params.get("session_id")
        if isinstance(stream, str) and stream:
            if self._stream is None:
                self._stream = stream
            elif stream != self._stream:
                return False
        return True

    def _frame(self, event: str, **fields: Any) -> Dict[str, Any]:
        self._seq += 1
        return {
            "role": "tool_progress",
            "event": event,
            "session_id": self.session_id,
            "reply_to": self.reply_to,
            "turn_id": self.turn_id,
            "seq": self._seq,
            **fields,
        }

    def observe(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self._ended or not isinstance(params, dict) or not self._same_execution(params):
            return None
        kind = params.get("type")
        payload = params.get("payload")
        if not isinstance(payload, dict):
            return None
        tool_id = payload.get("tool_id")
        if not isinstance(tool_id, str) or not tool_id:
            return None
        if kind == "tool.start":
            if tool_id not in self._closed and len(self._started) < TOOL_LIMIT:
                self._started.add(tool_id)
            return None
        if kind == "tool.progress":
            if tool_id not in self._started or tool_id in self._closed:
                return None  # foreign/unannounced tool, or late after its completion
            progress = _number(payload.get("progress"))
            if progress is None:
                return None
            total = _number(payload.get("total"))
            if total is not None and total <= 0:
                total = None
            percent = None
            if total is not None:
                percent = max(0, min(100, int(round(progress / total * 100))))
            self._reported.add(tool_id)
            return self._frame(
                "progress",
                tool_id=tool_id,
                name=_text(payload.get("name"), NAME_LIMIT) or "tool",
                progress=progress,
                total=total,
                percent=percent,
                message=_text(payload.get("message"), MESSAGE_LIMIT),
            )
        if kind == "tool.complete":
            if tool_id not in self._started or tool_id in self._closed:
                return None
            self._closed.add(tool_id)
            self._started.discard(tool_id)
            if tool_id not in self._reported:
                return None  # a non-reporting tool stays invisible here
            self._reported.discard(tool_id)
            return self._frame("complete", tool_id=tool_id, is_error=bool(payload.get("is_error")))
        return None

    def end(self, reason: str) -> Optional[Dict[str, Any]]:
        """Close the turn: every later frame is dropped. Payload only if the phone saw progress."""
        if self._ended:
            return None
        self._ended = True
        if not self.forwarded:
            return None
        return self._frame("end", reason=reason)
