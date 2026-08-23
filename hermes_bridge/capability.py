"""CapabilityDescriptor — the relay handshake payload. EXPERIMENTAL.

Vendored (not imported) from Hermes core's own experimental relay-connector
contract: ~/.hermes/hermes-agent/gateway/relay/descriptor.py +
~/.hermes/hermes-agent/docs/relay-connector-contract.md. We vendor rather than
import because that module lives in an EXPERIMENTAL, in-flux part of Hermes
core and this plugin installs onto arbitrary Hermes versions via a public
`curl | bash` install script — importing it live would give us two code paths
(present vs absent) for zero benefit, since we only need the wire contract,
not the rest of gateway.relay.

The relay (server/ws.ts, TypeScript) sends a JSON object shaped like this
dataclass (plus a `"type": "hello"` discriminator) right after a gateway
WebSocket connects. This module parses that frame and answers "does the
relay support op X?" with fail-open semantics: a relay that never sends
`supported_ops` (or sends none at all — i.e. no hello arrived) is assumed to
support the legacy op set every relay supported before this field existed.

Keep this file's fields a SUBSET of upstream's — do not diverge, and do not
claim fields upstream doesn't have. test_handshake.py's parity test asserts
this against the live upstream module when the Hermes venv has it importable.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

# Bump additively (never reinterpret an existing field). Mirrors upstream's
# CONTRACT_VERSION in gateway/relay/descriptor.py.
CONTRACT_VERSION = 1

# Fields this vendor adds ahead of upstream (upstream may not have them yet).
# test_handshake.py's parity test excludes these from its subset check —
# without this, adding a vendor-only field makes vendored NOT a subset of
# upstream and the parity test breaks the day it lands, backwards from its
# intent. #41 adds "supports_replay" here.
VENDOR_ONLY_FIELDS: frozenset = frozenset({"supports_replay"})


@dataclass(frozen=True)
class CapabilityDescriptor:
    """Immutable capability descriptor received at relay handshake."""

    contract_version: int
    platform: str
    label: str
    max_message_length: int
    supports_draft_streaming: bool
    supports_edit: bool
    supports_threads: bool
    markdown_dialect: str
    len_unit: str  # "chars" | "utf16"
    # Op-level capability discovery: the outbound op names the relay actually
    # implements (e.g. ["send", "edit", "follow_up", "send_media"]). Empty
    # tuple = the relay predates this field; callers MUST treat that as
    # "legacy op set" rather than "nothing supported", so an old relay keeps
    # working unchanged.
    supported_ops: tuple = ()
    # Transport capability, NOT an op name — whether the relay can replay a
    # phone→gateway backlog on reconnect (#41). Descriptor-parity-only today:
    # the adapter sends `?since=` on every connect regardless of this flag
    # (an old relay simply ignores the unknown query param), same honesty
    # precedent as `max_message_length` — consumed by nothing yet, advertised
    # accurately anyway.
    supports_replay: bool = False

    # The op set every relay supported before `supported_ops` existed.
    LEGACY_OPS = ("send", "edit", "typing", "follow_up")

    def supports_op(self, op: str) -> bool:
        """Whether the relay advertises the outbound op ``op``.

        Fail-open for legacy relays: an empty ``supported_ops`` means the
        relay predates op discovery, so assume the legacy op set. A NEW op
        (e.g. "prompt", "react") is therefore only True when explicitly
        advertised — exactly the discovery semantics needed: the adapter can
        probe capability without trying the op and parsing an error.
        """
        if not self.supported_ops:
            return op in self.LEGACY_OPS
        return op in self.supported_ops

    @classmethod
    def from_json(cls, data: str) -> "CapabilityDescriptor":
        """Deserialize from a handshake JSON string.

        Unknown keys are ignored (forward-compat: a newer relay may send
        fields this adapter does not know yet); missing optional keys fall
        back to dataclass defaults where they exist.
        """
        raw = json.loads(data)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in raw.items() if k in known}
        # Normalize the chunking bound at the trust boundary — a relay may
        # advertise 0 ("no limit"), or a buggy one a negative value. Map to
        # the documented 4096 default (mirrors upstream's from_json).
        if "max_message_length" in filtered:
            try:
                if int(filtered["max_message_length"]) <= 0:
                    filtered["max_message_length"] = 4096
            except (TypeError, ValueError):
                filtered["max_message_length"] = 4096
        # Normalize supported_ops at the trust boundary: JSON carries a list;
        # the frozen dataclass stores a tuple. Malformed values degrade to
        # () — the legacy-op-set fallback — rather than raising.
        if "supported_ops" in filtered:
            raw_ops = filtered["supported_ops"]
            if isinstance(raw_ops, (list, tuple)):
                filtered["supported_ops"] = tuple(
                    str(op) for op in raw_ops if isinstance(op, str) and op
                )
            else:
                filtered["supported_ops"] = ()
        return cls(**filtered)

    def to_json(self) -> str:
        """Serialize to a JSON string (used only by tests to build fixtures)."""
        return json.dumps(asdict(self), sort_keys=True, ensure_ascii=False)
