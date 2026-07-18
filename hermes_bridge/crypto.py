"""
E2E message encryption for the Hermes Bridge relay.

Algorithm: XChaCha20-Poly1305 (IETF) via PyNaCl.
Wire format: base64( 0x01 || nonce(24) || ciphertext )
AAD: utf8(profile_id + "|" + direction)  — binds frame to channel and direction.
Plaintext: utf8(JSON({ role, content, ts }))  — ts = epoch ms for replay defense.

TypeScript counterpart: lib/crypto.ts (must match byte-for-byte).
"""

import base64
import json
import os
import time
from collections import deque
from typing import Optional

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    randombytes,
)

VERSION = b"\x01"
NONCE_BYTES = 24

# Replay-defense window in seconds (60 seconds).
REPLAY_WINDOW_S = 60.0

# LRU nonce-dedup cache — keeps the last 256 nonces to detect immediate replays.
MAX_NONCE_CACHE = 256
_nonce_cache: deque = deque(maxlen=MAX_NONCE_CACHE)


def _build_aad(profile_id: str, direction: str) -> bytes:
    return f"{profile_id}|{direction}".encode()


def seal(
    profile_id: str,
    direction: str,
    payload: dict,
    psk: bytes,
) -> str:
    """
    Encrypt a message payload for transmission over the relay.

    Args:
        profile_id: profile the message is scoped to
        direction:  "in" (mobile→laptop) or "out" (laptop→mobile)
        payload:    dict with at least "role" and "content"
        psk:        32-byte pre-shared key

    Returns:
        base64-encoded sealed frame (str)
    """
    nonce = randombytes(NONCE_BYTES)
    aad = _build_aad(profile_id, direction)
    ts = int(time.time() * 1000)  # epoch ms, same as JS Date.now()
    plaintext = json.dumps({**payload, "ts": ts}).encode()

    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(
        message=plaintext,
        aad=aad,
        nonce=nonce,
        key=psk,
    )

    frame = VERSION + nonce + ct
    return base64.b64encode(frame).decode()


def open_frame(
    profile_id: str,
    direction: str,
    frame: str,
    psk: bytes,
) -> Optional[dict]:
    """
    Decrypt a sealed frame received from the relay.

    Returns:
        Decrypted payload dict ({"role": ..., "content": ...}),
        or None if the frame is invalid, tampered, replayed, or expired.
    """
    try:
        raw = base64.b64decode(frame)
    except Exception:
        return None

    # Minimum: 1 (version) + 24 (nonce) + 16 (tag) = 41 bytes
    if len(raw) < 41 or raw[0:1] != VERSION:
        return None

    nonce = raw[1 : 1 + NONCE_BYTES]
    ct = raw[1 + NONCE_BYTES :]
    aad = _build_aad(profile_id, direction)

    try:
        plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext=ct,
            aad=aad,
            nonce=nonce,
            key=psk,
        )
    except Exception:
        # Decryption failure (bad key, tampered, wrong direction/profile)
        return None

    try:
        parsed = json.loads(plaintext.decode())
    except Exception:
        return None

    # Replay defense: timestamp window
    ts = parsed.get("ts")
    if not isinstance(ts, (int, float)):
        return None
    age_s = abs(time.time() - ts / 1000.0)
    if age_s > REPLAY_WINDOW_S:
        return None

    # Replay defense: nonce dedup
    if nonce in _nonce_cache:
        return None
    _nonce_cache.append(nonce)

    parsed.pop("ts", None)
    return parsed


def load_psk(path: Optional[str] = None) -> bytes:
    """
    Load the 32-byte PSK from disk.

    Reads from the given path, or from ~/.hermes/psk by default.
    Raises RuntimeError if the file is absent or the key is not 32 bytes.
    """
    psk_path = path or os.path.join(os.path.expanduser("~/.hermes"), "psk")
    try:
        with open(psk_path, "rb") as f:
            key = f.read()
    except OSError as exc:
        raise RuntimeError(
            f"[hermes_bridge] PSK not found at {psk_path}. "
            "Run 'hermes gateway pair' to generate one."
        ) from exc
    if len(key) != 32:
        raise RuntimeError(
            f"[hermes_bridge] PSK at {psk_path} must be 32 bytes, got {len(key)}."
        )
    return key
