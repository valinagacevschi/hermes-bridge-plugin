"""
Crypto interop self-tests for the Hermes Bridge E2E encryption.

Run:
    ~/.hermes/hermes-agent/venv/bin/python test_crypto.py
  or with any Python ≥3.8 that has PyNaCl ≥1.6.2 installed.

These tests verify:
  1. Round-trip (seal → open_frame) produces the original payload.
  2. Direction binding: "in" frame cannot be opened as "out" (reflection defense).
  3. Profile binding: frame opened with wrong profile_id fails.
  4. Nonce LRU dedup: same frame rejected on second open.
  5. Timestamp window: frame with stale ts rejected.
  6. Tampered ciphertext rejected.
  7. Known-vector: a frame produced from a fixed key+nonce+payload can be decoded.
     (Paste the matching vector from scripts/crypto-test.js to verify TS↔Python interop.)
"""

import base64
import json
import os
import struct
import sys
import time
from collections import deque

# Import crypto.py DIRECTLY as a standalone module (not via the hermes_bridge
# package) — crypto.py is fully self-contained (stdlib + PyNaCl only), and going
# through the package __init__ would eagerly import adapter.py → gateway core,
# which isn't present outside a Hermes install. This keeps the crypto interop
# test runnable with only PyNaCl.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "hermes_bridge"))

# Patch the module-level cache for isolation between tests.
import crypto as _crypto_mod

def _reset_cache():
    _crypto_mod._nonce_cache = deque(maxlen=_crypto_mod.MAX_NONCE_CACHE)

from crypto import seal, open_frame, seal_blob, open_blob, VERSION, NONCE_BYTES

PSK = bytes(range(32))  # 0x00..0x1f — deterministic test key
PROFILE = "test_profile"

PASS = 0
FAIL = 0


def ok(name: str):
    global PASS
    PASS += 1
    print(f"  ✓  {name}")


def fail(name: str, detail: str = ""):
    global FAIL
    FAIL += 1
    print(f"  ✗  {name}" + (f": {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# 1. Round-trip
# ---------------------------------------------------------------------------
_reset_cache()
payload = {"role": "user", "content": "hello world"}
frame = seal(PROFILE, "in", payload, PSK)
result = open_frame(PROFILE, "in", frame, PSK)
if result == payload:
    ok("round-trip seal→open")
else:
    fail("round-trip seal→open", f"got {result}")

# ---------------------------------------------------------------------------
# 2. Direction binding (reflection defense)
# ---------------------------------------------------------------------------
_reset_cache()
frame_in = seal(PROFILE, "in", payload, PSK)
result = open_frame(PROFILE, "out", frame_in, PSK)
if result is None:
    ok("direction binding: 'in' frame rejected as 'out'")
else:
    fail("direction binding: 'in' frame rejected as 'out'", f"got {result}")

_reset_cache()
frame_out = seal(PROFILE, "out", payload, PSK)
result = open_frame(PROFILE, "in", frame_out, PSK)
if result is None:
    ok("direction binding: 'out' frame rejected as 'in'")
else:
    fail("direction binding: 'out' frame rejected as 'in'", f"got {result}")

# ---------------------------------------------------------------------------
# 3. Profile binding (cross-profile replay defense)
# ---------------------------------------------------------------------------
_reset_cache()
frame = seal(PROFILE, "in", payload, PSK)
result = open_frame("other_profile", "in", frame, PSK)
if result is None:
    ok("profile binding: different profile_id rejected")
else:
    fail("profile binding: different profile_id rejected", f"got {result}")

# ---------------------------------------------------------------------------
# 4. Nonce dedup (immediate replay)
# ---------------------------------------------------------------------------
_reset_cache()
frame = seal(PROFILE, "in", payload, PSK)
r1 = open_frame(PROFILE, "in", frame, PSK)  # first delivery — accepted
r2 = open_frame(PROFILE, "in", frame, PSK)  # replay — rejected
if r1 == payload and r2 is None:
    ok("nonce dedup: replay rejected")
else:
    fail("nonce dedup: replay rejected", f"r1={r1}, r2={r2}")

# ---------------------------------------------------------------------------
# 5. Timestamp window: stale frame rejected
# ---------------------------------------------------------------------------
_reset_cache()
# Craft a frame with ts = now - 90 seconds (outside 60s window)
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    randombytes,
)
stale_ts = int((time.time() - 90) * 1000)
stale_plain = json.dumps({"role": "user", "content": "stale", "ts": stale_ts}).encode()
nonce = randombytes(NONCE_BYTES)
aad = f"{PROFILE}|in".encode()
ct = crypto_aead_xchacha20poly1305_ietf_encrypt(message=stale_plain, aad=aad, nonce=nonce, key=PSK)
stale_frame = base64.b64encode(VERSION + nonce + ct).decode()
result = open_frame(PROFILE, "in", stale_frame, PSK)
if result is None:
    ok("timestamp window: stale frame rejected")
else:
    fail("timestamp window: stale frame rejected", f"got {result}")

# ---------------------------------------------------------------------------
# 6. Tampered ciphertext rejected
# ---------------------------------------------------------------------------
_reset_cache()
frame = seal(PROFILE, "in", payload, PSK)
raw = bytearray(base64.b64decode(frame))
# Flip a byte in the ciphertext area (after version + nonce)
raw[1 + NONCE_BYTES] ^= 0xFF
tampered_frame = base64.b64encode(bytes(raw)).decode()
result = open_frame(PROFILE, "in", tampered_frame, PSK)
if result is None:
    ok("tampered ciphertext rejected")
else:
    fail("tampered ciphertext rejected", f"got {result}")

# ---------------------------------------------------------------------------
# 7. Known-vector interop — a frame produced by the JS/mobile implementation
#    must decrypt byte-for-byte in Python.
# ---------------------------------------------------------------------------
# This verifies the WIRE FORMAT + AEAD (version byte, nonce layout, AAD binding,
# XChaCha20-Poly1305 key/tag) match the mobile app's lib/crypto.ts. It decrypts
# at the primitive layer and does NOT call open_frame, because a static vector
# carries a fixed `ts` that open_frame's freshness window would always reject —
# freshness is a live-transport policy, irrelevant to cross-language byte compat.
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as _aead_dec

KNOWN_VECTOR_FRAME = "AY6LrCbxe1+GBM9SzbjEvuQR5KxiXnDPNtMiFwSzKEH6gALWI3yYY0lTI2ZpYNbH/haP9HuGIjctV9LF4G/CAB+s6Uo35XL024XR+4I4dKer69MvCj/IxY863oGYoqHt6kQyZQ=="
KNOWN_VECTOR_KEY = bytes(range(32))  # must match the key used in the JS script

try:
    _kv_raw = base64.b64decode(KNOWN_VECTOR_FRAME)
    assert _kv_raw[0:1] == VERSION, "version byte mismatch"
    _kv_nonce = _kv_raw[1 : 1 + NONCE_BYTES]
    _kv_ct = _kv_raw[1 + NONCE_BYTES :]
    _kv_plain = _aead_dec(
        ciphertext=_kv_ct, aad=b"test_profile|in", nonce=_kv_nonce, key=KNOWN_VECTOR_KEY
    )
    _kv_payload = json.loads(_kv_plain.decode())
    if _kv_payload.get("role") == "user" and _kv_payload.get("content") == "interop test":
        ok("known-vector JS→Python interop (wire-format + AEAD)")
    else:
        fail("known-vector JS→Python interop", f"got {_kv_payload}")
except Exception as exc:
    fail("known-vector JS→Python interop", f"raised {type(exc).__name__}: {exc}")

# ---------------------------------------------------------------------------
# 8. Sealed-blob round-trip + no-replay-guard + profile binding
#    (attachments/voice use seal_blob/open_blob, not seal/open_frame — see
#    crypto.py's _build_blob_aad docstring for why they're a separate path.)
# ---------------------------------------------------------------------------
blob_plain = b"hello blob bytes \xff\x00"
sealed = seal_blob(PROFILE, blob_plain, PSK)
opened = open_blob(PROFILE, sealed, PSK)
if opened == blob_plain:
    ok("blob round-trip seal_blob→open_blob")
else:
    fail("blob round-trip seal_blob→open_blob", f"got {opened!r}")

# Re-open (no replay/nonce-dedup guard on blobs — see crypto.py docstring)
# must ALSO succeed.
opened_again = open_blob(PROFILE, sealed, PSK)
if opened_again == blob_plain:
    ok("blob re-open (no replay guard) succeeds")
else:
    fail("blob re-open (no replay guard) succeeds", f"got {opened_again!r}")

if open_blob("other_profile", sealed, PSK) is None:
    ok("blob profile binding: wrong profile rejected")
else:
    fail("blob profile binding: wrong profile rejected")

_tampered = bytearray(sealed)
_tampered[1 + NONCE_BYTES] ^= 0xFF
if open_blob(PROFILE, bytes(_tampered), PSK) is None:
    ok("blob tampered ciphertext rejected")
else:
    fail("blob tampered ciphertext rejected")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print()
print(f"{'PASS' if FAIL == 0 else 'FAIL'}  {PASS} passed, {FAIL} failed")
sys.exit(0 if FAIL == 0 else 1)
