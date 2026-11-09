"""Streaming TTS wire helpers + live STT session bookkeeping for hermes_bridge.

Keeps PCM→WAV packing and per-stream locks out of adapter.py. Segment size is
~1 s of PCM at the handle's AudioFormat so the phone can start playback before
the full reply is synthesized.
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


# Target segment duration for tts_chunk frames.
SEGMENT_SECONDS = 1.0
# Cap one live STT session so a forgotten mic can't pin a provider socket.
STT_MAX_DURATION_S = 120.0


def bytes_per_second(sample_rate: int, channels: int, sample_width: int) -> int:
    return int(sample_rate) * int(channels) * int(sample_width)


def segment_byte_target(sample_rate: int, channels: int, sample_width: int) -> int:
    return bytes_per_second(sample_rate, channels, sample_width) * int(SEGMENT_SECONDS)


def pcm_to_wav(
    pcm: bytes,
    *,
    sample_rate: int,
    channels: int,
    sample_width: int,
) -> bytes:
    """Wrap raw little-endian PCM in a minimal RIFF/WAVE header."""
    rate = int(sample_rate)
    ch = int(channels)
    width = int(sample_width)
    byte_rate = rate * ch * width
    block_align = ch * width
    data_size = len(pcm)
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + data_size,
        b"WAVE",
        b"fmt ",
        16,
        1,  # PCM
        ch,
        rate,
        byte_rate,
        block_align,
        width * 8,
        b"data",
        data_size,
    )
    return header + pcm


@dataclass
class StreamingTtsState:
    """Mutable per-handle state. Access only while holding ``lock`` across awaits."""

    stream_id: str
    chat_id: str
    sample_rate: int
    channels: int
    sample_width: int
    session_id: Optional[str] = None
    buffer: bytearray = field(default_factory=bytearray)
    next_seq: int = 0
    aborted: bool = False
    finished: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def segment_target(self) -> int:
        return segment_byte_target(self.sample_rate, self.channels, self.sample_width)

    def take_full_segments(self) -> list[bytes]:
        """Pop complete ~1 s segments; leave a short remainder buffered."""
        target = self.segment_target
        out: list[bytes] = []
        while len(self.buffer) >= target:
            chunk = bytes(self.buffer[:target])
            del self.buffer[:target]
            out.append(chunk)
        return out

    def take_remainder(self) -> Optional[bytes]:
        if not self.buffer:
            return None
        chunk = bytes(self.buffer)
        self.buffer.clear()
        return chunk


def wav_b64_for_pcm(state: StreamingTtsState, pcm: bytes) -> str:
    wav = pcm_to_wav(
        pcm,
        sample_rate=state.sample_rate,
        channels=state.channels,
        sample_width=state.sample_width,
    )
    return base64.b64encode(wav).decode("ascii")


def new_stream_id() -> str:
    return str(uuid.uuid4())


@dataclass
class LiveSttSession:
    """One phone→host live dictation session."""

    stream_id: str
    session: Any
    opened_at: float = field(default_factory=time.monotonic)
    cancelled: bool = False
    ended: bool = False
    next_seq: int = 0
    pending: Dict[int, bytes] = field(default_factory=dict)
    audio_changed: asyncio.Event = field(default_factory=asyncio.Event)
    had_partial: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    duration_task: Optional[asyncio.Task] = None

    def mark_partial(self) -> None:
        self.had_partial = True


def stt_expired(session: LiveSttSession, *, now: Optional[float] = None) -> bool:
    t = time.monotonic() if now is None else now
    return (t - session.opened_at) >= STT_MAX_DURATION_S


PartialEmitter = Callable[[str, str], None]
