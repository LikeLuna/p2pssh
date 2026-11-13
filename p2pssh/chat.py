"""C.2 - Chat service (Member 2).

The CLI calls  run_chat(session)  on BOTH sides after the service request was accepted
(see services.py): the connecting side through `p2pssh chat <peer>`, the host from `listen`.

Wire format: ONE secure record = ONE chat message = UTF-8 text, at most 4096 bytes.
There are no type bytes, no channel ids and no framing of our own, because the
connection carries exactly one service.  Leaving the chat = closing the session.

What this module protects against
  * terminal injection : text from the peer is cleaned before it is printed
                         (ANSI/OSC escape sequences, control characters and the
                         invisible "bidi" characters that can reorder text are removed)
  * fake lines         : a message can never start a new line, so a peer cannot make
                         "bob: send money" appear as if somebody else wrote it
  * bad input          : invalid UTF-8, empty records and records over 4 KiB are
                         ignored with a notice; they never end the chat or crash it
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
import unicodedata
from typing import Awaitable, Callable, Optional

from .errors import P2PSSHError
from .prompts import clean_text
from .session import SessionError

MAX_MESSAGE_BYTES = 4096
QUIT_COMMANDS = ("/quit", "/exit")

# Escape sequences: CSI (ESC [ ... final byte), OSC (ESC ] ... BEL or ESC \), and any
# other two-character ESC sequence.  Removed as a WHOLE so no "[31m" debris is left.
_ESCAPE_SEQUENCES = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"          # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"   # OSC
    r"|\x1b[ -/]*[0-~]"                 # other ESC sequences (e.g. ESC c = terminal reset)
    r"|\x1b"                            # a lone ESC
)
_KEEP_FORMAT_CHARS = {"‍"}          # zero-width joiner: needed inside emoji such as family emoji


def sanitize_incoming(text: str, limit: int = MAX_MESSAGE_BYTES) -> str:
    """Make text from the peer safe to print on one line."""
    text = _ESCAPE_SEQUENCES.sub("", text)
    out = []
    for ch in text:
        if ch in "\r\n\t":
            out.append(" ")                      # a message can never start a new line
        elif ch in _KEEP_FORMAT_CHARS:
            out.append(ch)
        elif unicodedata.category(ch)[0] == "C":   # control, format (bidi), surrogate, unassigned
            continue
        else:
            out.append(ch)
    cleaned = "".join(out)
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 3] + "..."


def prepare_outgoing(line: str) -> tuple[Optional[bytes], Optional[str]]:
    """Turn what the user typed into (record, None), (None, None) = nothing to send,
    or (None, problem) = refuse with this message.  Nothing is ever silently cut."""
    text = line.rstrip("\r\n")
    if not text.strip():
        return None, None
    try:
        data = text.encode("utf-8")
    except UnicodeEncodeError:
        return None, "that text cannot be sent (invalid characters)"
    if len(data) > MAX_MESSAGE_BYTES:
        return None, (f"message not sent: {len(data)} bytes is over the "
                      f"{MAX_MESSAGE_BYTES} byte limit")
    return data, None


def _default_out(text: str) -> None:
    print(text, flush=True)


async def _read_stdin_line() -> Optional[str]:
    """Next line typed by the user, None at end of input (Ctrl-D / Ctrl-Z).

    Runs in a worker thread so the event loop (and the incoming messages) keep going."""
    line = await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
    return line if line else None


def _peer_label(session) -> str:
    name = getattr(getattr(session, "conn", None), "peer_name", None)
    return clean_text(name, 40) if name else "peer"


def _stamp() -> str:
    return time.strftime("%H:%M")


async def _receive_loop(session, out: Callable[[str], None], label: str) -> None:
    """Print everything the peer says until the session ends."""
    while True:
        try:
            data = await session.recv()
        except (SessionError, P2PSSHError, ConnectionError, asyncio.IncompleteReadError):
            return                                    # peer left or the session broke
        if not data:
            continue                                  # empty record: nothing to show
        if len(data) > MAX_MESSAGE_BYTES:
            out(f"[{_stamp()}] (ignored a message over {MAX_MESSAGE_BYTES} bytes from {label})")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            out(f"[{_stamp()}] (ignored a message that was not valid text from {label})")
            continue
        shown = sanitize_incoming(text)
        if shown.strip():
            out(f"[{_stamp()}] {label}: {shown}")


async def _input_loop(session, read_line, out: Callable[[str], None]) -> None:
    """Send what the user types until they quit, press Ctrl-D, or the session breaks."""
    while True:
        line = await read_line()
        if line is None:                              # end of input
            return
        if line.strip().lower() in QUIT_COMMANDS:
            return
        data, problem = prepare_outgoing(line)
        if problem:
            out(f"({problem})")
            continue
        if data is None:
            continue
        try:
            await session.send(data)
        except (SessionError, P2PSSHError, ConnectionError):
            out("(could not send: the connection is gone)")
            return


async def run_chat(
    session,
    *,
    read_line: Optional[Callable[[], Awaitable[Optional[str]]]] = None,
    out: Optional[Callable[[str], None]] = None,
    label: Optional[str] = None,
) -> int:
    """Chat over an established, authenticated session.  Returns 0 when the chat ends.

    read_line / out / label are only for tests; the CLI calls run_chat(session).
    The caller (cli.py) closes the session afterwards, which is how the peer learns
    that we left.
    """
    out = out or _default_out
    read_line = read_line or _read_stdin_line
    label = label or _peer_label(session)

    out(f"chat with {label}: type a message and press Enter, /quit to leave")
    receiving = asyncio.create_task(_receive_loop(session, out, label))
    typing = asyncio.create_task(_input_loop(session, read_line, out))
    try:
        done, pending = await asyncio.wait({receiving, typing}, return_when=asyncio.FIRST_COMPLETED)
        if receiving in done:
            out(f"{label} left the chat (press Enter to exit)")
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()                             # surface unexpected errors
    except asyncio.CancelledError:
        for task in (receiving, typing):
            task.cancel()
        raise
    return 0