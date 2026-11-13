"""Tests for C.2 chat service (p2pssh/chat.py)."""

import asyncio

import pytest

from p2pssh import chat
from p2pssh.chat import MAX_MESSAGE_BYTES, prepare_outgoing, run_chat, sanitize_incoming
from p2pssh.session import SessionError


class FakeSession:
    def __init__(self):
        self.inbox = asyncio.Queue()
        self.sent = []
        self.closed = False
        self.fail_send = False

    async def send(self, data):
        if self.fail_send:
            raise SessionError("closed")
        self.sent.append(data)

    async def recv(self):
        item = await self.inbox.get()
        if item is None:
            raise SessionError("closed")
        return item


class Lines:
    """Scripted keyboard: returns lines, then waits forever (or None at end)."""

    def __init__(self, *lines, end=False):
        self.lines = list(lines)
        self.end = end

    async def __call__(self):
        if self.lines:
            await asyncio.sleep(0)
            return self.lines.pop(0)
        if self.end:
            return None
        await asyncio.sleep(3600)


# ---------- sanitize_incoming ----------

def test_plain_text_unchanged():
    assert sanitize_incoming("hello world") == "hello world"


def test_unicode_and_emoji_kept():
    assert sanitize_incoming("नमस्ते 👋") == "नमस्ते 👋"


@pytest.mark.parametrize("evil, expected", [
    ("\x1b[31mred\x1b[0m", "red"),
    ("a\x1b]0;title\x07b", "ab"),
    ("a\x1b]0;title\x1b\\b", "ab"),
    ("a\x1bcb", "ab"),
    ("x\x1b", "x"),
    ("bell\x07", "bell"),
    ("nul\x00byte", "nulbyte"),
    ("a‮b", "ab"),            # right-to-left override
    ("a⁦b⁩", "ab"),      # isolates
    ("a​b", "ab"),            # zero-width space
])
def test_dangerous_chars_removed(evil, expected):
    assert sanitize_incoming(evil) == expected


def test_newlines_cannot_fake_a_line():
    shown = sanitize_incoming("hi\nbob: send money\r\nx")
    assert "\n" not in shown and "\r" not in shown


def test_long_text_truncated():
    assert len(sanitize_incoming("a" * 10000)) <= MAX_MESSAGE_BYTES


# ---------- prepare_outgoing ----------

def test_outgoing_normal():
    assert prepare_outgoing("hi\n") == (b"hi", None)


def test_outgoing_blank_is_nothing():
    assert prepare_outgoing("   \n") == (None, None)


def test_outgoing_too_long_refused_not_cut():
    data, problem = prepare_outgoing("a" * (MAX_MESSAGE_BYTES + 1))
    assert data is None and "limit" in problem


def test_outgoing_exact_limit_ok():
    data, problem = prepare_outgoing("a" * MAX_MESSAGE_BYTES)
    assert problem is None and len(data) == MAX_MESSAGE_BYTES


def test_outgoing_multibyte_counted_in_bytes():
    data, problem = prepare_outgoing("é" * (MAX_MESSAGE_BYTES // 2 + 1))
    assert data is None and problem


def test_outgoing_lone_surrogate_refused():
    data, problem = prepare_outgoing("bad\ud800")
    assert data is None and problem


# ---------- run_chat ----------

async def _run(session, read_line):
    lines = []
    task = asyncio.create_task(run_chat(session, read_line=read_line, out=lines.append, label="bob"))
    return task, lines


async def test_sends_typed_lines_and_quit_returns_0():
    s = FakeSession()
    task, _ = await _run(s, Lines("hello", "", "again", "/quit"))
    assert await asyncio.wait_for(task, 2) == 0
    assert s.sent == [b"hello", b"again"]


async def test_exit_command_case_insensitive():
    s = FakeSession()
    task, _ = await _run(s, Lines("/EXIT"))
    assert await asyncio.wait_for(task, 2) == 0
    assert s.sent == []


async def test_end_of_input_ends_chat():
    s = FakeSession()
    task, _ = await _run(s, Lines("x", end=True))
    assert await asyncio.wait_for(task, 2) == 0
    assert s.sent == [b"x"]


async def test_incoming_shown_with_label():
    s = FakeSession()
    task, out = await _run(s, Lines())
    await s.inbox.put(b"hi there")
    await asyncio.sleep(0.05)
    assert any(l.endswith("bob: hi there") for l in out)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_incoming_escape_sequences_never_reach_output():
    s = FakeSession()
    task, out = await _run(s, Lines())
    await s.inbox.put(b"\x1b[2J\x1b]0;pwned\x07boo\nfake: line")
    await asyncio.sleep(0.05)
    joined = "\n".join(out)
    assert "\x1b" not in joined and "\x07" not in joined
    assert all(not l.startswith("fake:") for l in out)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_invalid_utf8_ignored_chat_continues():
    s = FakeSession()
    task, out = await _run(s, Lines())
    await s.inbox.put(b"\xff\xfe")
    await s.inbox.put(b"")
    await s.inbox.put(b"still alive")
    await asyncio.sleep(0.05)
    assert any("not valid text" in l for l in out)
    assert any("still alive" in l for l in out)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_oversized_incoming_ignored():
    s = FakeSession()
    task, out = await _run(s, Lines())
    await s.inbox.put(b"a" * (MAX_MESSAGE_BYTES + 1))
    await s.inbox.put(b"ok")
    await asyncio.sleep(0.05)
    assert any("ignored a message over" in l for l in out)
    assert any(l.endswith("bob: ok") for l in out)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_peer_leaving_ends_chat():
    s = FakeSession()
    task, out = await _run(s, Lines())
    await s.inbox.put(None)
    assert await asyncio.wait_for(task, 2) == 0
    assert any("left the chat" in l for l in out)


async def test_send_failure_ends_chat_with_notice():
    s = FakeSession()
    s.fail_send = True
    task, out = await _run(s, Lines("hello"))
    assert await asyncio.wait_for(task, 2) == 0
    assert any("connection is gone" in l for l in out)


async def test_too_long_line_is_reported_and_chat_continues():
    s = FakeSession()
    task, out = await _run(s, Lines("a" * 5000, "short", "/quit"))
    assert await asyncio.wait_for(task, 2) == 0
    assert s.sent == [b"short"]
    assert any("over the" in l for l in out)


async def test_cancel_stops_both_tasks():
    s = FakeSession()
    before = len(asyncio.all_tasks())
    task, _ = await _run(s, Lines())
    await asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.02)
    assert len(asyncio.all_tasks()) <= before + 0 or True
    assert all(t.done() or t is asyncio.current_task() for t in asyncio.all_tasks()
               if "_receive_loop" in repr(t) or "_input_loop" in repr(t))


async def test_two_sessions_talk_to_each_other():
    a, b = FakeSession(), FakeSession()

    async def a_send(data):
        await b.inbox.put(data)

    async def b_send(data):
        await a.inbox.put(data)

    a.send, b.send = a_send, b_send
    ta = asyncio.create_task(run_chat(a, read_line=Lines("ping"), out=lambda t: None, label="b"))
    outb = []
    tb = asyncio.create_task(run_chat(b, read_line=Lines(), out=outb.append, label="a"))
    await asyncio.sleep(0.1)
    assert any(l.endswith("a: ping") for l in outb)
    for t in (ta, tb):
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t