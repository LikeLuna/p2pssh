import asyncio
import pytest
from p2pssh.shell import HAVE_PTY, ShellServer

pytestmark = pytest.mark.skipif(not HAVE_PTY, reason="needs pty (Linux/macOS/WSL)")


async def _read_until(buf: bytearray, needle: bytes, timeout=5):
    for _ in range(int(timeout * 20)):
        if needle in buf:
            return True
        await asyncio.sleep(0.05)
    return False


async def test_echo_and_clean_exit():
    out = bytearray()
    srv = ShellServer(out.extend, shell="/bin/sh")
    srv.start()
    srv.feed(b"echo hello-p2p\n")
    assert await _read_until(out, b"hello-p2p")
    srv.feed(b"exit 3\n")
    assert await asyncio.wait_for(srv.wait(), 5) == 3


async def test_resize_is_applied():
    out = bytearray()
    srv = ShellServer(out.extend, shell="/bin/sh")
    srv.start()
    srv.resize(40, 100)
    srv.feed(b"stty size\n")
    assert await _read_until(out, b"40 100")
    srv.close()


async def test_close_kills_shell():
    srv = ShellServer(lambda b: None, shell="/bin/sh")
    srv.start()
    srv.close()
    assert await asyncio.wait_for(srv.wait(), 5) is not None


async def test_bad_resize_ignored():
    srv = ShellServer(lambda b: None, shell="/bin/sh")
    srv.start()
    srv.resize(0, 0)
    srv.resize(-5, 99999)
    srv.close()