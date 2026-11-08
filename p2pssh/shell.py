"""C.1 - remote shell over a pty (Member 1). Linux / macOS / WSL only.

ShellServer: runs a shell in a pseudo-terminal (host side).
run_client:  forwards my terminal to the remote shell (connecting side).
Both use plain callbacks so they work on a fake connection and, later,
on SecureSession. Only expose this to TRUSTED peers (enforced in the CLI).
"""
import asyncio
import os
import shutil
import signal
import struct
import sys

try:
    import fcntl
    import pty
    import termios
    import tty
    HAVE_PTY = True
except ImportError:      # native Windows
    HAVE_PTY = False

READ_SIZE = 4096


class ShellError(Exception):
    pass


def _require_pty():
    if not HAVE_PTY:
        raise ShellError("remote shell needs pty: use Linux, macOS or WSL")


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


class ShellServer:
    def __init__(self, on_output, on_exit=None, shell=None, rows=24, cols=80):
        _require_pty()
        self._on_output = on_output
        self._on_exit = on_exit
        self._shell = shell or os.environ.get("SHELL") or "/bin/sh"
        self._rows, self._cols = rows, cols
        self._pid = None
        self._fd = None
        self._loop = None
        self._wbuf = b""
        self._exit = None            # asyncio.Future for the exit code

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._exit = self._loop.create_future()
        pid, fd = pty.fork()
        if pid == 0:                                     # child: become the shell
            os.environ["TERM"] = os.environ.get("TERM", "xterm-256color")
            try:
                os.execvp(self._shell, [self._shell])
            finally:
                os._exit(127)
        self._pid, self._fd = pid, fd
        os.set_blocking(fd, False)
        _set_winsize(fd, self._rows, self._cols)
        self._loop.add_reader(fd, self._readable)

    def _readable(self) -> None:
        try:
            data = os.read(self._fd, READ_SIZE)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if data:
            self._on_output(data)
        else:
            self._finish()

    def feed(self, data: bytes) -> None:
        """Keystrokes from the remote user."""
        if self._fd is None:
            return
        self._wbuf += data
        self._flush()

    def _flush(self) -> None:
        while self._wbuf:
            try:
                n = os.write(self._fd, self._wbuf)
            except BlockingIOError:
                self._loop.add_writer(self._fd, self._flush)
                return
            except OSError:
                self._wbuf = b""
                return
            self._wbuf = self._wbuf[n:]
        self._loop.remove_writer(self._fd)

    def resize(self, rows: int, cols: int) -> None:
        if self._fd is not None and 1 <= rows <= 1000 and 1 <= cols <= 1000:
            _set_winsize(self._fd, rows, cols)

    def _finish(self) -> None:
        if self._fd is None:
            return
        self._loop.remove_reader(self._fd)
        self._loop.remove_writer(self._fd)
        os.close(self._fd)
        self._fd = None
        try:
            _, status = os.waitpid(self._pid, 0)
            code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            code = 0
        if self._on_exit:
            self._on_exit(code)
        if not self._exit.done():
            self._exit.set_result(code)

    async def wait(self) -> int:
        return await self._exit

    def close(self) -> None:
        """Kill the shell (peer disconnected)."""
        if self._pid is not None and self._fd is not None:
            try:
                os.kill(self._pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            self._finish()


async def run_client(send_input, send_resize, output_queue: "asyncio.Queue") -> None:
    """Connect my terminal to a remote shell.

    send_input(bytes)          - my keystrokes -> remote
    send_resize(rows, cols)    - my window size -> remote
    output_queue               - remote output bytes; None means remote closed
    """
    _require_pty()
    loop = asyncio.get_running_loop()
    fd_in = sys.stdin.fileno()
    saved = termios.tcgetattr(fd_in)

    def report_size(*_):
        size = shutil.get_terminal_size()
        send_resize(size.lines, size.columns)

    def on_stdin():
        data = os.read(fd_in, READ_SIZE)
        if data:
            send_input(data)

    try:
        tty.setraw(fd_in)
        loop.add_reader(fd_in, on_stdin)
        loop.add_signal_handler(signal.SIGWINCH, report_size)
        report_size()
        while True:
            chunk = await output_queue.get()
            if chunk is None:
                break
            os.write(sys.stdout.fileno(), chunk)
    finally:
        loop.remove_reader(fd_in)
        loop.remove_signal_handler(signal.SIGWINCH)
        termios.tcsetattr(fd_in, termios.TCSADRAIN, saved)   # always restore terminal





# ---------------------------------------------------------------- shell over a SecureSession
# Inside the "shell" service the two sides exchange tagged records:
#   client -> host : b"D" + keystrokes          b"R" + rows (2 bytes) + cols (2 bytes)
#   host -> client : b"O" + terminal output     b"X" + exit code (1 byte), then the host stops
TAG_IN, TAG_RESIZE, TAG_OUT, TAG_EXIT = b"D", b"R", b"O", b"X"
CHUNK = 8 * 1024          # well below the session's 16 KiB record limit


def pty_available() -> bool:
    try:
        _require_pty()
    except ShellError:
        return False
    return True


async def serve_shell(session, shell=None) -> int:
    """HOST side: run a shell in a pty and bridge it to the session. Returns its exit code.
    If the peer disconnects, the shell is killed (no orphan process)."""
    out = asyncio.Queue()
    exit_code = [0]

    def finished(code):
        exit_code[0] = code
        out.put_nowait(None)

    server = ShellServer(out.put_nowait, on_exit=finished, shell=shell)
    server.start()

    async def pump():
        while True:
            data = await out.get()
            if data is None:
                break
            for i in range(0, len(data), CHUNK):
                await session.send(TAG_OUT + data[i:i + CHUNK])
        await session.send(TAG_EXIT + bytes([exit_code[0] & 0xFF]))

    async def reader():
        while True:
            msg = await session.recv()
            tag, body = msg[:1], msg[1:]
            if tag == TAG_IN:
                server.feed(body)
            elif tag == TAG_RESIZE and len(body) == 4:
                rows, cols = struct.unpack(">HH", body)
                server.resize(rows, cols)
            # any other tag is ignored

    tasks = [asyncio.ensure_future(pump()), asyncio.ensure_future(reader())]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            t.result()                      # re-raise a session error, if any
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        server.close()
    return exit_code[0]


async def run_shell_client(session) -> int:
    """CLIENT side: connect my terminal to the host's shell. Returns the remote exit code."""
    _require_pty()
    out_q = asyncio.Queue()
    exit_code = [0]
    pending = set()

    def spawn(coro):
        task = asyncio.ensure_future(coro)
        pending.add(task)
        task.add_done_callback(lambda t: (pending.discard(t), t.cancelled() or t.exception()))

    def send_input(data):
        for i in range(0, len(data), CHUNK):
            spawn(session.send(TAG_IN + data[i:i + CHUNK]))

    def send_resize(rows, cols):
        spawn(session.send(TAG_RESIZE + struct.pack(">HH", min(rows, 65535), min(cols, 65535))))

    async def receiver():
        try:
            while True:
                msg = await session.recv()
                tag, body = msg[:1], msg[1:]
                if tag == TAG_OUT:
                    out_q.put_nowait(body)
                elif tag == TAG_EXIT:
                    exit_code[0] = body[0] if body else 0
                    return
        finally:
            out_q.put_nowait(None)          # tell run_client the remote side is gone

    recv_task = asyncio.ensure_future(receiver())
    try:
        await run_client(send_input, send_resize, out_q)
    finally:
        failure = None
        if recv_task.done() and not recv_task.cancelled():
            failure = recv_task.exception()
        recv_task.cancel()
        for t in list(pending):
            t.cancel()
        await asyncio.gather(recv_task, *pending, return_exceptions=True)
    if failure is not None:
        raise failure
    return exit_code[0]