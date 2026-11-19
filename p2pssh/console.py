"""Interactive console (msfconsole-style) on top of the existing CLI commands.

Run:  p2pssh            (or: python -m p2pssh console)

Console features: first-run wizard, background `listen` (keep typing while you
wait for calls), numbered `peers`, `chat 1` / `chat ben` shortcuts, friendly
error hints, status, tab-completion (Linux/macOS), use/set/run modules.
Every other command is the normal CLI command, run in-process.
"""
import collections
import shlex
import sys
import threading
import time
import asyncio
from pathlib import Path

from p2pssh.config import ConfigError, load_config
from p2pssh.errors import P2PSSHError
from p2pssh.identity import (PRIVATE_NAME, IdentityError, TrustError, TrustStore,
                             fingerprint, load_or_create_identity)

try:                                   # tab-complete + history (not on bare Windows)
    import readline
except ImportError:
    readline = None

_USE_COLOR = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


OK, WARN, BAD = (lambda t: c(t, "32")), (lambda t: c(t, "33")), (lambda t: c(t, "31"))

MODULES = {"chat": {"target": ""}, "send": {"target": "", "file": ""}, "shell": {"target": ""}}

COMMANDS = ["help", "whoami", "keygen", "fingerprint", "peers", "scan", "announce", "trust",
            "config", "listen", "stop", "status", "connect", "chat", "send", "shell",
            "use", "options", "set", "run", "back", "clear", "exit", "quit"]

HELP = """
Talking to people
  peers (scan)              find people on the WiFi (numbered)
  chat <name|#|IP:port>     secure chat          e.g.  chat 1   chat ben
  send <name|#|IP:port> <file>                   send a file
  shell <name|#|IP:port>    remote shell (the host must allow it)

Being reachable
  listen [port]             wait for calls IN THE BACKGROUND (default 5555)
  stop                      stop listening
  status                    who am I, am I listening, who do I trust

Identity and settings
  whoami | keygen | fingerprint
  trust list | add <n> <hex> | remove <n>
  config show | set <key> <value>        e.g.  config set name asha

Modules (msfconsole style)
  use <chat|send|shell>  ->  options  ->  set target ben  ->  run  ->  back

Other:  help | clear | exit
"""

# (text to look for in the output (lowercase), advice)
HINTS = [
    ("refused", "Nobody is listening at that address. Ask them to run: listen"),
    ("not found on the lan", "Not found on this WiFi. Ask them to run 'listen' (it prints their "
                             "address), then use: chat <IP:port>"),
    ("timed out", "No answer. Check you are on the same network and the firewall allows Python."),
    ("changed", "A trusted key changed. Verify the new fingerprint with the person, then: "
                "trust remove <name>"),
    ("getaddrinfo", "That address is not valid. Use a name from 'peers' or IP:port."),
    ("address already in use", "That port is busy. Try: listen 5556"),
]


class Tee:
    """Pass output through live while remembering it, so we can add a hint after errors."""
    def __init__(self, real):
        self.real, self.buf = real, []

    def write(self, s):
        self.buf.append(s)
        return self.real.write(s)

    def flush(self):
        self.real.flush()

    def __getattr__(self, name):
        return getattr(self.real, name)


class StdinRouter:
    """One reader owns the real stdin. Prompts from background sessions (trust question,
    incoming chat) take priority over the console prompt, so lines go to the right place."""
    def __init__(self, real):
        self.real, self.cv, self.lines = real, threading.Condition(), collections.deque()
        self.eof, self.sessions = False, 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            line = self.real.readline()
            with self.cv:
                if line == "":
                    self.eof = True
                else:
                    self.lines.append(line)
                self.cv.notify_all()
            if line == "":
                return

    def readline(self):
        is_main = threading.current_thread() is threading.main_thread()
        with self.cv:
            while True:
                if self.lines and (not is_main or self.sessions == 0):
                    return self.lines.popleft()
                if self.eof and not self.lines:
                    return ""
                self.cv.wait(0.2)

    def session(self, delta):
        with self.cv:
            self.sessions += delta
            self.cv.notify_all()


class Listener:
    """`listen` running in a background thread with its own event loop."""
    def __init__(self, cfg, port, router):
        self.cfg, self.port, self.router = cfg, port, router
        self.ready, self.error, self.note = threading.Event(), None, ""
        self.loop = self.stop_evt = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()
        self.ready.wait(10)
        if self.error:
            raise self.error

    def _run(self):
        try:
            asyncio.run(self._main())
        except Exception as e:
            self.error = e
            self.ready.set()

    async def _main(self):
        from p2pssh import cli
        from p2pssh.transport import Node
        ident = load_or_create_identity(self.cfg.key_dir)
        trust = TrustStore(self.cfg.trust_path)
        inner = cli.make_on_conn(ident, trust, self.cfg)

        async def on_conn(conn):
            self.router.session(+1)
            try:
                await inner(conn)
            finally:
                self.router.session(-1)

        node = Node()
        await node.listen("0.0.0.0", self.port, on_conn)
        self.port = node.port
        self.loop, self.stop_evt = asyncio.get_running_loop(), asyncio.Event()
        d = None
        try:
            d = await self.loop.run_in_executor(None, cli._announce_blocking, self.cfg.name,
                                                node.port, fingerprint(ident.public_bytes()))
        except Exception as e:
            self.note = f"not announced on the LAN ({e or type(e).__name__}); use the address"
        self.ready.set()
        try:
            await self.stop_evt.wait()
        finally:
            if d is not None:
                await self.loop.run_in_executor(None, d.close)
            await node.close()

    def stop(self):
        if self.loop and self.stop_evt:
            self.loop.call_soon_threadsafe(self.stop_evt.set)
        self.thread.join(5)


def my_ip():
    try:
        from p2pssh.discovery import _local_ip
        return _local_ip()
    except Exception:
        return "127.0.0.1"


class Console:
    def __init__(self, cfg):
        self.cfg = cfg
        self.module, self.opts = None, {}
        self.peers = []                  # last scan: PeerInfo list
        self.listener = None
        self.router = None
        self.real_stdin = sys.stdin
        if readline is not None:
            readline.set_completer(self._complete)
            readline.parse_and_bind("tab: complete")

    # ---------- plumbing ----------
    def _complete(self, text, state):
        words = COMMANDS + [p.name for p in self.peers]
        matches = [w for w in words if w.startswith(text)]
        return matches[state] if state < len(matches) else None

    def ask(self, label):
        if self.router is not None:      # background sessions may need the keyboard too
            sys.stdout.write(label)
            sys.stdout.flush()
            line = self.router.readline()
            if line == "":
                raise EOFError
            return line.rstrip("\r\n")
        return input(label)

    def run_cli(self, tokens):
        """Run a normal p2pssh command in-process; never crash the console; add hints."""
        from p2pssh import cli
        try:
            args = cli.build_parser().parse_args(tokens)
        except SystemExit:
            return 1
        real_out, tee = sys.stdout, None
        try:
            tee = sys.stdout = Tee(real_out)
            self.cfg = load_config()     # pick up `config set` immediately
            return args.func(args, self.cfg)
        except KeyboardInterrupt:
            print("\n[stopped]")
        except (ConfigError, IdentityError, TrustError, P2PSSHError) as e:
            print(BAD(f"error: {e}"))
        except Exception as e:
            print(BAD(f"error: {e}"))
        finally:
            sys.stdout = real_out
            if tee is not None:
                text = "".join(tee.buf).lower()
                for needle, advice in HINTS:
                    if needle in text and ("error" in text or "refused" in text or "warning" in text):
                        print(WARN(f"hint: {advice}"))
                        break
        return 1

    def target(self, tok):
        """'1' or 'ben' from the last scan -> 'host:port'; anything else unchanged."""
        if tok.isdigit() and 1 <= int(tok) <= len(self.peers):
            p = self.peers[int(tok) - 1]
            return f"{p.host}:{p.port}"
        for p in self.peers:
            if p.name == tok:
                return f"{p.host}:{p.port}"
        return tok

    # ---------- commands ----------
    def cmd_peers(self, rest):
        from p2pssh.discovery import Discovery
        wait = 3.0
        if rest[:1] == ["--wait"] and len(rest) > 1:
            try:
                wait = float(rest[1])
            except ValueError:
                pass
        d = Discovery()
        try:
            d.browse()
            time.sleep(wait)
            found = sorted(d.peers(), key=lambda p: p.name)
        except Exception as e:
            print(BAD(f"error: {e}"))
            return
        finally:
            d.close()
        self.peers = found
        if not found:
            print("no peers found. Is the other person running 'listen'? Same WiFi? "
                  "(some WiFi blocks discovery: then use IP:port)")
            return
        try:
            known = {v.get("fingerprint") for v in TrustStore(self.cfg.trust_path).list_peers().values()}
            mine = fingerprint(load_or_create_identity(self.cfg.key_dir).public_bytes())
        except Exception:
            known, mine = set(), ""
        print(f"  {'#':<3} {'NAME':<16} {'ADDRESS':<22} STATUS")
        for i, p in enumerate(found, 1):
            status = c("you", "36") if p.fingerprint == mine else (
                OK("trusted") if p.fingerprint in known else WARN("new (not trusted yet)"))
            print(f"  {i:<3} {p.name:<16} {p.host + ':' + str(p.port):<22} {status}")
        print("  tip: chat 1   (or:  chat <name>)")

    def cmd_listen(self, rest):
        if self.listener:
            print(f"already listening on {my_ip()}:{self.listener.port}  (type 'stop' to stop)")
            return
        port = self.cfg.port or 5555
        if rest:
            try:
                port = int(rest[-1])
            except ValueError:
                print("usage: listen [port]")
                return
        if self.router is None:          # from now on, sessions and console share the keyboard
            self.router = StdinRouter(sys.stdin)
            sys.stdin = self.router
        lst = Listener(load_config(), port, self.router)
        try:
            lst.start()
        except Exception as e:
            print(BAD(f"error: {e}"))
            for needle, advice in HINTS:
                if needle in str(e).lower():
                    print(WARN(f"hint: {advice}"))
            return
        self.listener = lst
        print(OK(f"[+] listening in the background as '{self.cfg.name}'"))
        print(f"    others can reach you at  {c(my_ip() + ':' + str(lst.port), '1')}"
              f"   (or by name '{self.cfg.name}' on the same WiFi)")
        if lst.note:
            print(WARN(f"    note: {lst.note}"))
        print("    you can keep using the console. 'stop' ends listening.")

    def cmd_stop(self):
        if not self.listener:
            print("not listening")
            return
        self.listener.stop()
        self.listener = None
        print("stopped listening")

    def cmd_status(self):
        try:
            ident = load_or_create_identity(self.cfg.key_dir)
            fp = fingerprint(ident.public_bytes())
            trusted = len(TrustStore(self.cfg.trust_path).list_peers())
        except Exception:
            fp, trusted = "(no key: run keygen)", 0
        print(f"  name:       {self.cfg.name}")
        print(f"  fingerprint {fp}")
        print(f"  listening:  " + (OK(f"yes, {my_ip()}:{self.listener.port}") if self.listener else "no"))
        print(f"  shell:      {'ON' if self.cfg.allow_shell else 'off'}")
        print(f"  trusted:    {trusted} peer(s)    last scan: {len(self.peers)} found")

    # ---------- first run ----------
    def first_run(self):
        if (Path(self.cfg.key_dir) / PRIVATE_NAME).exists():
            return
        print(c("\n  Welcome to p2pssh!", "1") + " Looks like your first time. Quick setup:\n")
        try:
            name = self.ask(f"  Pick a name others will see [{self.cfg.name}]: ").strip()
        except EOFError:
            name = ""
        if name:
            self.run_cli(["config", "set", "name", name])
        self.run_cli(["keygen"])
        self.cfg = load_config()
        print("\n  Try these next:")
        print("    listen          be reachable (shows your address)")
        print("    peers           see who is on your WiFi")
        print("    chat 1          chat with the first person found")
        print("    help            everything else\n")

    def banner(self):
        try:
            fp = fingerprint(load_or_create_identity(self.cfg.key_dir).public_bytes())
        except Exception:
            fp = "(no key yet)"
        print(c("  +-------------------------------------------+", "36"))
        print(c("  |  p2pssh console   peer-to-peer, no server |", "36"))
        print(c("  +-------------------------------------------+", "36"))
        print(f"  name: {self.cfg.name}   shell: {'ON' if self.cfg.allow_shell else 'off'}")
        print(f"  id:   {fp}")
        print("  type 'help' for commands\n")

    # ---------- main loop ----------
    def loop(self):
        self.first_run()
        self.banner()
        while True:
            label = f"p2pssh ({c(self.module, '33')}) > " if self.module else "p2pssh > "
            if self.listener:
                label = label.replace("p2pssh", "p2pssh[listening]", 1) if not _USE_COLOR else label
            try:
                line = self.ask(label)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            try:
                tokens = shlex.split(line)
            except ValueError as e:
                print(BAD(f"error: {e}"))
                continue
            if tokens and self.dispatch(tokens[0].lower(), tokens[1:]) == "exit":
                break
        if self.listener:
            self.listener.stop()
        return 0

    def dispatch(self, cmd, rest):
        if cmd in ("exit", "quit"):
            return "exit"
        if cmd in ("help", "?"):
            print(HELP)
        elif cmd == "clear":
            print("\033[2J\033[H", end="")
        elif cmd in ("peers", "scan", "find"):
            self.cmd_peers(rest)
        elif cmd == "listen":
            self.cmd_listen(rest)
        elif cmd == "stop":
            self.cmd_stop()
        elif cmd == "status":
            self.cmd_status()
        elif cmd == "use":
            if len(rest) != 1 or rest[0] not in MODULES:
                print(f"usage: use <{'|'.join(MODULES)}>")
            else:
                self.module, self.opts = rest[0], dict(MODULES[rest[0]])
        elif cmd == "back":
            self.module, self.opts = None, {}
        elif cmd == "options":
            if not self.module:
                print("no module selected (use <chat|send|shell>)")
            for k, v in (self.opts or {}).items():
                print(f"  {k:<8} {v or WARN('(not set)')}")
        elif cmd == "set":
            if not self.module:
                print("no module selected (use <chat|send|shell>)")
            elif len(rest) < 2 or rest[0] not in self.opts:
                print(f"usage: set <{'|'.join(self.opts) or 'key'}> <value>")
            else:
                self.opts[rest[0]] = " ".join(rest[1:])
                print(f"{rest[0]} => {self.opts[rest[0]]}")
        elif cmd == "run":
            self.run_module()
        elif cmd in ("chat", "send", "shell", "connect"):
            if rest:
                rest = [self.target(rest[0])] + rest[1:]
            self.run_cli([cmd] + rest)
        elif cmd == "console":
            print("already in the console")
        elif cmd in COMMANDS:
            self.run_cli([cmd] + rest)
        else:
            print(BAD(f"unknown command '{cmd}'") + " (type 'help')")

    def run_module(self):
        if not self.module:
            print("no module selected (use <chat|send|shell>)")
            return
        missing = [k for k, v in self.opts.items() if not v]
        if missing:
            print(WARN(f"missing option(s): {', '.join(missing)}  (use: set <key> <value>)"))
            return
        tgt = self.target(self.opts["target"])
        toks = [self.module, tgt] + ([self.opts["file"]] if self.module == "send" else [])
        self.run_cli(toks)


def console(cfg=None):
    return Console(cfg or load_config()).loop()


if __name__ == "__main__":
    sys.exit(console())