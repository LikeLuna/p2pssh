"""C.2a - command-line entry point

Usage:  python -m p2pssh.cli <command>
Commands: whoami | fingerprint | keygen | peers (find) | announce
          trust list/add/remove | config show/set
          listen | connect | chat | send | shell
"""
import argparse
import dataclasses
import os
import asyncio
import sys
import time
from pathlib import Path

from p2pssh.config import (ConfigError, config_path, load_config, save_config)
from p2pssh.errors import E_KEYCHANGED, HandshakeError, P2PSSHError
from p2pssh.handshake import perform_handshake
from p2pssh.discovery import Discovery, DiscoveryError, parse_hostport
from p2pssh.identity import (PRIVATE_NAME, IdentityError, TrustError, TrustStore,
                             fingerprint, load_or_create_identity)
from p2pssh.files import FileTransferError, receive_file, send_file
from p2pssh.prompts import clean_text, confirm_fingerprint
from p2pssh.services import (SERVICE_CHAT, SERVICE_FILE, SERVICE_SHELL, make_authorizer,
                             request_service, serve_service)
from p2pssh.session import SecureSession, SessionError
from p2pssh.shell import ShellError, pty_available, run_shell_client, serve_shell
from p2pssh.transport import Node

# Everything a command can raise while talking to a peer; shown as "error: ...", never a traceback.
_RUNTIME_ERRORS = (P2PSSHError, SessionError, FileTransferError, ShellError, OSError)


def cmd_whoami(args, cfg):
    ident = load_or_create_identity(cfg.key_dir)
    print(f"name:        {cfg.name}")
    print(f"fingerprint: {fingerprint(ident.public_bytes())}")
    print(f"public key:  {ident.public_bytes().hex()}")
    print(f"key folder:  {cfg.key_dir}")
    print(f"port:        {cfg.port or 'auto'}")
    print(f"shell:       {'ON' if cfg.allow_shell else 'off'}")
    return 0


def cmd_keygen(args, cfg):
    existed = (Path(cfg.key_dir) / PRIVATE_NAME).exists()
    ident = load_or_create_identity(cfg.key_dir)
    print("key already exists (not changed)" if existed else "new key created")
    print(f"fingerprint: {fingerprint(ident.public_bytes())}")
    return 0


def cmd_fingerprint(args, cfg):
    print(fingerprint(load_or_create_identity(cfg.key_dir).public_bytes()))
    return 0


def cmd_peers(args, cfg):
    d = Discovery()
    try:
        d.browse()
        time.sleep(args.wait)
        peers = d.peers()
    finally:
        d.close()
    if not peers:
        print("no peers found")
        return 0
    for p in sorted(peers, key=lambda p: p.name):
        print(f"{p.name:<20} {p.host}:{p.port:<6} {p.fingerprint}")
    return 0


def cmd_announce(args, cfg):
    if cfg.port == 0:
        print("error: set a fixed port first: config set port 5000")
        return 1
    ident = load_or_create_identity(cfg.key_dir)
    d = Discovery()
    try:
        d.announce(cfg.name, cfg.port, fingerprint(ident.public_bytes()))
        print(f"announcing '{cfg.name}' on port {cfg.port}  (Ctrl+C to stop)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        d.close()
    return 0


def cmd_trust(args, cfg):
    store = TrustStore(cfg.trust_path)
    if args.action == "list":
        peers = store.list_peers()
        if not peers:
            print("no trusted peers")
        for name, e in sorted(peers.items()):
            print(f"{name:<20} {e['fingerprint']}  first seen {e['first_seen']}")
    elif args.action == "add":
        if not args.name or not args.pubkey_hex:
            print("error: usage: trust add <name> <64-char-hex-public-key>")
            return 1
        try:
            pub = bytes.fromhex(args.pubkey_hex)
        except ValueError:
            print("error: public key must be hex")
            return 1
        if len(pub) != 32:
            print("error: public key must be 32 bytes (64 hex characters)")
            return 1
        try:
            store.add(args.name, pub)
        except TrustError as exc:
            print(f"error: {exc}")
            return 1
        print(f"trusted '{args.name}' ({fingerprint(pub)})")
    elif args.action == "remove":
        if not args.name:
            print("error: usage: trust remove <name>")
            return 1
        store.remove(args.name)
        print(f"removed '{args.name}' (if it existed)")
    return 0


def cmd_config(args, cfg):
    if args.action == "show":
        print(f"file: {config_path()}")
        for k, v in dataclasses.asdict(cfg).items():
            print(f"{k:<12} {v}")
        return 0
    if args.key not in ("name", "port", "allow_self", "allow_shell") or args.value is None:
        print("error: usage: config set <name|port|allow_self|allow_shell> <value>")
        return 1
    if args.key == "port":
        try:
            value = int(args.value)
        except ValueError:
            print("error: port must be a number")
            return 1
    elif args.key in ("allow_self", "allow_shell"):
        if args.value.lower() not in ("true", "false"):
            print(f"error: {args.key} must be true or false")
            return 1
        value = args.value.lower() == "true"
    else:
        value = args.value
    save_config(dataclasses.replace(cfg, **{args.key: value}))
    print(f"{args.key} = {value}")
    return 0


# ---------------------------------------------------------------- listen / connect
async def _confirm(fp, name):
    """Handshake callback for NEW peers. input() runs in a thread so the event loop stays alive."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: confirm_fingerprint(name, fp))


def _load_chat():
    """chat.py (Member 2) must expose  async def run_chat(session). None until it exists."""
    try:
        from p2pssh.chat import run_chat
    except ImportError:
        return None
    return run_chat


def _host_handlers(cfg):
    """What this host offers to peers that connect to it."""
    async def file_handler(session):
        dest = Path(cfg.key_dir) / "downloads"
        dest.mkdir(parents=True, exist_ok=True)
        path = await receive_file(session, dest)
        print(f"received file: {path}")

    handlers = {SERVICE_FILE: file_handler, SERVICE_SHELL: serve_shell}
    chat = _load_chat()
    if chat is not None:
        handlers[SERVICE_CHAT] = chat
    return handlers


def _host_authorizer(cfg, trust, peer_fingerprint):
    """Host-side permission check: the shell needs allow_shell ON + a trusted key + a pty."""
    base = make_authorizer(cfg, trust, peer_fingerprint)

    def authorize(name):
        reason = base(name)
        if reason:
            return reason
        if name == SERVICE_SHELL and not pty_available():
            return "this host cannot run a shell (needs Linux, macOS or WSL)"
        return None
    return authorize


def _report_handshake_error(e, trust, name):
    if isinstance(e, HandshakeError) and e.code == E_KEYCHANGED:
        old = trust.list_peers().get(name, {}).get("fingerprint", "?")
        print(f"WARNING: the key for '{clean_text(name)}' CHANGED (trusted: {old}). Refused.")
        print(f"If this is legitimate, verify the new fingerprint, then: p2pssh trust remove {clean_text(name)}")
    else:
        print(f"handshake failed: {getattr(e, 'message', None) or e}")


def _resolve_target(target):
    """'IP:port' or a peer name found on the LAN -> (host, port, label)."""
    if ":" in target:
        host, port = parse_hostport(target)
        return host, port, target
    d = Discovery()
    try:
        d.browse()
        time.sleep(3.0)
        peers = d.peers()
    finally:
        d.close()
    for p in peers:                       # mDNS is only a hint; trust still comes from the handshake
        if p.name == target:
            return p.host, p.port, p.name
    raise DiscoveryError(f"peer '{clean_text(target)}' not found on the LAN (try IP:port)")


def make_on_conn(ident, trust, cfg):
    """Callback for Node.listen: handshake as responder, then serve ONE service."""
    async def on_conn(conn):
        try:
            keys = await perform_handshake(conn, ident, trust, "responder",
                                           cfg.allow_self, confirm=_confirm)
        except P2PSSHError as e:
            _report_handshake_error(e, trust, getattr(conn, "peer_name", "?"))
            return
        session = SecureSession(conn, keys)
        print(f"secure channel established (responder) with {keys.peer_fingerprint}")
        try:
            name = await serve_service(session, _host_handlers(cfg),
                                       _host_authorizer(cfg, trust, keys.peer_fingerprint))
            print(f"'{name}' session finished")
        except _RUNTIME_ERRORS as e:
            print(f"session ended: {e}")
        finally:
            await session.close()
    return on_conn


def _announce_blocking(name, port, fp):
    d = Discovery()                       # zeroconf must be used OUTSIDE the asyncio loop thread
    try:
        d.announce(name, port, fp)
    except Exception:
        d.close()
        raise
    return d


def cmd_listen(args, cfg):
    ident = load_or_create_identity(cfg.key_dir)
    trust = TrustStore(cfg.trust_path)
    port = args.port if args.port is not None else cfg.port

    async def run():
        loop = asyncio.get_running_loop()
        node = Node()
        await node.listen("0.0.0.0", port, make_on_conn(ident, trust, cfg))
        print(f"listening on port {node.port} as '{cfg.name}'  (Ctrl+C to stop)")
        d = None
        try:
            d = await loop.run_in_executor(
                None, _announce_blocking, cfg.name, node.port, fingerprint(ident.public_bytes()))
        except Exception as e:            # discovery is optional; IP:port still works
            print(f"note: not announced on the LAN ({e or type(e).__name__})")
        try:
            await asyncio.Event().wait()
        finally:
            if d is not None:
                await loop.run_in_executor(None, d.close)
            await node.close()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nstopped")
    except P2PSSHError as e:
        print(f"error: {e}")
        return 1
    return 0


def _run_client(cfg, target, service, client_fn):
    """Dial a peer, handshake, ask for ONE service, run client_fn(session) on it.
    service=None only proves the secure channel works (used by `connect`)."""
    host, port, label = _resolve_target(target)
    ident = load_or_create_identity(cfg.key_dir)
    trust = TrustStore(cfg.trust_path)

    async def run():
        conn = await Node().dial(host, port, name=label)
        try:
            keys = await perform_handshake(conn, ident, trust, "initiator",
                                           cfg.allow_self, confirm=_confirm)
        except P2PSSHError as e:
            _report_handshake_error(e, trust, label)
            await conn.close()
            return 1
        session = SecureSession(conn, keys)
        print(f"secure channel established (initiator) with {keys.peer_fingerprint}")
        try:
            if service is not None:
                await request_service(session, service)
                return await client_fn(session) or 0
            return 0
        except _RUNTIME_ERRORS as e:
            print(f"error: {e}")
            return 1
        finally:
            await session.close()

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        print("\nstopped")
        return 1
    except _RUNTIME_ERRORS as e:
        print(f"error: {e}")
        return 1


def cmd_connect(args, cfg):
    if not args.target:
        print("error: usage: connect <peer-name | IP:port>")
        return 1
    return _run_client(cfg, args.target, None, None)


def cmd_send(args, cfg):
    if not args.target or not args.path:
        print("error: usage: send <peer-name | IP:port> <file>")
        return 1
    if not os.path.isfile(args.path):
        print(f"error: file not found: {args.path}")
        return 1

    async def client(session):
        await send_file(session, args.path)
        print(f"sent {os.path.basename(args.path)}")
    return _run_client(cfg, args.target, SERVICE_FILE, client)


def cmd_shell(args, cfg):
    if not args.target:
        print("error: usage: shell <peer-name | IP:port>")
        return 1
    if not pty_available():
        print("error: remote shell needs a Unix terminal: use Linux, macOS or WSL")
        return 1
    return _run_client(cfg, args.target, SERVICE_SHELL, run_shell_client)


def cmd_chat(args, cfg):
    if not args.target:
        print("error: usage: chat <peer-name | IP:port>")
        return 1
    run_chat = _load_chat()
    if run_chat is None:
        print("'chat' is not available yet (waiting for chat.py).")
        return 2
    return _run_client(cfg, args.target, SERVICE_CHAT, run_chat)


def build_parser():
    p = argparse.ArgumentParser(prog="p2pssh", description="Peer-to-peer secure communication")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("whoami", help="show my name and fingerprint").set_defaults(func=cmd_whoami)
    sub.add_parser("keygen", help="create my key (never overwrites)").set_defaults(func=cmd_keygen)
    sub.add_parser("fingerprint", help="print my fingerprint").set_defaults(func=cmd_fingerprint)

    sp = sub.add_parser("peers", aliases=["find"], help="list peers found on the LAN")
    sp.add_argument("--wait", type=float, default=3.0, help="seconds to listen")
    sp.set_defaults(func=cmd_peers)

    sub.add_parser("announce", help="make me visible on the LAN").set_defaults(func=cmd_announce)

    sp = sub.add_parser("trust", help="manage trusted peers")
    sp.add_argument("action", choices=["list", "add", "remove"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("pubkey_hex", nargs="?")
    sp.set_defaults(func=cmd_trust)

    sp = sub.add_parser("config", help="show or change settings")
    sp.add_argument("action", choices=["show", "set"])
    sp.add_argument("key", nargs="?")
    sp.add_argument("value", nargs="?")
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser("listen", help="accept connections")
    sp.add_argument("--port", type=int)
    sp.set_defaults(func=cmd_listen)
    sp = sub.add_parser("connect", help="connect to a peer name or IP:port")
    sp.add_argument("target", nargs="?")
    sp.set_defaults(func=cmd_connect)

    sp = sub.add_parser("chat", help="chat with a peer name or IP:port")
    sp.add_argument("target", nargs="?")
    sp.set_defaults(func=cmd_chat)

    sp = sub.add_parser("shell", help="open a shell on a peer (the HOST must allow it)")
    sp.add_argument("target", nargs="?")
    sp.set_defaults(func=cmd_shell)

    sp = sub.add_parser("send", help="send a file to a peer name or IP:port")
    sp.add_argument("target", nargs="?")
    sp.add_argument("path", nargs="?")
    sp.set_defaults(func=cmd_send)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, load_config())
    except (ConfigError, IdentityError, TrustError, DiscoveryError, *_RUNTIME_ERRORS) as e:
        print(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())