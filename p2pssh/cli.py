"""C.2a - command-line entry point 

Usage:  python -m p2pssh.cli <command>
Commands: whoami | peers | announce | trust list/add/remove | config show/set
          connect | shell | chat   (placeholders until the handshake exists)
"""
import argparse
import dataclasses
import sys
import time

from p2pssh.config import (Config, ConfigError, config_path, load_config,
                           save_config)
from p2pssh.discovery import Discovery, DiscoveryError
from p2pssh.identity import (IdentityError, TrustError, TrustStore,
                             fingerprint, load_or_create_identity)


def cmd_whoami(args, cfg):
    ident = load_or_create_identity(cfg.key_dir)
    print(f"name:        {cfg.name}")
    print(f"fingerprint: {fingerprint(ident.public_bytes())}")
    print(f"public key:  {ident.public_bytes().hex()}")
    print(f"key folder:  {cfg.key_dir}")
    print(f"port:        {cfg.port or 'auto'}")
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
        if(len(pub)!=32):
            print("error: public key must be 32 bytes (64 hex characters)")
            return 1
        
        store.add(args.name, pub)
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
    if args.key not in ("name", "port", "allow_self") or args.value is None:
        print("error: usage: config set <name|port|allow_self> <value>")
        return 1
    if args.key == "port":
        try:
            value = int(args.value)
        except ValueError:
            print("error: port must be a number")
            return 1
    elif args.key == "allow_self":
        if args.value.lower() not in ("true", "false"):
            print("error: allow_self must be true or false")
            return 1
        value = args.value.lower() == "true"
    else:
        value = args.value
    save_config(dataclasses.replace(cfg, **{args.key: value}))
    print(f"{args.key} = {value}")
    return 0


def cmd_not_ready(args, cfg):
    print(f"'{args.command}' is not available yet (needs the handshake from Member 2).")
    return 2


def build_parser():
    p = argparse.ArgumentParser(prog="p2pssh", description="Peer-to-peer secure communication")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("whoami", help="show my name and fingerprint").set_defaults(func=cmd_whoami)

    sp = sub.add_parser("peers", help="list peers found on the LAN")
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

    for name in ("connect", "shell", "chat"):
        sub.add_parser(name, help="(needs handshake)").set_defaults(func=cmd_not_ready)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, load_config())
    except (ConfigError, IdentityError, TrustError, DiscoveryError) as e:
        print(f"error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())