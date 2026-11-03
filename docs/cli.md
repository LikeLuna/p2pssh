# CLI, config and trust prompts (Member 1)

**Files:** `p2pssh/cli.py`, `config.py`, `prompts.py`, `__main__.py`
**Tests:** `tests/test_cli.py`, `test_config.py`, `test_prompts.py`, `test_truststore_lookup.py`

Run as `python -m p2pssh <command>` or `p2pssh <command>`.

## Commands
| Command | What it does | Status |
|---|---|---|
| `whoami`, `fingerprint`, `keygen` | show or create my identity (keygen never overwrites) | done |
| `peers` (alias `find`) | list peers seen on the LAN (mDNS) | done |
| `announce` | make me visible on the LAN | done |
| `trust list / add / remove` | manage the trusted-peers file | done |
| `config show / set` | name, port, allow_self, allow_shell | done |
| `listen [--port N]` | accept connections; handshake as responder | done (stops after the handshake) |
| `connect <name or IP:port>` | dial a peer; handshake as initiator | done (stops after the handshake) |
| `chat`, `send`, `shell` | input is checked (`_precheck`); real work needs the secure session | waiting for M3 |

## Trust prompts (TOFU)
- Known peer, same key: connects silently.
- **NEW** peer: shows the fingerprint and asks `yes/no`. Anything except a clear yes is a no. Compare the fingerprint with the peer by another channel first.
- **CHANGED** key (initiator side): refused, even if the user would say yes. Fix with `trust remove <name>` after verifying.
- The responder knows the client only by key, so it stores new peers under their fingerprint.
- Peer-controlled text is cleaned before printing (no terminal escape injection).

## Files and settings
Everything lives in `$P2PSSH_HOME` (default `~/.p2pssh`): `id_ed25519` (private, 0600), `id_ed25519.pub`, `known_peers.json`, `config.json`. A corrupt config or trust file is backed up and replaced, never a crash.

## How listen / connect work
`cli.py` is a thin layer: `Node` (transport) gives a `Connection`, `perform_handshake` (handshake) gives `SessionKeys`, and `_after_handshake(conn, keys, cfg, role)` is where chat, file transfer and shell will plug in once `SecureSession(conn, keys)` exists. `listen` also announces itself by mDNS (optional; `IP:port` always works).

## Manual test (two terminals)
```
$env:P2PSSH_HOME="D:\tmp\a"; python -m p2pssh listen --port 5000
$env:P2PSSH_HOME="D:\tmp\b"; python -m p2pssh connect 127.0.0.1:5000
```
Answer `yes` on both sides the first time; the second connect needs no prompt.