# p2pssh: Peer-to-Peer Secure Communication (No Central Server)

Every machine runs the same program and acts as both client and server. Two peers find each other, prove who they are with public keys, agree on a one-time secret, and then **chat, transfer files, or open a remote shell** over an encrypted channel. No relay or central server is involved.

> Minor project, 3 members. This README tells you **what exists, who owns which file, and how to work without stepping on each other.** Read it fully before writing code.

---

## 1. Quick Start

```bash
git clone https://github.com/LikeLuna/p2pssh.git
cd p2pssh
python -m venv venv
```

Activate the virtual environment (use the line for your shell):

| Shell | Command |
|---|---|
| Git Bash | `source venv/Scripts/activate` |
| PowerShell | `.\venv\Scripts\Activate.ps1` |
| Linux / macOS / WSL | `source venv/bin/activate` |

```bash
pip install -r requirements.txt
pytest            # should pass (only a sanity test at the start)
```

**Platform notes**
- Use **Linux, macOS or WSL** for anything involving `pty` (remote shell, Member 1 / C.1). Native Windows has no `pty` module.
- File-permission tests (`chmod 0600`) do not behave on native Windows. Run them in WSL.
- Always run `git` and `pytest` from the **repo root** (the first `p2pssh` folder).

---

## 2. The Big Picture (layman version)

Think of three friends on the same WiFi who want to talk privately, with no company in the middle.

| Layer | What it means | Simple analogy |
|---|---|---|
| **A: Crypto** | Identity, handshake, encryption | ID cards, secret handshake, sealed envelopes |
| **B: Network** | Finding peers, connecting, sending bytes | Phonebook and phone line |
| **C: Application** | Chat, files, shell, CLI, testing | What the user actually does, and proof it works |

### The pipeline: what happens when Asha talks to Ben

```
 1. DISCOVERY      Asha's laptop sees Ben on the WiFi                      (discovery.py)
        |
 2. CONNECT        Asha dials Ben over TCP; messages are length-prefixed   (transport.py)
        |
 3. IDENTITY       Each side loads its permanent key pair and checks the   (identity.py)
        |          other's key against the trusted-peers address book
        |
 4. HANDSHAKE      Both prove identity (signatures) and agree on fresh     (handshake.py)
        |          secret keys that nobody else can compute
        |
 5. SECURE LAYER   Every message is encrypted + tamper-proofed + numbered  (record.py, session.py)
        |
 6. APPLICATION    Chat / file transfer / remote shell run on top          (chat.py, files.py, shell.py)
        |
 7. USER           Typed commands: p2pssh chat ben, p2pssh send ...        (cli.py, config.py)
```

Each step only needs the **interface** of the step before it, not its code. That is why we can all work at the same time.

---

## 3. Who Owns What

> **Rule: you edit only the files you own.** If you need a change in someone else's file, ask them or open a small pull request and tag them.

### Ownership table

| Member | Owns (edits freely) | Tasks |
|---|---|---|
| **Member 1** | `identity.py`, `discovery.py`, `shell.py`, `cli.py`, `config.py` and their tests | A.1 Identity + trust store, B.1 mDNS discovery, C.1 Remote shell, C.2a CLI skeleton + config |
| **Member 2** | `handshake.py`, `transport.py`, `chat.py`, `docs/protocol.md` and their tests | A.2 Handshake, B.2 Connection manager + framing, C.2b Chat |
| **Member 3** | `record.py`, `session.py`, `files.py`, `nat.py` (or `mesh.py`), `tests/stubs.py`, `tests/integration/`, `scripts/`, `.github/`, and docs other than the protocol | A.3 Record layer, B.3 NAT / multi-peer (bonus), C.2c File transfer, C.3 Testing, security analysis, report |

*(Detailed per-task work items, test cases and boundary cases are in `P2P_Secure_Comm_Project_Plan.md`.)*

### What each member does, in plain words

**Member 1: the ID cards, the phonebook and the remote control**
- `identity.py`: creates each laptop's permanent ID card (Ed25519 key pair), and keeps an address book of trusted peers. If a known peer's card suddenly changes, it warns loudly.
- `discovery.py`: shouts "I'm here!" on the WiFi and lists who else is nearby (mDNS). Also supports typing `IP:port` by hand.
- `shell.py`: lets you type commands on a friend's computer, safely. Off by default.
- `cli.py` + `config.py`: the command-line entry point (`p2pssh listen / peers / chat / send / shell / keygen / trust`) and the settings file.

**Member 2: the secret handshake, the phone line and chat**
- `handshake.py`: two laptops prove identity and agree on one-time secret keys (X25519 + signatures + HKDF).
- `transport.py`: opens TCP connections (every node can listen and dial), sends data in length-labelled "envelopes", handles timeouts and disconnects.
- `chat.py`: interactive secure chat on top of the secure session.
- `docs/protocol.md`: the written specification of the handshake and message format. This is the document everyone relies on.

**Member 3: the sealed envelopes, file transfer, and proof**
- `record.py` + `session.py`: encrypts every message with the session key, numbers them, and rejects anything changed, repeated or reordered. `session.py` is the object the application layer uses (`send` / `recv`).
- `files.py`: file transfer with hash check and safe filenames.
- `nat.py` / `mesh.py`: bonus, reaching beyond one LAN or group chat.
- Tests, CI, Docker lab, Wireshark and MITM demos, final report.

### Shared files (everyone touches, change carefully)

| File | Purpose | Change rule |
|---|---|---|
| `p2pssh/constants.py` | Frame sizes, message type numbers, version | Small PR, **all 3 must approve** |
| `p2pssh/errors.py` | Error codes and exception classes | Small PR, **all 3 must approve** |
| `requirements.txt` | Dependencies | Small PR, 1 approval, add only what you need |
| `pytest.ini`, `.gitignore` | Test and git config | Member 3 maintains; ask before editing |
| `README.md` | This file | Update your own section/status only |
| `docs/protocol.md` | Wire format spec | Member 2 edits; others review |

---

## 4. Folder Map

```
p2pssh/                      <- repo root: run git and pytest here
  README.md  requirements.txt  pytest.ini  .gitignore
  .github/workflows/test.yml          (M3)  CI: runs pytest on every push
  docs/
    protocol.md                       (M2)  handshake + message spec
    architecture.md  threat_model.md  (M3)
  p2pssh/                    <- the Python package
    __init__.py
    constants.py  errors.py           SHARED
    identity.py                       (M1)  A.1
    discovery.py                      (M1)  B.1
    shell.py                          (M1)  C.1
    cli.py  config.py                 (M1)  C.2a
    handshake.py                      (M2)  A.2
    transport.py                      (M2)  B.2
    chat.py                           (M2)  C.2b
    record.py  session.py             (M3)  A.3
    files.py                          (M3)  C.2c
    nat.py / mesh.py                  (M3)  B.3 (bonus)
  tests/
    stubs.py                          (M3)  fakes so everyone can test alone
    test_identity.py test_discovery.py test_shell.py test_cli.py      (M1)
    test_handshake.py test_transport.py test_chat.py                  (M2)
    test_record.py test_files.py test_nat.py                          (M3)
    integration/                      (M3)  tests combining modules
  scripts/                            (M3)  mitm_proxy.py, demo.sh
```

---

## 5. Working Independently: Stubs and Interfaces

The function signatures that everyone agreed on are listed in section 4.5 of the plan and exist as empty stubs (`raise NotImplementedError`) in each file. **Do not change a signature on your own.** If you must, tell the team first.

What each person fakes until the real module arrives:

| You need | From | Until then use |
|---|---|---|
| Fingerprint function | Member 1 | Any fixed string such as `"SHA256:test"` |
| A real connection (`send_frame` / `recv_frame`) | Member 2 | A fake pair built on `asyncio.Queue` (see `tests/stubs.py`) |
| Session keys | Member 2 | Two random 32-byte keys from `os.urandom(32)` |
| A secure session (`send` / `recv`) | Member 3 | The same fake queue pair |
| A peer list | Member 1 | A hard-coded list |

Integration (plugging the real modules together) happens in **Week 4**.

---

## 6. Git Workflow (every task, every time)

```bash
git checkout main && git pull                  # 1. start from latest main
git checkout -b feat/a1-identity               # 2. one branch per task
# ... write code AND tests ...
pytest                                         # 3. tests must pass locally
git add .
git commit -m "A.1: key generation and loading"
git push -u origin feat/a1-identity            # 4. push your branch
```

5. Open a **Pull Request** on GitHub into `main`.
6. A teammate reviews it. CI must be green.
7. Merge, then `git checkout main && git pull`.

**Branch names:** `feat/<task>-<name>`, e.g. `feat/b1-discovery`, `feat/a2-handshake`, `feat/c1-shell`.

**Rules**
- Never push directly to `main` after the skeleton commit.
- Never commit private keys, `known_peers.json`, `.p2pssh/`, or your venv. They are in `.gitignore`; if `git status` shows them, stop and ask.
- Commit small and often. Pull `main` into your branch at least every couple of days.
- A task is **done** only when its tests (normal + boundary) pass and its exit criteria in the plan are met.

---

## 7. Interface Cheat-Sheet (what other people will call)

```python
# identity.py (M1)
load_or_create_identity(path) -> Identity
Identity.sign(data) -> bytes ; Identity.public_bytes() -> bytes   # 32 bytes
fingerprint(pub) -> "SHA256:..."
TrustStore.check(name, pub) -> NEW | TRUSTED | CHANGED ; .add(name, pub) ; .remove(name)

# discovery.py (M1)
Discovery.announce(name, port, fingerprint) ; .browse(callback) ; .peers() -> list[PeerInfo]

# transport.py (M2)
Node.listen(host, port, on_connection) ; Node.dial(host, port) -> Connection
Connection.send_frame(bytes) ; .recv_frame() -> bytes ; .close()

# handshake.py (M2)
perform_handshake(conn, identity, trust, role) -> SessionKeys   # role: "initiator" | "responder"

# record.py / session.py (M3)
RecordLayer(send_key, recv_key).seal(plaintext) -> bytes ; .open(record) -> bytes
SecureSession.send(msg_type, channel, payload) ; .recv()
```

Message types, frame limits and error codes are in `constants.py` and `errors.py`.

---

## 8. Timeline and Status

| Week | Goal | M1 | M2 | M3 |
|---|---|---|---|---|
| 1 | Skeleton, contracts, stubs | A.1 start | Protocol spec, B.2 start | Repo, CI, stubs |
| 2 | Core modules alone | A.1 done, B.1 start | A.2 on stubs, B.2 | A.3 core |
| 3 | Core modules finish | B.1 done, C.1 start | A.2, B.2 done, chat start | A.3 done, files, B.3 start |
| 4 | Integration | C.1 shell, cli.py | Chat polish | Integration tests, Wireshark |
| 5 | Features + polish | Shell polish | Bug fixes | MITM demo, soak test |
| 6 | Freeze, report, demo | Docs for own files | Docs for own files | Report, slides, evidence |

**Progress checklist** (tick when merged to `main` with passing tests)

- [X] A.1 Identity + trust store (M1)
- [X] B.1 Discovery (M1)
- [x] C.1 Remote shell (M1)
- [X] CLI + config (M1)
- [ ] A.2 Handshake (M2)
- [ ] B.2 Transport (M2)
- [ ] Chat (M2)
- [ ] A.3 Record layer + session (M3)
- [ ] File transfer (M3)
- [ ] B.3 NAT / multi-peer (M3, bonus)
- [ ] CI + stubs (M3)
- [ ] Integration tests I-1 to I-12 (all)
- [ ] Wireshark + MITM evidence (M3)
- [ ] Report, slides, demo rehearsed (all)

---

## 9. Security Rules for Everyone

- Use only the `cryptography` library. **Never invent your own crypto.**
- Never log or print private keys, session keys or plaintext of secure traffic.
- Treat all network input as hostile: check lengths before allocating, never trust filenames or terminal control characters.
- Discovery data (mDNS, invite codes) is only a **hint**. Real trust comes from the handshake and the trust store.
- The remote shell is **off by default** and only for explicitly allowed, trusted peers.

---

## 10. Contacts and Meetings

| Member | Name | GitHub | Owns |
|---|---|---|---|
| 1 | _fill in_ | _fill in_ | Identity, discovery, shell, CLI |
| 2 | _fill in_ | _fill in_ | Handshake, transport, chat |
| 3 | _fill in_ | _fill in_ | Record layer, files, tests, docs |

Weekly sync: _day and time_. Integration build: end of every week, from Week 4.