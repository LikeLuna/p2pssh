# p2pssh: private chat, file transfer and remote shell. No server. No accounts. No middleman.

## What is this?

**p2pssh lets two computers talk to each other directly and privately.**

Think WhatsApp + Dropbox + SSH, except there is no company in the middle. No sign-up, no cloud, no server that can read or log your data. Your computer talks straight to your friend's computer over an encrypted channel.

| Problem with normal apps | What p2pssh does instead |
|---|---|
| A company server sits between you and your friend | Direct connection, nothing in the middle |
| You need an account and password | Your identity is a cryptographic key made on your own machine |
| You trust the app to be honest | You verify your friend's key fingerprint yourself |
| Messages can be read or altered on the server | Everything is encrypted and tamper-proof from end to end |

## What can you do with it?

| Feature | What you get |
|---|---|
| **Secure chat** | Live, encrypted 1-to-1 chat |
| **File transfer** | Send any file; its SHA-256 hash is checked so it arrives intact, and it never overwrites your files |
| **Remote shell** | Run commands on a friend's machine. **Off by default**; the host must switch it on and trust your key |
| **Auto discovery** | See who is on the same WiFi by name, no IP needed |
| **Interactive console** | Just type `p2pssh`: a friendly prompt with help, status and shortcuts |
| **Key trust** | Compare fingerprints once; if a trusted key ever changes, the connection is refused |

## How does it work? (the 30-second version)

1. **Identity.** Each machine makes a permanent key pair (Ed25519). The public half is your ID card.
2. **Trust on first use.** The first time you meet someone you both see a *fingerprint*. Compare it by call or message. If it matches, say `yes`. After that they are trusted.
3. **Handshake.** You prove who you are with signatures and agree on one-time secret keys (X25519 + HKDF) that nobody else can work out.
4. **Secure channel.** Every message is encrypted, numbered and tamper-checked. Anything changed, repeated or reordered is rejected.
5. **Use it.** Chat, send files, or open a shell on top of that channel.

**Safety net:** if a trusted friend's key changes (a sign of an impostor), p2pssh refuses and warns you.

---

## Install (one time, 2 minutes)

You need Python 3.10+ and git.

```
git clone https://github.com/LikeLuna/p2pssh.git
cd p2pssh
python -m venv venv
```

Activate the environment:

| Your terminal | Command |
|---|---|
| Windows PowerShell | `.\venv\Scripts\Activate.ps1` |
| Git Bash | `source venv/Scripts/activate` |
| Linux / macOS / WSL | `source venv/bin/activate` |

Then install the `p2pssh` command:

```
pip install -e .
```

That's it. From now on, with the environment active, just type:

```
p2pssh
```

> The `p2pssh` command only exists while the venv is activated. Developers who want to run the tests also run `pip install -r requirements.txt`.
>
> Remote shell needs Linux, macOS or WSL. Chat and file transfer work everywhere.

---

## Your first 60 seconds

Type `p2pssh`. On first run it asks for a name, creates your key, and prints what to try next:

```
  Welcome to p2pssh! Looks like your first time. Quick setup:

  Pick a name others will see [mylaptop]: asha
  new key created

  Try these next:
    listen          be reachable (shows your address)
    peers           see who is on your WiFi
    chat 1          chat with the first person found
    help            everything else

p2pssh >
```

### Console commands

| Command | Does |
|---|---|
| `help` | List everything |
| `status` | Your name, fingerprint, are you listening, trusted count |
| `listen [port]` | Wait for calls **in the background** (default port 5555). Prints the address others can reach you at. You can keep typing |
| `stop` | Stop listening |
| `peers` | Numbered list of people on your WiFi (trusted / new) |
| `chat <name \| # \| IP:port>` | Secure chat, e.g. `chat 1` or `chat ben` |
| `send <name \| # \| IP:port> <file>` | Send a file |
| `shell <name \| # \| IP:port>` | Remote shell (host must allow it) |
| `trust list / add / remove` | Manage trusted people |
| `config show / set name asha` | View or change settings |
| `use chat` then `set target ben` then `run` | The step-by-step "module" style |
| `exit` | Leave |

Normal one-line commands still work too, e.g. `p2pssh chat 192.168.1.7:5555`.

When something fails, you get a hint, for example:
```
error: peer 'nobody' not found on the LAN (try IP:port)
hint: Not found on this WiFi. Ask them to run 'listen' ...
```

---

## Demo A: two laptops on the same WiFi

**Laptop 1 (Asha):**
```
p2pssh
p2pssh > listen
[+] listening in the background as 'asha'
    others can reach you at  192.168.1.5:5555
```

**Laptop 2 (Ben):**
```
p2pssh
p2pssh > peers
  #   NAME   ADDRESS            STATUS
  1   asha   192.168.1.5:5555   new (not trusted yet)
p2pssh > chat 1
```

Both screens show a fingerprint. Compare it with the other person (call or message), then type `yes`. Now type messages. `/quit` leaves the chat; the other side presses Enter to return to the console.

**Send a file** (Ben to Asha):
```
p2pssh > send 1 myfile.pdf
```
Asha finds it in her `downloads` folder inside her p2pssh home (`~/.p2pssh/downloads`).

**If `peers` shows nobody** (some college or office WiFi blocks discovery), use the address Asha saw when she started `listen`:
```
p2pssh > chat 192.168.1.5:5555
```
A phone hotspot usually allows discovery.

---

## Demo B: only ONE laptop? No problem

Open two terminal windows and give each its own identity with `P2PSSH_HOME`. The program then sees two different people. The address `127.0.0.1` means "this same computer".

**Window 1 (Asha):**

PowerShell:
```
cd p2pssh
.\venv\Scripts\Activate.ps1
$env:P2PSSH_HOME="$HOME\p2p_a"
p2pssh
```
Linux/macOS/WSL: replace the `$env:` line with `export P2PSSH_HOME=~/p2p_a`.

Complete the wizard (name `asha`), then:
```
p2pssh > listen 5555
```

**Window 2 (Ben):**

PowerShell:
```
cd p2pssh
.\venv\Scripts\Activate.ps1
$env:P2PSSH_HOME="$HOME\p2p_b"
p2pssh
```
Linux/macOS/WSL: use `export P2PSSH_HOME=~/p2p_b`.

Complete the wizard (name `ben`), then:
```
p2pssh > chat 127.0.0.1:5555
```

Type `yes` in both windows when asked. Messages typed in one window appear in the other. Window 1's console stays usable the whole time.

Send a file from window 2:
```
p2pssh > send 127.0.0.1:5555 path\to\file.txt
```
It lands in `p2p_a\downloads\`.

---

## Demo C: remote shell (advanced, Linux/macOS/WSL)

The host must opt in. This is deliberate: nobody can run commands on your machine unless you allow it AND you trust their key.

**Host:**
```
p2pssh > config set allow_shell on
p2pssh > listen
```

**Guest:**
```
p2pssh > shell asha
```
(If the host refuses, they must first trust your key: `trust add ben <your public key from whoami>`.)

---

## Where things live

Your data is in `~/.p2pssh/` (or the folder in `P2PSSH_HOME`): private key (permission 0600), public key, trusted peers list, config, and received `downloads/`. **Never share or commit your private key.**

## Run the tests

```
pip install -r requirements.txt
pytest
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `p2pssh` not recognised | Activate the venv first, then run `pip install -e .` |
| `peers` shows nobody | WiFi blocks discovery. Use `IP:port`, or a phone hotspot |
| Connection refused / timeout | Is `listen` running on the other side? Allow Python through the firewall |
| "key CHANGED, refused" | Could be an impostor. Verify the new fingerprint with your friend, then `trust remove <name>` |
| Shell does not work on Windows | Use WSL; native Windows has no `pty` |
| Port already in use | `listen 5556` |
| Old `venv` folder errors | Delete it and recreate with `python -m venv venv` |

## Known limits

- 1-to-1 only: no group chat yet.
- No offline messages and no saved chat history: both people must be online.
- Works on one network (or a reachable IP:port); no NAT traversal yet.
- On Linux/macOS, after your first `listen`, tab-completion and arrow-key history in the console turn off.
- Student project: the protocol has not been independently audited. Don't use it to protect real secrets.