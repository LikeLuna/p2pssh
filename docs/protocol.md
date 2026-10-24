# p2pssh Handshake Protocol (v1)

**Status:** v1, contract decisions recorded (2026-10-23). Owner: A.2 (Member 2). Reviewed by Member 1 (identity / trust store); Member 3 (record layer) to confirm AES-256-GCM (section 10, decision 2).
**Source of truth for the frozen contract:** project plan, section 4.1 (framing), 4.2 (handshake), 4.6 (error codes).
Wire message sizes (97 / 161 / 64 bytes) are unchanged. The only change to the frozen plan is the role prefix on the signed data (section 3.2), agreed in the review of the first draft. All decisions are recorded in section 10.

---

## 1. Goals

After the handshake both peers hold:

| Property | How |
|---|---|
| **Mutual authentication** | Each side signs a hash of the handshake transcript with its long-term Ed25519 identity key |
| **Key agreement** | Ephemeral X25519 Diffie-Hellman |
| **Forward secrecy** | Ephemeral private keys are discarded after the handshake; stealing an identity key later does not reveal old sessions |
| **Replay / reflection protection** | Fresh 32-byte nonces from both sides, signed transcript, role-asymmetric signatures |
| **MITM detection** | Signatures bind both ephemeral keys; the identity key is checked against the TrustStore (TOFU) |
| **Two directional keys** | `c2s_key` and `s2c_key`, so a record sent one way can never be replayed the other way |

**Non-goals:** anonymity (identity public keys are sent in the clear), NAT traversal, hiding that a p2pssh connection exists.

## 2. Roles and transport

- **Initiator** = the side that dialed (client). **Responder** = the side that accepted (server).
- Every handshake message is sent as **one frame** of the B.2 transport: `[4-byte big-endian length N][N bytes]`, `MAX_FRAME_SIZE = 65536`.
- All integers/fields are raw bytes. There is no text, JSON or varint encoding in the handshake.
- The handshake runs on a fresh TCP connection **before** any application data. Nothing else may be sent until it finishes.

## 3. Messages

`version` is `0x01` for this document.

```
1. ClientHello  (97 bytes)
   version(1) | client_eph_pub(32) | client_nonce(32) | client_id_pub(32)

2. ServerHello  (161 bytes)
   version(1) | server_eph_pub(32) | server_nonce(32) | server_id_pub(32) | sig_server(64)

3. ClientAuth   (64 bytes)
   sig_client(64)
```

Field meaning:

| Field | Size | Content |
|---|---|---|
| `version` | 1 | `0x01` |
| `*_eph_pub` | 32 | Fresh X25519 public key, raw bytes, generated for this connection only |
| `*_nonce` | 32 | `os.urandom(32)` |
| `*_id_pub` | 32 | Long-term Ed25519 public key, raw bytes (`Identity.public_bytes()`) |
| `sig_*` | 64 | Ed25519 signature |

### 3.1 Flow

```
Initiator (client)                                  Responder (server)
------------------                                  ------------------
gen eph key c_e, nonce c_n
ClientHello  --------------------------------------------------->
                                                    gen eph key s_e, nonce s_n
                                                    sig_server = Sign(s_id, H1)
<---------------------------------------------------  ServerHello
verify sig_server with server_id_pub
TrustStore.check(server)  (NEW -> ask user, CHANGED -> abort)
sig_client = Sign(c_id, H2)
ClientAuth  --------------------------------------------------->
                                                    verify sig_client with client_id_pub
                                                    TrustStore.check(client)
derive keys                                         derive keys
== encrypted records (A.3) from here on ==
```

### 3.2 Transcript hashes

Hashes are computed over the **exact bytes sent/received on the wire**. Never re-serialize a parsed message.

```
CH       = ClientHello bytes (97)
SH_nosig = ServerHello bytes without the last 64 bytes (97)
SH       = full ServerHello bytes (161)

H1 = SHA256( CH || SH_nosig )      # signed by the server
H2 = SHA256( CH || SH )            # signed by the client (covers the server signature too)
```

Signed data carries a role-specific, fixed 16-byte prefix (domain separation):

```
PREFIX_SERVER = b"p2pssh v1 server"     # 16 bytes
PREFIX_CLIENT = b"p2pssh v1 client"     # 16 bytes

sig_server = Ed25519.sign(server_id_priv, PREFIX_SERVER || H1)    # signs 48 bytes
sig_client = Ed25519.sign(client_id_priv, PREFIX_CLIENT || H2)    # signs 48 bytes
```

The prefix is **not** sent on the wire, so message sizes do not change. Verification rebuilds the same 48 bytes. The prefix and the fact that H1 and H2 are different values together mean a signature made for one role or one protocol can never be accepted as the other role's signature (this is what stops reflection and cross-context reuse of signatures). `Identity.sign()` / `verify()` (A.1) work on arbitrary bytes, so no change is needed there.

## 4. Key derivation

```
shared  = X25519(my_eph_priv, peer_eph_pub)                 # 32 bytes
salt    = SHA256( client_nonce || server_nonce )
keys    = HKDF-SHA256(ikm = shared, salt = salt, info = b"p2pssh v1", length = 64)
c2s_key = keys[0:32]        # client -> server
s2c_key = keys[32:64]       # server -> client
session_id = H2[0:16]       # 16 bytes, for logging / correlation only; not secret
```

| Role | `send_key` | `recv_key` |
|---|---|---|
| Initiator | `c2s_key` | `s2c_key` |
| Responder | `s2c_key` | `c2s_key` |

The result is returned as `SessionKeys(send_key, recv_key, peer_pub, peer_fingerprint, session_id)` and handed to `RecordLayer(send_key, recv_key)` (A.3).

**Record-layer cipher:** AES-256-GCM (decision 2 in section 10; the original plan text said ChaCha20-Poly1305). The handshake only outputs two independent 32-byte keys, so it does not depend on the cipher choice. Both ciphers use a 12-byte nonce, so the plan's nonce format (4 zero bytes + 8-byte counter) is unchanged.

**Low-order points:** if `X25519()` raises, or if `shared` is 32 zero bytes, abort with `E_AUTH`.

**Cleanup:** after deriving, drop references to the ephemeral private key and to `shared` (best effort in Python). Do not log keys, `shared`, or the private identity key.

## 5. Verification rules (order matters)

Receiver of any handshake message, in this order:

1. **Length** is exactly the expected size, else `E_PROTOCOL`.
2. **Message order** is correct (ClientHello, then ServerHello, then ClientAuth), else `E_PROTOCOL`.
3. **Version** byte equals `0x01`, else `E_VERSION`.
4. **Reflection / self-connect checks** (section 6). These run before any trust prompt.
5. **Signature** verifies with the `*_id_pub` that is *inside the same hello*, else `E_AUTH`.
6. **X25519** succeeds and is not all-zero (section 4), else `E_AUTH`.
7. **TrustStore** (only after the signature is valid; never trust an unsigned key):

| `TrustStore.check()` | Action |
|---|---|
| `TRUSTED` | Continue silently |
| `NEW` | Call the UI callback with the fingerprint. User says no: abort with `E_AUTH`, **store nothing**. User says yes: `TrustStore.add()` then continue |
| `CHANGED` | Abort with `E_KEYCHANGED`. Never auto-accept. The user must explicitly `trust remove <name>` and reconnect |

Signature check always happens before the trust prompt so a user is never asked about a key that the peer cannot prove it owns.

**Peer name for `TrustStore.check(name, pub)` (decision 1):** the name is only a label; the public-key fingerprint is the identity, and `TrustStore` decisions rest on the key, not on the name alone.
- *Initiator:* uses `conn.peer_name`, set by `Node.dial()` to the discovery name, or `"host:port"` when the user gave an address.
- *Responder:* the connecting client has no stable name (its source port is random), so the responder looks the client up by the client's fingerprint string (`"SHA256:..."`). Consequence: on the responder side an unknown key is always `NEW` (there is no per-name `CHANGED`). This is the same as an allow-list of fingerprints. **To be confirmed with Member 1.**

## 6. Attack analysis and defenses

| Attack | Defense |
|---|---|
| **Passive eavesdropper** | AEAD records keyed from ephemeral DH; nothing secret on the wire |
| **Active MITM swapping ephemeral keys** | Both ephemeral keys are inside the signed transcript, so the swap changes H1/H2 and the signature fails (`E_AUTH`) |
| **MITM substituting identity key** | Signature verifies only with the attacker's own key, which the TrustStore reports as `NEW` (user prompt) or `CHANGED` (abort) |
| **Replay of an old ServerHello / ClientAuth** | Both sides contribute a fresh nonce. An old signature is over a different transcript and fails |
| **Reflection** (attacker bounces our own ClientHello back at us) | Initiator rejects a ServerHello whose `server_eph_pub`, `server_nonce` or `server_id_pub` equals its own. Connecting to your own node (`server_id_pub` equals own identity) is rejected unless `allow_self=True` (CLI: `--allow-self`, for local testing only); every other check still runs in that mode. Responder rejects a ClientHello whose `client_nonce` equals the one it already generated. Signatures are role-asymmetric (H1 vs H2) |
| **Downgrade** | Single version `0x01`; unknown version is a hard fail with `E_VERSION`. No algorithm negotiation exists, so nothing to downgrade |
| **Truncated / oversized / garbage message** | Exact length checks; frame limit 64 KiB enforced by B.2; any parse problem is `E_PROTOCOL` with no stack trace leaked to the peer |
| **Slowloris at handshake** | Overall handshake deadline 10 s (`HANDSHAKE_TIMEOUT`), then `E_TIMEOUT` and the socket is closed |
| **Low-order X25519 key** | Reject zero shared secret (section 4) |
| **Key compromise later** | Forward secrecy from ephemeral keys |
| **Timing leaks** | Any equality check on secret-derived values uses `hmac.compare_digest` |

**Out of scope for v1:** hiding identities from a passive observer, protection against a compromised endpoint, denial of service by connection flooding (B.2 rate limits help but are not a security proof).

## 7. Errors

Codes from plan section 4.6. Handshake maps conditions like this:

| Code | Name | When |
|---|---|---|
| 1 | `E_VERSION` | Unknown `version` byte |
| 2 | `E_AUTH` | Bad signature, low-order key, user rejected a `NEW` peer |
| 3 | `E_KEYCHANGED` | `TrustStore.check()` returned `CHANGED` |
| 7 | `E_TIMEOUT` | 10 s deadline exceeded |
| 8 | `E_PROTOCOL` | Wrong length, wrong order, premature close, reflection detected |

On any failure the implementation raises `HandshakeError(code, message)` locally and **closes the connection without sending an error detail** (no plaintext error frame before authentication, so failures do not act as an oracle). The local log shows the code and reason, never key material.

## 8. Python interface (frozen, plan 4.5)

```python
async def perform_handshake(conn: Connection, identity: Identity,
                            trust: TrustStore, role: str,
                            allow_self: bool = False) -> SessionKeys
# role in {"initiator", "responder"}; raises HandshakeError
# allow_self is an optional keyword with a default, so the frozen 4-argument call still works
```

```python
@dataclass
class SessionKeys:
    send_key: bytes        # 32
    recv_key: bytes        # 32
    peer_pub: bytes        # 32, peer's Ed25519 identity key
    peer_fingerprint: str  # "SHA256:..."
    session_id: bytes      # 16
```

## 9. Test plan

Normal (A2-N1..N6): keys match crosswise, keys differ every connection, NEW accepted / rejected, TRUSTED silent, derived keys usable with `RecordLayer`.
Boundary / attack (A2-B1..B14): MITM swap, bit-flipped signature, truncated message, wrong order, wrong version, timeout, zero shared secret, close mid-handshake, reflection, replayed ServerHello, signer key differs from hello key.
Run first against `tests/stubs.py` (in-memory queues), then over real TCP with B.2.

## 10. Decisions (resolved from the review of the first draft)

| # | Question | Decision |
|---|---|---|
| 1 | Peer name for `TrustStore.check(name, pub)` | `Node.dial()` sets `conn.peer_name` (discovery name, or `"host:port"` for a direct address). The name is a label, the key fingerprint is the identity. Responder side looks up the client by fingerprint (section 5). Responder lookup still to be confirmed with Member 1 |
| 2 | Record-layer cipher | **AES-256-GCM**, matching the merged `record.py`. Awaiting explicit confirmation from Member 3. The project plan text and the report must be updated from ChaCha20-Poly1305 |
| 3 | Domain separation in signed data | **Adopted.** Signed bytes are `PREFIX || H` with the 16-byte prefixes in section 3.2. Not sent on the wire |
| 4 | Self-connect | **Rejected by default.** Allowed only with `allow_self=True` / `--allow-self`; no other check is skipped |

## Appendix A. Reference computation (for test vectors)

```python
import hashlib, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# signing (see section 3.2)
sig_server = server_id_priv.sign(b"p2pssh v1 server" + H1)
sig_client = client_id_priv.sign(b"p2pssh v1 client" + H2)

salt = hashlib.sha256(client_nonce + server_nonce).digest()
shared = my_eph_priv.exchange(peer_eph_pub)
keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"p2pssh v1").derive(shared)
c2s_key, s2c_key = keys[:32], keys[32:]
```