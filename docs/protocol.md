# p2pssh Handshake Protocol (v1)

**Status:** DRAFT for Week-1 review. Owner: A.2 (Member 2). Reviewers: Member 1 (identity / trust store), Member 3 (record layer).
**Source of truth for the frozen contract:** project plan, section 4.1 (framing), 4.2 (handshake), 4.6 (error codes).
This document does **not** change any frozen byte layout. Where the plan leaves something open, it is listed in section 10 (Open questions) so we can decide it together.

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

- `sig_server = Ed25519.sign(server_id_priv, H1)`
- `sig_client = Ed25519.sign(client_id_priv, H2)`

Because H1 and H2 are different values, a signature produced by one role can never be accepted as the other role's signature (this is what stops reflection of signatures).

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

**Low-order points:** if `X25519()` raises, or if `shared` is 32 zero bytes, abort with `E_AUTH`.

**Cleanup:** after deriving, drop references to the ephemeral private key and to `shared` (best effort in Python). Do not log keys, `shared`, or the private identity key.

## 5. Verification rules (order matters)

Receiver of any handshake message, in this order:

1. **Length** is exactly the expected size, else `E_PROTOCOL`.
2. **Message order** is correct (ClientHello, then ServerHello, then ClientAuth), else `E_PROTOCOL`.
3. **Version** byte equals `0x01`, else `E_VERSION`.
4. **Reflection checks** (section 6).
5. **Signature** verifies with the `*_id_pub` that is *inside the same hello*, else `E_AUTH`.
6. **X25519** succeeds and is not all-zero (section 4), else `E_AUTH`.
7. **TrustStore** (only after the signature is valid; never trust an unsigned key):

| `TrustStore.check()` | Action |
|---|---|
| `TRUSTED` | Continue silently |
| `NEW` | Call the UI callback with the fingerprint. User says no: abort with `E_AUTH`, **store nothing**. User says yes: `TrustStore.add()` then continue |
| `CHANGED` | Abort with `E_KEYCHANGED`. Never auto-accept. The user must explicitly `trust remove <name>` and reconnect |

Signature check always happens before the trust prompt so a user is never asked about a key that the peer cannot prove it owns.

## 6. Attack analysis and defenses

| Attack | Defense |
|---|---|
| **Passive eavesdropper** | AEAD records keyed from ephemeral DH; nothing secret on the wire |
| **Active MITM swapping ephemeral keys** | Both ephemeral keys are inside the signed transcript, so the swap changes H1/H2 and the signature fails (`E_AUTH`) |
| **MITM substituting identity key** | Signature verifies only with the attacker's own key, which the TrustStore reports as `NEW` (user prompt) or `CHANGED` (abort) |
| **Replay of an old ServerHello / ClientAuth** | Both sides contribute a fresh nonce. An old signature is over a different transcript and fails |
| **Reflection** (attacker bounces our own ClientHello back at us) | Initiator rejects a ServerHello whose `server_eph_pub`, `server_nonce` or `server_id_pub` equals its own. Responder rejects a ClientHello whose `client_nonce` equals the one it already generated. Signatures are role-asymmetric (H1 vs H2) |
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
                            trust: TrustStore, role: str) -> SessionKeys
# role in {"initiator", "responder"}; raises HandshakeError
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

## 10. Open questions (decide at the Week-1 contract review)

1. **How does the handshake know the peer's *name* for `TrustStore.check(peer_name, pub)`?** The frozen interface has no `peer_name` argument. Proposal: `Node.dial()` sets `conn.peer_name` (discovery name or `"host:port"`), and the responder uses the claimed peer's fingerprint string as the lookup key. Needs agreement with Member 1.
2. **Cipher in A.3.** Plan 4.3 says ChaCha20-Poly1305; the current `record.py` uses AES-GCM. Pick one and update either the code or the plan. The handshake does not care, as it only outputs two 32-byte keys.
3. **Optional hardening:** add a domain-separation prefix such as `b"p2pssh v1 server"` / `b"p2pssh v1 client"` to the signed data. This would change the frozen signature input, so it needs everyone's approval; v1 is safe without it because H1 != H2.
4. **Self-connect:** should connecting to your own node be allowed (useful for local testing) or rejected as reflection?

## Appendix A. Reference computation (for test vectors)

```python
import hashlib, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

salt = hashlib.sha256(client_nonce + server_nonce).digest()
shared = my_eph_priv.exchange(peer_eph_pub)
keys = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=b"p2pssh v1").derive(shared)
c2s_key, s2c_key = keys[:32], keys[32:]
```