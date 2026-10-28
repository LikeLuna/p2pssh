import asyncio
import enum
import hashlib
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from p2pssh.errors import (
    E_AUTH,
    E_KEYCHANGED,
    E_PROTOCOL,
    E_TIMEOUT,
    E_VERSION,
    ConnectionClosed,
    ConnTimeout,
    HandshakeError,
)
from p2pssh.handshake import PREFIX_CLIENT, PREFIX_SERVER, perform_handshake
from p2pssh.identity import fingerprint
from p2pssh.transport import Node


# ----------------------------------------------------------------- test doubles
class FakeIdentity:
    """Only what the handshake needs: sign() and public_bytes()."""

    def __init__(self):
        self._k = Ed25519PrivateKey.generate()

    def sign(self, data: bytes) -> bytes:
        return self._k.sign(data)

    def public_bytes(self) -> bytes:
        return self._k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )


class V(enum.Enum):
    NEW = 1
    TRUSTED = 2
    CHANGED = 3


class FakeTrust:
    def __init__(self, known=None):
        self.db = dict(known or {})

    def check(self, name, pub):
        if name not in self.db:
            return V.NEW
        return V.TRUSTED if self.db[name] == pub else V.CHANGED

    def add(self, name, pub):
        self.db[name] = pub

    def find_by_fingerprint(self, fp):
        for name, pub in self.db.items():
            if fingerprint(pub) == fp:
                return name
        return None


class LegacyTrust(FakeTrust):
    """A TrustStore without find_by_fingerprint (older version)."""
    find_by_fingerprint = None


class Prompt:
    def __init__(self, answer=True, delay=0.0):
        self.answer, self.delay, self.calls = answer, delay, []

    async def __call__(self, fp, name):
        self.calls.append((fp, name))
        if self.delay:
            await asyncio.sleep(self.delay)
        return self.answer


class MemConn:
    """In-memory stand-in for transport.Connection, with an optional man-in-the-middle."""

    def __init__(self, inbox, outbox, direction, tamper=None, peer_name=None):
        self._in, self._out = inbox, outbox
        self._dir, self._tamper, self._n = direction, tamper, 0
        self.closed = False
        self.peer_name = peer_name

    async def send_frame(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionClosed("closed")
        n, self._n = self._n, self._n + 1
        if self._tamper:
            data = self._tamper(self._dir, n, bytes(data))
            if data is None:
                return
        await self._out.put(bytes(data))

    async def recv_frame(self, timeout=None) -> bytes:
        try:
            item = await asyncio.wait_for(self._in.get(), timeout)
        except asyncio.TimeoutError:
            await self.close()
            raise ConnTimeout("timeout")
        if item is None:
            self.closed = True
            raise ConnectionClosed("peer disconnected")
        return item

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            self._out.put_nowait(None)


def pair(tamper=None, client_peer_name=None):
    a, b = asyncio.Queue(), asyncio.Queue()
    return (MemConn(b, a, "c2s", tamper, client_peer_name), MemConn(a, b, "s2c", tamper))


async def run_both(c_conn, s_conn, c_id, s_id, c_trust, s_trust, c_kw=None, s_kw=None, **common):
    c_kw, s_kw = dict(common, **(c_kw or {})), dict(common, **(s_kw or {}))
    return await asyncio.gather(
        perform_handshake(c_conn, c_id, c_trust, "initiator", **c_kw),
        perform_handshake(s_conn, s_id, s_trust, "responder", **s_kw),
        return_exceptions=True,
    )


def code_of(result) -> int:
    assert isinstance(result, HandshakeError), f"expected HandshakeError, got {result!r}"
    return result.code


def flip(data: bytes, index: int = -1) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


async def ok_pair(**kw):
    c, s = pair()
    ci, si = FakeIdentity(), FakeIdentity()
    res = await run_both(c, s, ci, si, FakeTrust(), FakeTrust(),
                         confirm=Prompt(True), **kw)
    return res, ci, si


# ------------------------------------------------------------------- normal
async def test_A2_N1_keys_match_crosswise():
    (ck, sk), ci, si = (await ok_pair())[0], None, None
    assert ck.send_key == sk.recv_key and ck.recv_key == sk.send_key
    assert ck.send_key != ck.recv_key and len(ck.send_key) == 32


async def test_A2_N2_over_real_tcp():
    si, ci = FakeIdentity(), FakeIdentity()
    results = asyncio.get_running_loop().create_future()

    async def on_conn(conn):
        try:
            results.set_result(await perform_handshake(conn, si, FakeTrust(), "responder",
                                                       confirm=Prompt(True)))
        except Exception as e:
            results.set_result(e)

    server = Node()
    await server.listen("127.0.0.1", 0, on_conn)
    conn = await Node().dial("127.0.0.1", server.port, name="srv")
    ck = await perform_handshake(conn, ci, FakeTrust(), "initiator", confirm=Prompt(True))
    sk = await asyncio.wait_for(results, 5)
    assert ck.send_key == sk.recv_key and ck.recv_key == sk.send_key
    await conn.close(); await server.close()


async def test_A2_N3_new_keys_every_time():
    (a, _), _, _ = await ok_pair()
    (b, _), _, _ = await ok_pair()
    assert a.send_key != b.send_key and a.recv_key != b.recv_key


async def test_A2_N4_new_accepted_then_trusted_without_prompt():
    c, s = pair()
    ci, si = FakeIdentity(), FakeIdentity()
    ct, st = FakeTrust(), FakeTrust()
    cp, sp = Prompt(True), Prompt(True)
    r1 = await run_both(c, s, ci, si, ct, st, c_kw={"confirm": cp}, s_kw={"confirm": sp})
    assert not any(isinstance(r, Exception) for r in r1)
    assert len(cp.calls) == 1 and len(sp.calls) == 1
    assert si.public_bytes() in ct.db.values() and ci.public_bytes() in st.db.values()
    c2, s2 = pair()
    r2 = await run_both(c2, s2, ci, si, ct, st, c_kw={"confirm": cp}, s_kw={"confirm": sp})
    assert not any(isinstance(r, Exception) for r in r2)
    assert len(cp.calls) == 1 and len(sp.calls) == 1     # TRUSTED: nobody was asked again


async def test_A2_N5_new_rejected_aborts_and_stores_nothing():
    c, s = pair()
    ci, si = FakeIdentity(), FakeIdentity()
    ct, st = FakeTrust(), FakeTrust()
    rc, rs = await run_both(c, s, ci, si, ct, st, c_kw={"confirm": Prompt(False)},
                            s_kw={"confirm": Prompt(True)})
    assert code_of(rc) == E_AUTH
    assert ct.db == {}


async def test_A2_N5b_no_confirm_callback_fails_closed():
    c, s = pair()
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust())
    assert code_of(rc) == E_AUTH


async def test_A2_N6_peer_info_and_session_id():
    (ck, sk), ci, si = await ok_pair()
    assert ck.peer_pub == si.public_bytes() and sk.peer_pub == ci.public_bytes()
    assert ck.peer_fingerprint == fingerprint(si.public_bytes())
    assert ck.session_id == sk.session_id and len(ck.session_id) == 16
    assert "send_key" not in repr(ck)          # keys never show up in logs


async def test_keys_work_with_aead():
    (ck, sk), _, _ = await ok_pair()
    nonce = bytes(12)
    box = AESGCM(ck.send_key).encrypt(nonce, b"secret", None)
    assert AESGCM(sk.recv_key).decrypt(nonce, box, None) == b"secret"


async def test_changed_key_aborts_without_prompt():
    c, s = pair(client_peer_name="bob")
    ci, si, old = FakeIdentity(), FakeIdentity(), FakeIdentity()
    ct = FakeTrust({"bob": old.public_bytes()})          # we trusted a different key for "bob"
    prompt = Prompt(True)
    rc, rs = await run_both(c, s, ci, si, ct, FakeTrust(), confirm=prompt)
    assert code_of(rc) == E_KEYCHANGED
    assert not any(name == "bob" for _, name in prompt.calls)   # the user was never asked about "bob"


async def test_peer_name_is_used_for_lookup():
    c, s = pair(client_peer_name="laptopA")
    ci, si = FakeIdentity(), FakeIdentity()
    ct = FakeTrust()
    rc, rs = await run_both(c, s, ci, si, ct, FakeTrust(), confirm=Prompt(True))
    assert "laptopA" in ct.db


# ------------------------------------------------------------ attacks / edge
async def test_A2_B1_mitm_swaps_client_ephemeral_key():
    evil = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def tamper(d, n, data):
        return data[:1] + evil + data[33:] if (d, n) == ("c2s", 0) else data

    c, s = pair(tamper)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rc) == E_AUTH


async def test_A2_B2_mitm_swaps_server_ephemeral_key():
    evil = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def tamper(d, n, data):
        return data[:1] + evil + data[33:] if (d, n) == ("s2c", 0) else data

    c, s = pair(tamper)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rc) == E_AUTH


async def test_A2_B3_bitflip_in_server_signature():
    c, s = pair(lambda d, n, x: flip(x) if (d, n) == ("s2c", 0) else x)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rc) == E_AUTH


async def test_A2_B4_bitflip_in_client_signature():
    c, s = pair(lambda d, n, x: flip(x) if (d, n) == ("c2s", 1) else x)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rs) == E_AUTH


@pytest.mark.parametrize("cut", [0, 1, 96, 98])
async def test_A2_B5_bad_clienthello_length(cut):
    def tamper(d, n, data):
        if (d, n) != ("c2s", 0):
            return data
        return data[:cut] if cut < 97 else data + b"\x00" * (cut - 97)
    c, s = pair(tamper)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rs) == E_PROTOCOL


@pytest.mark.parametrize("cut", [0, 160, 162])
async def test_A2_B6_bad_serverhello_length(cut):
    def tamper(d, n, data):
        if (d, n) != ("s2c", 0):
            return data
        return data[:cut] if cut < 161 else data + b"\x00"
    c, s = pair(tamper)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rc) == E_PROTOCOL


async def test_A2_B7_wrong_version_in_clienthello():
    c, s = pair(lambda d, n, x: b"\x02" + x[1:] if (d, n) == ("c2s", 0) else x)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rs) == E_VERSION


async def test_A2_B7b_wrong_version_in_serverhello():
    c, s = pair(lambda d, n, x: b"\x02" + x[1:] if (d, n) == ("s2c", 0) else x)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rc) == E_VERSION


async def test_A2_B8_bad_clientauth_length():
    c, s = pair(lambda d, n, x: x[:10] if (d, n) == ("c2s", 1) else x)
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True))
    assert code_of(rs) == E_PROTOCOL


async def test_A2_B9_initiator_times_out_if_server_silent():
    c, s = pair()                                   # nobody runs the responder
    with pytest.raises(HandshakeError) as e:
        await perform_handshake(c, FakeIdentity(), FakeTrust(), "initiator", timeout=0.3)
    assert e.value.code == E_TIMEOUT and c.closed


async def test_A2_B9b_responder_times_out_if_client_silent():
    c, s = pair()
    with pytest.raises(HandshakeError) as e:
        await perform_handshake(s, FakeIdentity(), FakeTrust(), "responder",
                                timeout=0.3, prompt_allowance=0)
    assert e.value.code == E_TIMEOUT


async def test_A2_B9c_responder_times_out_waiting_for_clientauth():
    c, s = pair(lambda d, n, x: None if (d, n) == ("c2s", 1) else x)   # ClientAuth is dropped
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=Prompt(True), timeout=0.3, prompt_allowance=0)
    assert code_of(rs) == E_TIMEOUT


async def test_A2_B10_connection_closes_mid_handshake():
    c, s = pair()
    await s.close()
    with pytest.raises(HandshakeError) as e:
        await perform_handshake(c, FakeIdentity(), FakeTrust(), "initiator", timeout=1)
    assert e.value.code == E_PROTOCOL


async def test_A2_B11_low_order_ephemeral_key_rejected():
    c, s = pair()
    atk = FakeIdentity()
    server = asyncio.create_task(perform_handshake(s, FakeIdentity(), FakeTrust(), "responder",
                                                   confirm=Prompt(True)))
    ch = b"\x01" + bytes(32) + os.urandom(32) + atk.public_bytes()      # all-zero X25519 key
    await c.send_frame(ch)
    sh = await c.recv_frame(timeout=2)
    h2 = hashlib.sha256(ch + sh).digest()
    await c.send_frame(atk.sign(PREFIX_CLIENT + h2))                    # otherwise valid
    with pytest.raises(HandshakeError) as e:
        await asyncio.wait_for(server, 3)
    assert e.value.code == E_AUTH


async def test_A2_B12_reflection_of_our_own_hello_is_rejected():
    c, s = pair()
    client = asyncio.create_task(perform_handshake(c, FakeIdentity(), FakeTrust(), "initiator",
                                                   confirm=Prompt(True)))
    ch = await s.recv_frame(timeout=2)
    atk = FakeIdentity()
    # attacker mirrors the client's own ephemeral key and nonce back
    sh = b"\x01" + ch[1:33] + ch[33:65] + atk.public_bytes() + bytes(64)
    await s.send_frame(sh)
    with pytest.raises(HandshakeError) as e:
        await asyncio.wait_for(client, 3)
    assert e.value.code == E_PROTOCOL


async def test_A2_B13_signer_is_not_the_key_in_the_hello():
    c, s = pair()
    victim, atk = FakeIdentity(), FakeIdentity()
    client = asyncio.create_task(perform_handshake(c, FakeIdentity(), FakeTrust(), "initiator",
                                                   confirm=Prompt(True)))
    ch = await s.recv_frame(timeout=2)
    eph = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sh_nosig = b"\x01" + eph + os.urandom(32) + victim.public_bytes()   # claims to be the victim
    h1 = hashlib.sha256(ch + sh_nosig).digest()
    await s.send_frame(sh_nosig + atk.sign(PREFIX_SERVER + h1))         # but signs with its own key
    with pytest.raises(HandshakeError) as e:
        await asyncio.wait_for(client, 3)
    assert e.value.code == E_AUTH


async def test_A2_B14_replayed_serverhello_fails_on_a_new_connection():
    captured = []

    def record(d, n, data):
        if (d, n) == ("s2c", 0):
            captured.append(data)
        return data

    c1, s1 = pair(record)
    r = await run_both(c1, s1, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                       confirm=Prompt(True))
    assert not any(isinstance(x, Exception) for x in r)

    c2, s2 = pair()
    client = asyncio.create_task(perform_handshake(c2, FakeIdentity(), FakeTrust(), "initiator",
                                                   confirm=Prompt(True)))
    await s2.recv_frame(timeout=2)
    await s2.send_frame(captured[0])                  # attacker replays the old ServerHello
    with pytest.raises(HandshakeError) as e:
        await asyncio.wait_for(client, 3)
    assert e.value.code == E_AUTH


async def test_A2_B15_self_connect_rejected_by_default_and_allowed_with_flag():
    me = FakeIdentity()
    c, s = pair()
    rc, rs = await run_both(c, s, me, me, FakeTrust(), FakeTrust(), confirm=Prompt(True))
    assert code_of(rc) == E_PROTOCOL and code_of(rs) == E_PROTOCOL

    c, s = pair()
    rc, rs = await run_both(c, s, me, me, FakeTrust(), FakeTrust(), confirm=Prompt(True),
                            allow_self=True)
    assert rc.send_key == rs.recv_key


async def test_A2_B16_invalid_role():
    c, s = pair()
    with pytest.raises(ValueError):
        await perform_handshake(c, FakeIdentity(), FakeTrust(), "client")


async def test_A2_B17_confirm_callback_that_crashes_fails_closed():
    def boom(fp, name):
        raise RuntimeError("ui crashed")
    c, s = pair()
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            c_kw={"confirm": boom}, s_kw={"confirm": Prompt(True)})
    assert code_of(rc) == E_AUTH


async def test_A2_B18_slow_user_prompt_does_not_time_out_the_handshake():
    c, s = pair()
    slow = Prompt(True, delay=0.6)                    # user thinks longer than the 0.3 s deadline
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            c_kw={"confirm": slow}, s_kw={"confirm": Prompt(True)},
                            timeout=0.3, prompt_allowance=3)
    assert not isinstance(rc, Exception) and not isinstance(rs, Exception)


async def test_sync_confirm_callback_is_supported():
    c, s = pair()
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), FakeTrust(),
                            confirm=lambda fp, name: True)
    assert rc.send_key == rs.recv_key


async def test_A2_B15b_initiator_itself_refuses_a_server_with_our_own_key():
    # Only the initiator's own check can catch this: the "server" is hand-driven and accepts anything.
    c, s = pair()
    me = FakeIdentity()
    client = asyncio.create_task(perform_handshake(c, me, FakeTrust(), "initiator",
                                                   confirm=Prompt(True)))
    ch = await s.recv_frame(timeout=2)
    eph = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sh_nosig = b"\x01" + eph + os.urandom(32) + me.public_bytes()      # same identity as the client
    h1 = hashlib.sha256(ch + sh_nosig).digest()
    await s.send_frame(sh_nosig + me.sign(PREFIX_SERVER + h1))          # perfectly valid signature
    with pytest.raises(HandshakeError) as e:
        await asyncio.wait_for(client, 3)
    assert e.value.code == E_PROTOCOL and "ourselves" in e.value.message


async def test_A2_B19_deadline_expiry_fails_fast():
    import time
    c, s = pair()
    t0 = time.monotonic()
    with pytest.raises(HandshakeError) as e:
        await perform_handshake(c, FakeIdentity(), FakeTrust(), "initiator", timeout=0)
    assert e.value.code == E_TIMEOUT
    assert time.monotonic() - t0 < 1.0


async def test_A2_B20_responder_trusts_a_known_key_stored_under_a_real_name():
    # The real TrustStore is keyed by NAME ("bob"). The responder only knows the fingerprint.
    c, s = pair()
    ci, si = FakeIdentity(), FakeIdentity()
    st = FakeTrust({"bob": ci.public_bytes()})
    sp = Prompt(True)
    rc, rs = await run_both(c, s, ci, si, FakeTrust(), st,
                            c_kw={"confirm": Prompt(True)}, s_kw={"confirm": sp})
    assert not isinstance(rs, Exception)
    assert sp.calls == []                              # known peer: nobody is asked


async def test_A2_B21_responder_unknown_key_is_new_and_stored_by_fingerprint():
    c, s = pair()
    ci, si = FakeIdentity(), FakeIdentity()
    st = FakeTrust()
    sp = Prompt(True)
    rc, rs = await run_both(c, s, ci, si, FakeTrust(), st,
                            c_kw={"confirm": Prompt(True)}, s_kw={"confirm": sp})
    assert len(sp.calls) == 1
    assert st.db == {fingerprint(ci.public_bytes()): ci.public_bytes()}


async def test_A2_B22_responder_rejects_unknown_key_when_user_says_no():
    c, s = pair()
    st = FakeTrust()
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), st,
                            c_kw={"confirm": Prompt(True)}, s_kw={"confirm": Prompt(False)})
    assert code_of(rs) == E_AUTH and st.db == {}


async def test_A2_B23_older_truststore_without_find_by_fingerprint_still_works():
    c, s = pair()
    rc, rs = await run_both(c, s, FakeIdentity(), FakeIdentity(), FakeTrust(), LegacyTrust(),
                            confirm=Prompt(True))
    assert rc.send_key == rs.recv_key