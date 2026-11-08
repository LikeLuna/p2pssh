import asyncio
from types import SimpleNamespace

import pytest

from p2pssh.identity import TrustStore, fingerprint
from p2pssh.services import (
    SERVICE_CHAT, SERVICE_FILE, SERVICE_SHELL, ServiceError,
    make_authorizer, request_service, serve_service,
)

KEY1 = bytes(range(32))


class FakeSession:
    """Two of these joined back to back behave like a SecureSession pair."""

    def __init__(self):
        self.inbox = asyncio.Queue()
        self.peer = None

    async def send(self, data: bytes):
        await self.peer.inbox.put(data)

    async def recv(self) -> bytes:
        return await asyncio.wait_for(self.inbox.get(), 2)


def pair():
    a, b = FakeSession(), FakeSession()
    a.peer, b.peer = b, a
    return a, b


async def run_both(client_coro, server_coro):
    return await asyncio.gather(client_coro, server_coro, return_exceptions=True)


@pytest.fixture
def store(tmp_path):
    return TrustStore(tmp_path / "known_peers.json")


async def test_chat_request_runs_handler():
    client, server = pair()
    ran = []

    async def chat(session):
        ran.append("chat")

    result = await run_both(request_service(client, SERVICE_CHAT),
                            serve_service(server, {SERVICE_CHAT: chat}))
    assert result == [None, SERVICE_CHAT]
    assert ran == ["chat"]


@pytest.mark.parametrize("name", [SERVICE_CHAT, SERVICE_SHELL, SERVICE_FILE])
async def test_every_known_service_can_be_selected(name):
    client, server = pair()

    async def handler(session):
        pass

    result = await run_both(request_service(client, name),
                            serve_service(server, {name: handler}))
    assert result == [None, name]


async def test_handler_can_talk_over_the_same_session_afterwards():
    client, server = pair()

    async def echo(session):
        await session.send(b"hello from host")

    async def client_side():
        await request_service(client, SERVICE_CHAT)
        return await client.recv()

    result = await run_both(client_side(), serve_service(server, {SERVICE_CHAT: echo}))
    assert result == [b"hello from host", SERVICE_CHAT]


async def test_service_not_offered_is_denied():
    client, server = pair()
    result = await run_both(request_service(client, SERVICE_FILE),
                            serve_service(server, {SERVICE_CHAT: None}))
    assert isinstance(result[0], ServiceError) and "not available" in str(result[0])
    assert isinstance(result[1], ServiceError)


async def test_authorizer_reason_reaches_the_client_and_handler_never_runs():
    client, server = pair()
    ran = []

    async def shell(session):
        ran.append(1)

    result = await run_both(
        request_service(client, SERVICE_SHELL),
        serve_service(server, {SERVICE_SHELL: shell}, authorize=lambda n: "no way"))
    assert isinstance(result[0], ServiceError) and "no way" in str(result[0])
    assert ran == []


async def test_unknown_service_name_is_denied():
    client, server = pair()
    await client.send(b"svc:rm-rf")
    with pytest.raises(ServiceError):
        await serve_service(server, {SERVICE_CHAT: None})
    assert b"denied:unknown service" == await client.recv()


@pytest.mark.parametrize("junk", [b"", b"chat", b"svc", b"SVC:chat", b"svc:\xff\xfe", b"svc:" + b"a" * 500])
async def test_malformed_requests_are_denied_not_crashed(junk):
    client, server = pair()
    await client.send(junk)
    with pytest.raises(ServiceError):
        await serve_service(server, {SERVICE_CHAT: None})
    assert (await client.recv()).startswith(b"denied:")


async def test_client_rejects_unexpected_reply():
    client, server = pair()

    async def rude_server():
        await server.recv()
        await server.send(b"whatever")

    result = await run_both(request_service(client, SERVICE_CHAT), rude_server())
    assert isinstance(result[0], ServiceError)


async def test_hostile_denial_reason_cannot_inject_escape_codes():
    client, server = pair()

    async def evil_server():
        await server.recv()
        await server.send(b"denied:\x1b[2Jcleared")

    result = await run_both(request_service(client, SERVICE_CHAT), evil_server())
    assert isinstance(result[0], ServiceError) and "\x1b" not in str(result[0])


async def test_unknown_name_on_client_side_raises_value_error():
    client, _ = pair()
    with pytest.raises(ValueError):
        await request_service(client, "telnet")


# ---------- host-side shell gate ----------

def cfg(allow):
    return SimpleNamespace(allow_shell=allow)


def test_chat_and_file_need_no_permission(store):
    authorize = make_authorizer(cfg(False), store, "SHA256:whatever")
    assert authorize(SERVICE_CHAT) is None
    assert authorize(SERVICE_FILE) is None


def test_shell_refused_when_switch_is_off_even_for_trusted_peer(store):
    store.add("ben", KEY1)
    authorize = make_authorizer(cfg(False), store, fingerprint(KEY1))
    assert "disabled" in authorize(SERVICE_SHELL)


def test_shell_refused_for_untrusted_peer_even_when_switch_is_on(store):
    authorize = make_authorizer(cfg(True), store, fingerprint(KEY1))
    assert "not trusted" in authorize(SERVICE_SHELL)


def test_shell_allowed_only_for_trusted_peer_with_switch_on(store):
    store.add("ben", KEY1)
    authorize = make_authorizer(cfg(True), store, fingerprint(KEY1))
    assert authorize(SERVICE_SHELL) is None