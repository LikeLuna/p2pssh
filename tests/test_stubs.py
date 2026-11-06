
import pytest

from tests.stubs import StubConnection, StubSession


@pytest.mark.asyncio
async def test_stub_connection_send_receive():
    a, b = StubConnection.pair()

    await a.send_frame(b"hello")
    assert await b.recv_frame() == b"hello"


@pytest.mark.asyncio
async def test_stub_session_send_receive():
    a, b = StubSession.pair()

    await a.send(b"hello")
    assert await b.recv() == b"hello"


@pytest.mark.asyncio
async def test_stub_connection_close():
    a, b = StubConnection.pair()

    await a.close()

    with pytest.raises(RuntimeError, match="Peer disconnected"):
        await b.recv_frame()


@pytest.mark.asyncio
async def test_stub_session_close():
    a, b = StubSession.pair()

    await a.close()

    with pytest.raises(RuntimeError, match="Peer disconnected"):
        await b.recv()


@pytest.mark.asyncio
async def test_closed_connection_rejects_send():
    a, b = StubConnection.pair()

    await a.close()

    with pytest.raises(RuntimeError, match="Connection is closed"):
        await a.send_frame(b"hello")


@pytest.mark.asyncio
async def test_closed_session_rejects_send():
    a, b = StubSession.pair()

    await a.close()

    with pytest.raises(RuntimeError, match="Session is closed"):
        await a.send(b"hello")
