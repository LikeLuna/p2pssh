
import asyncio
import hashlib
import json

import pytest

from p2pssh import files
from p2pssh.files import (
    CHUNK_SIZE,
    MAX_FILE_SIZE,
    FileTransferError,
    send_file,
    receive_file,
    _validate_filename,
)


class FakeSession:
    """Simple asynchronous session for testing file transfers."""

    def __init__(self, incoming=None):
        self.queue = incoming if incoming is not None else asyncio.Queue()
        self.closed = False

    async def send(self, data):
        if self.closed:
            raise RuntimeError("Session is closed")
        await self.queue.put(data)

    async def recv(self):
        if self.closed:
            raise RuntimeError("Session is closed")
        return await self.queue.get()

    async def close(self):
        self.closed = True


def make_metadata(filename, content):
    return {
        "type": "file",
        "filename": filename,
        "size": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


@pytest.mark.asyncio
async def test_normal_file_transfer(tmp_path):
    """A normal file should transfer successfully."""

    source = tmp_path / "hello.txt"
    source.write_bytes(b"Hello from P2P SSH")

    queue = asyncio.Queue()
    sender = FakeSession(queue)
    receiver = FakeSession(queue)

    destination = tmp_path / "received"

    await asyncio.gather(
        send_file(sender, source),
        receive_file(receiver, destination),
    )

    received = destination / "hello.txt"

    assert received.exists()
    assert received.read_bytes() == b"Hello from P2P SSH"


@pytest.mark.asyncio
async def test_empty_file_transfer(tmp_path):
    """An empty file should transfer successfully."""

    source = tmp_path / "empty.txt"
    source.write_bytes(b"")

    queue = asyncio.Queue()
    sender = FakeSession(queue)
    receiver = FakeSession(queue)

    destination = tmp_path / "received"

    await asyncio.gather(
        send_file(sender, source),
        receive_file(receiver, destination),
    )

    received = destination / "empty.txt"

    assert received.exists()
    assert received.read_bytes() == b""


@pytest.mark.asyncio
async def test_large_file_is_split_into_valid_chunks(tmp_path):
    """Large files should be divided into records within the limit."""

    content = b"A" * (CHUNK_SIZE * 2 + 100)

    source = tmp_path / "large.bin"
    source.write_bytes(content)

    queue = asyncio.Queue()
    sender = FakeSession(queue)
    receiver = FakeSession(queue)

    destination = tmp_path / "received"

    await asyncio.gather(
        send_file(sender, source),
        receive_file(receiver, destination),
    )

    received = destination / "large.bin"

    assert received.read_bytes() == content


@pytest.mark.asyncio
async def test_sha256_mismatch_rejected(tmp_path):
    """A file with an incorrect hash must be rejected."""

    content = b"Original content"

    queue = asyncio.Queue()
    session = FakeSession(queue)

    metadata = make_metadata("bad.txt", content)
    metadata["sha256"] = "0" * 64

    await queue.put(json.dumps(metadata).encode("utf-8"))
    await queue.put(content)

    with pytest.raises(FileTransferError, match="SHA-256 mismatch"):
        await receive_file(session, tmp_path)

    assert session.closed
    assert not (tmp_path / "bad.txt").exists()


@pytest.mark.asyncio
async def test_unsafe_filename_rejected(tmp_path):
    """Unsafe filenames must never be written."""

    content = b"test content"

    queue = asyncio.Queue()
    session = FakeSession(queue)

    metadata = make_metadata("../outside.txt", content)

    await queue.put(json.dumps(metadata).encode("utf-8"))

    with pytest.raises(FileTransferError, match="Unsafe filename"):
        await receive_file(session, tmp_path)

    assert session.closed
    assert not (tmp_path.parent / "outside.txt").exists()


@pytest.mark.asyncio
async def test_windows_reserved_filename_rejected():
    """Windows reserved filenames must be rejected."""

    with pytest.raises(FileTransferError):
        _validate_filename("CON.txt")

    with pytest.raises(FileTransferError):
        _validate_filename("NUL")


@pytest.mark.asyncio
async def test_existing_file_is_not_overwritten(tmp_path):
    """Existing destination files must remain unchanged."""

    existing = tmp_path / "hello.txt"
    existing.write_bytes(b"Original data")

    new_content = b"New incoming data"

    queue = asyncio.Queue()
    session = FakeSession(queue)

    metadata = make_metadata("hello.txt", new_content)

    await queue.put(json.dumps(metadata).encode("utf-8"))
    await queue.put(new_content)

    with pytest.raises(
        FileTransferError,
        match="already exists",
    ):
        await receive_file(session, tmp_path)

    assert existing.read_bytes() == b"Original data"
    assert session.closed


@pytest.mark.asyncio
async def test_file_size_limit_rejected(tmp_path, monkeypatch):
    """Files exceeding the configured limit must be rejected."""

    source = tmp_path / "large.txt"
    source.write_bytes(b"1234567890")

    monkeypatch.setattr(files, "MAX_FILE_SIZE", 5)

    session = FakeSession()

    with pytest.raises(FileTransferError, match="100 MiB limit"):
        await send_file(session, source)

    assert session.queue.empty()


@pytest.mark.asyncio
async def test_missing_source_file_rejected(tmp_path):
    """A missing source file must raise FileNotFoundError."""

    session = FakeSession()

    with pytest.raises(FileNotFoundError):
        await send_file(session, tmp_path / "missing.txt")


@pytest.mark.asyncio
async def test_invalid_metadata_rejected(tmp_path):
    """Invalid JSON metadata must be rejected."""

    queue = asyncio.Queue()
    session = FakeSession(queue)

    await queue.put(b"not valid json")

    with pytest.raises(FileTransferError, match="Invalid file metadata"):
        await receive_file(session, tmp_path)

    assert session.closed


@pytest.mark.asyncio
async def test_wrong_message_type_rejected(tmp_path):
    """Non-file messages must not be treated as file metadata."""

    queue = asyncio.Queue()
    session = FakeSession(queue)

    await queue.put(
        json.dumps({"type": "message"}).encode("utf-8")
    )

    with pytest.raises(FileTransferError, match="Unexpected message type"):
        await receive_file(session, tmp_path)

    assert session.closed


@pytest.mark.asyncio
async def test_invalid_chunk_rejected(tmp_path):
    """Empty chunks must be rejected for non-empty files."""

    content = b"Some file content"

    queue = asyncio.Queue()
    session = FakeSession(queue)

    metadata = make_metadata("chunk.txt", content)

    await queue.put(json.dumps(metadata).encode("utf-8"))
    await queue.put(b"")

    with pytest.raises(FileTransferError, match="Invalid file chunk"):
        await receive_file(session, tmp_path)

    assert session.closed
    assert not (tmp_path / "chunk.txt").exists()
