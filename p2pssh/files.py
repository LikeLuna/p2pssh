
import hashlib
import json
import os
import tempfile

from pathlib import Path, PureWindowsPath


CHUNK_SIZE = 1024 * 1024       # 1 MiB
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB


class FileTransferError(Exception):
    """Raised when a file transfer is invalid or incomplete."""


def send_file(session, file_path) -> None:
    """Send one file using an established secure Session."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(path)

    size = path.stat().st_size

    if size > MAX_FILE_SIZE:
        raise FileTransferError("File exceeds the 100 MiB limit")

    digest = hashlib.sha256()

    # Calculate the hash before transferring.
    with path.open("rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)

    metadata = {
        "type": "file",
        "filename": path.name,
        "size": size,
        "sha256": digest.hexdigest(),
    }

    session.send(json.dumps(metadata).encode("utf-8"))

    # Send chunks as separate encrypted records.
    with path.open("rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            session.send(chunk)


def receive_file(session, destination_dir) -> Path:
    """Receive a file, verify its hash, then save without overwriting."""
    try:
        metadata = json.loads(session.recv().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FileTransferError("Invalid file metadata") from exc

    if not isinstance(metadata, dict) or metadata.get("type") != "file":
        raise FileTransferError("Unexpected message type")

    filename = metadata.get("filename")
    size = metadata.get("size")
    expected_hash = metadata.get("sha256")

    # Reject paths such as ../../secret.txt and Windows paths.
    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or PureWindowsPath(filename).name != filename
    ):
        raise FileTransferError("Unsafe filename")

    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        raise FileTransferError("Invalid file size")

    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(c not in "0123456789abcdef" for c in expected_hash)
    ):
        raise FileTransferError("Invalid SHA-256 hash")

    destination = Path(destination_dir)
    destination.mkdir(parents=True, exist_ok=True)

    # Temporary file is created inside the destination directory.
    fd, temp_name = tempfile.mkstemp(
        prefix=".p2pssh-",
        suffix=".part",
        dir=destination,
    )
    temp_path = Path(temp_name)

    digest = hashlib.sha256()
    remaining = size

    try:
        with os.fdopen(fd, "wb") as output:
            while remaining > 0:
                chunk = session.recv()

                if not chunk or len(chunk) > min(CHUNK_SIZE, remaining):
                    raise FileTransferError("Invalid file chunk size")

                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

        if digest.hexdigest() != expected_hash:
            raise FileTransferError("SHA-256 mismatch; file rejected")

        final_path = destination / filename

        # Exclusive creation: never overwrite an existing file.
        with final_path.open("xb") as output:
            with temp_path.open("rb") as source:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    output.write(chunk)

        return final_path

    finally:
        temp_path.unlink(missing_ok=True)
