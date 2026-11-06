
import asyncio
import hashlib
import json
import os
import tempfile

from pathlib import Path, PureWindowsPath


# Maximum encrypted record size: 16 KB.
# Record overhead = 8-byte sequence number + 16-byte GCM tag.
MAX_RECORD_SIZE = 16 * 1024
RECORD_OVERHEAD = 8 + 16
CHUNK_SIZE = MAX_RECORD_SIZE - RECORD_OVERHEAD

# Maximum file size = 100 MiB.
MAX_FILE_SIZE = 100 * 1024 * 1024


class FileTransferError(Exception):
    """Raised when a file transfer is invalid or incomplete."""


def _validate_filename(filename):
    """Reject unsafe or platform-specific filenames."""

    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
        or ":" in filename
        or filename.endswith((" ", "."))
        or PureWindowsPath(filename).name != filename
        or any(ord(char) < 32 for char in filename)
    ):
        raise FileTransferError("Unsafe filename")

    reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }

    if filename.split(".")[0].upper() in reserved:
        raise FileTransferError("Reserved filename")

    return filename


async def send_file(session, file_path) -> None:
    """Send a file through an established asynchronous SecureSession."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(path)

    size = path.stat().st_size

    if size > MAX_FILE_SIZE:
        raise FileTransferError("File exceeds the 100 MiB limit")

    filename = _validate_filename(path.name)

    digest = hashlib.sha256()

    try:
        # Calculate SHA-256 before sending metadata.
        with path.open("rb") as source:
            while True:
                chunk = await asyncio.to_thread(
                    source.read, CHUNK_SIZE
                )

                if not chunk:
                    break

                digest.update(chunk)

        metadata = {
            "type": "file",
            "filename": filename,
            "size": size,
            "sha256": digest.hexdigest(),
        }

        # Send metadata as the first encrypted record.
        await session.send(
            json.dumps(metadata).encode("utf-8")
        )

        # Send file contents in encrypted chunks.
        with path.open("rb") as source:
            while True:
                chunk = await asyncio.to_thread(
                    source.read, CHUNK_SIZE
                )

                if not chunk:
                    break

                await session.send(chunk)

    except asyncio.CancelledError:
        await session.close()
        raise

    except Exception as exc:
        await session.close()
        raise FileTransferError("File sending failed") from exc


async def receive_file(session, destination_dir) -> Path:
    """Receive a file, verify SHA-256 and save without overwriting."""

    try:
        raw_metadata = await session.recv()

        if not isinstance(raw_metadata, bytes):
            raise FileTransferError("Invalid metadata frame")

        metadata = json.loads(
            raw_metadata.decode("utf-8")
        )

    except asyncio.CancelledError:
        await session.close()
        raise

    except FileTransferError:
        await session.close()
        raise

    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        await session.close()
        raise FileTransferError("Invalid file metadata") from exc

    if (
        not isinstance(metadata, dict)
        or metadata.get("type") != "file"
    ):
        await session.close()
        raise FileTransferError("Unexpected message type")

    try:
        filename = _validate_filename(
            metadata.get("filename")
        )
    except FileTransferError:
        await session.close()
        raise

    size = metadata.get("size")
    expected_hash = metadata.get("sha256")

    if type(size) is not int or not 0 <= size <= MAX_FILE_SIZE:
        await session.close()
        raise FileTransferError("Invalid file size")

    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(
            char not in "0123456789abcdef"
            for char in expected_hash
        )
    ):
        await session.close()
        raise FileTransferError("Invalid SHA-256 hash")

    destination = Path(destination_dir)

    try:
        destination.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(
            prefix=".p2pssh-",
            suffix=".part",
            dir=destination,
        )

    except OSError as exc:
        await session.close()
        raise FileTransferError(
            "Could not create destination file"
        ) from exc

    temp_path = Path(temp_name)
    final_path = destination / filename

    digest = hashlib.sha256()
    remaining = size

    # Track only the file created by this transfer.
    created_final = False

    try:
        # Receive chunks into a temporary file.
        with os.fdopen(fd, "wb") as output:

            while remaining > 0:
                chunk = await session.recv()

                if (
                    not isinstance(chunk, bytes)
                    or not chunk
                    or len(chunk) > CHUNK_SIZE
                    or len(chunk) > remaining
                ):
                    raise FileTransferError(
                        "Invalid file chunk size"
                    )

                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

            output.flush()
            os.fsync(output.fileno())

        # Verify SHA-256 before creating the final file.
        if digest.hexdigest() != expected_hash:
            raise FileTransferError(
                "SHA-256 mismatch; file rejected"
            )

        # Exclusive creation prevents overwriting existing files.
        try:
            with final_path.open("xb") as output:
                created_final = True

                with temp_path.open("rb") as source:
                    while True:
                        chunk = await asyncio.to_thread(
                            source.read, CHUNK_SIZE
                        )

                        if not chunk:
                            break

                        output.write(chunk)

        except FileExistsError as exc:
            raise FileTransferError(
                "A file with this name already exists"
            ) from exc

        return final_path

    except asyncio.CancelledError:
        await session.close()

        if created_final and final_path.exists():
            final_path.unlink()

        raise

    except Exception:
        await session.close()

        # Delete only the incomplete file created by this transfer.
        # Never delete a pre-existing destination file.
        if created_final and final_path.exists():
            final_path.unlink()

        raise

    finally:
        # Always remove the temporary file.
        temp_path.unlink(missing_ok=True)
