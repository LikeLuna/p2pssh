import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from p2pssh.identity import IdentityError, load_or_create_identity

posix_only = pytest.mark.skipif(os.name == "nt", reason="chmod not meaningful on Windows")


def test_first_run_creates_key_files(tmp_path):              # A1-N1
    ident = load_or_create_identity(str(tmp_path))
    assert (tmp_path / "id_ed25519").exists()
    assert (tmp_path / "id_ed25519.pub").exists()
    assert len(ident.public_bytes()) == 32


def test_second_run_loads_same_key(tmp_path):                # A1-N2
    first = load_or_create_identity(str(tmp_path))
    second = load_or_create_identity(str(tmp_path))
    assert first.public_bytes() == second.public_bytes()


def test_different_folders_give_different_keys(tmp_path):
    a = load_or_create_identity(str(tmp_path / "a"))
    b = load_or_create_identity(str(tmp_path / "b"))
    assert a.public_bytes() != b.public_bytes()


@posix_only
def test_private_key_permissions_are_0600(tmp_path):         # A1-N1 (perms)
    load_or_create_identity(str(tmp_path))
    mode = stat.S_IMODE(os.stat(tmp_path / "id_ed25519").st_mode)
    assert mode == 0o600




def write_key_file(folder, data: bytes):
    """Write a fake key file with SAFE permissions, so the loader reaches the content check."""
    path = folder / "id_ed25519"
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def test_corrupted_key_raises_and_is_not_overwritten(tmp_path):   # A1-B6
    path = write_key_file(tmp_path, b"this is garbage")
    with pytest.raises(IdentityError, match="corrupted"):
        load_or_create_identity(str(tmp_path))
    assert path.read_bytes() == b"this is garbage"


def test_empty_key_file_raises(tmp_path):                         # A1-B6
    path = write_key_file(tmp_path, b"")
    with pytest.raises(IdentityError, match="corrupted"):
        load_or_create_identity(str(tmp_path))
    assert path.read_bytes() == b""


def test_wrong_key_type_raises(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = write_key_file(tmp_path, pem)
    with pytest.raises(IdentityError, match="not an Ed25519"):
        load_or_create_identity(str(tmp_path))
    assert path.read_bytes() == pem

@posix_only
def test_loose_permissions_are_refused(tmp_path):            # A1-B7
    load_or_create_identity(str(tmp_path))
    os.chmod(tmp_path / "id_ed25519", 0o644)
    with pytest.raises(IdentityError):
        load_or_create_identity(str(tmp_path))
    os.chmod(tmp_path / "id_ed25519", 0o600)                 # fixed -> loads again
    load_or_create_identity(str(tmp_path))


def test_missing_public_file_is_recreated(tmp_path):
    first = load_or_create_identity(str(tmp_path))
    (tmp_path / "id_ed25519.pub").unlink()
    second = load_or_create_identity(str(tmp_path))
    assert (tmp_path / "id_ed25519.pub").exists()
    assert first.public_bytes() == second.public_bytes()