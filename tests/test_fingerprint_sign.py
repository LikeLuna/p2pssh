import base64
import hashlib
import os

import pytest

from p2pssh.identity import fingerprint, load_or_create_identity, verify


def flip_bit(data: bytes, index: int = 0) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 1
    return bytes(changed)


@pytest.fixture
def ident(tmp_path):
    return load_or_create_identity(str(tmp_path / "a"))


@pytest.fixture
def other(tmp_path):
    return load_or_create_identity(str(tmp_path / "b"))


# ---------- fingerprint ----------

def test_fingerprint_format(ident):
    fp = fingerprint(ident.public_bytes())
    assert fp.startswith("SHA256:")
    assert "=" not in fp


def test_fingerprint_matches_independent_computation(ident):
    pub = ident.public_bytes()
    digest = hashlib.sha256(pub).digest()
    expected = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    assert fingerprint(pub) == expected


def test_fingerprint_is_stable(ident):                         # A1-N4
    pub = ident.public_bytes()
    assert fingerprint(pub) == fingerprint(pub)


def test_fingerprint_differs_between_keys(ident, other):
    assert fingerprint(ident.public_bytes()) != fingerprint(other.public_bytes())


@pytest.mark.parametrize("size", [0, 31, 33])
def test_fingerprint_wrong_length_raises(size):
    with pytest.raises(ValueError):
        fingerprint(b"\x01" * size)


# ---------- sign / verify ----------

def test_sign_then_verify(ident):                              # A1-N3
    sig = ident.sign(b"hello")
    assert len(sig) == 64
    assert verify(ident.public_bytes(), b"hello", sig) is True


def test_signature_is_deterministic(ident):
    assert ident.sign(b"same") == ident.sign(b"same")


def test_tampered_data_fails(ident):                           # A1-B1
    sig = ident.sign(b"hello")
    assert verify(ident.public_bytes(), flip_bit(b"hello"), sig) is False


def test_tampered_signature_fails(ident):
    sig = ident.sign(b"hello")
    assert verify(ident.public_bytes(), b"hello", flip_bit(sig, 10)) is False


def test_wrong_key_fails(ident, other):
    sig = ident.sign(b"hello")
    assert verify(other.public_bytes(), b"hello", sig) is False


@pytest.mark.parametrize("size", [0, 63, 65])
def test_signature_wrong_length_is_false(ident, size):         # A1-B2
    assert verify(ident.public_bytes(), b"hello", b"\x00" * size) is False


def test_empty_message(ident):                                 # A1-B4
    sig = ident.sign(b"")
    assert verify(ident.public_bytes(), b"", sig) is True


def test_large_message(ident):                                 # A1-B5
    data = os.urandom(10 * 1024 * 1024)
    sig = ident.sign(data)
    assert verify(ident.public_bytes(), data, sig) is True


@pytest.mark.parametrize("size", [31, 33])
def test_verify_public_key_wrong_length_raises(ident, size):   # A1-B3
    sig = ident.sign(b"hello")
    with pytest.raises(ValueError):
        verify(b"\x01" * size, b"hello", sig)