import inspect
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from p2pssh import identity
from p2pssh.identity import (
    IdentityError,
    TrustResult,
    TrustStore,
    load_or_create_identity,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
KEY1 = bytes(range(32))

posix_only = pytest.mark.skipif(os.name == "nt", reason="needs POSIX file semantics")


# ---------- A1-B11: encrypted key / wrong passphrase ----------

def test_encrypted_key_file_gives_clear_error_without_leaking(tmp_path):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"secret-passphrase"),
    )
    path = tmp_path / "id_ed25519"
    path.write_bytes(pem)
    os.chmod(path, 0o600)                      # reach the content check, not the perm check

    with pytest.raises(IdentityError, match="corrupted or encrypted") as exc:
        load_or_create_identity(str(tmp_path))

    assert "PRIVATE KEY" not in str(exc.value)
    assert "secret-passphrase" not in str(exc.value)
    assert path.read_bytes() == pem            # file untouched


# ---------- A1-B8 extras ----------

def test_check_never_writes_the_file(tmp_path):
    path = tmp_path / "known_peers.json"
    assert TrustStore(path).check("ben", KEY1) == TrustResult.NEW
    assert not path.exists()


def test_corrupt_backup_keeps_original_bytes(tmp_path):
    path = tmp_path / "known_peers.json"
    path.write_bytes(b"\xff\xfe not utf-8 and not json")
    assert TrustStore(path).check("ben", KEY1) == TrustResult.NEW
    assert (tmp_path / "known_peers.json.corrupt").read_bytes() == b"\xff\xfe not utf-8 and not json"
    assert not path.exists()


# ---------- A1-B9: several PROCESSES writing at once ----------

WRITER = (
    "import os, sys\n"
    "from p2pssh.identity import TrustStore\n"
    "TrustStore(sys.argv[1]).add(sys.argv[2], os.urandom(32))\n"
)


@posix_only
def test_concurrent_processes_never_corrupt_the_file(tmp_path):
    path = tmp_path / "known_peers.json"
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", WRITER, str(path), f"peer{i}"],
            cwd=REPO_ROOT,
        )
        for i in range(8)
    ]
    assert [p.wait() for p in procs] == [0] * 8

    data = json.loads(path.read_text(encoding="utf-8"))   # still valid JSON
    assert 1 <= len(data) <= 8     # last writer wins: some entries may be lost, none corrupted
    assert [p.name for p in tmp_path.iterdir()] == ["known_peers.json"]   # no temp files left


# ---------- exit criteria ----------

def test_identity_module_never_prints_or_logs():
    source = (REPO_ROOT / "p2pssh" / "identity.py").read_text(encoding="utf-8")
    assert not re.search(r"(?<![\w.])print\s*\(", source)   # 'fingerprint(' must not match
    assert "logging" not in source


def test_public_api_matches_the_frozen_interface():
    def params(fn):
        return list(inspect.signature(fn).parameters)

    assert params(identity.load_or_create_identity) == ["path"]
    assert params(identity.fingerprint) == ["pub"]
    assert params(identity.verify) == ["pub", "data", "sig"]
    assert params(identity.Identity.sign) == ["self", "data"]
    assert params(identity.Identity.public_bytes) == ["self"]
    assert params(identity.TrustStore.check) == ["self", "peer_name", "pub"]
    assert params(identity.TrustStore.add) == ["self", "peer_name", "pub"]
    assert params(identity.TrustStore.remove) == ["self", "peer_name"]