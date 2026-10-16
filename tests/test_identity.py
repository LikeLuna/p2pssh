import os
import stat

import pytest

from p2pssh.identity import load_or_create_identity


def test_first_run_creates_key_files(tmp_path):          # A1-N1
    ident = load_or_create_identity(str(tmp_path))
    assert (tmp_path / "id_ed25519").exists()
    assert (tmp_path / "id_ed25519.pub").exists()
    assert len(ident.public_bytes()) == 32


def test_second_run_loads_same_key(tmp_path):            # A1-N2
    first = load_or_create_identity(str(tmp_path))
    second = load_or_create_identity(str(tmp_path))
    assert first.public_bytes() == second.public_bytes()


def test_different_folders_give_different_keys(tmp_path):
    a = load_or_create_identity(str(tmp_path / "a"))
    b = load_or_create_identity(str(tmp_path / "b"))
    assert a.public_bytes() != b.public_bytes()


@pytest.mark.skipif(os.name == "nt", reason="chmod not meaningful on Windows")
def test_private_key_permissions_are_0600(tmp_path):     # A1-N1 (perms)
    load_or_create_identity(str(tmp_path))
    mode = stat.S_IMODE(os.stat(tmp_path / "id_ed25519").st_mode)
    assert mode == 0o600