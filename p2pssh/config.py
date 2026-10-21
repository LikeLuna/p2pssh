"""C.2a - settings load/save (Member 1).

Config lives in <home>/config.json, where <home> is $P2PSSH_HOME or ~/.p2pssh.
Missing file -> defaults. Corrupt file -> backed up and defaults used (never crash).
"""
import json
import os
import re
import socket
import tempfile
from dataclasses import dataclass, asdict, fields
from pathlib import Path

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")


class ConfigError(Exception):
    pass


def home_dir() -> Path:
    return Path(os.environ.get("P2PSSH_HOME") or Path.home() / ".p2pssh")


def _default_name() -> str:
    raw = re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname())[:32]
    return raw or "peer"


@dataclass
class Config:
    name: str = ""
    port: int = 0              # 0 = let the OS pick a free port
    key_dir: str = ""          # folder passed to load_or_create_identity
    trust_path: str = ""       # file passed to TrustStore
    allow_self: bool = False   # allow connecting to our own node (testing only)

    def __post_init__(self):
        h = home_dir()
        self.name = self.name or _default_name()
        self.key_dir = self.key_dir or str(h)
        self.trust_path = self.trust_path or str(h / "known_peers.json")

    def validate(self) -> None:
        if not isinstance(self.name, str) or not _NAME_RE.match(self.name):
            raise ConfigError("name must be 1-32 chars of letters, digits, . _ -")
        if not isinstance(self.port, int) or isinstance(self.port, bool) \
                or not (0 <= self.port <= 65535):
            raise ConfigError("port must be 0-65535")
        if not isinstance(self.allow_self, bool):
            raise ConfigError("allow_self must be true or false")
        for f in ("key_dir", "trust_path"):
            if not isinstance(getattr(self, f), str) or not getattr(self, f):
                raise ConfigError(f"{f} must be a non-empty string")


def config_path() -> Path:
    return home_dir() / "config.json"


def load_config(path: Path = None) -> Config:
    path = Path(path) if path else config_path()
    if not path.exists():
        return Config()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("not an object")
    except (ValueError, OSError):
        path.replace(path.with_suffix(".json.bad"))  # keep the broken file
        return Config()
    known = {f.name for f in fields(Config)}
    cfg = Config(**{k: v for k, v in data.items() if k in known})  # ignore unknown keys
    cfg.validate()
    return cfg


def save_config(cfg: Config, path: Path = None) -> None:
    cfg.validate()
    path = Path(path) if path else config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(asdict(cfg), f, indent=2)
        os.replace(tmp, path)  # atomic: never leaves a half-written file
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise