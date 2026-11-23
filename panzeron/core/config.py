"""Configuration and secure local state (data dir, salt, defaults)."""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path


def default_home() -> Path:
    env = os.environ.get("PANZERON_HOME")
    if env:
        return Path(env)
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Panzeron"
    return Path.home() / ".panzeron"


DEFAULT_SETTINGS = {
    "ai_enabled": True,
    "ollama_host": "http://127.0.0.1:11434",
    "ollama_model": "qwen2.5:3b",
    "ai_timeout_seconds": 45,
    "allow_remote_processing": False,   # explicit consent required before ANY non-loopback AI host is used
    "tesseract_path": "",
    "max_scan_file_mb": 200,
    "scan_mode": "smart",               # smart | deep
}

# Reserved for features that are NOT implemented. Shown in the UI as unavailable, never as working.
UNIMPLEMENTED_SETTINGS = ["cloud_hash_lookup", "realtime_monitor"]


@dataclass
class Paths:
    home: Path
    db: Path
    vault: Path        # quarantine
    outputs: Path      # redacted / sanitised copies
    inbox: Path        # uploaded files for analysis
    demo: Path
    logs: Path
    salt_file: Path

    @classmethod
    def create(cls, home: Path | None = None) -> "Paths":
        home = Path(home) if home else default_home()
        p = cls(home, home / "panzeron.db", home / "quarantine_vault", home / "safe_copies",
                home / "inbox", home / "demo", home / "logs", home / "secret.key")
        for d in (p.home, p.vault, p.outputs, p.inbox, p.demo, p.logs):
            d.mkdir(parents=True, exist_ok=True)
        return p

    def load_salt(self) -> bytes:
        """Per-install random salt. Entity hashes are meaningless without it."""
        if self.salt_file.exists():
            return self.salt_file.read_bytes()
        salt = secrets.token_bytes(32)
        self.salt_file.write_bytes(salt)
        try:
            os.chmod(self.salt_file, 0o600)
        except OSError:
            pass
        return salt
