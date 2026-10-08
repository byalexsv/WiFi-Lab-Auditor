from __future__ import annotations

import re
from pathlib import Path

MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_mac(value: str) -> bool:
    return bool(MAC_RE.fullmatch(value))


def is_channel(value: int) -> bool:
    return value in set(range(1, 15)) | set(range(32, 178, 4))


def safe_file(path: str | Path, base: str | Path) -> Path:
    candidate, root = Path(path).resolve(), Path(base).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError("Path is outside the permitted storage directory")
    return candidate
