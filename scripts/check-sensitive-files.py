from __future__ import annotations

import subprocess
import sys
from pathlib import Path

FORBIDDEN_SUFFIXES = {".cap", ".pcap", ".pcapng", ".22000", ".potfile", ".restore", ".db", ".sqlite", ".sqlite3"}
FORBIDDEN_NAMES = {".env"}
MAX_BYTES = 5 * 1024 * 1024


def tracked_or_worktree_files(root: Path) -> list[Path]:
    result = subprocess.run(["git", "ls-files", "--others", "--cached", "--exclude-standard"], cwd=root, capture_output=True, text=True, check=True)
    return [root / line for line in result.stdout.splitlines() if line]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    issues: list[str] = []
    for path in tracked_or_worktree_files(root):
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            issues.append(f"Sensitive artifact: {path.relative_to(root)}")
        elif path.is_file() and path.stat().st_size > MAX_BYTES:
            issues.append(f"Large file (>5 MiB): {path.relative_to(root)}")
    if issues:
        print("Sensitive-file check failed:", *issues, sep="\n- ")
        return 1
    print("Sensitive-file check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
