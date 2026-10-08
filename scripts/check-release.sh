#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"
python_bin=python3
[ -x .venv/bin/python ] && python_bin=.venv/bin/python
ruff_bin=$(command -v ruff || true)
[ -x .venv/bin/ruff ] && ruff_bin="$root_dir/.venv/bin/ruff"
black_bin=$(command -v black || true)
[ -x .venv/bin/black ] && black_bin="$root_dir/.venv/bin/black"
python3 scripts/check-sensitive-files.py
"$python_bin" -m pytest -q
if [ -n "$ruff_bin" ]; then "$ruff_bin" check app tests; else echo 'WARNING: ruff not installed; skipped.'; fi
if [ -n "$black_bin" ]; then "$black_bin" --workers 1 --check app tests; else echo 'WARNING: black not installed; skipped.'; fi
"$python_bin" -c "import tomllib; print('Version:', tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"
for file in README.md LICENSE CHANGELOG.md packaging/debian/control; do test -s "$file" || { echo "Missing $file"; exit 1; }; done
echo 'Repository checks passed. Hardware validation and production acceptance are separate requirements.'
