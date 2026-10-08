#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"
python_bin=python3
[ -x .venv/bin/python ] && python_bin=.venv/bin/python
WIFI_LAB_MOCK=1 "$python_bin" -m pytest -q
