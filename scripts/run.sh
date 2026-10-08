#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"
python_bin=python3
[ -x .venv/bin/python ] && python_bin=.venv/bin/python
if ! "$python_bin" -c 'from app.ui.qt import QApplication; import sqlalchemy' 2>/dev/null; then
  echo 'Faltan dependencias. Ejecuta ./scripts/install-kali.sh y revisa su salida.' >&2
  exit 1
fi
exec "$python_bin" -m app.main "$@"
