#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"
if ! command -v python3 >/dev/null; then
  echo 'Se necesita Python 3.12 o posterior.' >&2
  exit 1
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else "Se necesita Python 3.12 o posterior")'
if [ ! -d .venv ]; then
  python3 -m venv --system-site-packages .venv
fi
if [ ! -x .venv/bin/python ]; then
  echo 'El entorno .venv existente no contiene un intérprete válido. Revísalo antes de continuar.' >&2
  exit 1
fi
if ! .venv/bin/python -c 'from app.ui.qt import QApplication; import sqlalchemy' 2>/dev/null; then
  echo 'Faltan dependencias de ejecución. En Kali instala:' >&2
  echo '  sudo apt install python3-venv python3-pyqt6 python3-sqlalchemy network-manager iw aircrack-ng tshark wireshark-common hcxtools hcxdumptool hashcat policykit-1' >&2
  echo 'Si tu .venv no permite paquetes del sistema, instala PyQt6 y SQLAlchemy en ese entorno.' >&2
  exit 1
fi
cat > .venv/bin/wifi-lab-auditor <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root_dir"
exec .venv/bin/python -m app.main "$@"
LAUNCHER
chmod +x .venv/bin/wifi-lab-auditor
for tool in nmcli iw airmon-ng dumpcap tshark hcxpcapngtool hcxdumptool hashcat pkexec; do
  if command -v "$tool" >/dev/null; then echo "$tool: disponible"; else echo "$tool: falta (necesario para su función correspondiente)"; fi
done
echo 'Entorno preparado. Inicia con ./scripts/run.sh'
echo 'También puedes activar el entorno: source .venv/bin/activate; wifi-lab-auditor'
