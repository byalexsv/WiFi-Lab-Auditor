#!/usr/bin/env bash
set -euo pipefail
root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"
python3 - <<'PY'
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

root = Path.cwd()
version = os.environ.get(
    'PACKAGE_VERSION',
    tomllib.loads((root / 'pyproject.toml').read_text())['project']['version'],
)
(root / 'build').mkdir(exist_ok=True)
(root / 'dist').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='deb-', dir=root / 'build') as temporary:
    stage = Path(temporary)
    control = stage / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text((root / 'packaging/debian/control').read_text().replace('@VERSION@', version))
    library = stage / 'usr/lib/wifi-lab-auditor'
    library.mkdir(parents=True)
    shutil.copytree(root / 'app', library / 'app', ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
    (library / 'fixtures').mkdir()
    shutil.copy2(root / 'fixtures/mock_scenarios.json', library / 'fixtures/mock_scenarios.json')
    applications = stage / 'usr/share/applications'
    applications.mkdir(parents=True)
    shutil.copy2(root / 'packaging/wifi-lab-auditor.desktop', applications)
    binaries = stage / 'usr/bin'
    binaries.mkdir(parents=True)
    launcher = binaries / 'wifi-lab-auditor'
    launcher.write_text('#!/usr/bin/env sh\ncd /usr/lib/wifi-lab-auditor || exit 1\nexec python3 -m app.main "$@"\n')
    stage.chmod(0o755)
    for entry in stage.rglob('*'):
        entry.chmod(0o755 if entry.is_dir() else 0o644)
    launcher.chmod(0o755)
    subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(stage), str(root / 'dist' / f'wifi-lab-auditor_{version}_all.deb')], check=True)
PY
