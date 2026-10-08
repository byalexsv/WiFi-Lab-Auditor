from pathlib import Path

from app.core.interface_manager import InterfaceManager
from app.core.mock_mode import scenario

ROOT = Path(__file__).parents[1]


def test_production_code_has_no_local_home_or_universal_interface() -> None:
    production = "\n".join(path.read_text() for path in (ROOT / "app").rglob("*.py"))
    assert "/home/miguel" not in production
    assert '"wlan0"' not in production
    assert "CHANNEL=11" not in production


def test_mock_mode_is_deterministic(monkeypatch) -> None:
    monkeypatch.setenv("WIFI_LAB_MOCK", "1")
    monkeypatch.setenv("WIFI_LAB_MOCK_SCENARIO", "capture-valid")
    scenario.cache_clear()
    first, second = (
        InterfaceManager().list_interfaces(),
        InterfaceManager().list_interfaces(),
    )
    assert first == second
    assert first[0].name == "labwifi0"


def test_process_manager_has_no_shell_execution() -> None:
    source = (ROOT / "app/core/process_manager.py").read_text()
    assert "shell=True" not in source


def test_sensitive_artifacts_are_ignored() -> None:
    ignored = (ROOT / ".gitignore").read_text()
    for suffix in ("*.pcapng", "*.22000", "*.sqlite3", ".venv/"):
        assert suffix in ignored
