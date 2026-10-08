from app.core import diagnostics
from app.core.diagnostics import redact


def test_diagnostics_redacts_paths_secrets_and_macs() -> None:
    result = redact("password=hunter2 /home/alice 02:00:00:00:00:01")
    assert "hunter2" not in result
    assert "/home/alice" not in result
    assert "02:00:00:00:00:01" not in result


def test_system_health_is_online_when_required_backend_checks_pass(monkeypatch):
    monkeypatch.setattr(
        diagnostics.shutil,
        "which",
        lambda tool: f"/usr/bin/{tool}",
    )

    def fake_run(arguments, timeout=5):
        return "connected:full\n" if arguments[0] == "nmcli" else "1. wlan0\n"

    monkeypatch.setattr(diagnostics, "run_tool", fake_run)
    health = diagnostics.system_health()

    assert health.online
    assert "backend local está listo" in health.message


def test_system_health_is_offline_when_capture_permissions_fail(monkeypatch):
    monkeypatch.setattr(
        diagnostics.shutil,
        "which",
        lambda tool: f"/usr/bin/{tool}",
    )

    def fake_run(arguments, timeout=5):
        if arguments[0] == "dumpcap":
            raise diagnostics.SystemToolError("permiso denegado")
        return "connected:full\n"

    monkeypatch.setattr(diagnostics, "run_tool", fake_run)
    health = diagnostics.system_health()

    assert not health.online
    assert "dumpcap no está listo" in health.details
