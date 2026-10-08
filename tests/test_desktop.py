import csv
import time

import pytest

from app.database import create_session_factory


@pytest.fixture
def window(monkeypatch, tmp_path):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    monkeypatch.setenv("QT_QPA_PLATFORMTHEME", "basic")
    monkeypatch.setenv("WIFI_LAB_MOCK", "1")
    monkeypatch.setenv("WIFI_LAB_MOCK_SCENARIO", "capture-valid")
    qt = pytest.importorskip("app.ui.qt")
    from app.ui import main_window

    application = qt.QApplication.instance() or qt.QApplication([])
    factory = create_session_factory(tmp_path / "ui.sqlite3")
    monkeypatch.setattr(main_window, "create_session_factory", lambda: factory)
    instance = main_window.MainWindow()
    instance._test_application = application
    settle(instance)
    yield instance
    instance.close()
    instance.executor.shutdown(wait=True, cancel_futures=True)


def settle(window):
    deadline = time.monotonic() + 5
    while window.jobs and time.monotonic() < deadline:
        window._test_application.processEvents()
        time.sleep(0.01)
    assert not window.jobs, "Background query did not finish"


def test_inventory_filter_and_failed_refresh_keep_previous_results(window, monkeypatch):
    assert window.networks_table.rowCount() == 1
    assert window.interfaces_table.rowCount() == 1
    window.search.setText("no-such-network")
    assert window.networks_table.rowCount() == 0
    window.search.clear()

    def fail(**kwargs):
        raise RuntimeError("NetworkManager unavailable")

    monkeypatch.setattr(window.scanner, "scan", fail)
    window.refresh_networks()
    assert not window.scan_button.isEnabled()
    settle(window)
    assert window.scan_button.isEnabled()
    assert window.networks_table.rowCount() == 1
    assert "NetworkManager unavailable" in window.network_status.text()


def test_system_indicator_reflects_backend_health(window):
    assert window.system_indicator.text() in {"● SYSTEM ONLINE", "● SYSTEM OFFLINE"}
    assert window.system_indicator.objectName() in {"system-online", "system-offline"}


def test_network_scan_explains_monitor_mode_block(window, monkeypatch):
    from app.core.interface_manager import WirelessInterface
    from app.ui import main_window

    monkeypatch.setattr(main_window, "enabled", lambda: False)
    window.interface_records = [WirelessInterface("wlan0mon", mode="monitor")]
    window._networks_ready([])

    assert "modo monitor" in window.network_status.text()
    assert not window.network_adapter_button.isHidden()


def test_network_authorization_requires_active_project(window):
    window.networks_table.selectRow(0)
    window.authorize_selected_network()

    assert "proyecto activo" in window.network_status.text()


def test_create_project_persists_and_export_labels_source(
    window, monkeypatch, tmp_path
):
    from app.ui.main_window import MainWindow, QFileDialog

    window.project_name.setText("UI laboratory")
    window.responsible.setText("Test operator")
    window.authorization.setPlainText("Synthetic test authorization")
    window.create_project()
    assert window.projects_table.rowCount() == 1
    destination = tmp_path / "inventory.csv"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName", lambda *args: (str(destination), "CSV")
    )
    window.export_networks()
    with destination.open(encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    assert rows[0]["source"] == "mock"
    assert rows[0]["ssid"] == "LAB-NETWORK-01"
    reopened = MainWindow()
    try:
        assert reopened.projects_table.rowCount() == 1
    finally:
        reopened.close()
        reopened.executor.shutdown(wait=True, cancel_futures=True)


def test_inventory_marks_the_bssid_authorized_for_active_project(window):
    from app.core.scope_manager import ScopeManager

    window.project_name.setText("Authorized UI lab")
    window.responsible.setText("Test operator")
    window.authorization.setPlainText("Synthetic test authorization")
    window.create_project()
    project_id = window.project_selector.currentData()
    network = window.networks[0]
    with window.sessions() as session:
        ScopeManager(session).authorize_target(
            project_id, network.bssid, network.ssid, network.channel
        )
    window._render_networks()
    assert window.networks_table.item(0, 6).text() == "Autorizada"


def test_lab_jobs_disable_context_and_close_cancels(window):
    def operation(job):
        assert job.cancelled.wait(3), "Close must request cancellation"
        return "saved"

    window._start_lab(operation, window.capture_status, 5)
    assert not window.project_selector.isEnabled()
    assert not window.project_create_button.isEnabled()
    assert not window.scan_button.isEnabled()
    assert window.capture_stop.isEnabled()
    window.close()
    settle(window)
    assert window.lab_job is None
    assert window.close_pending


def test_recovery_dictionary_queue_accepts_multiple_files(
    window, monkeypatch, tmp_path
):
    from app.ui.qt import QFileDialog, Qt

    first = tmp_path / "principal.txt"
    second = tmp_path / "complementario.dic"
    first.write_text("first\n")
    second.write_text("second\n")
    monkeypatch.setattr(
        QFileDialog,
        "getOpenFileNames",
        lambda *args: ([str(first), str(second), str(first)], "Texto"),
    )

    window.choose_dictionary()

    assert window.dictionary_list.count() == 2
    paths = [
        window.dictionary_list.item(index).data(Qt.ItemDataRole.UserRole)
        for index in range(window.dictionary_list.count())
    ]
    assert paths == [str(first.resolve()), str(second.resolve())]

    window.dictionary_list.item(0).setSelected(True)
    window.remove_selected_dictionaries()
    assert window.dictionary_list.count() == 1
    window.clear_dictionaries()
    assert window.dictionary_list.count() == 0
