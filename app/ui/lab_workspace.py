"""Native Qt workspace for scoped capture artifacts and recovery jobs."""

from __future__ import annotations

import json
import time
from pathlib import Path

from sqlalchemy import select

from app.core.lab_jobs import JobCancelled, ToolJob
from app.core.mock_mode import enabled
from app.core.scope_manager import ScopeManager
from app.database import AuthorizedTarget
from app.database.database import RecoveryJob
from app.ui.datetime_utils import format_local_datetime
from app.ui.qt import (
    QAbstractItemView,
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QSpinBox,
    QSplitter,
    Qt,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
)

STATUS = {
    "pending": "Pendiente",
    "running": "En curso",
    "captured": "Guardada",
    "analyzing": "Analizando",
    "analyzed": "Sin material recuperable",
    "ready": "Lista para recuperar",
    "failed": "Error",
    "interrupted": "Interrumpida",
    "recovered": "Recuperada",
    "partial": "Resultado parcial",
    "exhausted": "Diccionario agotado",
}

AUTOMATIC_RECONNECT_ATTEMPTS = 1
RECOMMENDED_CAPTURE_SECONDS = 120


class LabWorkspace:
    def _artifact_status(self, item):
        if item.status != "analyzed":
            return STATUS.get(item.status, item.status)
        try:
            evidence = json.loads(item.evidence_json)
        except (TypeError, json.JSONDecodeError):
            evidence = {}
        if not evidence.get("packets"):
            return "BSSID no visto"
        if not evidence.get("eapol"):
            return "Capturada · sin EAPOL"
        return "Analizada · sin material WPA"

    def _field(self, name, widget):
        widget.setAccessibleName(name)
        return widget

    def _captures(self):
        page, box = self._page(
            "Capturas",
            "Captura tráfico de tu red autorizada o importa un archivo PCAP/PCAPNG para analizarlo.",
        )
        controls = QWidget()
        controls.setObjectName("card")
        content = QVBoxLayout(controls)
        content.setContentsMargins(18, 18, 18, 16)
        content.setSpacing(10)

        def section(title, description="", parent_layout=content):
            panel = QWidget()
            panel.setObjectName("subcard")
            layout = QVBoxLayout(panel)
            layout.setContentsMargins(12, 10, 12, 10)
            layout.setSpacing(8)
            layout.addWidget(self._label(title.upper(), "section-label"))
            if description:
                layout.addWidget(self._label(description, "section-copy"))
            parent_layout.addWidget(panel)
            return panel, layout

        _, target_layout = section(
            "01 · Red autorizada",
            "El BSSID y el canal se reutilizan automáticamente en toda la captura.",
        )
        target_row = QHBoxLayout()
        self.target_selector = self._field("Red autorizada del proyecto", QComboBox())
        self.target_selector.currentIndexChanged.connect(self._target_changed)
        target_row.addWidget(self.target_selector, 1)
        self.manual_target_button = self._button(
            "Registrar BSSID…", self.authorize_manual, True
        )
        target_row.addWidget(self.manual_target_button)
        target_layout.addLayout(target_row)

        _, radio_layout = section(
            "02 · Radio y adaptador",
            "Ventana recomendada: 120 s para dar tiempo a la reconexión y a los cuatro mensajes EAPOL.",
        )
        row = QHBoxLayout()
        self.capture_interface = self._field("Adaptador de captura", QComboBox())
        row.addWidget(self.capture_interface, 1)
        self.capture_frequency = self._field("Frecuencia de captura en MHz", QSpinBox())
        self.capture_frequency.setRange(2400, 7125)
        self.capture_frequency.setValue(2412)
        self.capture_frequency.setSuffix(" MHz")
        self.capture_frequency.setReadOnly(True)
        self.capture_frequency.setButtonSymbols(
            QAbstractSpinBox.ButtonSymbols.NoButtons
        )
        self.capture_frequency.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.capture_frequency.setToolTip(
            "Se calcula automáticamente a partir del canal de la red autorizada."
        )
        row.addWidget(self._label("Frecuencia automática", "field-label"))
        row.addWidget(self.capture_frequency)
        self.capture_seconds = self._field(
            "Duración máxima de captura en segundos", QSpinBox()
        )
        self.capture_seconds.setRange(5, 3600)
        self.capture_seconds.setValue(RECOMMENDED_CAPTURE_SECONDS)
        self.capture_seconds.setSuffix(" s")
        row.addWidget(self._label("Duración", "field-label"))
        row.addWidget(self.capture_seconds)
        radio_layout.addLayout(row)
        self.monitor_consent = QCheckBox("Permitir modo monitor")
        self.monitor_consent.setAccessibleName(self.monitor_consent.text())
        monitor_actions = QHBoxLayout()
        monitor_actions.setSpacing(8)
        monitor_actions.addWidget(self.monitor_consent)
        self.monitor_prepare_button = self._button(
            "Preparar monitor…", self.prepare_monitor, True
        )
        self.monitor_restore_button = self._button(
            "Restaurar adaptador", self.restore_monitor, True
        )
        monitor_actions.addWidget(self.monitor_prepare_button)
        monitor_actions.addWidget(self.monitor_restore_button)
        monitor_actions.addStretch()
        radio_layout.addLayout(monitor_actions)

        _, station_layout = section(
            "03 · Cliente detectado automáticamente",
            "Solo se muestran clientes que transmiten datos o una asociación real; no se toman MAC de balizas ni sondeos.",
        )
        station_row = QHBoxLayout()
        self.station_selector = self._field("Cliente autorizado detectado", QComboBox())
        self.station_selector.addItem("Detectando clientes…", None)
        self.station_selector.currentIndexChanged.connect(self._set_lab_controls)
        station_row.addWidget(self.station_selector, 1)
        self.station_detect_button = self._button(
            "Volver a detectar", self.discover_stations, True
        )
        station_row.addWidget(self.station_detect_button)
        station_layout.addLayout(station_row)
        self.reconnect_consent = QCheckBox("Red y cliente autorizados")
        self.reconnect_consent.setAccessibleName(self.reconnect_consent.text())
        self.reconnect_consent.toggled.connect(self._set_lab_controls)
        reconnect_actions = QHBoxLayout()
        reconnect_actions.setSpacing(8)
        reconnect_actions.addWidget(self.reconnect_consent)
        self.reconnect_automatic = QCheckBox(
            f"Reconectar automáticamente ({AUTOMATIC_RECONNECT_ATTEMPTS} intentos)"
        )
        self.reconnect_automatic.setAccessibleName(self.reconnect_automatic.text())
        self.reconnect_automatic.toggled.connect(self._set_lab_controls)
        reconnect_actions.addWidget(self.reconnect_automatic)
        self.reconnect_button = self._button(
            "Probar ahora", self.request_reconnect, True
        )
        reconnect_actions.addWidget(self.reconnect_button)
        reconnect_actions.addStretch()
        station_layout.addLayout(reconnect_actions)

        footer = QWidget()
        footer.setObjectName("action-strip")
        actions_layout = QHBoxLayout(footer)
        actions_layout.setContentsMargins(4, 2, 4, 2)
        actions_layout.setSpacing(10)
        self.capture_button = self._button("Iniciar captura", self.start_capture)
        self.import_button = self._button(
            "Importar archivo…", self.import_capture, True
        )
        self.analyze_button = self._button(
            "Analizar selección", self.analyze_selected, True
        )
        for button in (self.capture_button, self.import_button, self.analyze_button):
            actions_layout.addWidget(button)
        actions_layout.addStretch()
        content.addWidget(footer)
        box.addWidget(controls)
        self.reconnect_status = self._label(
            "La detección se ejecuta sola al seleccionar una interfaz monitor.",
            "notice",
        )
        box.addWidget(self.reconnect_status)
        self.capture_status = self._label(
            "Selecciona un proyecto y registra una red para empezar. Para obtener EAPOL, mantén un cliente autorizado conectado y reconéctalo durante la captura.",
            "notice",
        )
        box.addWidget(self.capture_status)
        self.show_failed_captures = QCheckBox("Mostrar intentos fallidos anteriores")
        self.show_failed_captures.setAccessibleName(self.show_failed_captures.text())
        self.show_failed_captures.toggled.connect(self._refresh_artifacts)
        box.addWidget(self.show_failed_captures)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.artifacts_table = self._table(["Archivo", "Origen", "Estado", "Creado"])
        self.artifacts_table.itemSelectionChanged.connect(self._artifact_selected)
        split.addWidget(self.artifacts_table)
        self.evidence_view = QTextEdit()
        self.evidence_view.setReadOnly(True)
        self.evidence_view.setAccessibleName("Evidencia de la captura seleccionada")
        self.evidence_view.setPlainText(
            "EVIDENCIA\n\nSelecciona una captura para ver tramas, material WPA y huella del archivo."
        )
        split.addWidget(self.evidence_view)
        split.setSizes([620, 300])
        split.setMinimumHeight(260)
        box.addWidget(split, 1)
        artifact_actions = QHBoxLayout()
        self.delete_capture_button = self._button(
            "Eliminar captura seleccionada", self.delete_selected_capture, True
        )
        self.clear_captures_button = self._button(
            "Limpiar capturas", self.clear_captures, True
        )
        artifact_actions.addWidget(self.delete_capture_button)
        artifact_actions.addWidget(self.clear_captures_button)
        artifact_actions.addStretch()
        box.addLayout(artifact_actions)
        self.capture_stop = self._button(
            "Detener y conservar archivo", self.stop_lab_job, True
        )
        self.capture_stop.setEnabled(False)
        box.addWidget(self.capture_stop, alignment=Qt.AlignmentFlag.AlignLeft)
        box.addWidget(
            self._label(
                "Límite de captura: 64 MB. Con reconexión automática se usan al menos 120 s. Comprueba la frecuencia de tu red; un canal incorrecto puede producir una captura vacía. Las balizas por sí solas no contienen material WPA recuperable."
            )
        )
        return page

    def _recovery_page(self):
        page, box = self._page(
            "Recuperación offline",
            "Prueba un diccionario local contra el material WPA de una captura autorizada. Los resultados permanecen en este equipo.",
        )
        card = QWidget()
        card.setObjectName("card")
        form = QFormLayout(card)
        form.setContentsMargins(20, 20, 20, 20)
        form.setSpacing(12)
        self.recovery_artifact = self._field(
            "Captura con material WPA compatible", QComboBox()
        )
        form.addRow("Captura", self.recovery_artifact)
        dictionary_panel = QWidget()
        dictionary_layout = QVBoxLayout(dictionary_panel)
        dictionary_layout.setContentsMargins(0, 0, 0, 0)
        dictionary_layout.setSpacing(8)
        self.dictionary_list = QListWidget()
        self.dictionary_list.setAccessibleName("Diccionarios locales para probar")
        self.dictionary_list.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection
        )
        self.dictionary_list.setAlternatingRowColors(True)
        self.dictionary_list.setMinimumHeight(96)
        self.dictionary_list.setToolTip(
            "Cada archivo se probará en orden y quedará registrado por separado en el historial."
        )
        self.dictionary_list.itemSelectionChanged.connect(self._set_lab_controls)
        dictionary_layout.addWidget(self.dictionary_list)
        dictionary_actions = QHBoxLayout()
        dictionary_actions.setContentsMargins(0, 0, 0, 0)
        dictionary_actions.setSpacing(8)
        self.dictionary_button = self._button(
            "Añadir diccionarios…", self.choose_dictionary, True
        )
        self.dictionary_remove_button = self._button(
            "Quitar seleccionados", self.remove_selected_dictionaries, True
        )
        self.dictionary_clear_button = self._button(
            "Limpiar lista", self.clear_dictionaries, True
        )
        dictionary_actions.addWidget(self.dictionary_button)
        dictionary_actions.addWidget(self.dictionary_remove_button)
        dictionary_actions.addWidget(self.dictionary_clear_button)
        dictionary_actions.addStretch()
        dictionary_layout.addLayout(dictionary_actions)
        dictionary_layout.addWidget(
            self._label(
                "Se probarán secuencialmente. El tiempo máximo se aplica a cada diccionario y cada intento queda en el historial.",
                "section-copy",
            )
        )
        form.addRow("Diccionarios", dictionary_panel)
        self.recovery_seconds = self._field(
            "Tiempo máximo de recuperación en segundos", QSpinBox()
        )
        self.recovery_seconds.setRange(10, 3600)
        self.recovery_seconds.setValue(300)
        self.recovery_seconds.setSuffix(" s")
        form.addRow("Tiempo máximo", self.recovery_seconds)
        actions = QHBoxLayout()
        self.recover_button = self._button("Iniciar recuperación", self.start_recovery)
        self.recovery_stop = self._button("Detener trabajo", self.stop_lab_job, True)
        self.recovery_stop.setEnabled(False)
        actions.addWidget(self.recover_button)
        actions.addWidget(self.recovery_stop)
        actions.addStretch()
        form.addRow("", actions)
        box.addWidget(card)
        self.recovery_status = self._label(
            "Importa o captura material WPA y analízalo para habilitar una recuperación.",
            "notice",
        )
        box.addWidget(self.recovery_status)
        self.lab_progress = QProgressBar()
        self.lab_progress.setAccessibleName(
            "Tiempo transcurrido respecto al límite del trabajo"
        )
        self.lab_progress.setRange(0, 100)
        self.lab_progress.setValue(0)
        self.lab_progress.setTextVisible(True)
        box.addWidget(self.lab_progress)
        self.recovery_live = self._label(
            "Hashcat todavía no ha emitido un estado de progreso.", "muted"
        )
        self.recovery_live.setMinimumHeight(32)
        box.addWidget(self.recovery_live)
        self.recovery_table = self._table(
            ["Inicio", "Captura", "Diccionario", "Resultado"]
        )
        self.recovery_table.itemSelectionChanged.connect(self._recovery_selected)
        box.addWidget(self.recovery_table, 1)
        self.recovery_detail = self._label(
            "Selecciona un trabajo para consultar su resultado."
        )
        box.addWidget(self.recovery_detail)
        self.result_button = self._button(
            "Mostrar resultado local…", self.show_recovered, True
        )
        self.result_button.setEnabled(False)
        box.addWidget(self.result_button, alignment=Qt.AlignmentFlag.AlignLeft)
        recovery_actions = QHBoxLayout()
        self.delete_recovery_button = self._button(
            "Eliminar recuperación seleccionada", self.delete_selected_recovery, True
        )
        self.clear_recoveries_button = self._button(
            "Limpiar recuperaciones", self.clear_recoveries, True
        )
        recovery_actions.addWidget(self.delete_recovery_button)
        recovery_actions.addWidget(self.clear_recoveries_button)
        recovery_actions.addStretch()
        box.addLayout(recovery_actions)
        return page

    def _project_changed(self, *_):
        if not hasattr(self, "project_selector"):
            return
        project_id = self.project_selector.currentData()
        selected = self.target_selector.currentData()
        self.target_selector.blockSignals(True)
        self.target_selector.clear()
        if project_id:
            with self.sessions() as session:
                targets = session.scalars(
                    select(AuthorizedTarget).where(
                        AuthorizedTarget.project_id == project_id
                    )
                ).all()
            for target in targets:
                radio = next(
                    (
                        item
                        for item in getattr(self, "networks", [])
                        if item.bssid == target.bssid
                    ),
                    None,
                )
                band = f" · {radio.band}" if radio is not None else ""
                signal = (
                    f" · señal {radio.signal_percent}%"
                    if radio is not None and radio.signal_percent is not None
                    else ""
                )
                self.target_selector.addItem(
                    f'{target.ssid or "SSID oculto"} · {target.bssid} · canal {target.channel}{band}{signal}',
                    target.bssid,
                )
        index = self.target_selector.findData(selected)
        self.target_selector.setCurrentIndex(max(0, index))
        self.target_selector.blockSignals(False)
        self._target_changed()
        if hasattr(self, "networks_table"):
            self._render_networks()
        self._refresh_artifacts()
        self._refresh_recoveries()
        self._set_lab_controls()

    def _target_changed(self, *_):
        if not hasattr(self, "project_selector"):
            return
        # A new target (or a reselected target) needs a fresh passive scan.
        # The interface refresh performed after every capture keeps the same
        # target, so the signature guard below prevents an unwanted rescan.
        self._station_discovery_signature = None
        project_id = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        if hasattr(self, "station_selector"):
            self.station_selector.blockSignals(True)
            self.station_selector.clear()
            self.station_selector.addItem("Detectando clientes…", None)
            self.station_selector.blockSignals(False)
            self._stop_station_retry()
            self.reconnect_consent.setChecked(False)
        if project_id and bssid:
            with self.sessions() as session:
                target = session.scalar(
                    select(AuthorizedTarget).where(
                        AuthorizedTarget.project_id == project_id,
                        AuthorizedTarget.bssid == bssid,
                    )
                )
            if target:
                frequency = self._target_frequency(project_id, bssid)
                self.capture_frequency.setValue(frequency)
                if self.lab_job is None:
                    sibling_notice = self._sibling_radio_notice(target)
                    self._notice(
                        self.capture_status,
                        sibling_notice
                        or "Red autorizada seleccionada. Importa una captura o configura el adaptador para capturar.",
                    )
        self._set_lab_controls()
        self._queue_station_discovery()

    def _sibling_radio_notice(self, target):
        """Explain why one SSID can require testing more than one BSSID.

        NetworkManager reports each physical radio separately. A client can be
        associated with the 5 GHz sibling while the selected target is its
        2.4 GHz BSSID; seeing the SSID alone is therefore not enough.
        """
        siblings = [
            item
            for item in getattr(self, "networks", [])
            if item.ssid == target.ssid and item.bssid != target.bssid
        ]
        if not siblings:
            return ""
        radios = ", ".join(
            f"{item.bssid} · canal {item.channel} · {item.band}"
            for item in siblings[:3]
        )
        return (
            f"SSID con varias radios. El objetivo actual es {target.bssid} · canal {target.channel}; "
            f"también se detectó {radios}. El cliente debe estar asociado a este BSSID exacto."
        )

    def _set_lab_controls(self):
        if not hasattr(self, "project_selector"):
            return
        busy = self.lab_job is not None
        background_busy = busy or "estaciones" in self.jobs
        project = bool(self.project_selector.currentData())
        target = bool(self.target_selector.currentData())
        real = not enabled()
        for widget in (
            self.project_selector,
            self.target_selector,
            self.capture_interface,
            self.capture_seconds,
            self.capture_frequency,
            self.monitor_consent,
            self.station_selector,
            self.reconnect_consent,
            self.reconnect_automatic,
            self.recovery_artifact,
            self.dictionary_list,
            self.dictionary_button,
            self.dictionary_remove_button,
            self.dictionary_clear_button,
            self.recovery_seconds,
        ):
            widget.setEnabled(not background_busy)
        self.capture_frequency.setEnabled(target and not background_busy)
        self.manual_target_button.setEnabled(project and not background_busy)
        self.station_detect_button.setEnabled(
            real
            and not background_busy
            and target
            and self._selected_interface_mode() == "monitor"
            and "estaciones" not in self.jobs
        )
        self.scope_button.setEnabled(project and not background_busy)
        if hasattr(self, "remove_target_button"):
            selected_network = self.networks_table.currentRow() >= 0
            authorized = (
                selected_network
                and self.networks_table.item(self.networks_table.currentRow(), 6).text()
                == "Autorizada"
            )
            self.remove_target_button.setEnabled(
                project and authorized and not background_busy
            )
        if hasattr(self, "clear_inventory_button"):
            self.clear_inventory_button.setEnabled(
                bool(getattr(self, "networks", [])) and not background_busy
            )
        self.dictionary_remove_button.setEnabled(
            not background_busy and bool(self.dictionary_list.selectedItems())
        )
        self.dictionary_clear_button.setEnabled(
            not background_busy and self.dictionary_list.count() > 0
        )
        if hasattr(self, "project_delete_button"):
            self.project_delete_button.setEnabled(
                self.projects_table.currentRow() >= 0 and not background_busy
            )
        self.project_create_button.setEnabled(not background_busy)
        self.scan_button.setEnabled(not background_busy and "redes" not in self.jobs)
        self.capture_button.setEnabled(
            real
            and project
            and target
            and not background_busy
            and self.capture_interface.count() > 0
            and self._selected_interface_mode() == "monitor"
            and (
                not self.reconnect_automatic.isChecked()
                or (
                    bool(self._selected_station())
                    and self.reconnect_consent.isChecked()
                )
            )
        )
        self.monitor_prepare_button.setEnabled(
            real
            and not background_busy
            and self.capture_interface.count() > 0
            and self._selected_interface_mode() != "monitor"
        )
        self.monitor_restore_button.setEnabled(
            real
            and not background_busy
            and self._selected_interface_mode() == "monitor"
        )
        self.import_button.setEnabled(
            real and project and target and not background_busy
        )
        self.analyze_button.setEnabled(
            real
            and not background_busy
            and self._selected_id(self.artifacts_table) is not None
        )
        if hasattr(self, "delete_capture_button"):
            self.delete_capture_button.setEnabled(
                not background_busy
                and self._selected_id(self.artifacts_table) is not None
            )
        if hasattr(self, "clear_captures_button"):
            self.clear_captures_button.setEnabled(
                project and not background_busy and self.artifacts_table.rowCount() > 0
            )
        self.recover_button.setEnabled(
            real
            and not background_busy
            and self.recovery_artifact.count() > 0
            and bool(self._dictionary_paths())
        )
        self.capture_stop.setEnabled(busy)
        self.recovery_stop.setEnabled(busy)
        if hasattr(self, "delete_recovery_button"):
            self.delete_recovery_button.setEnabled(
                not background_busy
                and self._selected_id(self.recovery_table) is not None
            )
        if hasattr(self, "clear_recoveries_button"):
            self.clear_recoveries_button.setEnabled(
                project and not background_busy and self.recovery_table.rowCount() > 0
            )
        reconnect_ready = (
            real
            and self.capture_active
            and busy
            and project
            and target
            and bool(self._selected_station())
            and self.reconnect_consent.isChecked()
            and "reconexion" not in self.jobs
        )
        self.reconnect_button.setEnabled(reconnect_ready)
        if not busy and not project:
            self._notice(
                self.capture_status,
                "Crea o selecciona un proyecto en Proyectos para registrar tu red.",
            )
        elif not busy and not target:
            self._notice(
                self.capture_status,
                "Registra el BSSID de tu laboratorio o añade una red desde Redes Wi-Fi.",
            )
        elif not busy and enabled():
            self._notice(
                self.capture_status,
                "Modo demostración: reinicia sin WIFI_LAB_MOCK=1 para realizar operaciones reales.",
            )

    def _load_capture_interfaces(self, interfaces):
        selected = self.capture_interface.currentData()
        self.capture_interface.clear()
        for item in interfaces:
            self.capture_interface.addItem(f"{item.name} · {item.mode}", item.name)
            index = self.capture_interface.count() - 1
            self.capture_interface.setItemData(
                index, item.mode, Qt.ItemDataRole.UserRole + 1
            )
        index = self.capture_interface.findData(selected)
        self.capture_interface.setCurrentIndex(max(0, index))
        self._set_lab_controls()
        self._queue_station_discovery()

    def _selected_interface_mode(self):
        if self.capture_interface.currentIndex() < 0:
            return ""
        return (
            self.capture_interface.itemData(
                self.capture_interface.currentIndex(), Qt.ItemDataRole.UserRole + 1
            )
            or ""
        )

    def _selected_station(self):
        return (self.station_selector.currentData() or "").strip().upper()

    def _ensure_station_authorized(self):
        project = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        station = self._selected_station()
        if not project or not bssid or not station:
            raise ValueError("No hay un cliente detectado para autorizar.")
        with self.sessions() as session:
            ScopeManager(session).authorize_station(project, bssid, station)

    def _queue_station_discovery(self):
        project = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        interface = self.capture_interface.currentData()
        mode = self._selected_interface_mode()
        if not project or not bssid or not interface or mode != "monitor":
            return
        if "estaciones" in self.jobs:
            return
        signature = (project, bssid, interface, mode)
        if self._station_discovery_signature == signature:
            return
        self._station_discovery_signature = signature
        QTimer.singleShot(0, self.discover_stations)

    def discover_stations(self):
        if "estaciones" in self.jobs:
            return
        project = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        interface = self.capture_interface.currentData()
        if not project or not bssid or not interface:
            return
        self._station_discovery_signature = (
            project,
            bssid,
            interface,
            self._selected_interface_mode(),
        )
        job = ToolJob()
        self.station_discovery_job = job
        self._notice(
            self.reconnect_status,
            "Detectando clientes visibles automáticamente…",
        )
        self._submit(
            "estaciones",
            lambda: self.laboratory.discover_stations(bssid, interface, job),
            self._stations_ready,
            self.reconnect_status,
            self.station_detect_button,
        )
        self._set_lab_controls()

    def _stations_ready(self, stations):
        self.station_discovery_job = None
        self.station_selector.blockSignals(True)
        self.station_selector.clear()
        for station in stations:
            self.station_selector.addItem(f"{station} · detectado", station)
        if not stations:
            self.station_selector.addItem("No se detectaron clientes todavía", None)
        self.station_selector.blockSignals(False)
        if stations:
            self.reconnect_consent.setChecked(True)
            self.reconnect_automatic.setChecked(True)
            self._stop_station_retry()
        else:
            self._start_station_retry()
        self._notice(
            self.reconnect_status,
            (
                f"{len(stations)} cliente(s) detectado(s). Hasta {AUTOMATIC_RECONNECT_ATTEMPTS} reconexiones quedan preparadas para el cliente seleccionado."
                if stations
                else "No se detectó un cliente activo. La app seguirá comprobando automáticamente cada 15 s; mantén un dispositivo conectado al BSSID autorizado."
            ),
            error=not bool(stations),
        )
        self._set_lab_controls()

    def _start_station_retry(self):
        timer = getattr(self, "_station_retry_timer", None)
        if timer is not None and not timer.isActive():
            timer.start()

    def _stop_station_retry(self):
        timer = getattr(self, "_station_retry_timer", None)
        if timer is not None:
            timer.stop()

    def _retry_station_discovery(self):
        if (
            self.lab_job is None
            and "estaciones" not in self.jobs
            and self.target_selector.currentData()
            and self._selected_interface_mode() == "monitor"
            and not self._selected_station()
        ):
            self.discover_stations()

    def prepare_monitor(self):
        interface = self.capture_interface.currentData()
        if not self.monitor_consent.isChecked():
            self._notice(
                self.capture_status,
                "Confirma que puedes desconectar el adaptador antes de preparar modo monitor.",
                error=True,
            )
            self.monitor_consent.setFocus()
            return
        answer = QMessageBox.warning(
            self,
            "Preparar modo monitor",
            f"Se desconectará {interface} y el sistema pedirá permisos para crear una interfaz monitor. ¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_lab(
            lambda job: self.laboratory.prepare_monitor(
                interface, self.capture_frequency.value(), job
            ),
            self.capture_status,
            90,
        )

    def restore_monitor(self):
        interface = self.capture_interface.currentData()
        answer = QMessageBox.warning(
            self,
            "Restaurar adaptador",
            f"Se detendrá el modo monitor de {interface}. ¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start_lab(
            lambda job: self.laboratory.restore_monitor(interface, job),
            self.capture_status,
            90,
        )

    def authorize_selected_network(self):
        if not self.project_selector.currentData():
            self._notice(
                self.network_status,
                "Selecciona un proyecto activo en la barra superior antes de registrar esta red.",
                error=True,
            )
            self.project_selector.setFocus()
            return
        row = self.networks_table.currentRow()
        if row < 0:
            self._notice(
                self.network_status,
                "Selecciona una fila del inventario antes de añadirla.",
                error=True,
            )
            return
        bssid = self.networks_table.item(row, 1).text()
        network = next(item for item in self.networks if item.bssid == bssid)
        self.authorize_manual(network.ssid, network.bssid, network.channel)

    def authorize_station(self):
        project = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        station = self._selected_station()
        if not project or not bssid:
            self._notice(
                self.reconnect_status,
                "Selecciona un proyecto y una red autorizada antes de registrar el cliente.",
                error=True,
            )
            return
        try:
            self._ensure_station_authorized()
            self._notice(
                self.reconnect_status,
                f"Cliente {station.upper()} autorizado para {bssid.upper()}.",
            )
            self._set_lab_controls()
        except Exception as error:
            self._notice(self.reconnect_status, str(error), error=True)
            self.station_selector.setFocus()

    def authorize_manual(self, ssid="", bssid="", channel=1):
        project = self.project_selector.currentData()
        if not project:
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("Registrar red autorizada")
        dialog.setMinimumWidth(500)
        form = QFormLayout(dialog)
        name = self._field("SSID de la red", QLineEdit(ssid))
        address = self._field("BSSID de la red, obligatorio", QLineEdit(bssid))
        address.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        channel_field = self._field("Canal de la red", QSpinBox())
        channel_field.setRange(1, 196)
        channel_field.setValue(channel)
        consent = QCheckBox(
            "Esta red está incluida en la autorización de este proyecto."
        )
        consent.setAccessibleName(consent.text())
        error = self._label("")
        form.addRow("SSID", name)
        form.addRow("BSSID", address)
        form.addRow("Canal", channel_field)
        form.addRow(consent)
        form.addRow(error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setText("Registrar red")
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Cancelar")
        buttons.rejected.connect(dialog.reject)

        def save():
            if not consent.isChecked():
                error.setText("Confirma que el permiso del proyecto incluye esta red.")
                consent.setFocus()
                return
            try:
                with self.sessions() as session:
                    ScopeManager(session).authorize_target(
                        project,
                        address.text().strip(),
                        name.text(),
                        channel_field.value(),
                    )
                dialog.accept()
            except Exception as exception:
                error.setText(str(exception))
                address.setFocus()

        buttons.accepted.connect(save)
        form.addRow(buttons)
        address.setFocus()
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._project_changed()
            self.target_selector.setCurrentIndex(
                self.target_selector.findData(address.text().strip().upper())
            )
            self._notice(
                self.network_status,
                "Red registrada en el proyecto. Continúa en Capturas.",
            )
            self.nav.setCurrentRow(2)

    def _selected_id(self, table):
        row = table.currentRow()
        return (
            table.item(row, 0).data(Qt.ItemDataRole.UserRole)
            if row >= 0 and table.item(row, 0)
            else None
        )

    def _refresh_artifacts(self):
        project = self.project_selector.currentData()
        artifacts = self.laboratory.artifacts(project) if project else []
        if not self.show_failed_captures.isChecked():
            artifacts = [item for item in artifacts if item.status != "failed"]
        selected = self._selected_id(self.artifacts_table)
        self.artifacts_table.blockSignals(True)
        self.artifacts_table.setSortingEnabled(False)
        self.artifacts_table.setRowCount(0)
        for row, item in enumerate(artifacts):
            self.artifacts_table.insertRow(row)
            from app.ui.qt import QTableWidgetItem

            for column, value in enumerate(
                (
                    item.name,
                    "Importada" if item.source == "import" else "Adaptador",
                    self._artifact_status(item),
                    format_local_datetime(item.created_at, "%d/%m %H:%M"),
                )
            ):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.id)
                self.artifacts_table.setItem(row, column, cell)
        self.artifacts_table.setSortingEnabled(True)
        self.artifacts_table.blockSignals(False)
        chosen = self.recovery_artifact.currentData()
        self.recovery_artifact.clear()
        for item in artifacts:
            if item.status == "ready":
                self.recovery_artifact.addItem(f"{item.name} · {item.bssid}", item.id)
        self.recovery_artifact.setCurrentIndex(
            max(0, self.recovery_artifact.findData(chosen))
        )
        for row in range(self.artifacts_table.rowCount()):
            if (
                self.artifacts_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
                == selected
            ):
                self.artifacts_table.selectRow(row)
                break
        self._artifact_selected()

    def _artifact_selected(self):
        identifier = self._selected_id(self.artifacts_table)
        if identifier:
            item = self.laboratory.artifact(identifier)
            evidence = json.loads(item.evidence_json)
            lines = [
                item.name,
                f"Estado: {self._artifact_status(item)}",
                f"BSSID: {item.bssid}",
                "",
                item.message,
            ]
            if evidence:
                lines += [
                    "",
                    "EVIDENCIA OBSERVADA",
                    f'Tramas del BSSID: {evidence.get("packets", 0)}',
                    f'EAPOL: {evidence.get("eapol", 0)}',
                    f'Tráfico de datos: {evidence.get("data_frames", 0)}',
                    f'Asociación/reasociación: {evidence.get("association_frames", 0)}',
                    f'Autenticación 802.11: {evidence.get("authentication_frames", 0)}',
                    "PMF: "
                    + (
                        "obligatorio"
                        if evidence.get("pmf_required")
                        else (
                            "compatible"
                            if evidence.get("pmf_capable")
                            else "no anunciado"
                        )
                    ),
                    f'Desautenticaciones observadas: {evidence.get("deauth_frames", 0)}',
                    f'Material WPA convertible: {evidence.get("hashes", 0)}',
                    f'PMKID: {evidence.get("pmkid", 0)} · EAPOL convertible: {evidence.get("eapol_hashes", 0)}',
                    " · ".join(
                        f"M{number}: {count}"
                        for number, count in evidence.get("messages", {}).items()
                    ),
                    "",
                    evidence.get("note", ""),
                ]
                peers = evidence.get("peer_frames") or {}
                frequencies = evidence.get("channel_frequencies") or {}
                if peers:
                    lines += [
                        "",
                        "CLIENTES OBSERVADOS",
                        " · ".join(
                            f"{mac} ({count} tramas)" for mac, count in peers.items()
                        ),
                    ]
                if frequencies:
                    lines += [
                        "",
                        "FRECUENCIAS OBSERVADAS",
                        " · ".join(
                            f"{frequency} MHz ({count})"
                            for frequency, count in frequencies.items()
                        ),
                    ]
                    expected_frequency = self._target_frequency(
                        item.project_id, item.bssid
                    )
                    if (
                        expected_frequency is not None
                        and str(expected_frequency) not in frequencies
                    ):
                        lines += [
                            "",
                            "ALERTA DE RADIO",
                            f"La captura esperaba {expected_frequency} MHz, pero no observó esa frecuencia. Revisa el BSSID y el canal del monitor.",
                        ]
                diagnosis = evidence.get("diagnosis") or {}
                if diagnosis:
                    lines += [
                        "",
                        "DIAGNÓSTICO AUTOMÁTICO",
                        diagnosis.get("title", ""),
                        diagnosis.get("action", ""),
                    ]
                packets = evidence.get("packets", 0)
                eapol = evidence.get("eapol", 0)
                if packets == 0:
                    lines += [
                        "",
                        "DIAGNÓSTICO",
                        "El BSSID autorizado no apareció en la captura. Comprueba que seleccionaste el módem correcto y que la frecuencia coincide con su canal.",
                    ]
                elif not eapol:
                    lines += [
                        "",
                        "SIGUIENTE PASO",
                        (
                            "Solo se observaron balizas/sondeos; no hubo tráfico de datos de un cliente. "
                            "Mantén un cliente autorizado asociado al BSSID y vuelve a capturar."
                            if not evidence.get("data_frames")
                            else "Se observaron tramas del BSSID, pero ninguna autenticación EAPOL. Mantén conectado un cliente autorizado y vuelve a autenticarlo mientras capturas."
                        ),
                        f"La captura puede solicitar hasta {AUTOMATIC_RECONNECT_ATTEMPTS} reconexiones dirigidas al cliente detectado y autorizado.",
                    ]
            lines += [
                "",
                "HUELLA SHA-256",
                item.sha256 or "Pendiente",
                "",
                "ARCHIVO LOCAL",
                item.path,
            ]
            self.evidence_view.setPlainText("\n".join(lines))
        else:
            self.evidence_view.setPlainText(
                "EVIDENCIA\n\nSelecciona una captura para ver el análisis."
            )
        self._set_lab_controls()

    def _refresh_recoveries(self):
        project = self.project_selector.currentData()
        records = self.laboratory.recoveries(project) if project else []
        self.recovery_table.setSortingEnabled(False)
        self.recovery_table.setRowCount(len(records))
        from app.ui.qt import QTableWidgetItem

        for row, item in enumerate(records):
            for column, value in enumerate(
                (
                    format_local_datetime(item.created_at, "%d/%m %H:%M"),
                    item.artifact_id[:8],
                    Path(item.dictionary).name,
                    STATUS.get(item.status, item.status),
                )
            ):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, item.id)
                self.recovery_table.setItem(row, column, cell)
        self.recovery_table.setSortingEnabled(True)
        self._recovery_selected()

    def _recovery_selected(self):
        identifier = self._selected_id(self.recovery_table)
        self.result_button.setEnabled(False)
        if not identifier:
            self.recovery_detail.setText(
                "Selecciona un trabajo para consultar su resultado."
            )
            return
        with self.sessions() as session:
            item = session.get(RecoveryJob, identifier)
        self.recovery_detail.setText(item.message)
        self.result_button.setEnabled(
            item.status in ("recovered", "partial", "interrupted")
            and Path(item.result_path).exists()
            and Path(item.result_path).stat().st_size > 0
        )

    def _start_lab(self, action, label, limit):
        if self.lab_job is not None:
            return False
        if "redes" in self.jobs or "estaciones" in self.jobs:
            self._notice(
                label,
                "Espera a que termine la consulta de redes antes de iniciar un trabajo.",
                error=True,
            )
            return False
        job = self.lab_job = ToolJob()
        self.lab_limit = limit
        self.lab_label = label
        self._set_lab_controls()
        self._notice(label, "Preparando trabajo…")
        if label is getattr(self, "recovery_status", None):
            self.recovery_live.setText(
                "Iniciando Hashcat; aparecerá el conteo de pruebas en unos segundos…"
            )

        def execute():
            try:
                return action(job), None
            except Exception as error:
                return None, error

        self._submit("laboratorio", execute, self._lab_done, label, self.capture_stop)
        self.capture_stop.setEnabled(True)
        return True

    def request_reconnect(self, confirm=True):
        if not self.capture_active or self.lab_job is None:
            self._notice(
                self.reconnect_status,
                "Inicia una captura antes de solicitar la reconexión del cliente.",
                error=True,
            )
            return False
        if "reconexion" in self.jobs:
            return False
        project = self.project_selector.currentData()
        bssid = self.target_selector.currentData()
        station = self._selected_station()
        interface = self.capture_interface.currentData()
        if not self.reconnect_consent.isChecked():
            self._notice(
                self.reconnect_status,
                "Confirma la autorización de la red y del cliente antes de continuar.",
                error=True,
            )
            return False
        try:
            self._ensure_station_authorized()
        except Exception as error:
            self._notice(self.reconnect_status, str(error), error=True)
            return False
        if confirm:
            answer = QMessageBox.warning(
                self,
                "Solicitar reconexión dirigida",
                f"Se solicitarán hasta {AUTOMATIC_RECONNECT_ATTEMPTS} reconexiones dirigidas para {station.upper()} en {bssid.upper()}, con pausas entre intentos. Solo se afectará ese cliente autorizado. ¿Continuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return False
        job = ToolJob()
        self.reconnect_job = job
        self._notice(self.reconnect_status, "Solicitando reconexión dirigida…")
        self._submit(
            "reconexion",
            lambda: self.laboratory.trigger_reconnect(
                project, bssid, station, interface, job
            ),
            self._reconnect_done,
            self.reconnect_status,
            self.reconnect_button,
        )
        return True

    def _reconnect_done(self, result):
        self.reconnect_job = None
        if isinstance(result, str) and result.startswith("local:"):
            device = result.split(":", 1)[1]
            message = (
                f"El cliente local {device} se reconectó automáticamente. "
                "Mantén la captura activa mientras se completa EAPOL."
            )
        elif isinstance(result, int):
            message = (
                f"Reconexión solicitada; el adaptador recibió {result} ACK(s). "
                "Mantén la captura activa mientras el cliente vuelve a autenticarse."
            )
        else:
            message = (
                "Solicitud enviada. Mantén la captura activa mientras el cliente "
                "vuelve a autenticarse."
            )
        self._notice(
            self.reconnect_status,
            message,
        )
        self._set_lab_controls()

    def _lab_done(self, outcome):
        result, error = outcome
        label = self.lab_label
        self._stop_automatic_reconnects()
        self.lab_job = None
        self.capture_active = False
        self.lab_progress.setValue(100 if error is None else 0)
        if not getattr(self, "close_pending", False):
            self.refresh_interfaces()
        self._refresh_artifacts()
        self._refresh_recoveries()
        self._set_lab_controls()
        success_message = (
            "Trabajo finalizado. Selecciona el registro para consultar el resultado."
        )
        if error is None and result and label is self.capture_status:
            try:
                artifact = self.laboratory.artifact(result)
                if artifact.status == "analyzed":
                    evidence = {}
                    try:
                        evidence = json.loads(artifact.evidence_json or "{}")
                    except (TypeError, ValueError):
                        pass
                    packets = evidence.get("packets")
                    prefix = (
                        f"Intento finalizado sin material WPA: {packets} tramas observadas. "
                        if isinstance(packets, int)
                        else "Intento finalizado sin material WPA. "
                    )
                    success_message = prefix + artifact.message
                elif artifact.status == "ready":
                    success_message = (
                        "Captura válida: se obtuvo material WPA convertible. "
                        "Selecciona el registro para iniciar la recuperación offline."
                    )
            except Exception:
                pass
        elif error is None and result and label is self.recovery_status:
            success_message = str(result)
        self._notice(
            label,
            str(error) if error else success_message,
            error=error is not None,
        )
        if getattr(self, "close_pending", False):
            QTimer.singleShot(0, self.close)

    def _update_lab_progress(self):
        if self.lab_job is None:
            return
        elapsed = int(time.monotonic() - self.lab_job.started)
        progress = getattr(self.lab_job, "progress", {}) or {}
        total = progress.get("total", 0)
        current = progress.get("current", 0)
        percent = progress.get("percent")
        if total and percent is not None:
            try:
                current = max(0, int(current))
                total = max(1, int(total))
                percent = max(0.0, min(100.0, float(percent)))
            except (TypeError, ValueError):
                total = 0
        if total:
            self.lab_label.setText(
                f"{self.lab_job.stage} · {percent:.2f}% · {elapsed} s transcurridos"
            )
            self.lab_progress.setValue(min(100, int(percent)))
            speed = self._format_hashcat_speed(progress.get("speed", 0))
            recovered = progress.get("recovered")
            hashes = progress.get("hashes")
            match_count = (
                f" · coincidencias {recovered}/{hashes}"
                if recovered is not None and hashes is not None
                else ""
            )
            self.recovery_live.setText(
                f"Pruebas realizadas: {current:,} de {total:,} · {percent:.2f}% · {speed}{match_count}"
            )
        else:
            self.lab_label.setText(f"{self.lab_job.stage} · {elapsed} s transcurridos")
            self.lab_progress.setValue(
                min(99, int(elapsed * 100 / max(self.lab_limit, 1)))
            )

    @staticmethod
    def _format_hashcat_speed(value):
        try:
            speed = max(0, float(value))
        except (TypeError, ValueError):
            return "velocidad no disponible"
        if speed >= 1_000_000:
            return f"{speed / 1_000_000:.2f} MH/s"
        if speed >= 1_000:
            return f"{speed / 1_000:.1f} kH/s"
        return f"{speed:.0f} H/s"

    def stop_lab_job(self):
        self._stop_automatic_reconnects()
        if self.lab_job:
            self.lab_job.cancel()
            self.lab_job.stage = "Deteniendo y conservando resultados…"
        if self.reconnect_job:
            self.reconnect_job.cancel()
            self.reconnect_status.setText("Deteniendo la reconexión dirigida…")

    def start_capture(self):
        project, bssid = (
            self.project_selector.currentData(),
            self.target_selector.currentData(),
        )
        interface = self.capture_interface.currentData()
        frequency, seconds = (
            self.capture_frequency.value(),
            self.capture_seconds.value(),
        )
        consent = self.monitor_consent.isChecked()
        target_frequency = self._target_frequency(project, bssid)
        if target_frequency is not None and frequency != target_frequency:
            frequency = target_frequency
            self.capture_frequency.setValue(target_frequency)
            self._notice(
                self.capture_status,
                f"Frecuencia corregida automáticamente a {target_frequency} MHz según el canal autorizado.",
            )
        if self.reconnect_automatic.isChecked():
            if seconds < RECOMMENDED_CAPTURE_SECONDS:
                seconds = RECOMMENDED_CAPTURE_SECONDS
                self.capture_seconds.setValue(seconds)
            if not self._selected_station() or not self.reconnect_consent.isChecked():
                self._notice(
                    self.reconnect_status,
                    "Mantén un cliente conectado, espera a que aparezca en la detección automática y confirma la autorización antes de activar la reconexión.",
                    error=True,
                )
                return
            try:
                self._ensure_station_authorized()
            except Exception as error:
                self._notice(self.reconnect_status, str(error), error=True)
                return
            answer = QMessageBox.warning(
                self,
                "Reconexión dirigida autorizada",
                f"Se solicitarán hasta {AUTOMATIC_RECONNECT_ATTEMPTS} reconexiones dirigidas para {self._selected_station()} durante la captura. Solo se afectará ese cliente autorizado. ¿Continuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.capture_active = True
        started = self._start_lab(
            lambda job: self.laboratory.capture(
                project,
                bssid,
                interface,
                frequency,
                seconds,
                consent,
                job,
                automatic_methods=True,
            ),
            self.capture_status,
            seconds + 360,
        )
        if not started:
            self.capture_active = False
            return
        if started and self.reconnect_automatic.isChecked():
            self._start_automatic_reconnects()

    def _start_automatic_reconnects(self):
        self._automatic_reconnect_attempts = 0
        self._notice(
            self.reconnect_status,
            f"Captura activa. Preparando {AUTOMATIC_RECONNECT_ATTEMPTS} intentos dirigidos sobre el cliente seleccionado…",
        )
        QTimer.singleShot(1200, self._automatic_reconnect_attempt)

    def _automatic_reconnect_attempt(self):
        if not self.capture_active or self.lab_job is None:
            self._stop_automatic_reconnects()
            return
        if "reconexion" in self.jobs:
            return
        if self._automatic_reconnect_attempts >= AUTOMATIC_RECONNECT_ATTEMPTS:
            self._stop_automatic_reconnects()
            return
        attempt = self._automatic_reconnect_attempts + 1
        self._notice(
            self.reconnect_status,
            f"Solicitando reconexión automática {attempt}/{AUTOMATIC_RECONNECT_ATTEMPTS}…",
        )
        if self.request_reconnect(confirm=False):
            self._automatic_reconnect_attempts = attempt
            if attempt < AUTOMATIC_RECONNECT_ATTEMPTS:
                self._automatic_reconnect_timer.start()
            else:
                self._stop_automatic_reconnects()

    def _automatic_reconnect_retry(self):
        if self._automatic_reconnect_attempts >= AUTOMATIC_RECONNECT_ATTEMPTS:
            self._stop_automatic_reconnects()
            return
        self._automatic_reconnect_attempt()

    def _stop_automatic_reconnects(self):
        timer = getattr(self, "_automatic_reconnect_timer", None)
        if timer is not None:
            timer.stop()

    def _target_frequency(self, project_id, bssid):
        if not project_id or not bssid:
            return None
        with self.sessions() as session:
            target = session.scalar(
                select(AuthorizedTarget).where(
                    AuthorizedTarget.project_id == project_id,
                    AuthorizedTarget.bssid == bssid,
                )
            )
        if target is None:
            return None
        observed = next(
            (
                item.frequency
                for item in getattr(self, "networks", [])
                if item.bssid == bssid and item.frequency is not None
            ),
            None,
        )
        if observed is not None:
            return observed
        if target.channel == 14:
            return 2484
        if target.channel < 14:
            return 2407 + target.channel * 5
        return 5000 + target.channel * 5

    def import_capture(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Importar captura propia",
            "",
            "Capturas (*.pcap *.pcapng *.cap);;Todos los archivos (*)",
        )
        if not filename:
            return
        project, bssid = (
            self.project_selector.currentData(),
            self.target_selector.currentData(),
        )
        self._start_lab(
            lambda job: self.laboratory.import_capture(
                project, bssid, Path(filename), job
            ),
            self.capture_status,
            240,
        )

    def analyze_selected(self):
        identifier = self._selected_id(self.artifacts_table)
        if identifier:
            self._start_lab(
                lambda job: self.laboratory.analyze(identifier, job),
                self.capture_status,
                240,
            )

    def delete_selected_capture(self):
        identifier = self._selected_id(self.artifacts_table)
        if not identifier:
            return
        if not self._confirm_destructive(
            "Eliminar captura",
            "Se eliminarán el PCAP/PCAPNG, su análisis y las recuperaciones asociadas. Esta acción no se puede deshacer. ¿Continuar?",
        ):
            return
        try:
            self.laboratory.delete_artifact(identifier)
            self._refresh_artifacts()
            self._refresh_recoveries()
            self._notice(
                self.capture_status, "Captura eliminada y archivos locales limpiados."
            )
        except Exception as error:
            self._notice(self.capture_status, str(error), error=True)

    def clear_captures(self):
        project = self.project_selector.currentData()
        if not project:
            return
        count = self.artifacts_table.rowCount()
        if not count:
            return
        if not self._confirm_destructive(
            "Limpiar capturas",
            f"Se eliminarán las {count} capturas del proyecto, sus análisis, hashes y recuperaciones asociadas. Esta acción no se puede deshacer. ¿Continuar?",
        ):
            return
        try:
            removed = self.laboratory.clear_artifacts(project)
            self._refresh_artifacts()
            self._refresh_recoveries()
            self._notice(
                self.capture_status,
                f"Se limpiaron {removed} capturas y sus archivos locales.",
            )
        except Exception as error:
            self._notice(self.capture_status, str(error), error=True)

    def _dictionary_paths(self):
        paths = []
        seen = set()
        for index in range(self.dictionary_list.count()):
            item = self.dictionary_list.item(index)
            value = item.data(Qt.ItemDataRole.UserRole) or item.text()
            path = Path(str(value)).expanduser()
            key = str(path.resolve(strict=False))
            if key not in seen:
                paths.append(path)
                seen.add(key)
        return paths

    def choose_dictionary(self):
        filenames, _ = QFileDialog.getOpenFileNames(
            self,
            "Seleccionar diccionarios locales",
            "",
            "Texto (*.txt *.dic *.dict);;Todos los archivos (*)",
        )
        existing = {
            str(path.resolve(strict=False)) for path in self._dictionary_paths()
        }
        for filename in filenames:
            path = Path(filename).expanduser()
            key = str(path.resolve(strict=False))
            if key in existing:
                continue
            self.dictionary_list.addItem(path.name)
            item = self.dictionary_list.item(self.dictionary_list.count() - 1)
            item.setData(Qt.ItemDataRole.UserRole, key)
            item.setToolTip(key)
            existing.add(key)
        self._set_lab_controls()

    def remove_selected_dictionaries(self):
        rows = sorted(
            (
                self.dictionary_list.row(item)
                for item in self.dictionary_list.selectedItems()
            ),
            reverse=True,
        )
        for row in rows:
            self.dictionary_list.takeItem(row)
        self._set_lab_controls()

    def clear_dictionaries(self):
        self.dictionary_list.clear()
        self._set_lab_controls()

    def start_recovery(self):
        identifier = self.recovery_artifact.currentData()
        dictionaries = self._dictionary_paths()
        if not identifier:
            self._notice(
                self.recovery_status,
                "Selecciona una captura con material WPA antes de iniciar.",
                error=True,
            )
            return
        if not dictionaries:
            self._notice(
                self.recovery_status,
                "Añade al menos un diccionario local antes de iniciar.",
                error=True,
            )
            self.dictionary_button.setFocus()
            return
        runtime = self.recovery_seconds.value()

        def recover_batch(job):
            completed = 0
            failures = []
            for position, dictionary in enumerate(dictionaries, start=1):
                if job.cancelled.is_set():
                    raise JobCancelled("Trabajo detenido por el usuario.")
                job.stage = (
                    f"Diccionario {position}/{len(dictionaries)} · {dictionary.name}"
                )
                try:
                    recovery_id = self.laboratory.recover(
                        identifier, dictionary, runtime, job
                    )
                except JobCancelled:
                    raise
                except Exception as error:
                    failures.append(f"{dictionary.name}: {error}")
                    continue
                completed += 1
                with self.sessions() as session:
                    recovery = session.get(RecoveryJob, recovery_id)
                if recovery and recovery.status in {"recovered", "partial"}:
                    result = (
                        "Clave recuperada con "
                        f"{dictionary.name}. Se detuvo la cola después de "
                        f"{completed} diccionario(s)."
                    )
                    if failures:
                        result += f" Incidencias anteriores: {len(failures)}."
                    return result
            result = (
                f"Se probaron {completed} de {len(dictionaries)} diccionario(s) "
                "sin obtener una coincidencia."
            )
            if failures:
                result += f" {len(failures)} no se pudieron iniciar."
            return result

        self._start_lab(
            recover_batch,
            self.recovery_status,
            runtime * len(dictionaries),
        )

    def delete_selected_recovery(self):
        identifier = self._selected_id(self.recovery_table)
        if not identifier:
            return
        if not self._confirm_destructive(
            "Eliminar recuperación",
            "Se eliminarán este registro, su resultado y su log local. La captura original se conservará. ¿Continuar?",
        ):
            return
        try:
            self.laboratory.delete_recovery(identifier)
            self._refresh_recoveries()
            self._notice(
                self.recovery_status,
                "Recuperación eliminada y archivos locales limpiados.",
            )
        except Exception as error:
            self._notice(self.recovery_status, str(error), error=True)

    def clear_recoveries(self):
        project = self.project_selector.currentData()
        if not project:
            return
        count = self.recovery_table.rowCount()
        if not count:
            return
        if not self._confirm_destructive(
            "Limpiar recuperaciones",
            f"Se eliminarán las {count} recuperaciones del proyecto y sus resultados locales. Las capturas se conservarán. ¿Continuar?",
        ):
            return
        try:
            removed = self.laboratory.clear_recoveries(project)
            self._refresh_recoveries()
            self._notice(
                self.recovery_status,
                f"Se limpiaron {removed} recuperaciones.",
            )
        except Exception as error:
            self._notice(self.recovery_status, str(error), error=True)

    def show_recovered(self):
        identifier = self._selected_id(self.recovery_table)
        if not identifier:
            return
        with self.sessions() as session:
            row = session.get(RecoveryJob, identifier)
        try:
            lines = Path(row.result_path).read_text().splitlines()
            results = []
            for line in lines:
                encoded = line.rsplit(":", 1)[-1]
                results.append(bytes.fromhex(encoded).decode("utf-8", errors="replace"))
            dialog = QDialog(self)
            dialog.setWindowTitle("Resultado local de recuperación")
            dialog.resize(520, 300)
            layout = QVBoxLayout(dialog)
            layout.addWidget(
                self._label("Claves recuperadas para el material de esta captura.")
            )
            text = QTextEdit()
            text.setReadOnly(True)
            text.setAccessibleName("Claves recuperadas")
            text.setPlainText("\n".join(results))
            layout.addWidget(text)
            close = self._button("Cerrar", dialog.accept)
            layout.addWidget(close)
            dialog.exec()
        except (OSError, ValueError) as error:
            self._notice(self.recovery_detail, str(error), error=True)
