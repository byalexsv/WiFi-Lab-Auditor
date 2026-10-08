from __future__ import annotations

import csv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from app.core.diagnostics import SystemHealth, system_health, system_status
from app.core.interface_manager import InterfaceManager
from app.core.laboratory import Laboratory
from app.core.mock_mode import enabled
from app.core.network_scanner import NetworkScanner
from app.core.scope_manager import ScopeManager
from app.database import AuthorizedTarget, Project, create_session_factory
from app.ui.datetime_utils import format_local_datetime
from app.ui.lab_workspace import LabWorkspace
from app.ui.qt import (
    QAbstractItemView,
    QColor,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
)
from app.ui.theme import STYLE


class MainWindow(LabWorkspace, QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("WiFi Lab Auditor")
        self.resize(1440, 920)
        self.setMinimumSize(1100, 760)
        self.sessions = create_session_factory()
        self.laboratory = Laboratory(self.sessions)
        self.lab_job = None
        self.capture_active = False
        self.reconnect_job = None
        self.station_discovery_job = None
        self._station_retry_timer = QTimer(self)
        self._station_retry_timer.setInterval(15000)
        self._station_retry_timer.timeout.connect(self._retry_station_discovery)
        self._automatic_reconnect_attempts = 0
        self._automatic_reconnect_timer = QTimer(self)
        self._automatic_reconnect_timer.setInterval(15000)
        self._automatic_reconnect_timer.timeout.connect(self._automatic_reconnect_retry)
        # Automatic station discovery is tied to the current scope/interface.
        # Refreshing interfaces after a capture must not start a second scan
        # and overwrite the capture result that is still on screen.
        self._station_discovery_signature = None
        self.scanner = NetworkScanner()
        self.networks = []
        self.interface_records = []
        self._network_scan_completed = False
        self.executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="wifi-lab")
        self.jobs = {}
        self._build()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._poll_jobs)
        self.timer.start(100)
        self.refresh_projects()
        self.refresh_interfaces()
        self.refresh_networks()
        self.refresh_system_health()

    def _label(self, text, name="muted"):
        label = QLabel(text)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setObjectName(name)
        label.setWordWrap(True)
        return label

    def _page(self, title, description):
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(32, 30, 32, 24)
        box.setSpacing(16)
        box.addWidget(self._label(title, "title"))
        box.addWidget(self._label(description))
        return page, box

    def _button(self, text, callback, secondary=False):
        button = QPushButton(text)
        button.setAccessibleName(text)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if secondary:
            button.setObjectName("secondary")
        button.clicked.connect(lambda _checked=False: callback())
        return button

    def _confirm_destructive(self, title, message):
        answer = QMessageBox.warning(
            self,
            title,
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _table(self, headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setAccessibleName("Tabla: " + ", ".join(headers))
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(46)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        return table

    def _fill(self, table, rows):
        table.setSortingEnabled(False)
        table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem()
                item.setData(Qt.ItemDataRole.DisplayRole, value)
                table.setItem(row, column, item)
        table.setSortingEnabled(True)

    def _build(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(208)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 30, 20, 22)
        side.addWidget(self._label("WiFi Lab", "brand"))
        side.addWidget(self._label("Laboratorio inalámbrico", "eyebrow"))
        side.addSpacing(30)
        self.nav = QListWidget()
        self.pages = QStackedWidget()
        self.nav.setAccessibleName("Navegación principal")
        for name, page in (
            ("Resumen", self._dashboard()),
            ("Redes Wi-Fi", self._networks()),
            ("Capturas", self._captures()),
            ("Recuperación", self._recovery_page()),
            ("Adaptadores", self._interfaces()),
            ("Proyectos", self._projects()),
            ("Diagnóstico", self._diagnostics()),
        ):
            scroll = QScrollArea()
            scroll.setObjectName("page-scroll")
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setWidget(page)
            page = scroll
            self.nav.addItem(name)
            self.pages.addWidget(page)
        self.nav.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.nav.setCurrentRow(1)
        side.addWidget(self.nav)
        side.addWidget(
            self._label(
                "●  Demostración" if enabled() else "●  Equipo local", "eyebrow"
            )
        )
        side.addSpacing(12)
        side.addWidget(self._label("Capturas y resultados\nguardados localmente"))
        layout.addWidget(sidebar)
        workspace = QWidget()
        workspace_layout = QVBoxLayout(workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)
        topbar = QWidget()
        topbar.setObjectName("topbar")
        top = QHBoxLayout(topbar)
        top.setContentsMargins(32, 12, 32, 12)
        top.addWidget(self._label("Espacio de trabajo", "brand"))
        top.addStretch()
        self.system_indicator = self._label("● SYSTEM CHECKING", "system-checking")
        self.system_indicator.setToolTip("Comprobando el backend local…")
        top.addWidget(self.system_indicator)
        top.addSpacing(22)
        top.addWidget(self._label("Proyecto activo"))
        self.project_selector = QComboBox()
        self.project_selector.setMinimumWidth(240)
        self.project_selector.setAccessibleName("Proyecto activo")
        self.project_selector.currentIndexChanged.connect(self._project_changed)
        top.addWidget(self.project_selector)
        workspace_layout.addWidget(topbar)
        workspace_layout.addWidget(self.pages, 1)
        layout.addWidget(workspace, 1)
        self.setStyleSheet(STYLE)
        for card in self.findChildren(QWidget):
            if card.objectName() != "card":
                continue
            glow = QGraphicsDropShadowEffect(card)
            glow.setBlurRadius(22)
            glow.setColor(QColor(0, 183, 230, 42))
            glow.setOffset(0, 4)
            card.setGraphicsEffect(glow)
        self.statusBar().showMessage("Listo")

    def _dashboard(self):
        page, box = self._page(
            "Resumen del laboratorio",
            "Inventario y proyectos disponibles en este equipo.",
        )
        cards = QHBoxLayout()
        self.metrics = {}
        for key, title, description in (
            ("interfaces", "Adaptadores", "Interfaces Wi-Fi detectadas"),
            ("networks", "Redes", "Último inventario consultado"),
            ("projects", "Proyectos", "Guardados en este equipo"),
        ):
            card = QWidget()
            card.setObjectName("card")
            content = QVBoxLayout(card)
            content.setContentsMargins(20, 20, 20, 20)
            content.addWidget(self._label(title))
            metric = self._label("—", "metric")
            self.metrics[key] = metric
            content.addWidget(metric)
            content.addWidget(self._label(description))
            cards.addWidget(card)
        box.addLayout(cards)
        self.dashboard_status = self._label("Consultando el equipo…", "notice")
        box.addWidget(self.dashboard_status)
        box.addWidget(self._label("Empieza por el inventario", "brand"))
        box.addWidget(
            self._label(
                "La consulta inicial lee las redes conocidas por NetworkManager. En Redes Wi-Fi puedes solicitar una nueva exploración y exportar los resultados a CSV."
            )
        )
        box.addWidget(
            self._button("Ver redes Wi-Fi →", lambda: self.nav.setCurrentRow(1)),
            alignment=Qt.AlignmentFlag.AlignLeft,
        )
        box.addStretch()
        box.addWidget(
            self._label(
                "Flujo de trabajo: proyecto → red autorizada → captura o importación → análisis → recuperación offline."
            )
        )
        return page

    def _networks(self):
        page, box = self._page(
            "Redes Wi-Fi",
            "Inventario de NetworkManager. La señal real se muestra en porcentaje; no se estima el RSSI.",
        )
        actions = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setAccessibleName("Buscar redes por nombre, BSSID o seguridad")
        self.search.setPlaceholderText("Buscar por nombre, BSSID o seguridad…")
        self.search.textChanged.connect(self._render_networks)
        actions.addWidget(self.search, 1)
        self.scan_button = self._button(
            "Buscar redes", lambda: self.refresh_networks(True)
        )
        actions.addWidget(self.scan_button)
        self.network_adapter_button = self._button(
            "Gestionar adaptador",
            lambda: self.nav.setCurrentRow(2),
            True,
        )
        self.network_adapter_button.setVisible(False)
        actions.addWidget(self.network_adapter_button)
        self.export_button = self._button("Exportar CSV", self.export_networks, True)
        self.export_button.setEnabled(False)
        actions.addWidget(self.export_button)
        self.clear_inventory_button = self._button(
            "Limpiar inventario", self.clear_inventory, True
        )
        actions.addWidget(self.clear_inventory_button)
        box.addLayout(actions)
        self.network_status = self._label("Sin consulta realizada.", "notice")
        box.addWidget(self.network_status)
        self.networks_table = self._table(
            [
                "Red / SSID",
                "BSSID",
                "Canal",
                "Banda",
                "Señal",
                "Seguridad",
                "Estado",
            ]
        )
        box.addWidget(self.networks_table, 1)
        scope_actions = QHBoxLayout()
        self.scope_button = self._button(
            "Añadir red seleccionada al proyecto", self.authorize_selected_network, True
        )
        self.remove_target_button = self._button(
            "Quitar autorización", self.remove_selected_target, True
        )
        scope_actions.addWidget(self.scope_button)
        scope_actions.addWidget(self.remove_target_button)
        scope_actions.addStretch()
        box.addLayout(scope_actions)
        box.addWidget(
            self._label(
                "Buscar redes solicita una exploración normal a NetworkManager; no es una captura pasiva en modo monitor. Exportar incluye todo el último inventario, aunque haya un filtro."
            )
        )
        return page

    def _interfaces(self):
        page, box = self._page(
            "Adaptadores",
            "Interfaces y controladores que el kernel expone mediante iw.",
        )
        self.interface_status = self._label("Consultando interfaces…", "notice")
        box.addWidget(self.interface_status)
        self.interfaces_table = self._table(
            ["Interfaz", "Radio / PHY", "Controlador", "MAC", "Modo"]
        )
        box.addWidget(self.interfaces_table, 1)
        self.interface_button = self._button(
            "Actualizar adaptadores", self.refresh_interfaces
        )
        box.addWidget(self.interface_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def _projects(self):
        page, box = self._page(
            "Proyectos",
            "Registra el responsable y la autorización de cada trabajo. Los proyectos se conservan al cerrar la app.",
        )
        self.projects_table = self._table(["ID", "Proyecto", "Responsable", "Creado"])
        self.projects_table.itemSelectionChanged.connect(self._set_lab_controls)
        box.addWidget(self.projects_table, 1)
        project_actions = QHBoxLayout()
        self.project_delete_button = self._button(
            "Eliminar proyecto y sus datos", self.delete_selected_project, True
        )
        project_actions.addWidget(self.project_delete_button)
        project_actions.addStretch()
        box.addLayout(project_actions)
        form = QFormLayout()
        form.setSpacing(12)
        self.project_name = QLineEdit()
        self.project_name.setMaxLength(120)
        self.responsible = QLineEdit()
        self.responsible.setMaxLength(120)
        self.authorization = QTextEdit()
        self.authorization.setMaximumHeight(95)
        self.authorization.setPlaceholderText(
            "Propietario, referencia del permiso y alcance autorizado"
        )
        form.addRow("Nombre del proyecto", self.project_name)
        form.addRow("Responsable", self.responsible)
        form.addRow("Autorización", self.authorization)
        box.addLayout(form)
        self.project_create_button = self._button(
            "Guardar proyecto", self.create_project
        )
        box.addWidget(self.project_create_button, alignment=Qt.AlignmentFlag.AlignLeft)
        self.project_result = self._label("")
        self.project_name.setAccessibleName("Nombre del proyecto, obligatorio")
        self.responsible.setAccessibleName("Responsable")
        self.authorization.setAccessibleName("Autorización, obligatoria")
        box.addWidget(self.project_result)
        return page

    def _diagnostics(self):
        page, box = self._page(
            "Diagnóstico del sistema",
            "Comprueba herramientas, servicio de red, radio Wi-Fi y dispositivos. Esta consulta siempre inspecciona el equipo real.",
        )
        self.diagnostic_log = QTextEdit()
        self.diagnostic_log.setReadOnly(True)
        self.diagnostic_log.setPlainText(
            "Pulsa Comprobar sistema para consultar el estado actual."
        )
        box.addWidget(self.diagnostic_log, 1)
        self.diagnostic_button = self._button(
            "Comprobar sistema", self.refresh_diagnostics
        )
        box.addWidget(self.diagnostic_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def _submit(self, key, function, success, error_label, button=None):
        if key in self.jobs:
            return
        if button is not None:
            button.setEnabled(False)
        self.jobs[key] = (self.executor.submit(function), success, error_label, button)

    def _poll_jobs(self):
        self._update_lab_progress()
        for key, (future, success, error_label, button) in list(self.jobs.items()):
            if not future.done():
                continue
            del self.jobs[key]
            if button is not None:
                button.setEnabled(True)
            if key == "reconexion":
                self.reconnect_job = None
            if key == "estaciones":
                self.station_discovery_job = None
            try:
                success(future.result())
            except Exception as error:
                message = str(error)
                if key == "salud":
                    self._set_system_indicator(
                        "SYSTEM OFFLINE", "offline", f"{message}\nRevisa Diagnóstico."
                    )
                elif isinstance(error_label, QTextEdit):
                    error_label.setPlainText(message)
                else:
                    self._notice(error_label, message, error=True)
                self.dashboard_status.setText(
                    f"No se pudo completar {key}. Revisa la sección correspondiente o Diagnóstico."
                )
                self.statusBar().showMessage(message, 12000)
            if key == "estaciones":
                self._set_lab_controls()

    def _set_system_indicator(self, text, state, tooltip):
        self.system_indicator.setText(f"● {text}")
        self.system_indicator.setObjectName(f"system-{state}")
        self.system_indicator.setToolTip(tooltip)
        self.system_indicator.style().unpolish(self.system_indicator)
        self.system_indicator.style().polish(self.system_indicator)

    def _system_health_ready(self, health: SystemHealth):
        self._set_system_indicator(
            "SYSTEM ONLINE" if health.online else "SYSTEM OFFLINE",
            "online" if health.online else "offline",
            f"{health.message}\n{health.details}".strip(),
        )

    def refresh_system_health(self):
        if "salud" in self.jobs:
            return
        self._set_system_indicator(
            "SYSTEM CHECKING", "checking", "Comprobando el backend local…"
        )
        self._submit(
            "salud", system_health, self._system_health_ready, self.system_indicator
        )

    def _notice(self, label, message, error=False):
        label.setObjectName("error" if error else "notice")
        label.setMinimumHeight(34 if error else 0)
        label.setText(message)
        label.style().unpolish(label)
        label.style().polish(label)
        label.updateGeometry()
        label.adjustSize()

    def refresh_interfaces(self):
        if "adaptadores" in self.jobs:
            return
        self._notice(self.interface_status, "Consultando interfaces…")
        self._submit(
            "adaptadores",
            InterfaceManager().list_interfaces,
            self._interfaces_ready,
            self.interface_status,
            self.interface_button,
        )

    def _interfaces_ready(self, records):
        self._fill(
            self.interfaces_table,
            [
                (item.name, item.phy, item.driver, item.mac, item.mode)
                for item in records
            ],
        )
        self.interface_records = records
        self.metrics["interfaces"].setText(str(len(records)))
        self._load_capture_interfaces(records)
        if self._network_scan_completed:
            self._networks_ready(self.networks)
        self._notice(
            self.interface_status,
            (
                f"{len(records)} adaptador(es) detectado(s)."
                if records
                else "No se detectaron interfaces Wi-Fi. Revisa la conexión del adaptador y su controlador en Diagnóstico."
            ),
        )

    def refresh_networks(self, rescan=False):
        if "redes" in self.jobs:
            return
        self._notice(
            self.network_status,
            "Consultando redes… Los resultados anteriores, si existen, se conservan hasta completar la consulta.",
        )
        self._submit(
            "redes",
            lambda: self.scanner.scan(rescan=rescan),
            self._networks_ready,
            self.network_status,
            self.scan_button,
        )

    def _networks_ready(self, records):
        self.networks = records
        self._network_scan_completed = True
        self._render_networks()
        self.metrics["networks"].setText(str(len(records)))
        self.export_button.setEnabled(bool(records))
        source = "Datos sintéticos" if enabled() else "NetworkManager"
        stamp = datetime.now().strftime("%H:%M:%S")
        ssid_count = len({item.ssid for item in records})
        message = (
            f"{len(records)} radios · {ssid_count} nombres · {source} · "
            f"Actualizado a las {stamp}"
        )
        monitor_names = [
            item.name for item in self.interface_records if item.mode == "monitor"
        ]
        monitor_scan_blocked = not records and bool(monitor_names) and not enabled()
        if not records:
            if monitor_scan_blocked:
                names = ", ".join(monitor_names)
                message += (
                    f". NetworkManager no puede explorar mientras {names} está en modo monitor. "
                    "Ve a Capturas, pulsa Restaurar adaptador, vuelve aquí y pulsa Buscar redes."
                )
            else:
                message += ". No hay redes disponibles. Comprueba el adaptador y la radio en Diagnóstico; prueba Buscar redes."
        self.network_adapter_button.setVisible(monitor_scan_blocked)
        self._notice(self.network_status, message, error=monitor_scan_blocked)
        self.dashboard_status.setText(message)
        self.statusBar().showMessage("Inventario actualizado", 5000)

    def _render_networks(self, *_):
        query = self.search.text().casefold().strip()
        records = [
            item
            for item in self.networks
            if query in f"{item.ssid} {item.bssid} {item.security}".casefold()
        ]
        project_id = self.project_selector.currentData()
        authorized = set()
        if project_id:
            with self.sessions() as session:
                authorized = set(
                    session.scalars(
                        select(AuthorizedTarget.bssid).where(
                            AuthorizedTarget.project_id == project_id
                        )
                    ).all()
                )
        self._fill(
            self.networks_table,
            [
                (
                    item.ssid or "(SSID oculto)",
                    item.bssid,
                    item.channel,
                    item.band,
                    (
                        f"{item.signal_percent}%"
                        if item.signal_percent is not None
                        else f"{item.rssi} dBm" if item.rssi is not None else "—"
                    ),
                    item.security,
                    "Autorizada" if item.bssid in authorized else "Solo inventario",
                )
                for item in records
            ],
        )
        self._set_lab_controls()

    def clear_inventory(self):
        if not self.networks:
            return
        if not self._confirm_destructive(
            "Limpiar inventario",
            "Se quitarán de esta sesión todas las redes detectadas. Las autorizaciones y capturas guardadas no se borrarán. ¿Continuar?",
        ):
            return
        self.networks = []
        self._network_scan_completed = False
        self._render_networks()
        self.metrics["networks"].setText("0")
        self.network_status.setText(
            "Inventario limpiado. Pulsa Buscar redes para explorar de nuevo."
        )
        self.dashboard_status.setText(self.network_status.text())
        self.statusBar().showMessage("Inventario limpiado", 5000)

    def remove_selected_target(self):
        project_id = self.project_selector.currentData()
        row = self.networks_table.currentRow()
        if not project_id or row < 0:
            return
        bssid = self.networks_table.item(row, 1).text()
        status = self.networks_table.item(row, 6).text()
        if status != "Autorizada":
            self._notice(
                self.network_status,
                "Selecciona una red autorizada para quitarla del proyecto.",
                error=True,
            )
            return
        if not self._confirm_destructive(
            "Quitar autorización",
            f"Se quitará {bssid} del proyecto activo y sus clientes autorizados. Las capturas existentes se conservarán. ¿Continuar?",
        ):
            return
        try:
            with self.sessions() as session:
                ScopeManager(session).remove_target(project_id, bssid)
            self._project_changed()
            self._notice(self.network_status, f"Autorización retirada para {bssid}.")
        except Exception as error:
            self._notice(self.network_status, str(error), error=True)

    def export_networks(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Exportar inventario", "inventario-wifi.csv", "CSV (*.csv)"
        )
        if not filename:
            return
        try:
            authorized = {
                target.bssid for target in self._authorized_targets_for_active_project()
            }
            with Path(filename).open("w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    [
                        "ssid",
                        "bssid",
                        "channel",
                        "frequency_mhz",
                        "band",
                        "signal_percent",
                        "rssi_dbm",
                        "security",
                        "authorized",
                        "source",
                    ]
                )
                for item in self.networks:
                    # SSIDs are untrusted input when opened in spreadsheet applications.
                    values = [
                        item.ssid,
                        item.bssid,
                        item.channel,
                        item.frequency,
                        item.band,
                        item.signal_percent,
                        item.rssi,
                        item.security,
                        item.bssid in authorized,
                        "mock" if enabled() else "NetworkManager",
                    ]
                    writer.writerow(
                        [
                            (
                                "'" + value
                                if isinstance(value, str)
                                and value.lstrip().startswith(("=", "+", "-", "@"))
                                else value
                            )
                            for value in values
                        ]
                    )
            self.statusBar().showMessage(f"Inventario exportado: {filename}", 8000)
        except OSError as error:
            QMessageBox.warning(self, "No se pudo exportar", str(error))

    def _authorized_targets_for_active_project(self):
        project_id = self.project_selector.currentData()
        if not project_id:
            return []
        with self.sessions() as session:
            return session.scalars(
                select(AuthorizedTarget).where(
                    AuthorizedTarget.project_id == project_id
                )
            ).all()

    def refresh_projects(self):
        with self.sessions() as session:
            projects = session.scalars(
                select(Project).order_by(Project.created_at.desc())
            ).all()
        self._fill(
            self.projects_table,
            [
                (
                    item.id,
                    item.name,
                    item.responsible,
                    format_local_datetime(item.created_at, "%Y-%m-%d %H:%M"),
                )
                for item in projects
            ],
        )
        self.metrics["projects"].setText(str(len(projects)))
        selected = self.project_selector.currentData()
        self.project_selector.blockSignals(True)
        self.project_selector.clear()
        self.project_selector.addItem("Selecciona un proyecto…", None)
        for project in projects:
            self.project_selector.addItem(project.name, project.id)
        index = self.project_selector.findData(selected)
        if selected is None and len(projects) == 1:
            index = 1
        self.project_selector.setCurrentIndex(max(0, index))
        self.project_selector.blockSignals(False)
        self._project_changed()

    def create_project(self):
        try:
            with self.sessions() as session:
                project = ScopeManager(session).create_project(
                    self.project_name.text(),
                    self.responsible.text(),
                    self.authorization.toPlainText(),
                )
            self.refresh_projects()
            self.project_result.setText(
                f"Proyecto #{project.id} guardado: {project.name}"
            )
            self.project_selector.setCurrentIndex(
                self.project_selector.findData(project.id)
            )
            self.project_name.clear()
            self.responsible.clear()
            self.authorization.clear()
        except Exception as error:
            QMessageBox.warning(self, "No se pudo guardar el proyecto", str(error))

    def delete_selected_project(self):
        row = self.projects_table.currentRow()
        if row < 0 or not self.projects_table.item(row, 0):
            self.project_result.setText("Selecciona un proyecto antes de eliminarlo.")
            return
        project_id = int(self.projects_table.item(row, 0).text())
        project_name = self.projects_table.item(row, 1).text()
        if not self._confirm_destructive(
            "Eliminar proyecto",
            f"Se eliminará {project_name}, sus autorizaciones, capturas, hashes y recuperaciones locales. Esta acción no se puede deshacer. ¿Continuar?",
        ):
            return
        try:
            self.laboratory.delete_project(project_id)
            self.refresh_projects()
            self.project_result.setText(f"Proyecto eliminado: {project_name}")
        except Exception as error:
            QMessageBox.warning(self, "No se pudo eliminar el proyecto", str(error))

    def refresh_diagnostics(self):
        self.diagnostic_log.setPlainText("Consultando el sistema…")
        self._submit(
            "diagnóstico",
            system_status,
            self.diagnostic_log.setPlainText,
            self.diagnostic_log,
            self.diagnostic_button,
        )

    def closeEvent(self, event):
        if self.lab_job is not None:
            if hasattr(self, "_automatic_reconnect_timer"):
                self._automatic_reconnect_timer.stop()
            self.lab_job.cancel()
            if self.reconnect_job is not None:
                self.reconnect_job.cancel()
            if self.station_discovery_job is not None:
                self.station_discovery_job.cancel()
            self.close_pending = True
            self.statusBar().showMessage(
                "Deteniendo el trabajo y guardando su estado antes de cerrar…"
            )
            event.ignore()
            return
        if self.reconnect_job is not None:
            self.reconnect_job.cancel()
        if self.station_discovery_job is not None:
            self.station_discovery_job.cancel()
        if hasattr(self, "_automatic_reconnect_timer"):
            self._automatic_reconnect_timer.stop()
        if hasattr(self, "_station_retry_timer"):
            self._station_retry_timer.stop()
        self.timer.stop()
        self.executor.shutdown(wait=False, cancel_futures=True)
        super().closeEvent(event)
