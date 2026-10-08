from __future__ import annotations

import sys

from app.database.database import default_database_path
from app.ui.main_window import MainWindow
from app.ui.qt import QApplication, QLockFile, QMessageBox


def main() -> int:
    application = QApplication(sys.argv)
    application.setApplicationName("WiFi Lab Auditor")
    application.setStyle("Fusion")
    try:
        database = default_database_path()
        database.parent.mkdir(parents=True, exist_ok=True)
        lock = QLockFile(str(database.with_suffix(".lock")))
        lock.setStaleLockTime(0)
        if not lock.tryLock(0):
            QMessageBox.information(
                None,
                "WiFi Lab Auditor",
                "Ya hay una instancia abierta para esta base de datos.",
            )
            return 1
        window = MainWindow()
        window.laboratory.recover_interrupted()
        window._project_changed()
    except Exception as error:
        print(f"No se pudo iniciar WiFi Lab Auditor: {error}", file=sys.stderr)
        QMessageBox.critical(None, "No se pudo iniciar WiFi Lab Auditor", str(error))
        return 1
    window.show()
    try:
        return application.exec()
    finally:
        lock.unlock()


if __name__ == "__main__":
    raise SystemExit(main())
