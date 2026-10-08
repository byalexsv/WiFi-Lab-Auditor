from __future__ import annotations

from pathlib import Path

from sqlalchemy import Connection, text


def apply_migrations(connection: Connection) -> None:
    connection.execute(
        text("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
    )
    completed = {
        row[0]
        for row in connection.execute(text("SELECT version FROM schema_migrations"))
    }
    for script in sorted(Path(__file__).parent.glob("*.sql")):
        if script.name in completed:
            continue
        for statement in script.read_text(encoding="utf-8").split(";"):
            if statement.strip():
                connection.execute(text(statement))
        connection.execute(
            text("INSERT INTO schema_migrations (version) VALUES (:version)"),
            {"version": script.name},
        )
