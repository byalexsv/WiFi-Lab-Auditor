from sqlalchemy import text

from app.database.database import create_session_factory


def test_capture_evidence_migration_is_applied(tmp_path) -> None:
    factory = create_session_factory(tmp_path / "migration.sqlite3")
    with factory() as session:
        versions = (
            session.execute(text("SELECT version FROM schema_migrations"))
            .scalars()
            .all()
        )
    assert "0002_capture_evidence.sql" in versions
