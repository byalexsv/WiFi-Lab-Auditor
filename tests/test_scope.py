import pytest
from sqlalchemy import select

from app.core.scope_manager import ScopeError, ScopeManager
from app.database.database import (
    AuthorizedStation,
    AuthorizedTarget,
    create_session_factory,
)


def test_active_scope_requires_authorized_target_and_station(tmp_path) -> None:
    factory = create_session_factory(tmp_path / "test.sqlite3")
    with factory() as session:
        scope = ScopeManager(session)
        project = scope.create_project("Lab A", "Miguel", "Written authorization A-1")
        with pytest.raises(ScopeError):
            scope.require_active_scope(project.id, "02:11:22:33:44:55")
        scope.authorize_target(project.id, "02:11:22:33:44:55", "Lab", 6)
        scope.authorize_station(project.id, "02:11:22:33:44:55", "02:AA:BB:CC:DD:01")
        scope.require_active_scope(project.id, "02:11:22:33:44:55", "02:AA:BB:CC:DD:01")


def test_remove_target_also_removes_its_authorized_stations(tmp_path) -> None:
    factory = create_session_factory(tmp_path / "test.sqlite3")
    with factory() as session:
        scope = ScopeManager(session)
        project = scope.create_project("Lab B", "Miguel", "Written authorization B-1")
        scope.authorize_target(project.id, "02:11:22:33:44:55", "Lab", 6)
        scope.authorize_station(project.id, "02:11:22:33:44:55", "02:AA:BB:CC:DD:01")
        scope.remove_target(project.id, "02:11:22:33:44:55")
        assert session.scalars(select(AuthorizedTarget)).all() == []
        assert session.scalars(select(AuthorizedStation)).all() == []
