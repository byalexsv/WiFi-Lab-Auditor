from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from app.core.mock_mode import enabled
from app.database.migrations.runner import apply_migrations


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    responsible: Mapped[str] = mapped_column(String(120), default="")
    authorization_notes: Mapped[str] = mapped_column(Text, default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    targets: Mapped[list[AuthorizedTarget]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    bssid: Mapped[str] = mapped_column(String(17))
    ssid: Mapped[str] = mapped_column(String(128), default="")
    channel: Mapped[int] = mapped_column(Integer)
    project: Mapped[Project] = relationship(back_populates="targets")


class AuthorizedStation(Base):
    __tablename__ = "authorized_stations"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    bssid: Mapped[str] = mapped_column(String(17))
    mac: Mapped[str] = mapped_column(String(17))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    project: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(120))
    result: Mapped[str] = mapped_column(String(40))
    details: Mapped[str] = mapped_column(Text, default="")


class CaptureArtifact(Base):
    __tablename__ = "capture_artifacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    bssid: Mapped[str] = mapped_column(String(17))
    source: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    evidence_json: Mapped[str] = mapped_column(Text, default="{}")
    hash_path: Mapped[str] = mapped_column(Text, default="")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class RecoveryJob(Base):
    __tablename__ = "recovery_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    artifact_id: Mapped[str] = mapped_column(ForeignKey("capture_artifacts.id"))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"))
    status: Mapped[str] = mapped_column(String(30), default="running")
    dictionary: Mapped[str] = mapped_column(Text)
    result_path: Mapped[str] = mapped_column(Text)
    log_path: Mapped[str] = mapped_column(Text)
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


def default_database_path() -> Path:
    filename = "demo.sqlite3" if enabled() else "auditor.sqlite3"
    return Path.home() / ".local/share/wifi-lab-auditor" / filename


def create_session_factory(path: Path | None = None):
    path = path or default_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        apply_migrations(connection)
    return sessionmaker(bind=engine, expire_on_commit=False)
