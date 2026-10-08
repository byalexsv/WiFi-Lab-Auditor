from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.database import AuthorizedStation, AuthorizedTarget, Project
from app.utils.validation import is_mac


class ScopeError(PermissionError):
    """Raised before an active operation falls outside the recorded authorization."""


class ScopeManager:
    def __init__(self, session: Session):
        self.session = session

    def create_project(
        self, name: str, responsible: str, authorization_notes: str
    ) -> Project:
        name = name.strip()
        responsible = responsible.strip()
        authorization_notes = authorization_notes.strip()
        if not name or not authorization_notes:
            raise ValueError("A project name and authorization notes are required")
        if len(name) > 120 or len(responsible) > 120:
            raise ValueError(
                "Project name and responsible are limited to 120 characters"
            )
        project = Project(
            name=name,
            responsible=responsible,
            authorization_notes=authorization_notes,
        )
        self.session.add(project)
        self.session.commit()
        return project

    def authorize_target(
        self, project_id: int, bssid: str, ssid: str, channel: int
    ) -> AuthorizedTarget:
        project = self.session.get(Project, project_id)
        if not project or not project.active:
            raise ScopeError(
                "Selecciona un proyecto activo antes de autorizar una red."
            )
        ssid = ssid.strip()
        if len(ssid) > 128:
            raise ValueError("SSID is limited to 128 characters")
        if not is_mac(bssid) or not 1 <= channel <= 196:
            raise ValueError("Invalid BSSID or channel")
        target = self.session.scalar(
            select(AuthorizedTarget).where(
                AuthorizedTarget.project_id == project_id,
                AuthorizedTarget.bssid == bssid.upper(),
            )
        )
        if target:
            target.ssid, target.channel = ssid, channel
        else:
            target = AuthorizedTarget(
                project_id=project_id, bssid=bssid.upper(), ssid=ssid, channel=channel
            )
        self.session.add(target)
        self.session.commit()
        return target

    def authorize_station(
        self, project_id: int, bssid: str, mac: str
    ) -> AuthorizedStation:
        if not is_mac(bssid) or not is_mac(mac):
            raise ValueError("Invalid station or BSSID")
        self.require_active_scope(project_id, bssid)
        existing = self.session.scalar(
            select(AuthorizedStation).where(
                AuthorizedStation.project_id == project_id,
                AuthorizedStation.bssid == bssid.upper(),
                AuthorizedStation.mac == mac.upper(),
            )
        )
        if existing:
            return existing
        station = AuthorizedStation(
            project_id=project_id, bssid=bssid.upper(), mac=mac.upper()
        )
        self.session.add(station)
        self.session.commit()
        return station

    def remove_target(self, project_id: int, bssid: str) -> None:
        """Remove one authorized radio and its explicitly registered clients."""
        if not is_mac(bssid):
            raise ValueError("El BSSID no es válido.")
        target = self.session.scalar(
            select(AuthorizedTarget).where(
                AuthorizedTarget.project_id == project_id,
                AuthorizedTarget.bssid == bssid.upper(),
            )
        )
        if target is None:
            raise ValueError("La red no está registrada en este proyecto.")
        self.session.execute(
            delete(AuthorizedStation).where(
                AuthorizedStation.project_id == project_id,
                AuthorizedStation.bssid == bssid.upper(),
            )
        )
        self.session.delete(target)
        self.session.commit()

    def require_active_scope(
        self, project_id: int, bssid: str, station: str | None = None
    ) -> None:
        project = self.session.get(Project, project_id)
        if not project or not project.active:
            raise ScopeError("An active project is required")
        target = self.session.scalar(
            select(AuthorizedTarget).where(
                AuthorizedTarget.project_id == project_id,
                AuthorizedTarget.bssid == bssid.upper(),
            )
        )
        if not target:
            raise ScopeError("The selected BSSID is not authorized for this project")
        if station and not self.session.scalar(
            select(AuthorizedStation).where(
                AuthorizedStation.project_id == project_id,
                AuthorizedStation.bssid == bssid.upper(),
                AuthorizedStation.mac == station.upper(),
            )
        ):
            raise ScopeError("The selected station is not authorized for this target")
