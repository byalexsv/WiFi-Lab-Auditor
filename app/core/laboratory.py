"""Real capture, analysis and bounded offline recovery for recorded project scope."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import Counter
from math import ceil
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from sqlalchemy import delete, select, update

from app.core.interface_manager import InterfaceManager
from app.core.lab_jobs import JobCancelled, ToolJob
from app.core.mock_mode import enabled, scenario
from app.core.scope_manager import ScopeManager
from app.core.system_commands import SystemToolError, run_tool, split_nmcli
from app.database.database import (
    AuditLog,
    AuthorizedStation,
    CaptureArtifact,
    Project,
    RecoveryJob,
)
from app.utils.validation import is_mac

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_ANALYSIS_PACKETS = 200_000


def frequency_to_channel(frequency: int) -> int:
    """Convert a center frequency in MHz to the channel argument airmon-ng expects."""
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 5000 <= frequency <= 5895 and (frequency - 5000) % 5 == 0:
        return (frequency - 5000) // 5
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    raise ValueError("La frecuencia no corresponde a un canal Wi-Fi conocido.")


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_capture(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.is_file():
        raise ValueError(
            "No se encontró el archivo de captura. Comprueba que dumpcap terminó correctamente y que el adaptador está en modo monitor."
        )
    size = path.stat().st_size
    if size < 24:
        raise ValueError(
            "La captura está vacía o incompleta. Comprueba el canal y el modo monitor del adaptador."
        )
    if size > MAX_CAPTURE_BYTES:
        raise ValueError("Selecciona una captura PCAP/PCAPNG entre 24 bytes y 512 MiB.")
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic not in (
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    ):
        raise ValueError("El archivo no tiene una cabecera PCAP o PCAPNG válida.")
    return path


def scoped_hashes(text: str, bssid: str) -> list[str]:
    """Only structurally valid HC22000 rows for the explicitly authorized AP."""
    if not is_mac(bssid):
        raise ValueError("BSSID no válido.")
    selected = []
    for line in text.splitlines():
        fields = line.strip().split("*")
        if len(fields) != 9 or fields[0] != "WPA" or fields[1] not in ("01", "02"):
            continue
        if fields[3].lower() != bssid.replace(":", "").lower():
            continue
        if not all(re.fullmatch(r"[0-9a-fA-F]*", field) for field in fields[2:]):
            continue
        if len(fields[2]) != 32 or len(fields[3]) != 12 or len(fields[4]) != 12:
            continue
        if not 2 <= len(fields[5]) <= 64 or len(fields[5]) % 2:
            continue
        if fields[1] == "02" and (
            len(fields[6]) != 64
            or not 198 <= len(fields[7]) <= 512
            or len(fields[7]) % 2
            or len(fields[8]) != 2
        ):
            continue
        if fields[1] == "01" and (
            fields[6] or fields[7] or len(fields[8]) not in (0, 2)
        ):
            continue
        if line.strip() not in selected:
            selected.append(line.strip())
    return selected


def parse_frames(text: str, target_bssid: str | None = None) -> dict:
    evidence = {
        "packets": 0,
        "eapol": 0,
        "data_frames": 0,
        "deauth_frames": 0,
        "association_frames": 0,
        "authentication_frames": 0,
        "peer_frames": {},
        "channel_frequencies": {},
        "pmf_capable": False,
        "pmf_required": False,
        "messages": {str(n): 0 for n in range(1, 5)},
        "radiotap": False,
        "duration_seconds": 0,
        "analysis_packet_limit": MAX_ANALYSIS_PACKETS,
    }
    timestamps = []
    target = target_bssid.upper() if target_bssid else ""
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 6:
            continue
        number, timestamp, encap, eapol_type, message, rssi = fields[:6]
        frame_type = fields[6] if len(fields) > 6 else ""
        frame_subtype = fields[7] if len(fields) > 7 else ""
        addresses = fields[8:12] if len(fields) >= 12 else []
        channel_frequency = fields[12] if len(fields) > 12 else ""
        pmf_capable = fields[13] if len(fields) > 13 else ""
        pmf_required = fields[14] if len(fields) > 14 else ""
        evidence["packets"] += 1
        if timestamp:
            timestamps.append(float(timestamp))
        evidence["radiotap"] |= encap == "23"
        if eapol_type:
            evidence["eapol"] += 1
        if frame_type == "2":
            evidence["data_frames"] += 1
        normalized_subtype = frame_subtype.lower()
        if normalized_subtype in {"0x0000", "0x0001", "0x0020", "0x0021"}:
            evidence["association_frames"] += 1
        if normalized_subtype == "0x000b":
            evidence["authentication_frames"] += 1
        if normalized_subtype == "0x000c":
            evidence["deauth_frames"] += 1
        # A deauthentication frame contains the station address too, but it
        # is not evidence that the station is currently associated. Count
        # peers only in data, association, reassociation or authentication
        # frames; keep deauth/disassoc totals separate below.
        peer_relevant = frame_type == "2" or normalized_subtype in {
            "0x0000",
            "0x0001",
            "0x0020",
            "0x0021",
            "0x000b",
        }
        if peer_relevant:
            frame_peers = set()
            for address in addresses:
                address = address.strip().upper()
                if (
                    not is_mac(address)
                    or address == "00:00:00:00:00:00"
                    or address == target
                    or int(address.split(":")[0], 16) & 1
                ):
                    continue
                frame_peers.add(address)
            for address in frame_peers:
                evidence["peer_frames"][address] = (
                    evidence["peer_frames"].get(address, 0) + 1
                )
        if channel_frequency:
            try:
                frequency = str(int(float(channel_frequency)))
            except (TypeError, ValueError):
                frequency = ""
            if frequency:
                evidence["channel_frequencies"][frequency] = (
                    evidence["channel_frequencies"].get(frequency, 0) + 1
                )
        evidence["pmf_capable"] |= pmf_capable in {"1", "true", "True"}
        evidence["pmf_required"] |= pmf_required in {"1", "true", "True"}
        if message in evidence["messages"]:
            evidence["messages"][message] += 1
    if timestamps:
        evidence["duration_seconds"] = round(max(timestamps) - min(timestamps), 3)
    evidence["peer_frames"] = dict(
        sorted(
            evidence["peer_frames"].items(),
            key=lambda item: (-item[1], item[0]),
        )[:8]
    )
    evidence["channel_frequencies"] = dict(
        sorted(
            evidence["channel_frequencies"].items(),
            key=lambda item: (-item[1], item[0]),
        )[:8]
    )
    return evidence


def capture_diagnosis(evidence: dict) -> dict:
    """Classify what a capture proves and give the next bounded action.

    A BSSID frame count or an aireplay ACK is not an authentication exchange.
    Keeping this decision in the core makes the desktop and future report
    exporters show the same evidence-based result.
    """
    packets = int(evidence.get("packets", 0) or 0)
    eapol = int(evidence.get("eapol", 0) or 0)
    hashes = int(evidence.get("hashes", 0) or 0)
    data_frames = int(evidence.get("data_frames", 0) or 0)
    associations = int(evidence.get("association_frames", 0) or 0)
    peers = evidence.get("peer_frames") or {}
    if hashes:
        return {
            "code": "material_ready",
            "severity": "success",
            "title": "Material WPA recuperable",
            "action": "Analiza el hash autorizado en Recuperación offline.",
        }
    if not packets:
        return {
            "code": "bssid_not_seen",
            "severity": "error",
            "title": "El BSSID no apareció",
            "action": "Verifica la radio, el canal automático y que el adaptador esté en monitor.",
        }
    if not eapol and not data_frames and not associations:
        if int(evidence.get("deauth_frames", 0) or 0):
            return {
                "code": "deauth_without_client",
                "severity": "warning",
                "title": "Solo se observaron desautenticaciones",
                "action": "No hay evidencia de que un cliente siguiera asociado. Mantén un cliente autorizado conectado al BSSID exacto antes de iniciar la única reconexión.",
            }
        return {
            "code": "beacon_only",
            "severity": "warning",
            "title": "Solo se observaron balizas o sondeos",
            "action": "Selecciona el BSSID de la radio donde está asociado el cliente y mantén ese cliente conectado.",
        }
    if not eapol and peers and not associations:
        pmf_hint = (
            " El BSSID anuncia PMF obligatorio; una reconexión no protegida no puede provocar EAPOL."
            if evidence.get("pmf_required")
            else ""
        )
        return {
            "code": "client_seen_no_reauth",
            "severity": "warning",
            "title": "Cliente observado, pero sin nueva autenticación",
            "action": "El cliente puede estar asociado a otra radio/SSID, usar PMF o no haberse vuelto a autenticar durante la captura."
            + pmf_hint,
        }
    if not eapol and associations:
        return {
            "code": "association_without_eapol",
            "severity": "warning",
            "title": "Hubo asociación, pero no EAPOL recuperable",
            "action": (
                "Revisa el BSSID exacto y el canal observado; captura la radio donde el cliente se asocia."
                + (
                    " El BSSID anuncia PMF obligatorio, por lo que no se debe repetir una reconexión no protegida."
                    if evidence.get("pmf_required")
                    else ""
                )
            ),
        }
    if eapol:
        return {
            "code": "eapol_without_hash",
            "severity": "warning",
            "title": "EAPOL observado, sin material convertible",
            "action": "Revisa el archivo original y vuelve a analizarlo con hcxpcapngtool actualizado.",
        }
    return {
        "code": "traffic_without_eapol",
        "severity": "warning",
        "title": "Tráfico observado, sin EAPOL",
        "action": (
            "Mantén un cliente autorizado asociado al BSSID y usa una sola reconexión dirigida durante la captura."
            + (
                " El BSSID anuncia PMF obligatorio; cambia a captura pasiva y autentica el cliente desde su propio dispositivo."
                if evidence.get("pmf_required")
                else ""
            )
        ),
    }


def parse_hashcat_progress(text: str) -> dict | None:
    """Extract the newest structured status line emitted by Hashcat.

    Hashcat writes status JSON intermixed with its terminal prompts.  The
    parser deliberately keeps only counters and throughput; it never puts a
    candidate password into the UI or into the application database.
    """
    latest = None
    for line in text.splitlines():
        start, end = line.find("{"), line.rfind("}")
        if start < 0 or end <= start:
            continue
        try:
            payload = json.loads(line[start : end + 1])
        except (TypeError, ValueError):
            continue
        progress = payload.get("progress")
        if not isinstance(progress, list) or len(progress) < 2:
            continue
        try:
            current, total = int(progress[0]), int(progress[1])
        except (TypeError, ValueError):
            continue
        if total <= 0:
            continue
        devices = payload.get("devices") or []
        speed = 0
        if isinstance(devices, list):
            for device in devices:
                try:
                    speed += int(device.get("speed", 0))
                except (AttributeError, TypeError, ValueError):
                    continue
        recovered = payload.get("recovered_hashes") or []
        recovered_count = None
        recovered_total = None
        if isinstance(recovered, list) and len(recovered) >= 2:
            try:
                recovered_count, recovered_total = int(recovered[0]), int(recovered[1])
            except (TypeError, ValueError):
                pass
        latest = {
            "current": max(0, current),
            "total": total,
            "percent": max(0.0, min(100.0, current * 100 / total)),
            "speed": max(0, speed),
            "recovered": recovered_count,
            "hashes": recovered_total,
            "status": payload.get("status"),
        }
    return latest


def verified_results(path: Path, hashes: list[str], bssid: str) -> int:
    if not path.exists():
        return 0
    expected = set()
    for line in hashes:
        fields = line.split("*")
        expected.add(
            (
                *[value.lower().encode("ascii") for value in fields[2:5]],
                bytes.fromhex(fields[5]),
            )
        )
    count = 0
    for line in path.read_bytes().splitlines():
        encoded_hash, separator, hex_plain = line.rpartition(b":")
        if not separator:
            raise ValueError("Hashcat produjo un resultado con formato no válido.")
        if encoded_hash.startswith(b"WPA*"):
            text = encoded_hash.decode("ascii")
            if not scoped_hashes(text, bssid):
                raise ValueError("Resultado fuera del alcance autorizado.")
            fields = text.split("*")
            signature = (
                *[value.lower().encode("ascii") for value in fields[2:5]],
                bytes.fromhex(fields[5]),
            )
        else:
            # Hashcat 22000 writes digest:AP:station:ESSID for outfile-format 1.
            fields = encoded_hash.split(b":", 3)
            if len(fields) != 4:
                raise ValueError(
                    "Hashcat produjo un identificador de resultado no válido."
                )
            ssid = fields[3]
            if ssid.startswith(b"$HEX[") and ssid.endswith(b"]"):
                ssid = bytes.fromhex(ssid[5:-1].decode("ascii"))
            signature = (*[value.lower() for value in fields[:3]], ssid)
        if signature not in expected:
            raise ValueError("El resultado no corresponde al material seleccionado.")
        try:
            plaintext = bytes.fromhex(hex_plain.decode("ascii"))
        except (ValueError, UnicodeError) as error:
            raise ValueError(
                "El resultado recuperado no contiene una clave codificada válida."
            ) from error
        if not plaintext:
            raise ValueError("Hashcat produjo una clave vacía.")
        count += 1
    return count


class Laboratory:
    def __init__(self, sessions, storage: Path | None = None):
        self.sessions = sessions
        # Tests and alternate databases keep their artifacts beside that database.
        database = Path(sessions.kw["bind"].url.database)
        self.storage = storage or database.parent / (
            "demo-artifacts" if enabled() else "artifacts"
        )

    def recover_interrupted(self):
        """Called once after the application acquires its single-instance lock."""
        with self.sessions() as session:
            for model in (CaptureArtifact, RecoveryJob):
                session.execute(
                    update(model)
                    .where(model.status.in_(["running", "analyzing"]))
                    .values(
                        status="interrupted",
                        message="La aplicación se cerró antes de finalizar. Revisa los archivos conservados.",
                    )
                )
            session.commit()

    def require_scope(self, project_id, bssid, station=None):
        if enabled():
            raise ValueError(
                "Las operaciones reales no se ejecutan en modo demostración. Reinicia sin WIFI_LAB_MOCK=1."
            )
        with self.sessions() as session:
            ScopeManager(session).require_active_scope(project_id, bssid, station)

    def _directory(self, identifier):
        directory = self.storage / identifier
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        return directory

    def _update(self, model, identifier, **values):
        with self.sessions() as session:
            row = session.get(model, identifier)
            for key, value in values.items():
                setattr(row, key, value)
            session.add(
                AuditLog(
                    project=str(row.project_id),
                    action=model.__tablename__,
                    result=values.get("status", "updated"),
                    details=identifier,
                )
            )
            session.commit()

    def artifacts(self, project_id):
        with self.sessions() as session:
            return session.scalars(
                select(CaptureArtifact)
                .where(CaptureArtifact.project_id == project_id)
                .order_by(CaptureArtifact.created_at.desc())
            ).all()

    def recoveries(self, project_id):
        with self.sessions() as session:
            return session.scalars(
                select(RecoveryJob)
                .where(RecoveryJob.project_id == project_id)
                .order_by(RecoveryJob.created_at.desc())
            ).all()

    def artifact(self, identifier):
        with self.sessions() as session:
            row = session.get(CaptureArtifact, identifier)
            if row is None:
                raise ValueError("No se encontró la captura seleccionada.")
            return row

    def _remove_storage_directory(self, path: str | Path) -> None:
        """Remove an application-owned artifact directory, never an input path."""
        directory = Path(path).expanduser().resolve().parent
        storage = self.storage.expanduser().resolve()
        if directory.parent != storage or not directory.name:
            return
        shutil.rmtree(directory, ignore_errors=False)

    def delete_artifact(self, identifier):
        """Delete one capture, its analysis and any recovery jobs."""
        with self.sessions() as session:
            artifact = session.get(CaptureArtifact, identifier)
            if artifact is None:
                raise ValueError("No se encontró la captura seleccionada.")
            if artifact.status in {"running", "analyzing"}:
                raise ValueError("Detén el trabajo antes de eliminar esta captura.")
            recovery_rows = session.scalars(
                select(RecoveryJob).where(RecoveryJob.artifact_id == identifier)
            ).all()
            if any(row.status == "running" for row in recovery_rows):
                raise ValueError(
                    "Detén la recuperación antes de eliminar esta captura."
                )
            path = artifact.path
            recovery_paths = [row.result_path for row in recovery_rows]
            project_id = artifact.project_id
            for row in recovery_rows:
                session.delete(row)
            session.delete(artifact)
            session.add(
                AuditLog(
                    project=str(project_id),
                    action="capture_artifacts",
                    result="deleted",
                    details=identifier,
                )
            )
            session.commit()
        self._remove_storage_directory(path)
        for recovery_path in recovery_paths:
            self._remove_storage_directory(recovery_path)
        return project_id

    def clear_artifacts(self, project_id: int) -> int:
        identifiers = [row.id for row in self.artifacts(project_id)]
        for identifier in identifiers:
            self.delete_artifact(identifier)
        return len(identifiers)

    def delete_recovery(self, identifier):
        """Delete one offline recovery record and its local result files."""
        with self.sessions() as session:
            row = session.get(RecoveryJob, identifier)
            if row is None:
                raise ValueError("No se encontró la recuperación seleccionada.")
            if row.status == "running":
                raise ValueError("Detén la recuperación antes de eliminarla.")
            path = row.result_path
            project_id = row.project_id
            session.delete(row)
            session.add(
                AuditLog(
                    project=str(project_id),
                    action="recovery_jobs",
                    result="deleted",
                    details=identifier,
                )
            )
            session.commit()
        self._remove_storage_directory(path)
        return project_id

    def clear_recoveries(self, project_id: int) -> int:
        identifiers = [row.id for row in self.recoveries(project_id)]
        for identifier in identifiers:
            self.delete_recovery(identifier)
        return len(identifiers)

    def delete_project(self, project_id: int) -> None:
        """Delete a project, all scope records and all locally stored evidence."""
        with self.sessions() as session:
            project = session.get(Project, project_id)
            if project is None:
                raise ValueError("No se encontró el proyecto seleccionado.")
            artifacts = session.scalars(
                select(CaptureArtifact).where(CaptureArtifact.project_id == project_id)
            ).all()
            recoveries = session.scalars(
                select(RecoveryJob).where(RecoveryJob.project_id == project_id)
            ).all()
            if any(
                row.status in {"running", "analyzing"}
                for row in [*artifacts, *recoveries]
            ):
                raise ValueError(
                    "Detén los trabajos activos antes de eliminar el proyecto."
                )
            artifact_paths = [row.path for row in artifacts]
            recovery_paths = [row.result_path for row in recoveries]
            session.execute(
                delete(AuthorizedStation).where(
                    AuthorizedStation.project_id == project_id
                )
            )
            session.execute(
                delete(RecoveryJob).where(RecoveryJob.project_id == project_id)
            )
            session.execute(
                delete(CaptureArtifact).where(CaptureArtifact.project_id == project_id)
            )
            session.execute(delete(AuditLog).where(AuditLog.project == str(project_id)))
            session.delete(project)
            session.commit()
        for path in [*artifact_paths, *recovery_paths]:
            self._remove_storage_directory(path)

    def _new_artifact(self, project_id, bssid, source, name, extension=".pcapng"):
        self.require_scope(project_id, bssid)
        identifier = uuid4().hex
        directory = self._directory(identifier)
        path = directory / f"capture{extension}"
        with self.sessions() as session:
            session.add(
                CaptureArtifact(
                    id=identifier,
                    project_id=project_id,
                    bssid=bssid.upper(),
                    source=source,
                    name=name,
                    path=str(path),
                    status="running",
                )
            )
            session.commit()
        return identifier, path

    def import_capture(self, project_id, bssid, source: Path, job: ToolJob):
        self.require_scope(project_id, bssid)
        source = validate_capture(source)
        with source.open("rb") as stream:
            extension = ".pcapng" if stream.read(4) == b"\x0a\x0d\x0d\x0a" else ".pcap"
        identifier, path = self._new_artifact(
            project_id, bssid, "import", source.name, extension
        )
        try:
            job.stage = "Copiando captura original…"
            with source.open("rb") as incoming, path.open("xb") as output:
                copied = 0
                for block in iter(lambda: incoming.read(1024 * 1024), b""):
                    if job.cancelled.is_set():
                        raise JobCancelled("Importación detenida.")
                    copied += len(block)
                    if copied > MAX_CAPTURE_BYTES:
                        raise ValueError("La captura supera el límite de 512 MiB.")
                    output.write(block)
            self._update(
                CaptureArtifact, identifier, sha256=fingerprint(path), status="captured"
            )
            self.analyze(identifier, job)
        except Exception as error:
            self._update(
                CaptureArtifact,
                identifier,
                status="interrupted" if isinstance(error, JobCancelled) else "failed",
                message=str(error),
            )
            raise
        return identifier

    def capture(
        self,
        project_id,
        bssid,
        interface,
        frequency,
        seconds,
        monitor_consent,
        job: ToolJob,
        automatic_methods=False,
    ):
        self.require_scope(project_id, bssid)
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces:
            raise ValueError("El adaptador seleccionado ya no está disponible.")
        if interfaces[interface].mode != "monitor" and not monitor_consent:
            raise ValueError(
                "Usa una interfaz monitor o acepta activar modo monitor en el adaptador seleccionado."
            )
        if interfaces[interface].mode != "monitor":
            raise ValueError(
                f"{interface} sigue en modo gestionado. Prepara una interfaz monitor con «Preparar monitor» y vuelve a actualizar los adaptadores."
            )
        if not 5 <= seconds <= 3600 or not 2400 <= frequency <= 7125:
            raise ValueError("Duración o frecuencia fuera de rango.")
        # Do not let an arbitrary MHz value put the monitor and injector on
        # different channels. The UI normally derives this from the
        # authorized target, but the core validates it for every caller.
        channel = frequency_to_channel(frequency)
        self._set_monitor_channel(interface, channel, frequency, job)
        identifier, path = self._new_artifact(
            project_id, bssid, "live", f"Captura · {interface}"
        )
        try:
            args = ["dumpcap", "-i", interface]
            args += [
                "-k",
                str(frequency),
                "-f",
                f"wlan host {bssid}",
                "-a",
                f"duration:{seconds}",
                "-a",
                "filesize:65536",
                "-w",
                str(path),
                "-q",
            ]
            job.stage = f"Capturando {bssid} · {seconds} s como máximo"
            retry_args = args.copy()
            channel_option = retry_args.index("-k")
            del retry_args[channel_option : channel_option + 2]

            def preserve_stopped_capture():
                if path.exists() and path.stat().st_size >= 24:
                    self._update(
                        CaptureArtifact,
                        identifier,
                        status="captured",
                        sha256=fingerprint(path),
                        message="Captura detenida y guardada. Selecciona Analizar para revisar el material.",
                    )
                    return True
                return False

            try:
                job.run(args, path.parent, seconds + 15, "capture.log")
            except SystemToolError as error:
                # A few monitor drivers reject libpcap's channel setter even
                # though airmon-ng already configured the monitor interface.
                # Retrying without -k lets dumpcap capture on that configured
                # channel instead of failing before it creates the pcapng.
                detail = str(error).casefold()
                if (
                    "set channel" not in detail
                    and "operation not supported" not in detail
                ):
                    raise
                job.stage = "Reintentando captura con el canal del monitor…"
                try:
                    job.run(retry_args, path.parent, seconds + 15, "capture-retry.log")
                except JobCancelled:
                    if preserve_stopped_capture():
                        return identifier
                    raise
            except JobCancelled:
                if preserve_stopped_capture():
                    return identifier
                raise
            if (not path.is_file() or path.stat().st_size < 24) and "-k" in args:
                job.stage = "Reintentando captura con el canal del monitor…"
                try:
                    job.run(retry_args, path.parent, seconds + 15, "capture-retry.log")
                except JobCancelled:
                    if preserve_stopped_capture():
                        return identifier
                    raise
            if not path.is_file():
                log_path = path.parent / "capture.log"
                detail = ""
                if log_path.is_file():
                    detail = log_path.read_text(errors="replace").strip()
                retry_log = path.parent / "capture-retry.log"
                if retry_log.is_file():
                    retry_detail = retry_log.read_text(errors="replace").strip()
                    detail = "\n".join(filter(None, (detail, retry_detail)))
                suffix = f" Detalle: {detail[-800:]}" if detail else ""
                raise SystemToolError(
                    "dumpcap terminó sin crear capture.pcapng. Comprueba que el adaptador está en modo monitor, que la frecuencia coincide con el canal autorizado y que el sistema permite la captura."
                    + suffix
                )
            validate_capture(path)
            self._update(
                CaptureArtifact, identifier, status="captured", sha256=fingerprint(path)
            )
            self.analyze(identifier, job)
            primary = self.artifact(identifier)
            if (
                automatic_methods
                and primary.status != "ready"
                and not job.cancelled.is_set()
            ):
                try:
                    fallback = self.capture_pmkid(
                        project_id,
                        bssid,
                        interface,
                        frequency,
                        seconds,
                        job,
                    )
                    fallback_artifact = self.artifact(fallback)
                    if fallback_artifact.status == "ready":
                        self._update(
                            CaptureArtifact,
                            identifier,
                            message=(
                                "La captura EAPOL no produjo material. El método PMKID automático "
                                f"sí produjo material recuperable en {fallback[:8]}."
                            ),
                        )
                    else:
                        self._update(
                            CaptureArtifact,
                            identifier,
                            message=(
                                "La captura EAPOL no produjo material y el método PMKID automático "
                                "tampoco obtuvo una respuesta recuperable. Consulta ambos registros."
                            ),
                        )
                except JobCancelled:
                    self._update(
                        CaptureArtifact,
                        identifier,
                        status="analyzed",
                        message=(
                            "La captura EAPOL quedó conservada sin material. "
                            "El método PMKID automático se detuvo antes de terminar."
                        ),
                    )
                    return identifier
                except Exception as error:
                    # A secondary strategy must not erase a valid primary
                    # capture or turn a completed audit into a false error.
                    self._update(
                        CaptureArtifact,
                        identifier,
                        message=(
                            "La captura EAPOL no produjo material. El intento PMKID automático "
                            f"no pudo ejecutarse: {error}"
                        ),
                    )
        except Exception as error:
            self._update(
                CaptureArtifact,
                identifier,
                status="interrupted" if isinstance(error, JobCancelled) else "failed",
                message=str(error),
            )
            raise
        return identifier

    def capture_pmkid(
        self,
        project_id,
        bssid,
        interface,
        frequency,
        seconds,
        job: ToolJob,
    ):
        """Run one BSSID-filtered PMKID/EAPOL capture as a fallback.

        hcxdumptool is intentionally constrained to the authorized AP with a
        generated BPF filter. Disassociation and probe-response injection are
        disabled; the method is a bounded association observation, not a
        broadcast attack against surrounding clients.
        """
        self.require_scope(project_id, bssid)
        if not shutil.which("hcxdumptool"):
            raise SystemToolError(
                "Falta hcxdumptool; instala el paquete hcxdumptool para activar el método PMKID automático."
            )
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces or interfaces[interface].mode != "monitor":
            raise ValueError("Selecciona una interfaz que esté en modo monitor.")
        channel = frequency_to_channel(frequency)
        self._set_monitor_channel(interface, channel, frequency, job)
        identifier, path = self._new_artifact(
            project_id, bssid, "live-pmkid", f"PMKID automático · {interface}"
        )
        try:
            directory = path.parent
            bpf = directory / "authorized-ap.bpf"
            bssid_hex = bssid.replace(":", "").lower()
            job.stage = "Preparando filtro PMKID para el BSSID autorizado…"
            job.run(
                ["hcxdumptool", f"--bpfc=wlan addr3 {bssid_hex}"],
                directory,
                30,
                "pmkid-filter.log",
                stdout_path=bpf,
            )
            if not bpf.is_file() or not bpf.read_text(errors="replace").strip():
                raise SystemToolError("No se pudo compilar el filtro BSSID autorizado.")
            minutes = max(1, min(5, ceil(seconds / 60)))
            job.stage = f"Método PMKID dirigido para {bssid.upper()}…"
            job.run(
                [
                    "pkexec",
                    "hcxdumptool",
                    "-i",
                    interface,
                    "-w",
                    str(path),
                    f"--bpf={bpf}",
                    "-f",
                    str(frequency),
                    "--tot",
                    str(minutes),
                    "--exitoneapol=3",
                    "--disable_disassociation",
                    "--proberesponsetx=0",
                    "--associationmax=1",
                ],
                directory,
                minutes * 60 + 45,
                "pmkid-capture.log",
            )
            validate_capture(path)
            self._update(
                CaptureArtifact,
                identifier,
                status="captured",
                sha256=fingerprint(path),
            )
            self.analyze(identifier, job)
        except Exception as error:
            self._update(
                CaptureArtifact,
                identifier,
                status="interrupted" if isinstance(error, JobCancelled) else "failed",
                message=str(error),
            )
            raise
        return identifier

    def _set_monitor_channel(self, interface, channel, frequency, job):
        """Pin the monitor radio before any capture or injection starts.

        Some drivers reject dumpcap's libpcap channel setter. Calling iw via
        polkit first prevents a stale channel from silently producing a valid
        PCAP containing another authorized radio.
        """
        job.stage = f"Fijando canal {channel} ({frequency} MHz) en {interface}…"
        try:
            job.run(
                [
                    "pkexec",
                    "iw",
                    "dev",
                    interface,
                    "set",
                    "channel",
                    str(channel),
                ],
                self.storage,
                30,
                "channel.log",
            )
            return True
        except SystemToolError:
            # Keep the existing dumpcap retry for drivers that already pin
            # the channel internally and reject a second explicit setter.
            job.stage = (
                f"El controlador no aceptó fijar el canal {channel}; "
                "se usará el canal actual del monitor…"
            )
            return False

    def prepare_monitor(self, interface, frequency, job: ToolJob):
        """Ask polkit for the explicit monitor-mode transition, then refresh iw."""
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces:
            raise ValueError("El adaptador seleccionado ya no está disponible.")
        if interfaces[interface].mode == "monitor":
            raise ValueError(f"{interface} ya está en modo monitor.")
        channel = frequency_to_channel(frequency)
        job.stage = f"Preparando modo monitor en {interface}…"
        job.run(
            ["pkexec", "airmon-ng", "start", interface, str(channel)],
            self.storage,
            90,
            "monitor.log",
        )
        job.stage = "Modo monitor preparado; actualizando adaptadores…"

    def restore_monitor(self, interface, job: ToolJob):
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces or interfaces[interface].mode != "monitor":
            raise ValueError("Selecciona una interfaz que esté en modo monitor.")
        job.stage = f"Restaurando {interface}…"
        job.run(
            ["pkexec", "airmon-ng", "stop", interface],
            self.storage,
            90,
            "monitor-stop.log",
        )

    def trigger_reconnect(self, project_id, bssid, station, interface, job: ToolJob):
        """Send one directed reconnect request to an explicitly authorized client."""
        self.require_scope(project_id, bssid, station)
        if not is_mac(station):
            raise ValueError("La MAC del cliente no es válida.")
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces or interfaces[interface].mode != "monitor":
            raise ValueError("Selecciona una interfaz que esté en modo monitor.")
        local_device = self._reconnect_local_client(bssid, job)
        if local_device:
            return f"local:{local_device}"
        job.stage = f"Solicitando reconexión dirigida para {station.upper()}…"
        job.run(
            [
                "pkexec",
                "aireplay-ng",
                "--deauth",
                "1",
                "-a",
                bssid,
                "-c",
                station,
                interface,
            ],
            self.storage,
            30,
            "reconnect.log",
        )
        # aireplay-ng can exit with status 0 after transmitting frames even
        # when the client acknowledged none of them. Treat that as an
        # unconfirmed request so the UI does not promise an EAPOL exchange
        # that the radio never observed.
        log_path = self.storage / "reconnect.log"
        log_text = log_path.read_text(errors="replace") if log_path.is_file() else ""
        ack_values = [
            int(value)
            for value in re.findall(r"\[\s*\d+\s*\|\s*(\d+)\s+ACKs\]", log_text)
        ]
        if ack_values and max(ack_values) == 0:
            raise SystemToolError(
                "aireplay-ng no recibió ACK del cliente. La reconexión no fue confirmada; "
                "comprueba que el cliente siga conectado, que el canal y BSSID sean correctos "
                "y que el punto de acceso no tenga PMF activo."
            )
        return max(ack_values) if ack_values else None

    def _reconnect_local_client(self, bssid, job: ToolJob):
        """Reconnect this host's own managed Wi-Fi client when one is present.

        This is the most reliable automatic source of a legitimate EAPOL
        exchange. It never selects a neighboring device: both NetworkManager
        state and the active BSSID must match the authorized target.
        """
        target = bssid.upper()
        try:
            status = run_tool(
                [
                    "nmcli",
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "DEVICE,TYPE,STATE,CONNECTION",
                    "device",
                    "status",
                ],
                timeout=8,
            )
            devices = {}
            for line in status.splitlines():
                fields = split_nmcli(line)
                if (
                    len(fields) >= 4
                    and fields[1] == "wifi"
                    and fields[2].startswith("connected")
                ):
                    devices[fields[0]] = fields[3]
            if not devices:
                return None
            active = run_tool(
                [
                    "nmcli",
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "ACTIVE,BSSID,DEVICE",
                    "device",
                    "wifi",
                    "list",
                    "--rescan",
                    "no",
                ],
                timeout=8,
            )
            device = None
            for line in active.splitlines():
                fields = split_nmcli(line)
                if len(fields) >= 3 and fields[0].lower() in {"yes", "sí"}:
                    if fields[1].upper() == target and fields[2] in devices:
                        device = fields[2]
                        break
            if not device:
                return None
        except (OSError, SystemToolError, ValueError):
            return None
        job.stage = f"Reconectando automáticamente el cliente local {device}…"
        job.run(
            ["pkexec", "nmcli", "device", "disconnect", device],
            self.storage,
            30,
            "local-reconnect-down.log",
        )
        job.run(
            ["pkexec", "nmcli", "device", "connect", device],
            self.storage,
            45,
            "local-reconnect-up.log",
        )
        return device

    def discover_stations(self, bssid, interface, job: ToolJob, seconds=20):
        """Passively observe client MACs for the selected BSSID.

        A connected station can be visible in either direction: as the
        transmitter/source of a data frame or as the unicast receiver of a
        null/action frame sent by the AP. Looking only at ``wlan.sa`` made
        active clients disappear when the AP was the side transmitting
        keepalives, so collect both sides while excluding the BSSID and
        multicast addresses.
        """
        if not is_mac(bssid):
            raise ValueError("BSSID no válido.")
        if enabled():
            target = bssid.upper()
            return [
                item["mac"].upper()
                for item in scenario().get("stations", [])
                if item.get("bssid", "").upper() == target
            ]
        interfaces = {item.name: item for item in InterfaceManager().list_interfaces()}
        if interface not in interfaces or interfaces[interface].mode != "monitor":
            raise ValueError("Selecciona una interfaz que esté en modo monitor.")
        self.storage.mkdir(parents=True, exist_ok=True, mode=0o700)
        with TemporaryDirectory(prefix="station-scan-", dir=self.storage) as folder:
            directory = Path(folder)
            pcap = directory / "stations.pcapng"
            job.stage = f"Detectando clientes visibles de {bssid.upper()}…"
            job.run(
                [
                    "dumpcap",
                    "-i",
                    interface,
                    "-f",
                    f"wlan host {bssid}",
                    "-a",
                    f"duration:{seconds}",
                    "-w",
                    str(pcap),
                    "-q",
                ],
                directory,
                seconds + 15,
                "discovery.log",
            )
            if not pcap.is_file() or pcap.stat().st_size < 24:
                return []
            rows = directory / "stations.tsv"
            job.run(
                [
                    "tshark",
                    "-n",
                    "-r",
                    str(pcap),
                    "-Y",
                    f"wlan.addr == {bssid} && (wlan.fc.type == 2 || wlan.fc.type_subtype == 0x0000 || wlan.fc.type_subtype == 0x0020 || wlan.fc.type_subtype == 0x000b)",
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-e",
                    "wlan.sa",
                    "-e",
                    "wlan.ta",
                    "-e",
                    "wlan.da",
                    "-e",
                    "wlan.ra",
                    "-e",
                    "wlan.fc.type",
                    "-e",
                    "wlan.fc.type_subtype",
                ],
                directory,
                30,
                "discovery-tshark.log",
                stdout_path=rows,
            )
            counts = Counter()
            target = bssid.upper()
            for line in rows.read_text(errors="replace").splitlines():
                # A client may be the sender or the unicast receiver of an
                # AP data/null frame. Never treat the AP itself or a group
                # address as a station candidate.
                fields = line.split("\t")
                frame_type = fields[4].strip() if len(fields) > 4 else ""
                weight = 3 if frame_type == "2" else 2
                peers = set()
                for value in fields[:4]:
                    value = value.strip().upper()
                    if (
                        value == target
                        or not is_mac(value)
                        or int(value.split(":")[0], 16) & 1
                    ):
                        continue
                    peers.add(value)
                for value in peers:
                    # Association/authentication observations are stronger
                    # evidence than a single management address, while data
                    # frames are the best indication of a currently active
                    # station. Keep the ranking deterministic for the UI.
                    counts[value] += weight
            return [mac for mac, _count in counts.most_common(8)]

    def analyze(self, identifier, job: ToolJob):
        artifact = self.artifact(identifier)
        self.require_scope(artifact.project_id, artifact.bssid)
        path = validate_capture(Path(artifact.path))
        if artifact.sha256 and fingerprint(path) != artifact.sha256:
            raise ValueError(
                "La captura cambió desde su registro. Importa el archivo de nuevo."
            )
        self._update(
            CaptureArtifact,
            identifier,
            status="analyzing",
            hash_path="",
            message="",
            evidence_json="{}",
        )
        analysis = path.parent / f"analysis-{uuid4().hex}"
        analysis.mkdir(mode=0o700)
        try:
            job.stage = "Analizando tramas con TShark…"
            fields = [
                "frame.number",
                "frame.time_epoch",
                "frame.encap_type",
                "eapol.type",
                "wlan_rsna_eapol.keydes.msgnr",
                "radiotap.dbm_antsignal",
                "wlan.fc.type",
                "wlan.fc.type_subtype",
                "wlan.sa",
                "wlan.ta",
                "wlan.da",
                "wlan.ra",
                "radiotap.channel.freq",
                "wlan.rsn.capabilities.mfpc",
                "wlan.rsn.capabilities.mfpr",
            ]
            args = [
                "tshark",
                "-n",
                "-r",
                str(path),
                "-c",
                str(MAX_ANALYSIS_PACKETS),
                "-Y",
                f"wlan.bssid == {artifact.bssid}",
                "-T",
                "fields",
                "-E",
                "occurrence=f",
            ]
            for field in fields:
                args += ["-e", field]
            rows = analysis / "frames.tsv"
            job.run(args, analysis, 120, "tshark.log", stdout_path=rows)
            evidence = parse_frames(
                rows.read_text(errors="replace"), target_bssid=artifact.bssid
            )
            diagnosis = capture_diagnosis(evidence)
            evidence["diagnosis"] = diagnosis
            evidence["note"] = (
                "Recuento sobre las primeras 200 000 tramas del archivo. M1–M4 observados no prueban por sí solos un handshake válido."
            )
            evidence["hashes"] = 0
            evidence["sha256"] = fingerprint(path)
            evidence["bytes"] = path.stat().st_size
            hash_path = ""
            if shutil.which("hcxpcapngtool"):
                job.stage = "Comprobando material WPA con HCX…"
                unfiltered = analysis / "converted.22000"
                job.run(
                    ["hcxpcapngtool", "-o", str(unfiltered), str(path)],
                    analysis,
                    120,
                    "hcx.log",
                )
                hashes = scoped_hashes(
                    unfiltered.read_text() if unfiltered.exists() else "",
                    artifact.bssid,
                )
                if unfiltered.exists():
                    unfiltered.unlink()
                evidence["hashes"] = len(hashes)
                evidence["pmkid"] = sum(line.startswith("WPA*01*") for line in hashes)
                evidence["eapol_hashes"] = sum(
                    line.startswith("WPA*02*") for line in hashes
                )
                if hashes:
                    destination = analysis / "authorized.22000"
                    destination.write_text("\n".join(hashes) + "\n")
                    hash_path = str(destination)
            else:
                evidence[
                    "note"
                ] += " Falta hcxpcapngtool; no se comprobó material para recuperación."
            if evidence["hashes"]:
                message = "Material compatible con recuperación offline."
            elif not evidence["packets"]:
                message = "El BSSID autorizado no apareció en la captura. Comprueba el módem, el BSSID y el canal seleccionados."
            elif not evidence["eapol"]:
                message = (
                    "Solo se observaron balizas/sondeos; no hubo tráfico de datos de un cliente asociado. Mantén un cliente autorizado conectado al BSSID y vuelve a capturar."
                    if not evidence["data_frames"]
                    else "Se observaron tramas del BSSID, pero no hubo autenticación EAPOL. Mantén un cliente autorizado conectado y vuelve a autenticarlo durante la captura."
                )
            else:
                message = "Se observaron tramas EAPOL, pero no se obtuvo material WPA recuperable para el BSSID autorizado."
            evidence["diagnosis"] = capture_diagnosis(evidence)
            if evidence["diagnosis"].get("code") != "material_ready":
                message = (
                    f"{evidence['diagnosis'].get('title', 'Diagnóstico de captura')}. "
                    f"{evidence['diagnosis'].get('action', '')}"
                ).strip()
            self._update(
                CaptureArtifact,
                identifier,
                status="ready" if hash_path else "analyzed",
                evidence_json=json.dumps(evidence),
                hash_path=hash_path,
                message=message,
                sha256=evidence["sha256"],
            )
        except Exception as error:
            self._update(
                CaptureArtifact,
                identifier,
                status="interrupted" if isinstance(error, JobCancelled) else "failed",
                message=str(error),
            )
            raise
        return identifier

    def recover(self, identifier, dictionary: Path, runtime: int, job: ToolJob):
        artifact = self.artifact(identifier)
        self.require_scope(artifact.project_id, artifact.bssid)
        if artifact.status != "ready" or not artifact.hash_path:
            raise ValueError(
                "Analiza una captura con material WPA compatible antes de recuperar."
            )
        dictionary = dictionary.expanduser().resolve(strict=True)
        if not dictionary.is_file() or not 0 < dictionary.stat().st_size <= 2 * 1024**3:
            raise ValueError(
                "Selecciona un diccionario local de texto, no vacío y de hasta 2 GiB."
            )
        with dictionary.open("rb") as stream:
            if b"\x00" in stream.read(4096):
                raise ValueError(
                    "El diccionario debe ser un archivo de texto sin comprimir."
                )
        if not 10 <= runtime <= 3600:
            raise ValueError("El tiempo máximo debe estar entre 10 y 3600 segundos.")
        text = Path(artifact.hash_path).read_text()
        hashes = scoped_hashes(text, artifact.bssid)
        if not hashes or len(hashes) != len(
            [line for line in text.splitlines() if line.strip()]
        ):
            raise ValueError(
                "El archivo de hashes contiene material inválido o fuera del alcance autorizado."
            )
        identifier = uuid4().hex
        directory = self._directory(identifier)
        input_hashes, results = directory / "input.22000", directory / "recovered.txt"
        input_hashes.write_text("\n".join(hashes) + "\n")
        with self.sessions() as session:
            session.add(
                RecoveryJob(
                    id=identifier,
                    artifact_id=artifact.id,
                    project_id=artifact.project_id,
                    dictionary=str(dictionary),
                    result_path=str(results),
                    log_path=str(directory / "hashcat.log"),
                    status="running",
                )
            )
            session.commit()
        try:
            job.stage = f"Hashcat · {dictionary.name} · máximo {runtime} s"
            job.progress = {
                "current": 0,
                "total": 0,
                "percent": 0.0,
                "speed": 0,
                "recovered": 0,
                "hashes": len(hashes),
            }
            args = [
                "hashcat",
                "-m",
                "22000",
                "-a",
                "0",
                str(input_hashes),
                str(dictionary),
                "--runtime",
                str(runtime),
                "--session",
                f"lab_{identifier}",
                "-w",
                "1",
                "--potfile-disable",
                "--restore-disable",
                "--logfile-disable",
                "--status",
                "--status-json",
                "--status-timer",
                "2",
                "--outfile",
                str(results),
                "--outfile-format",
                "1,3",
            ]
            code = job.run(
                args,
                directory,
                runtime + 120,
                "hashcat.log",
                accepted=(0, 1, 2, 3, 4, 5),
                progress_callback=lambda output: self._update_hashcat_progress(
                    job, output
                ),
            )
            recovered = verified_results(results, hashes, artifact.bssid) > 0
            if code == 0 and recovered:
                status, message = (
                    "recovered",
                    "Recuperación completada. El resultado se conserva localmente.",
                )
            elif recovered:
                status, message = (
                    "partial",
                    "Hay resultados parciales. La búsqueda no completó todos los hashes.",
                )
            elif code == 1:
                status, message = (
                    "exhausted",
                    "Diccionario agotado sin coincidencias. Esto no demuestra que la clave sea irrecuperable.",
                )
            elif code in (2, 3, 4, 5):
                status, message = (
                    "interrupted",
                    "Búsqueda interrumpida o tiempo máximo alcanzado; no se agotó el espacio de búsqueda.",
                )
            else:
                status, message = (
                    "failed",
                    "Hashcat terminó sin un resultado verificable.",
                )
            self._update(RecoveryJob, identifier, status=status, message=message)
        except Exception as error:
            self._update(
                RecoveryJob,
                identifier,
                status="interrupted" if isinstance(error, JobCancelled) else "failed",
                message=str(error),
            )
            raise
        return identifier

    @staticmethod
    def _update_hashcat_progress(job: ToolJob, output: str):
        progress = parse_hashcat_progress(output)
        if progress is not None:
            job.progress = progress
