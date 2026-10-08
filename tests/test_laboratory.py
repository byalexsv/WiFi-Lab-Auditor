import hashlib
import hmac
import json
import shutil
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

from app.core import lab_jobs
from app.core.lab_jobs import JobCancelled, ToolJob
from app.core.laboratory import (
    Laboratory,
    capture_diagnosis,
    fingerprint,
    frequency_to_channel,
    parse_frames,
    parse_hashcat_progress,
    scoped_hashes,
    validate_capture,
)
from app.core.scope_manager import ScopeError, ScopeManager
from app.core.system_commands import SystemToolError
from app.database import create_session_factory
from app.database.database import CaptureArtifact, RecoveryJob

BSSID = "02:11:22:33:44:55"


def synthetic_pcap(path):
    """Two locally constructed 802.11 frames; no real network material."""
    ssid = b"LAB-TEST"
    ap, client = bytes.fromhex("021122334455"), bytes.fromhex("02aabbccddee")
    pmk = hashlib.pbkdf2_hmac("sha1", b"labpass123", ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + ap + client, hashlib.sha1).digest()[:16]
    rsn = bytes.fromhex("0100000fac040100000fac040100000fac020000")

    def tag(kind, data):
        return bytes([kind, len(data)]) + data

    def frame(fc, dst, src, body, seq):
        return (
            bytes.fromhex("0000080000000000")
            + struct.pack("<HH", fc, 0)
            + dst
            + src
            + ap
            + struct.pack("<H", seq << 4)
            + body
        )

    beacon = frame(
        0x80,
        b"\xff" * 6,
        ap,
        struct.pack("<QHH", 0, 100, 0x11)
        + tag(0, ssid)
        + tag(1, bytes.fromhex("82848b96"))
        + tag(3, b"\x06")
        + tag(48, rsn),
        1,
    )
    assoc = frame(
        0,
        ap,
        client,
        struct.pack("<HH", 0x11, 10)
        + tag(0, ssid)
        + tag(1, bytes.fromhex("82848b96"))
        + tag(48, rsn + struct.pack("<H", 1) + pmkid),
        2,
    )
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    for n, packet in enumerate([beacon, assoc]):
        data += (
            struct.pack("<IIII", 1700000000 + n, 0, len(packet), len(packet)) + packet
        )
    path.write_bytes(data)
    return path


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setenv("WIFI_LAB_MOCK", "0")
    sessions = create_session_factory(tmp_path / "lab.sqlite3")
    with sessions() as session:
        scope = ScopeManager(session)
        project = scope.create_project(
            "Synthetic lab", "Test operator", "Synthetic fixtures only"
        )
        scope.authorize_target(project.id, BSSID, "LAB-TEST", 6)
    return Laboratory(sessions), project.id


def pmkid_line(bssid="021122334455"):
    return f'WPA*01*{"11" * 16}*{bssid}*02aabbccddee*4c41422d54455354***'


def test_delete_artifact_cleans_related_recovery_and_local_files(lab):
    service, project_id = lab
    identifier, path = service._new_artifact(
        project_id, BSSID, "import", "capture.pcapng"
    )
    path.write_bytes(b"capture")
    service._update(CaptureArtifact, identifier, status="captured")
    recovery_id = "recovery-test-123456789012345678901234"
    recovery_dir = service._directory(recovery_id)
    result_path = recovery_dir / "recovered.txt"
    result_path.write_text("result")
    with service.sessions() as session:
        session.add(
            RecoveryJob(
                id=recovery_id,
                artifact_id=identifier,
                project_id=project_id,
                dictionary="/tmp/words.txt",
                result_path=str(result_path),
                log_path=str(recovery_dir / "hashcat.log"),
                status="exhausted",
            )
        )
        session.commit()
    artifact_dir = path.parent
    service.delete_artifact(identifier)
    with service.sessions() as session:
        assert session.get(CaptureArtifact, identifier) is None
        assert session.get(RecoveryJob, recovery_id) is None
    assert not artifact_dir.exists()
    assert not recovery_dir.exists()


def test_delete_project_cleans_scope_records_and_artifacts(lab):
    service, project_id = lab
    with service.sessions() as session:
        ScopeManager(session).authorize_station(project_id, BSSID, "02:AA:BB:CC:DD:01")
    identifier, path = service._new_artifact(
        project_id, BSSID, "import", "capture.pcapng"
    )
    path.write_bytes(b"capture")
    service._update(CaptureArtifact, identifier, status="captured")
    artifact_dir = path.parent
    service.delete_project(project_id)
    with service.sessions() as session:
        assert session.get(CaptureArtifact, identifier) is None
        assert session.get(RecoveryJob, identifier) is None
    assert not artifact_dir.exists()


def test_scope_filters_converted_hashes_and_malformed_rows():
    valid = pmkid_line()
    text = "\n".join([valid, valid, pmkid_line("02ffeeddccbb"), "WPA*garbage"])
    assert scoped_hashes(text, BSSID) == [valid]
    assert scoped_hashes(valid.replace("*01*", "*02*"), BSSID) == []


def test_scope_rejects_oversized_project_and_ssid_fields(lab):
    service, project_id = lab
    with service.sessions() as session:
        scope = ScopeManager(session)
        with pytest.raises(ValueError, match="120 characters"):
            scope.create_project("x" * 121, "operator", "authorized")
        with pytest.raises(ValueError, match="128 characters"):
            scope.authorize_target(project_id, BSSID, "x" * 129, 6)


def test_progress_callback_is_advisory(monkeypatch, tmp_path):
    monkeypatch.setattr(lab_jobs.shutil, "which", lambda _tool: "/bin/sh")

    def callback(_output):
        raise RuntimeError("ui")

    ToolJob().run(
        ["sh", "-c", "printf progress >&2; sleep 0.2"],
        tmp_path,
        5,
        "tool.log",
        progress_callback=callback,
    )


def test_observed_messages_do_not_claim_a_valid_handshake():
    evidence = parse_frames("1\t1.0\t23\t3\t1\t-40\n2\t2.0\t23\t3\t2\t-40\n")
    assert evidence["eapol"] == 2
    assert evidence["radiotap"]
    assert evidence["duration_seconds"] == 1


def test_parse_frames_reports_data_and_deauth_counts():
    evidence = parse_frames(
        "1\t1.0\t23\t\t\t-40\t2\t0x0028\n" "2\t2.0\t23\t\t\t-40\t0\t0x000c\n"
    )
    assert evidence["data_frames"] == 1
    assert evidence["deauth_frames"] == 1
    assert "valid_eapol_pairs" not in evidence


def test_parse_frames_identifies_peers_association_and_radio_frequency():
    evidence = parse_frames(
        "1\t1.0\t23\t\t\t-40\t0\t0x0000\t"
        f"{BSSID}\t{BSSID}\t02:AA:BB:CC:DD:01\t02:AA:BB:CC:DD:01\t2437\n"
        "2\t2.0\t23\t\t\t-41\t2\t0x0028\t"
        f"02:AA:BB:CC:DD:01\t02:AA:BB:CC:DD:01\t{BSSID}\t{BSSID}\t2437\n"
    )
    assert evidence["association_frames"] == 1
    assert evidence["peer_frames"]["02:AA:BB:CC:DD:01"] == 2
    assert evidence["channel_frequencies"] == {"2437": 2}


def test_parse_frames_records_pmf_capability_flags():
    evidence = parse_frames(
        "1\t1.0\t23\t\t\t-40\t0\t0x0008\t"
        f"{BSSID}\t{BSSID}\tff:ff:ff:ff:ff:ff\tff:ff:ff:ff:ff:ff\t2427\t1\t1\n"
    )
    assert evidence["pmf_capable"]
    assert evidence["pmf_required"]


def test_parse_frames_does_not_treat_deauth_address_as_active_client():
    evidence = parse_frames(
        "1\t1.0\t23\t\t\t-40\t0\t0x000c\t"
        f"{BSSID}\t{BSSID}\t02:AA:BB:CC:DD:01\t02:AA:BB:CC:DD:01\t2427\n"
    )
    assert evidence["deauth_frames"] == 1
    assert evidence["peer_frames"] == {}


def test_capture_diagnosis_distinguishes_client_without_reauthentication():
    diagnosis = capture_diagnosis(
        {
            "packets": 1503,
            "eapol": 0,
            "hashes": 0,
            "data_frames": 100,
            "association_frames": 0,
            "peer_frames": {"02:AA:BB:CC:DD:01": 90},
        }
    )
    assert diagnosis["code"] == "client_seen_no_reauth"
    assert "otra radio" in diagnosis["action"]


def test_capture_diagnosis_does_not_call_deauth_alone_a_client():
    diagnosis = capture_diagnosis(
        {
            "packets": 100,
            "eapol": 0,
            "hashes": 0,
            "data_frames": 0,
            "association_frames": 0,
            "deauth_frames": 20,
            "peer_frames": {},
        }
    )
    assert diagnosis["code"] == "deauth_without_client"


def test_parse_hashcat_progress_reports_latest_counters_without_candidate():
    output = (
        "noise\n"
        '{"progress":[1200,10000],"devices":[{"speed":2500}],'
        '"recovered_hashes":[0,1]}\n'
        '{"progress":[3500,10000],"devices":[{"speed":3000}],'
        '"recovered_hashes":[0,1]}\n'
    )
    assert parse_hashcat_progress(output) == {
        "current": 3500,
        "total": 10000,
        "percent": 35.0,
        "speed": 3000,
        "recovered": 0,
        "hashes": 1,
        "status": None,
    }


def test_invalid_capture_rejected(tmp_path):
    path = tmp_path / "fake.pcap"
    path.write_text("this is not a capture" * 3)
    with pytest.raises(ValueError, match="cabecera"):
        validate_capture(path)


def test_import_denies_unauthorized_network_before_file_creation(lab, tmp_path):
    service, project = lab
    capture = synthetic_pcap(tmp_path / "source.pcap")
    with pytest.raises(ScopeError):
        service.import_capture(project, "02:00:00:00:00:99", capture, ToolJob())
    assert not service.artifacts(project)


def test_demo_cannot_execute_real_tools(lab, monkeypatch, tmp_path):
    service, project = lab
    monkeypatch.setenv("WIFI_LAB_MOCK", "1")
    with pytest.raises(ValueError, match="demostración"):
        service.import_capture(
            project, BSSID, synthetic_pcap(tmp_path / "test.pcap"), ToolJob()
        )


@pytest.mark.skipif(
    not (shutil.which("tshark") and shutil.which("hcxpcapngtool")),
    reason="requires tshark and hcxpcapngtool",
)
def test_real_tools_import_analyze_and_convert_synthetic_pmkid(lab, tmp_path):
    service, project = lab
    original = synthetic_pcap(tmp_path / "source.pcap")
    before = fingerprint(original)
    identifier = service.import_capture(project, BSSID, original, ToolJob())
    artifact = service.artifact(identifier)
    assert fingerprint(original) == before == artifact.sha256
    assert artifact.status == "ready"
    evidence = json.loads(artifact.evidence_json)
    assert evidence["packets"] == 2
    assert evidence["pmkid"] == 1
    assert evidence["hashes"] == 1
    assert len(scoped_hashes(Path(artifact.hash_path).read_text(), BSSID)) == 1
    Path(artifact.path).write_bytes(b"\x00" * 30)
    with pytest.raises(ValueError):
        service.analyze(identifier, ToolJob())


def test_cancellation_stops_only_owned_process(tmp_path):
    job = ToolJob()
    errors = []

    def work():
        try:
            job.run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                tmp_path,
                40,
                "tool.log",
            )
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=work)
    thread.start()
    deadline = time.monotonic() + 3
    while job.process is None and time.monotonic() < deadline:
        time.sleep(0.01)
    job.cancel()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], JobCancelled)
    assert job.process is None


def test_previous_unfinished_work_becomes_interrupted(lab, tmp_path):
    service, project = lab
    with service.sessions() as session:
        session.add(
            CaptureArtifact(
                id="a",
                project_id=project,
                bssid=BSSID,
                source="live",
                name="test",
                path=str(tmp_path / "a.pcap"),
                status="running",
            )
        )
        session.commit()
    service.recover_interrupted()
    assert service.artifact("a").status == "interrupted"


@pytest.mark.parametrize(
    "exit_code, expected", [(0, "failed"), (1, "exhausted"), (4, "interrupted")]
)
def test_recovery_exit_states_never_invent_success(lab, tmp_path, exit_code, expected):
    service, project = lab
    hashes = tmp_path / "authorized.22000"
    hashes.write_text(pmkid_line() + "\n")
    dictionary = tmp_path / "dictionary.txt"
    dictionary.write_text("labpass123\n")
    with service.sessions() as session:
        session.add(
            CaptureArtifact(
                id="a",
                project_id=project,
                bssid=BSSID,
                source="import",
                name="test",
                path="unused",
                status="ready",
                hash_path=str(hashes),
            )
        )
        session.commit()

    class FakeJob(ToolJob):
        def run(self, args, *a, **kw):
            assert "--force" not in args
            assert "--runtime" in args
            assert args[args.index("-m") + 1] == "22000"
            return exit_code

    identifier = service.recover("a", dictionary, 10, FakeJob())
    with service.sessions() as session:
        assert session.get(RecoveryJob, identifier).status == expected


def test_capture_builds_scoped_command_and_preserves_stopped_file(
    lab, tmp_path, monkeypatch
):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )

    class StopCapture(ToolJob):
        def run(self, args, *a, **kw):
            if args[0] == "pkexec":
                assert args[1:4] == ["iw", "dev", "labmon0"]
                assert args[-2:] == ["channel", "6"]
                return 0
            assert args[0] == "dumpcap"
            assert args[args.index("-f") + 1] == f"wlan host {BSSID}"
            assert args[args.index("-i") + 1] == "labmon0"
            assert "duration:5" in args and "filesize:65536" in args
            assert "-I" not in args
            assert args[args.index("-k") + 1] == "2437"
            synthetic_pcap(Path(args[args.index("-w") + 1]))
            raise JobCancelled("Stopped")

    identifier = service.capture(
        project, BSSID, "labmon0", 2437, 5, False, StopCapture()
    )
    artifact = service.artifact(identifier)
    assert artifact.status == "captured"
    assert Path(artifact.path).is_file()
    assert artifact.sha256


def test_monitor_mode_requires_explicit_consent(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("lab0", mode="managed")],
    )
    with pytest.raises(ValueError, match="acepta activar modo monitor"):
        service.capture(project, BSSID, "lab0", 2437, 5, False, ToolJob())
    assert service.artifacts(project) == []


def test_managed_interface_is_rejected_before_creating_error_artifact(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("wlan0", mode="managed")],
    )
    with pytest.raises(ValueError, match="sigue en modo gestionado"):
        service.capture(project, BSSID, "wlan0", 2462, 5, True, ToolJob())
    assert service.artifacts(project) == []


def test_capture_reports_when_dumpcap_does_not_create_output(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )

    class NoOutputCapture(ToolJob):
        def run(self, args, *unused, **kwargs):
            return 0

    with pytest.raises(SystemToolError, match="sin crear capture.pcapng"):
        service.capture(project, BSSID, "labmon0", 2437, 5, False, NoOutputCapture())

    artifact = service.artifacts(project)[0]
    assert artifact.status == "failed"
    assert "sin crear capture.pcapng" in artifact.message


def test_capture_retries_without_channel_setter_for_monitor_driver(
    lab, monkeypatch, tmp_path
):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )
    monkeypatch.setattr(service, "analyze", lambda identifier, job: None)
    calls = []

    class DriverWithoutChannelSetter(ToolJob):
        def run(self, args, *unused, **kwargs):
            calls.append(args)
            if args[0] == "dumpcap" and "-k" in args:
                raise SystemToolError(
                    "dumpcap: Failed to set channel: Operation not supported"
                )
            if args[0] == "dumpcap":
                synthetic_pcap(Path(args[args.index("-w") + 1]))
            return 0

    identifier = service.capture(
        project,
        BSSID,
        "labmon0",
        2437,
        5,
        False,
        DriverWithoutChannelSetter(),
    )

    dumpcap_calls = [args for args in calls if args[0] == "dumpcap"]
    assert len(dumpcap_calls) == 2
    assert "-k" in dumpcap_calls[0]
    assert "-k" not in dumpcap_calls[1]
    assert service.artifact(identifier).status == "captured"


def test_pmkid_fallback_builds_bssid_scoped_non_broadcast_command(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    # The fake job records commands directly, so this test must not depend on
    # hcxdumptool being installed on the CI runner.
    monkeypatch.setattr(laboratory.shutil, "which", lambda _tool: "/usr/bin/tool")
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )
    calls = []

    class PmkidJob(ToolJob):
        def run(self, args, directory, *unused, **kwargs):
            calls.append(args)
            directory.mkdir(parents=True, exist_ok=True)
            if args[:3] == ["pkexec", "iw", "dev"]:
                return 0
            if args[0] == "hcxdumptool":
                kwargs["stdout_path"].write_text("48 0 0 3\n6 0 0 0\n")
            else:
                Path(args[args.index("-w") + 1]).write_bytes(
                    b"\x0a\x0d\x0d\x0a" + b"0" * 28
                )
            return 0

    monkeypatch.setattr(service, "analyze", lambda identifier, job: None)
    identifier = service.capture_pmkid(project, BSSID, "labmon0", 2437, 5, PmkidJob())
    assert service.artifact(identifier).status == "captured"
    hcxdumptool_calls = [args for args in calls if args[0] == "hcxdumptool"]
    capture_calls = [args for args in calls if args[:2] == ["pkexec", "hcxdumptool"]]
    assert len(hcxdumptool_calls) == 1
    assert f"--bpfc=wlan addr3 {BSSID.replace(':', '').lower()}" in hcxdumptool_calls[0]
    assert len(capture_calls) == 1
    assert "--disable_disassociation" in capture_calls[0]
    assert "--proberesponsetx=0" in capture_calls[0]
    assert "--associationmax=1" in capture_calls[0]


def test_prepare_monitor_uses_explicit_polkit_command(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, _ = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("wlan0", mode="managed")],
    )

    class FakeJob(ToolJob):
        def run(self, args, *unused, **kwargs):
            assert args == ["pkexec", "airmon-ng", "start", "wlan0", "11"]
            return 0

    service.prepare_monitor("wlan0", 2462, FakeJob())


def test_trigger_reconnect_requires_authorized_station_and_targets_one_client(
    lab, monkeypatch
):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    station = "02:AA:BB:CC:DD:01"
    with service.sessions() as session:
        ScopeManager(session).authorize_station(project, BSSID, station)
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )

    class FakeJob(ToolJob):
        def run(self, args, *unused, **kwargs):
            assert args == [
                "pkexec",
                "aireplay-ng",
                "--deauth",
                "1",
                "-a",
                BSSID,
                "-c",
                station,
                "labmon0",
            ]
            return 0

    service.trigger_reconnect(project, BSSID, station, "labmon0", FakeJob())

    with pytest.raises(ScopeError, match="station"):
        service.trigger_reconnect(
            project, BSSID, "02:AA:BB:CC:DD:02", "labmon0", FakeJob()
        )


def test_trigger_reconnect_prefers_the_host_client_on_the_authorized_bssid(
    lab, monkeypatch
):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    station = "02:AA:BB:CC:DD:01"
    with service.sessions() as session:
        ScopeManager(session).authorize_station(project, BSSID, station)
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )
    escaped_bssid = BSSID.replace(":", "\\:")
    outputs = iter(
        [
            "wlan1:wifi:connected:Lab\\:Guest\n",
            f"yes:{escaped_bssid}:wlan1\n",
        ]
    )
    monkeypatch.setattr(laboratory, "run_tool", lambda *args, **kwargs: next(outputs))
    calls = []

    class LocalReconnectJob(ToolJob):
        def run(self, args, *unused, **kwargs):
            calls.append(args)
            return 0

    result = service.trigger_reconnect(
        project, BSSID, station, "labmon0", LocalReconnectJob()
    )
    assert result == "local:wlan1"
    assert calls == [
        ["pkexec", "nmcli", "device", "disconnect", "wlan1"],
        ["pkexec", "nmcli", "device", "connect", "wlan1"],
    ]


def test_trigger_reconnect_rejects_zero_ack_result(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, project = lab
    station = "02:AA:BB:CC:DD:01"
    with service.sessions() as session:
        ScopeManager(session).authorize_station(project, BSSID, station)
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )

    class FakeJob(ToolJob):
        def run(self, args, directory, *unused, **kwargs):
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "reconnect.log").write_text(
                "Sending 64 directed DeAuth (code 7). "
                "STMAC: [02:AA:BB:CC:DD:01] [ 0| 0 ACKs]"
            )
            return 0

    with pytest.raises(SystemToolError, match="no recibió ACK"):
        service.trigger_reconnect(project, BSSID, station, "labmon0", FakeJob())


def test_discover_stations_selects_observed_clients(lab, monkeypatch):
    from app.core import laboratory
    from app.core.interface_manager import WirelessInterface

    service, _project = lab
    monkeypatch.setattr(
        laboratory.InterfaceManager,
        "list_interfaces",
        lambda self: [WirelessInterface("labmon0", mode="monitor")],
    )

    seen = {}

    class DiscoveryJob(ToolJob):
        def run(self, args, *unused, **kwargs):
            if args[0] == "dumpcap":
                Path(args[args.index("-w") + 1]).write_bytes(
                    b"\x0a\x0d\x0d\x0a" + b"0" * 28
                )
            else:
                seen["args"] = args
                assert args[args.index("-E") + 1] == "separator=\t"
                assert "wlan.fc.type == 2" in args[args.index("-Y") + 1]
                kwargs["stdout_path"].write_text(
                    f"02:AA:BB:CC:DD:01\t{BSSID}\n"
                    f"02:AA:BB:CC:DD:01\t{BSSID}\n"
                    f"{BSSID}\t{BSSID}\t02:AA:BB:CC:DD:02\t02:AA:BB:CC:DD:02\n"
                    f"ff:ff:ff:ff:ff:ff\t{BSSID}\n"
                )
            return 0

    assert service.discover_stations(BSSID, "labmon0", DiscoveryJob()) == [
        "02:AA:BB:CC:DD:01",
        "02:AA:BB:CC:DD:02",
    ]
    assert "wlan.da" in seen["args"]


def test_frequency_to_channel_supports_common_bands():
    assert frequency_to_channel(2412) == 1
    assert frequency_to_channel(2462) == 11
    assert frequency_to_channel(5180) == 36
    with pytest.raises(ValueError):
        frequency_to_channel(2400)
    with pytest.raises(ValueError):
        frequency_to_channel(2460)


def test_failed_command_does_not_become_success(tmp_path):
    from app.core.system_commands import SystemToolError

    with pytest.raises(SystemToolError, match="código 7"):
        ToolJob().run(
            [sys.executable, "-c", 'import sys; print("failed"); sys.exit(7)'],
            tmp_path,
            5,
            "error.log",
        )


def test_current_hcx_pmkid_origin_flag_is_accepted():
    assert scoped_hashes(pmkid_line() + "10", BSSID) == [pmkid_line() + "10"]


def test_duplicate_target_is_updated(lab):
    service, project = lab
    with service.sessions() as session:
        scope = ScopeManager(session)
        first = scope.authorize_target(project, BSSID, "Updated lab", 11)
        second = scope.authorize_target(project, BSSID, "Updated lab", 11)
        assert first.id == second.id


def test_authorization_requires_existing_project(lab):
    service, _ = lab
    with service.sessions() as session:
        with pytest.raises(ScopeError):
            ScopeManager(session).authorize_target(9999, BSSID, "Lab", 1)


def test_real_hashcat_roundtrip_opt_in(lab, tmp_path):
    import os

    if os.environ.get("WIFI_LAB_TEST_HASHCAT") != "1":
        pytest.skip("Set WIFI_LAB_TEST_HASHCAT=1 to run the bounded real backend check")
    service, project = lab
    identifier = service.import_capture(
        project, BSSID, synthetic_pcap(tmp_path / "synthetic.pcap"), ToolJob()
    )
    dictionary = tmp_path / "dictionary.txt"
    dictionary.write_text("labpass123\n")
    service.recover(identifier, dictionary, 10, ToolJob())
    result = service.recoveries(project)[0]
    assert result.status == "recovered", result.message
    line = Path(result.result_path).read_text().strip()
    assert bytes.fromhex(line.rsplit(":", 1)[-1]) == b"labpass123"


def test_recovered_result_must_match_selected_hash(tmp_path):
    from app.core.laboratory import verified_results

    output = tmp_path / "recovered.txt"
    output.write_text(pmkid_line("02ffeeddccbb") + ":6c616270617373313233\n")
    with pytest.raises(ValueError):
        verified_results(output, [pmkid_line()], BSSID)
    output.write_text(pmkid_line() + ":6c616270617373313233\n")
    assert verified_results(output, [pmkid_line()], BSSID) == 1
