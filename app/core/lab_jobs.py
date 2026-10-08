"""Cancellable, bounded tools. Only processes started by this runner are stopped."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

from app.core.system_commands import SystemToolError


class JobCancelled(RuntimeError):
    pass


class ToolJob:
    def __init__(self):
        self.cancelled = threading.Event()
        self.stage = "Preparando…"
        self.started = time.monotonic()
        self.process = None
        # Optional structured progress emitted by tools such as Hashcat.
        # The Qt thread reads this snapshot; tool workers replace the whole
        # dictionary so the UI never observes a half-written update.
        self.progress = {}

    def cancel(self):
        self.cancelled.set()

    def run(
        self,
        args: list[str],
        directory: Path,
        timeout: int,
        log_name: str,
        accepted=(0,),
        stdout_path: Path | None = None,
        progress_callback=None,
    ) -> int:
        if self.cancelled.is_set():
            raise JobCancelled("Trabajo detenido por el usuario.")
        executable = shutil.which(args[0])
        if not executable:
            raise SystemToolError(
                f"Falta {args[0]}. Revisa Diagnóstico antes de continuar."
            )
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        log_path = directory / log_name
        progress_reader = None
        progress_position = 0
        with log_path.open("wb") as log:
            output = stdout_path.open("wb") if stdout_path else log
            try:
                if progress_callback is not None:
                    progress_reader = log_path.open("rb")
                self.process = subprocess.Popen(
                    [executable, *args[1:]],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=log,
                    cwd=directory,
                    start_new_session=True,
                    env={
                        **os.environ,
                        "LC_ALL": "C",
                        "XDG_DATA_HOME": str(directory / "tool-data"),
                    },
                )
                deadline = time.monotonic() + timeout
                while self.process.poll() is None:
                    if progress_reader is not None:
                        try:
                            progress_reader.seek(progress_position)
                            chunk = progress_reader.read()
                            if chunk:
                                progress_position += len(chunk)
                                try:
                                    progress_callback(chunk.decode(errors="replace"))
                                except Exception:
                                    # Progress is advisory. A UI/parser issue
                                    # must never turn a successful tool run into
                                    # a failed capture or recovery.
                                    pass
                        except OSError:
                            # Progress is advisory; never fail a capture or
                            # recovery because a log tail could not be read.
                            pass
                    if self.cancelled.wait(0.1) or time.monotonic() > deadline:
                        self._stop()
                        if self.cancelled.is_set():
                            raise JobCancelled("Trabajo detenido por el usuario.")
                        raise SystemToolError(
                            f"{args[0]} superó el límite de {timeout} segundos."
                        )
                code = self.process.returncode
            finally:
                if progress_reader is not None:
                    progress_reader.close()
                if self.process and self.process.poll() is None:
                    self._stop()
                if stdout_path:
                    output.close()
                self.process = None
        if code not in accepted:
            with log_path.open("rb") as stream:
                stream.seek(max(0, log_path.stat().st_size - 3000))
                detail = stream.read().decode(errors="replace").strip()
            raise SystemToolError(f"{args[0]} terminó con código {code}. {detail}")
        return code

    def _stop(self):
        process = self.process
        if process is None or process.poll() is not None:
            return
        try:
            # Every child starts its own session. Signal the whole process
            # group so wrappers such as pkexec/airmon-ng cannot survive a
            # cancellation and keep the radio in an unexpected state.
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
        except ProcessLookupError:
            pass
