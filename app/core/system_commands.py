"""Bounded, locale-independent access to host tools."""

from __future__ import annotations

import os
import shutil
import subprocess


class SystemToolError(RuntimeError):
    pass


def run_tool(arguments: list[str], timeout: int = 20) -> str:
    executable = shutil.which(arguments[0])
    if executable is None:
        raise SystemToolError(
            f"Falta la herramienta {arguments[0]}. Instálala y vuelve a intentar."
        )
    try:
        result = subprocess.run(
            [executable, *arguments[1:]],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as error:
        raise SystemToolError(
            f"{arguments[0]} no respondió en {timeout} segundos."
        ) from error
    except OSError as error:
        raise SystemToolError(f"No se pudo ejecutar {arguments[0]}: {error}") from error
    if result.returncode:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"código {result.returncode}"
        )
        raise SystemToolError(f"{arguments[0]}: {detail[:1200]}")
    return result.stdout


def split_nmcli(line: str) -> list[str]:
    """Decode nmcli terse fields, including escaped colons and backslashes."""
    fields, current = [], []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    return [*fields, "".join(current)]
