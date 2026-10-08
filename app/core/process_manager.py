from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(slots=True)
class ManagedProcess:
    id: str
    tool: str
    args: tuple[str, ...]
    started_at: datetime
    process: asyncio.subprocess.Process
    project_id: int | None = None
    capture_id: str | None = None
    output: list[str] = field(default_factory=list)


class ProcessManager:
    """Owns only children it starts; it never uses broad process termination."""

    def __init__(self) -> None:
        self._processes: dict[str, ManagedProcess] = {}

    @property
    def processes(self) -> tuple[ManagedProcess, ...]:
        return tuple(self._processes.values())

    async def start(
        self, tool: str, args: list[str], project_id: int | None = None
    ) -> ManagedProcess:
        process = await asyncio.create_subprocess_exec(
            tool,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        item = ManagedProcess(
            str(uuid4()), tool, tuple(args), datetime.now(UTC), process, project_id
        )
        self._processes[item.id] = item
        asyncio.create_task(self._collect(item))
        return item

    async def _collect(self, item: ManagedProcess) -> None:
        if item.process.stdout:
            async for raw in item.process.stdout:
                item.output.append(raw.decode(errors="replace").rstrip())

    async def stop(self, process_id: str) -> None:
        item = self._processes.get(process_id)
        if not item or item.process.returncode is not None:
            return
        item.process.terminate()
        try:
            await asyncio.wait_for(item.process.wait(), timeout=5)
        except TimeoutError:
            item.process.kill()
            await item.process.wait()

    async def stop_all(self) -> None:
        await asyncio.gather(*(self.stop(pid) for pid in tuple(self._processes)))
