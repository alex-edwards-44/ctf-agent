"""Docker sandbox for vuln-triage solver agents — native async via aiodocker."""

from __future__ import annotations

import asyncio
import io
import logging
import shlex
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import aiodocker

logger = logging.getLogger(__name__)

CONTAINER_LABEL = "vuln-triage"

# Concurrency control
_start_semaphore: asyncio.Semaphore | None = None
_active_count: int = 0
_count_lock = asyncio.Lock()

_WARN_THRESHOLDS = {100, 200, 500}


def configure_semaphore(max_concurrent: int = 50) -> None:
    """Set the max concurrent container starts. Call once at startup."""
    global _start_semaphore
    _start_semaphore = asyncio.Semaphore(max_concurrent)


async def _track_start() -> None:
    global _active_count
    async with _count_lock:
        _active_count += 1
        if _active_count in _WARN_THRESHOLDS:
            logger.warning("Active containers: %d", _active_count)


async def _track_stop() -> None:
    global _active_count
    async with _count_lock:
        _active_count = max(0, _active_count - 1)


async def cleanup_orphan_containers() -> None:
    """Kill any leftover vuln-triage containers from a previous run."""
    try:
        docker = aiodocker.Docker()
        try:
            containers = await docker.containers.list(
                all=True,
                filters={"label": [CONTAINER_LABEL]},
            )
            for c in containers:
                try:
                    await c.delete(force=True)
                except Exception:
                    pass
            if containers:
                logger.info("Cleaned up %d orphan container(s)", len(containers))
        finally:
            await docker.close()
    except Exception as e:
        logger.warning("Orphan cleanup failed: %s", e)


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass
class DockerSandbox:
    """Isolated Docker container for a single solver agent.

    For vuln-triage: set target_dir and finding_json_path.
    The container runs with --network none (no outbound access).
    """

    image: str
    target_dir: str = ""           # host path to target repo → /target:ro
    finding_json_path: str = ""    # host path to finding JSON → /finding.json:ro
    memory_limit: str = "8g"
    no_network: bool = True
    workspace_dir: str = ""
    _container: Any = field(default=None, repr=False)
    _docker: Any = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def container_id(self) -> str:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        return self._container.id

    def _parse_memory_limit(self) -> int:
        s = self.memory_limit.strip().lower()
        try:
            if s.endswith("g"):
                return int(s[:-1]) * 1024 * 1024 * 1024
            if s.endswith("m"):
                return int(s[:-1]) * 1024 * 1024
            return int(s)
        except (ValueError, IndexError):
            logger.warning("Invalid memory_limit %r, defaulting to 4GB", self.memory_limit)
            return 4 * 1024 * 1024 * 1024

    async def start(self) -> None:
        sem = _start_semaphore or asyncio.Semaphore(50)
        async with sem:
            self._docker = aiodocker.Docker()
            self.workspace_dir = tempfile.mkdtemp(prefix="vuln-workspace-")

            binds: list[str] = [f"{self.workspace_dir}:/workspace:rw"]

            if self.target_dir:
                target_root = Path(self.target_dir).resolve()
                binds.append(f"{target_root}:/target:ro")

            if self.finding_json_path:
                finding_path = Path(self.finding_json_path).resolve()
                binds.append(f"{finding_path}:/finding.json:ro")

            host_config: dict = {
                "Binds": binds,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "Memory": self._parse_memory_limit(),
                "NanoCpus": int(2 * 1e9),
            }

            if self.no_network:
                host_config["NetworkMode"] = "none"
            else:
                host_config["ExtraHosts"] = ["host.docker.internal:host-gateway"]

            config = {
                "Image": self.image,
                "Cmd": ["sleep", "infinity"],
                "WorkingDir": "/target",
                "Tty": False,
                "Labels": {CONTAINER_LABEL: "true"},
                "HostConfig": host_config,
            }

            self._container = await self._docker.containers.create(config)
            await self._container.start()
            await _track_start()

            info = await self._container.show()
            short_id = info["Id"][:12]
            logger.info("Sandbox started: %s", short_id)

    async def exec(self, command: str, timeout_s: int = 300) -> ExecResult:
        if not self._container:
            raise RuntimeError("Sandbox not started")

        async with self._lock:
            try:
                return await self._exec_inner(command, timeout_s)
            except aiodocker.exceptions.DockerError as e:
                return ExecResult(exit_code=-1, stdout="", stderr=f"Container gone: {e}")

    async def _exec_inner(self, command: str, timeout_s: int) -> ExecResult:
        wrapped = f"timeout --signal=KILL --kill-after=5 {timeout_s} bash -c {shlex.quote(command)}"
        exec_instance = await self._container.exec(
            cmd=["bash", "-c", wrapped],
            stdout=True,
            stderr=True,
            tty=False,
        )

        stream = exec_instance.start(detach=False)
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        async def _collect() -> None:
            while True:
                msg = await stream.read_out()
                if msg is None:
                    break
                if msg.stream == 1:
                    stdout_chunks.append(msg.data)
                else:
                    stderr_chunks.append(msg.data)

        try:
            await asyncio.wait_for(_collect(), timeout=timeout_s + 30)
        except TimeoutError:
            try:
                await stream.close()
            except Exception:
                pass
            return ExecResult(
                exit_code=-1,
                stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
                stderr="Command timed out",
            )

        inspect = await exec_instance.inspect()
        exit_code = inspect.get("ExitCode", 0)

        return ExecResult(
            exit_code=exit_code,
            stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
            stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
        )

    async def read_file(self, path: str) -> str | bytes:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        try:
            tar = await asyncio.wait_for(
                self._container.get_archive(path),
                timeout=30,
            )
        except TimeoutError as e:
            raise TimeoutError(f"Timed out reading {path}") from e

        with tar:
            for member in tar:
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        data = f.read()
                        try:
                            return data.decode("utf-8")
                        except UnicodeDecodeError:
                            return data
        raise FileNotFoundError(f"No file found at {path}")

    async def read_file_bytes(self, path: str) -> bytes:
        result = await self.read_file(path)
        if isinstance(result, str):
            return result.encode("utf-8")
        return result

    async def write_file(self, path: str, content: str | bytes) -> None:
        if not self._container:
            raise RuntimeError("Sandbox not started")
        if isinstance(content, str):
            content = content.encode("utf-8")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=Path(path).name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
        buf.seek(0)
        try:
            await asyncio.wait_for(
                self._container.put_archive(str(Path(path).parent), buf.getvalue()),
                timeout=30,
            )
        except TimeoutError as e:
            raise TimeoutError(f"Timed out writing {path}") from e

    async def copy_from(self, container_path: str, host_path: str) -> None:
        data = await self.read_file_bytes(container_path)
        Path(host_path).parent.mkdir(parents=True, exist_ok=True)
        Path(host_path).write_bytes(data)

    async def stop(self) -> None:
        if self._container:
            try:
                await self._container.delete(force=True)
            except Exception:
                pass
            self._container = None
            await _track_stop()

        if self._docker:
            try:
                await self._docker.close()
            except Exception:
                pass
            self._docker = None

        if self.workspace_dir:
            import shutil
            try:
                shutil.rmtree(self.workspace_dir, ignore_errors=True)
            except Exception:
                pass
            self.workspace_dir = ""
        logger.info("Sandbox stopped")
