"""Execution backends: run commands and move files in/out of the AmneziaWG container.

Two implementations share :class:`Backend`:

* :class:`DockerBackend`  - the real thing, via docker-py (``docker exec`` + tar streams).
* :class:`amnezia_manager.fake_backend.FakeBackend` - an in-memory simulation used by
  the demo, tests and ``--fake`` so the whole CLI is exercisable without a server.
"""
from __future__ import annotations

import abc
import io
import shlex
import tarfile
import time
from dataclasses import dataclass

from .config import Config
from .errors import ContainerError, DockerCommandError
from .logging_setup import get_logger

log = get_logger("backend")


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


class Backend(abc.ABC):
    """Command/file transport into the container."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._wg_bin: str | None = None
        self._wgquick_bin: str | None = None

    # -- required primitives -----------------------------------------
    @abc.abstractmethod
    def _exec(self, argv: list[str]) -> ExecResult: ...

    @abc.abstractmethod
    def read_file(self, path: str) -> str: ...

    @abc.abstractmethod
    def write_file(self, path: str, content: str, *, mode: int = 0o600) -> None: ...

    @abc.abstractmethod
    def health_check(self) -> None:
        """Raise :class:`ContainerError` unless the backend is ready to use."""

    # -- convenience ------------------------------------------------
    def exec(
        self,
        cmd: list[str] | str,
        *,
        shell: bool = False,
        check: bool = True,
    ) -> ExecResult:
        """Run *cmd* inside the container.

        Args:
            cmd: An argv list, or a string (implies ``shell=True``).
            shell: Wrap the command in ``sh -c`` so pipes/redirects work.
            check: Raise :class:`DockerCommandError` on non-zero exit.
        """
        if isinstance(cmd, str):
            shell = True
            argv = ["sh", "-c", cmd]
            printable = cmd
        elif shell:
            argv = ["sh", "-c", " ".join(cmd)]
            printable = " ".join(cmd)
        else:
            argv = cmd
            printable = shlex.join(cmd)

        log.debug("exec: %s", printable)
        result = self._exec(argv)
        if check and result.exit_code != 0:
            raise DockerCommandError(printable, result.exit_code, result.output)
        return result

    def pipe_into(self, stdin_text: str, cmd: str, *, check: bool = True) -> ExecResult:
        """Run ``printf %s <stdin_text> | <cmd>`` inside the container.

        Used for key derivation (``... | wg pubkey``) without needing a real stdin
        stream. *stdin_text* must be shell-safe (WireGuard keys always are).
        """
        return self.exec(f"printf %s {shlex.quote(stdin_text)} | {cmd}", check=check)

    # -- tool discovery -------------------------------------------
    @property
    def wg(self) -> str:
        """Path to the WireGuard CLI inside the container (``awg`` preferred)."""
        if self._wg_bin is None:
            self._wg_bin = self._discover("awg", "wg")
        return self._wg_bin

    @property
    def wg_quick(self) -> str:
        if self._wgquick_bin is None:
            self._wgquick_bin = self._discover("awg-quick", "wg-quick")
        return self._wgquick_bin

    def _discover(self, *candidates: str) -> str:
        expr = " || ".join(f"command -v {c}" for c in candidates)
        result = self.exec(expr, check=False)
        found = result.stdout.strip().splitlines()
        if result.exit_code == 0 and found:
            log.debug("discovered tool: %s", found[0])
            return found[0].strip()
        raise ContainerError(
            f"none of {candidates} found in container {self.config.container_name!r}"
        )


def _make_tar(name: str, data: bytes, mode: int) -> bytes:
    stream = io.BytesIO()
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    info.mtime = int(time.time())
    with tarfile.open(fileobj=stream, mode="w") as tar:
        tar.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class DockerBackend(Backend):
    """Talk to a real AmneziaWG container via the Docker Engine API."""

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self._client = None
        self._container = None

    # -- connection -----------------------------------------------
    @property
    def client(self):
        if self._client is None:
            try:
                import docker  # imported lazily: not needed for --help or --fake
            except ImportError as exc:  # pragma: no cover
                raise ContainerError(
                    "the 'docker' package is required for live operation "
                    "(pip install docker), or use --fake"
                ) from exc
            try:
                if self.config.docker_base_url:
                    self._client = docker.DockerClient(base_url=self.config.docker_base_url)
                else:
                    self._client = docker.from_env()
                self._client.ping()
            except docker.errors.DockerException as exc:
                raise ContainerError(f"cannot reach the Docker daemon: {exc}") from exc
        return self._client

    @property
    def container(self):
        if self._container is None:
            import docker

            name = self.config.container_name
            try:
                self._container = self.client.containers.get(name)
            except docker.errors.NotFound as exc:
                raise ContainerError(f"container {name!r} not found") from exc
            except docker.errors.APIError as exc:
                raise ContainerError(f"Docker API error looking up {name!r}: {exc}") from exc
        return self._container

    def health_check(self) -> None:
        container = self.container
        container.reload()
        if container.status != "running":
            raise ContainerError(
                f"container {self.config.container_name!r} is {container.status}, not running"
            )

    # -- primitives ---------------------------------------------
    def _exec(self, argv: list[str]) -> ExecResult:
        import docker

        try:
            rc, output = self.container.exec_run(argv, demux=True)
        except docker.errors.APIError as exc:
            raise ContainerError(f"docker exec failed: {exc}") from exc
        stdout_b, stderr_b = output if isinstance(output, tuple) else (output, None)
        return ExecResult(
            exit_code=rc if rc is not None else -1,
            stdout=(stdout_b or b"").decode("utf-8", "replace"),
            stderr=(stderr_b or b"").decode("utf-8", "replace"),
        )

    def read_file(self, path: str) -> str:
        result = self.exec(["cat", path], check=False)
        if result.exit_code != 0:
            raise ContainerError(f"cannot read {path} in container: {result.output}")
        return result.stdout

    def write_file(self, path: str, content: str, *, mode: int = 0o600) -> None:
        import docker

        directory, _, name = path.rpartition("/")
        directory = directory or "/"
        archive = _make_tar(name, content.encode("utf-8"), mode)
        try:
            ok = self.container.put_archive(directory, archive)
        except docker.errors.APIError as exc:
            raise ContainerError(f"cannot write {path} into container: {exc}") from exc
        if not ok:
            raise ContainerError(f"docker refused to write {path} into the container")
        log.info("wrote %d bytes to %s:%s", len(content), self.config.container_name, path)


def make_backend(config: Config) -> Backend:
    """Factory: return the fake or real backend per ``config.fake_backend``."""
    if config.fake_backend:
        from .fake_backend import FakeBackend

        return FakeBackend(config)
    return DockerBackend(config)
