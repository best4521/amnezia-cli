"""Exception hierarchy for the Amnezia CLI.

Every error the CLI raises on purpose derives from :class:`AmneziaCliError`, so the
entrypoint can catch a single base class, print a clean message and exit non-zero
instead of dumping a traceback on the operator.
"""
from __future__ import annotations


class AmneziaCliError(Exception):
    """Base class for all expected, user-facing errors.

    Attributes:
        exit_code: Process exit status the CLI should terminate with.
    """

    exit_code: int = 1


class ConfigError(AmneziaCliError):
    """The configuration file or an override value is missing/invalid."""

    exit_code = 78  # EX_CONFIG


class ValidationError(AmneziaCliError):
    """User-supplied input (username, date, ...) failed validation."""

    exit_code = 64  # EX_USAGE


class ContainerError(AmneziaCliError):
    """The Docker daemon or the AmneziaWG container is unreachable/misconfigured."""

    exit_code = 69  # EX_UNAVAILABLE


class DockerCommandError(AmneziaCliError):
    """A command executed inside the container returned a non-zero exit status."""

    exit_code = 70  # EX_SOFTWARE

    def __init__(self, command: str, exit_status: int, output: str) -> None:
        self.command = command
        self.exit_status = exit_status
        self.output = output.strip()
        super().__init__(
            f"in-container command failed (exit {exit_status}): {command}\n{self.output}"
        )


class UserNotFoundError(AmneziaCliError):
    """No user with the requested username exists in the database."""

    exit_code = 65  # EX_DATAERR

    def __init__(self, username: str) -> None:
        super().__init__(f"user {username!r} does not exist")


class UserExistsError(AmneziaCliError):
    """A user with the requested username is already present."""

    exit_code = 65

    def __init__(self, username: str) -> None:
        super().__init__(f"user {username!r} already exists")


class NoAddressAvailableError(AmneziaCliError):
    """The tunnel subnet has no free host address left to assign."""

    exit_code = 65
