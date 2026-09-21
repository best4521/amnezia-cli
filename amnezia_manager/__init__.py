"""Amnezia AWG2 (AmneziaWG) management toolkit.

Public surface:

    from amnezia_manager import AmneziaManager, Config, load_config
    from amnezia_manager.errors import AmneziaCliError
"""
from __future__ import annotations

from .config import Config, load_config
from .errors import (
    AmneziaCliError,
    ConfigError,
    ContainerError,
    DockerCommandError,
    NoAddressAvailableError,
    UserExistsError,
    UserNotFoundError,
    ValidationError,
)
from .manager import AmneziaManager

__all__ = [
    "AmneziaManager",
    "Config",
    "load_config",
    "AmneziaCliError",
    "ConfigError",
    "ContainerError",
    "DockerCommandError",
    "NoAddressAvailableError",
    "UserExistsError",
    "UserNotFoundError",
    "ValidationError",
]

__version__ = "1.0.0"
