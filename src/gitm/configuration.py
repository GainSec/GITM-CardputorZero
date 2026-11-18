"""Caller-owned configuration and CA input, kept outside privileged path reads."""

from dataclasses import asdict
import json
from pathlib import Path

from .certificates import atomic_private, read_private_input, validate_material
from .model import NetworkConfig
from .profiles import verify_profile
from .validation import validate_config


def load_config(path: Path) -> NetworkConfig:
    return validate_config(NetworkConfig(**json.loads(read_private_input(path))))


def save_config(config: NetworkConfig, path: Path) -> None:
    validate_config(config)
    atomic_private(path, (json.dumps(asdict(config), indent=2) + '\n').encode())


def load_ca_material(config: NetworkConfig):
    validate_config(config)
    if config.profile:
        return verify_profile(config.profile)
    if config.ca_cert:
        return validate_material(read_private_input(Path(config.ca_cert)), read_private_input(Path(config.ca_key)),
                                 read_private_input(Path(config.ca_chain)) if config.ca_chain else b'')
    return None
