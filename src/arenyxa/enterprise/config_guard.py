from __future__ import annotations


class ConfigIntegrityError(Exception):
    """Marker type for ConfigIntegrityError."""


def validate_config(required: list[str], config: dict) -> bool:
    missing = [item for item in required if item not in config]
    if missing:
        raise ConfigIntegrityError(f"Missing configuration: {missing}")
    return True
