"""Phase 1 credential migration helpers.

Use this layer when replacing embedded credentials.
"""

from .provider import SecretProvider


def resolve_secret(name: str, default: str | None = None) -> str | None:
    return SecretProvider.get(name, required=False, default=default)
