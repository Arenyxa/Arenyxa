class SecretError(Exception):
    """Base secret management error."""


class SecretNotFoundError(SecretError):
    """Requested secret is unavailable."""
