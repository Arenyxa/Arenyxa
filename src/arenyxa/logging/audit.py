from .factory import get_logger

logger = get_logger("audit")


def audit_event(event: str, **details: object) -> None:
    logger.info("%s %s", event, details)
