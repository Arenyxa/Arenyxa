from .factory import get_logger

logger = get_logger("security")


def security_event(event: str, **details: object) -> None:
    logger.warning("%s %s", event, details)
