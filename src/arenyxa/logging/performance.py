from .factory import get_logger

logger = get_logger("performance")


def performance_event(metric: str, value: object) -> None:
    logger.info("%s=%s", metric, value)
