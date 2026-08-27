from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.enrollment import _strict_json_loads


def fuzz(data: bytes):
    try:
        return _strict_json_loads(bytes(data))
    except ArenyxaError:
        return None
