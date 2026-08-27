from arenyxa.exceptions.types import SecurityError, NetworkError


def test_security_exception_types():
    assert issubclass(SecurityError, Exception)
    assert issubclass(NetworkError, Exception)
