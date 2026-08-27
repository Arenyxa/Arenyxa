from arenyxa.security.hardening.http_security import validate_headers


def test_header_limit():
    assert validate_headers({"x-test": "ok"}) is True
