from arenyxa.application.anti_bot_intelligence import AntiBotIntelligenceEngine, BlockKind, SafeAction, ClientProfile
from arenyxa.domain.models import FetchResponse


def response(status=200, body=b"ok", headers=None, content_type="text/html", redirects=None):
    return FetchResponse("https://example.test", "https://example.test", status, headers or {}, body, 1.0, "utf-8", content_type, redirects or [])


def test_429_is_rate_limited_and_honors_retry_after():
    result = AntiBotIntelligenceEngine().assess(response(429, headers={"Retry-After": "12"}))
    assert result.kind is BlockKind.RATE_LIMITED
    assert result.retry_after_seconds == 12
    assert SafeAction.THROTTLE in result.actions


def test_captcha_never_recommends_automatic_bypass():
    result = AntiBotIntelligenceEngine().assess(response(403, b"Please complete reCAPTCHA challenge"))
    assert result.kind is BlockKind.CAPTCHA_PRESENT
    assert result.actions == [SafeAction.OPERATOR_INTERVENTION, SafeAction.STOP]


def test_js_required_recommends_browser_render():
    result = AntiBotIntelligenceEngine().assess(response(200, b"JavaScript is required to continue"))
    assert result.kind is BlockKind.JS_REQUIRED
    assert result.actions == [SafeAction.BROWSER_RENDER]


def test_session_expiry_is_classified_before_generic_403():
    result = AntiBotIntelligenceEngine().assess(response(403, b"Your session has expired"))
    assert result.kind is BlockKind.SESSION_EXPIRED
    assert SafeAction.REFRESH_SESSION in result.actions


def test_redirect_loop_is_fail_closed():
    result = AntiBotIntelligenceEngine().assess(response(302, redirects=["https://a.test", "https://a.test"]))
    assert result.kind is BlockKind.REDIRECT_LOOP
    assert result.actions == [SafeAction.STOP]


def test_client_profile_rejects_header_injection():
    profile = ClientProfile(extra_headers={"X-Test": "ok\r\nInjected: yes"})
    try:
        profile.headers()
    except ValueError:
        pass
    else:
        raise AssertionError("CRLF injection must be rejected")
