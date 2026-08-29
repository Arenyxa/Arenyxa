import time
from datetime import datetime, timezone

import pytest

from arenyxa.application.anti_bot_intelligence import (
    AntiBotIntelligenceEngine,
    BlockAssessment,
    BlockKind,
    ClientProfile,
    HumanVerificationCoordinator,
    SafeAction,
)
from arenyxa.domain.models import FetchResponse


def response(status=200, body=b"ok", headers=None, content_type="text/html", redirects=None):
    return FetchResponse("https://example.test", "https://example.test", status, headers or {}, body, 1.0, "utf-8", content_type, redirects or [])


def test_429_is_rate_limited_and_honors_retry_after():
    result = AntiBotIntelligenceEngine().assess(response(429, headers={"Retry-After": "12"}))
    assert result.kind is BlockKind.RATE_LIMITED
    assert result.retry_after_seconds == 12
    assert SafeAction.THROTTLE in result.actions


def test_retry_after_supports_http_date_with_fixed_timezone_aware_now():
    now = datetime(2026, 10, 21, 7, 27, tzinfo=timezone.utc)
    parser = AntiBotIntelligenceEngine._retry_after
    assert parser({"Retry-After": "12"}, now=now) == 12.0
    assert parser({"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, now=now) == 60.0
    assert parser({"Retry-After": "Wed, 21 Oct 2026 09:28:00 +0200"}, now=now) == 60.0
    assert parser({"Retry-After": "Wed, 21 Oct 2020 07:28:00 GMT"}, now=now) == 0.0
    assert parser({"Retry-After": "not-a-date"}, now=now) is None


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


def test_terminal_human_verification_history_does_not_consume_pending_capacity():
    coordinator = HumanVerificationCoordinator(max_pending=2)
    assessment = BlockAssessment(BlockKind.CAPTCHA_PRESENT, 1.0)
    for index in range(12):
        ticket = coordinator.issue(f"https://example.test/{index}", assessment)
        coordinator.resolve(ticket.ticket_id, operator_id="operator", approved=bool(index % 2))
    assert coordinator.pending() == []
    assert len(coordinator._tickets) == 12
    first = coordinator.issue("https://example.test/pending-1", assessment)
    second = coordinator.issue("https://example.test/pending-2", assessment)
    assert {item.ticket_id for item in coordinator.pending()} == {first.ticket_id, second.ticket_id}
    with pytest.raises(RuntimeError, match="queue is full"):
        coordinator.issue("https://example.test/pending-3", assessment)


def test_expired_human_verification_ticket_releases_pending_capacity():
    coordinator = HumanVerificationCoordinator(max_pending=1)
    assessment = BlockAssessment(BlockKind.BOT_CHALLENGE_PRESENT, 1.0)
    expired = coordinator.issue("https://example.test/expired", assessment)
    expired.expires_at = time.time() - 1.0
    replacement = coordinator.issue("https://example.test/replacement", assessment)
    assert expired.state == "expired"
    assert [item.ticket_id for item in coordinator.pending()] == [replacement.ticket_id]
