from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from arenyxa.application.autopilot import (
    AutopilotEngine,
    ExperienceStore,
    FailureClassifier,
    SelectorRecoveryRanker,
)
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import FetchResponse, NetworkEvent


def _response(status: int = 200, body: str = "<html></html>", content_type: str = "text/html") -> FetchResponse:
    return FetchResponse(
        url="https://private.example/path?token=secret",
        final_url="https://private.example/path?token=secret",
        status=status,
        headers={"content-type": content_type},
        body=body.encode(),
        elapsed_ms=42.0,
        encoding="utf-8",
        content_type=content_type,
    )


def _event() -> NetworkEvent:
    return NetworkEvent(
        session_id="c1",
        source_type=CaptureSource.BROWSER,
        protocol="https",
        direction="out",
        size=100,
        method="GET",
        url="https://private.example/api/products?api_key=secret",
        status=200,
        request_headers={"Authorization": "Bearer secret"},
        response_headers={"content-type": "application/json"},
    )


@dataclass
class _Plan:
    recommended_engine: str
    confidence: float
    ranking: list[dict[str, Any]]
    reasons: list[str]
    data_sources: list[dict[str, Any]]
    optimization: dict[str, str]


class _Planner:
    def __init__(self) -> None:
        self.history: Mapping[str, float] | None = None

    def analyze(self, response: FetchResponse | None, events: Sequence[NetworkEvent], history_success: Mapping[str, float] | None = None) -> _Plan:
        self.history = history_success
        engine = max((history_success or {"http": 0.5}).items(), key=lambda item: item[1])[0]
        return _Plan(engine, 0.8, [{"engine": engine, "score": 1.0}], ["test"], [], {"selected": engine})


def test_experience_store_changes_smoothed_strategy_prior(tmp_path: Path) -> None:
    store = ExperienceStore(tmp_path / "experience.db")
    engine = AutopilotEngine(_Planner(), store)
    features = engine.features(_response(), [_event()])
    for _ in range(8):
        store.record_strategy(features, "api", success=True, latency_ms=100, completeness=1.0)
    for _ in range(2):
        store.record_strategy(features, "api", success=False, failure_code="TIMEOUT")
    priors, samples = store.strategy_priors(features.site_key)
    assert samples["api"] == 10
    assert 0.70 < priors["api"] < 0.90


def test_autopilot_feeds_local_history_back_into_planner(tmp_path: Path) -> None:
    planner = _Planner()
    store = ExperienceStore(tmp_path / "experience.db")
    engine = AutopilotEngine(planner, store)
    features = engine.features(_response(), [_event()])
    for _ in range(12):
        store.record_strategy(features, "api", success=True)
    plan = engine.analyze(_response(), [_event()])
    assert planner.history is not None
    assert planner.history["api"] > 0.80
    assert plan.recommended_engine == "api"
    assert plan.features.has_session_state is True
    assert plan.features.has_api_events is True


def test_failure_classifier_is_deterministic() -> None:
    classifier = FailureClassifier()
    assert classifier.classify(response=_response(429)).code == "RATE_LIMIT"
    assert classifier.classify(response=_response(403)).code == "AUTH_OR_ACCESS"
    assert classifier.classify(selector_matches=0).code == "SELECTOR_DRIFT"
    assert classifier.classify(exception_name="ReadTimeout").code == "TIMEOUT"
    assert classifier.classify(response=_response(200)) is None


def test_selector_ranker_learns_only_selector_category_not_raw_selector(tmp_path: Path) -> None:
    store = ExperienceStore(tmp_path / "experience.db")
    ranker = SelectorRecoveryRanker(store)
    site_key = "a" * 24
    stable = {"selector": 'button[data-testid="buy"]', "selector_type": "css", "confidence": 0.80, "evidence": ["stable"]}
    weak = {"selector": "button.random-class", "selector_type": "css", "confidence": 0.82, "evidence": ["class"]}
    for _ in range(10):
        ranker.record(site_key, stable, success=True)
        ranker.record(site_key, weak, success=False)
    ranked = ranker.rank(site_key, [weak, stable])
    assert ranked[0].selector == stable["selector"]
    with store._connect() as connection:                               
        raw = connection.execute("SELECT candidate_key FROM selector_outcomes").fetchall()
    assert all("buy" not in str(row[0]) and "random-class" not in str(row[0]) for row in raw)


def test_training_export_contains_no_raw_urls_headers_or_secrets(tmp_path: Path) -> None:
    store = ExperienceStore(tmp_path / "experience.db")
    engine = AutopilotEngine(_Planner(), store)
    engine.record_strategy_outcome(_response(), [_event()], "api", success=True, latency_ms=90, completeness=1.0)
    destination = store.export_training_jsonl(tmp_path / "training.jsonl")
    text = destination.read_text(encoding="utf-8")
    assert "private.example" not in text
    assert "/api/products" not in text
    assert "Bearer secret" not in text
    assert "api_key=secret" not in text
    row = json.loads(text.splitlines()[0])
    assert row["kind"] == "strategy"
    assert len(row["site_key"]) == 24
    assert row["features"]["has_session_state"] is True


def test_experience_store_retention_is_bounded(tmp_path: Path) -> None:
    store = ExperienceStore(tmp_path / "experience.db", max_strategy_rows=1000)
    engine = AutopilotEngine(_Planner(), store)
    features = engine.features(_response(), [])
    for _ in range(1050):
        store.record_strategy(features, "http", success=True)
    assert store.stats()["strategy_outcomes"] == 1000


def test_corrupt_experience_database_is_quarantined_not_startup_fatal(tmp_path: Path) -> None:
    path = tmp_path / "experience.db"
    path.write_bytes(b"not-a-sqlite-database")
    store = ExperienceStore(path)
    assert store.stats() == {"strategy_outcomes": 0, "selector_outcomes": 0, "sites": 0}
    quarantined = list(tmp_path.glob("experience.db.corrupt-*"))
    assert quarantined
    assert quarantined[0].read_bytes() == b"not-a-sqlite-database"
