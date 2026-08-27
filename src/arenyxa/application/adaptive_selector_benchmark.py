"""Deterministic adaptive-selector mutation benchmark for Arenyxa.

The benchmark measures recovery and false-match behavior against synthetic DOM
mutations. It is intentionally deterministic so release gates can compare engine
changes without depending on live third-party websites.
"""
from __future__ import annotations

import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from arenyxa.application.adaptive_extraction import AdaptiveExtractionEngine, AdaptiveSelectorStore


@dataclass(slots=True, frozen=True)
class AdaptiveSelectorBenchmarkCase:
    name: str
    original_markup: str
    original_selector: str
    mutated_markup: str
    expected_text: str
    selector_type: str = "css"


@dataclass(slots=True)
class AdaptiveSelectorBenchmarkResult:
    total_cases: int
    recovered: int
    review_required: int
    false_matches: int
    recovery_rate: float
    false_match_rate: float
    duration_ms: float
    cases: list[dict[str, object]]

    @property
    def passed_default_gate(self) -> bool:
        return self.recovery_rate >= 0.95 and self.false_match_rate <= 0.01

    def snapshot(self) -> dict[str, object]:
        payload = asdict(self)
        payload["passed_default_gate"] = self.passed_default_gate
        return payload


class AdaptiveSelectorBenchmark:
    def __init__(self, cases: Sequence[AdaptiveSelectorBenchmarkCase] | None = None) -> None:
        self.cases = list(cases or default_cases())
        if not self.cases:
            raise ValueError("Adaptive selector benchmark requires at least one case")

    def run(self, *, min_confidence: float = 0.92) -> AdaptiveSelectorBenchmarkResult:
        started = time.perf_counter()
        recovered = 0
        review_required = 0
        false_matches = 0
        details: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory(prefix="arenyxa-selector-bench-") as raw_root:
            store = AdaptiveSelectorStore(Path(raw_root) / "selectors.json", max_versions_per_key=256)
            engine = AdaptiveExtractionEngine(store)
            for index, case in enumerate(self.cases):
                site = f"benchmark-{index}.invalid"
                logical = "target"
                engine.remember(site, logical, case.original_markup, case.original_selector, case.selector_type)
                decision = engine.resolve(
                    site,
                    logical,
                    case.mutated_markup,
                    min_confidence=min_confidence,
                    auto_apply=True,
                )
                selected = decision.get("selected")
                status = str(decision.get("status", "unknown"))
                matched_expected = False
                if isinstance(selected, dict):
                    selector = str(selected.get("selector", ""))
                    selector_type = str(selected.get("selector_type", "css"))
                    analysis = engine.studio.analyze(case.mutated_markup, selector, selector_type)
                    fingerprint = analysis.get("fingerprint")
                    text = str(fingerprint.get("text", "")) if isinstance(fingerprint, dict) else ""
                    matched_expected = case.expected_text.casefold() in text.casefold()
                    if matched_expected:
                        recovered += 1
                    else:
                        false_matches += 1
                else:
                    review_required += 1
                details.append({
                    "name": case.name,
                    "status": status,
                    "selected": selected,
                    "matched_expected": matched_expected,
                })
        total = len(self.cases)
        return AdaptiveSelectorBenchmarkResult(
            total_cases=total,
            recovered=recovered,
            review_required=review_required,
            false_matches=false_matches,
            recovery_rate=round(recovered / total, 6),
            false_match_rate=round(false_matches / total, 6),
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
            cases=details,
        )


def default_cases() -> list[AdaptiveSelectorBenchmarkCase]:
    base = """<html><body><main><section class='catalog'><article id='product-card' class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></section></main></body></html>"""
    return [
        AdaptiveSelectorBenchmarkCase(
            "class-renamed",
            base,
            "#product-card",
            """<html><body><main><section class='catalog'><article class='item tile' data-testid='product'><h2>Alpha Camera</h2><span class='price-new'>$999</span></article><article class='item tile'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "id-removed-wrapper-added",
            base,
            "#product-card",
            """<html><body><main><div class='shell'><section class='catalog'><article class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></section></div></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "sibling-reordered",
            base,
            "#product-card",
            """<html><body><main><section class='catalog'><article class='product card'><h2>Beta Camera</h2></article><article class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "stable-attribute-retained",
            base,
            "article[data-testid=\"product\"]",
            """<html><body><div><section><article class='new-hash-123456' data-testid='product'><div><h2>Alpha Camera</h2></div><span>$999</span></article><article data-testid='other'><h2>Beta Camera</h2></article></section></div></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "semantic-text-retained",
            base,
            "#product-card",
            """<html><body><main><section><article class='listing-entry' data-qa='primary-product'><header><h2>Alpha Camera</h2></header><div>$999</div></article><article class='listing-entry'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "extra-decoy",
            base,
            "#product-card",
            """<html><body><main><section class='catalog'><article class='product card'><h2>Gamma Camera</h2></article><article class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "parent-type-changed",
            base,
            "#product-card",
            """<html><body><main><div class='catalog'><article class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></div></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "nested-content-expanded",
            base,
            "#product-card",
            """<html><body><main><section class='catalog'><article class='product card' data-testid='product'><div class='content'><h2>Alpha Camera</h2><p>Mirrorless camera</p></div><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "attribute-plus-class-shift",
            base,
            "#product-card",
            """<html><body><main><section class='catalog-v2'><article class='product tile-v2' data-testid='product'><h2>Alpha Camera</h2><span>$999</span></article><article class='product tile-v2'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
        AdaptiveSelectorBenchmarkCase(
            "unrelated-banner-inserted",
            base,
            "#product-card",
            """<html><body><aside><article class='product card'><h2>Sponsored Camera</h2></article></aside><main><section class='catalog'><article class='product card' data-testid='product'><h2>Alpha Camera</h2><span class='price'>$999</span></article><article class='product card'><h2>Beta Camera</h2></article></section></main></body></html>""",
            "Alpha Camera",
        ),
    ]
