from __future__ import annotations

import statistics
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from arenyxa.compat import dataclass
from arenyxa.application.autopilot import ExperienceStore

AUTOPILOT_VALIDATION_SCHEMA = "arenyxa.autopilot-validation/v1"


@dataclass(frozen=True, slots=True)
class AutopilotValidationCase:
    name: str
    passed: bool
    detail: str
    duration_ms: float


@dataclass(frozen=True, slots=True)
class AutopilotValidationReport:
    cases: tuple[AutopilotValidationCase, ...]
    contamination_shift: float
    recovery_shift: float
    read_p95_ms: float

    @property
    def stable(self) -> bool:
        return bool(self.cases) and all(item.passed for item in self.cases) and self.contamination_shift <= 0.20 and self.recovery_shift >= 0.04

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": AUTOPILOT_VALIDATION_SCHEMA,
            "stable": self.stable,
            "contamination_shift": round(self.contamination_shift, 4),
            "recovery_shift": round(self.recovery_shift, 4),
            "read_p95_ms": round(self.read_p95_ms, 3),
            "cases": [asdict(item) for item in self.cases],
        }


class AutopilotProductionValidator:
    def __init__(self, samples: int = 200) -> None:
        self.samples = max(40, min(5000, int(samples)))

    def run(self) -> AutopilotValidationReport:
        cases: list[AutopilotValidationCase] = []
        read_latencies: list[float] = []
        contamination_shift = 0.0
        recovery_shift = 0.0
        with tempfile.TemporaryDirectory(prefix="arenyxa-autopilot-validation-") as raw:
            store = ExperienceStore(Path(raw) / "experience.db", max_strategy_rows=max(500, self.samples * 8))
            site = "a" * 24
            baseline = self._record_case(cases, "bounded-priors", lambda: self._bounded_priors(store, site))
            before = self._prior(store, site, "http")
            self._poison(store, site, count=max(10, self.samples // 10))
            poisoned = self._prior(store, site, "http")
            contamination_shift = abs(poisoned - before)
            cases.append(AutopilotValidationCase("feedback-contamination-bounded", contamination_shift <= 0.20, f"prior shift={contamination_shift:.4f}", 0.0))
            recovery_before = poisoned
            self._recover(store, site, count=max(20, self.samples // 5))
            recovered = self._prior(store, site, "http")
            recovery_shift = recovered - recovery_before
            cases.append(AutopilotValidationCase("positive-feedback-recovery", recovery_shift >= 0.04, f"prior recovery={recovery_shift:.4f}", 0.0))
            for _ in range(80):
                started = time.perf_counter()
                store.strategy_priors(site)
                read_latencies.append((time.perf_counter() - started) * 1000.0)
            cases.append(AutopilotValidationCase("experience-store-read-latency", self._p95(read_latencies) < 50.0, f"p95={self._p95(read_latencies):.3f}ms", 0.0))
            self._record_case(cases, "corrupt-store-quarantine", lambda: self._corrupt_store_recovery(Path(raw)))
            self._record_case(cases, "bounded-export", lambda: self._bounded_export(store, Path(raw) / "training.jsonl"))
        return AutopilotValidationReport(tuple(cases), contamination_shift, recovery_shift, self._p95(read_latencies))

    def _record_case(self, cases: list[AutopilotValidationCase], name: str, operation: Callable[[], str]) -> str:
        started = time.perf_counter()
        try:
            detail = operation()
        except (OSError, RuntimeError, ValueError) as exc:
            cases.append(AutopilotValidationCase(name, False, f"{type(exc).__name__}: {exc}", (time.perf_counter() - started) * 1000.0))
            return ""
        cases.append(AutopilotValidationCase(name, True, detail, (time.perf_counter() - started) * 1000.0))
        return detail

    def _bounded_priors(self, store: ExperienceStore, site: str) -> str:
        from arenyxa.application.autopilot import SiteFeatures
        features = SiteFeatures(site, "unknown", True, False, False, False, False, False, 0, 200, 1000)
        for index in range(self.samples):
            store.record_strategy(features, "http", success=index % 5 != 0, latency_ms=10.0, peak_memory_mb=8.0, completeness=1.0)
        priors, samples = store.strategy_priors(site)
        value = float(priors.get("http", 0.0))
        if not 0.0 <= value <= 1.0 or samples.get("http", 0) != self.samples:
            raise RuntimeError("strategy prior bounds or sample accounting failed")
        return f"samples={samples['http']} prior={value:.4f}"

    @staticmethod
    def _prior(store: ExperienceStore, site: str, engine: str) -> float:
        return float(store.strategy_priors(site)[0].get(engine, 0.0))

    @staticmethod
    def _features(site: str) -> Any:
        from arenyxa.application.autopilot import SiteFeatures
        return SiteFeatures(site, "unknown", True, False, False, False, False, False, 0, 200, 1000)

    def _poison(self, store: ExperienceStore, site: str, *, count: int) -> None:
        features = self._features(site)
        for _ in range(count):
            store.record_strategy(features, "http", success=False, latency_ms=100.0, peak_memory_mb=16.0, completeness=0.0, failure_code="SYNTHETIC_BAD_FEEDBACK")

    def _recover(self, store: ExperienceStore, site: str, *, count: int) -> None:
        features = self._features(site)
        for _ in range(count):
            store.record_strategy(features, "http", success=True, latency_ms=8.0, peak_memory_mb=8.0, completeness=1.0)

    @staticmethod
    def _corrupt_store_recovery(root: Path) -> str:
        path = root / "corrupt.db"
        path.write_bytes(b"not-sqlite")
        store = ExperienceStore(path)
        stats = store.stats()
        if stats != {"strategy_outcomes": 0, "selector_outcomes": 0, "sites": 0}:
            raise RuntimeError("corrupt ExperienceStore did not recover cleanly")
        quarantined = list(root.glob("corrupt.db.corrupt-*"))
        if not quarantined:
            raise RuntimeError("corrupt ExperienceStore was not quarantined")
        return "corrupt store quarantined and recreated"

    @staticmethod
    def _bounded_export(store: ExperienceStore, destination: Path) -> str:
        store.export_training_jsonl(destination, limit=25)
        lines = destination.read_text(encoding="utf-8").splitlines()
        if len(lines) > 50:
            raise RuntimeError("bounded export exceeded combined strategy/selector cap")
        return f"export_lines={len(lines)}"

    @staticmethod
    def _p95(values: list[float]) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * 0.95))]
