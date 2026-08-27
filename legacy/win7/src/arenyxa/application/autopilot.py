from __future__ import annotations

from arenyxa.security.sql_safety import sql_identifier, sqlite_pragma_user_version
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from datetime import datetime
from arenyxa.compat import UTC
from pathlib import Path
from typing import Any, Iterator, Mapping, Protocol, Sequence
from urllib.parse import urlparse

from arenyxa.domain.models import FetchResponse, NetworkEvent


_ALLOWED_ENGINES = {"http", "api", "browser", "distributed"}
_FRAMEWORK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nextjs", re.compile(r"__NEXT_DATA__|/_next/", re.I)),
    ("nuxt", re.compile(r"__NUXT__|/_nuxt/", re.I)),
    ("react", re.compile(r"react(?:dom)?|data-reactroot", re.I)),
    ("vue", re.compile(r"vue(?:\.runtime)?|data-v-[0-9a-f]+", re.I)),
    ("angular", re.compile(r"ng-version|angular", re.I)),
)


class PlannerProtocol(Protocol):
    def analyze(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        history_success: Mapping[str, float] | None = None,
    ) -> Any: ...


@dataclass(slots=True, frozen=True)
class SiteFeatures:
    






    site_key: str
    framework: str
    has_html: bool
    has_json: bool
    has_graphql: bool
    has_api_events: bool
    has_session_state: bool
    js_heavy: bool
    event_count: int
    response_status: int | None
    response_bytes: int


@dataclass(slots=True)
class FailureDiagnosis:
    code: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AutopilotPlan:
    site_key: str
    recommended_engine: str
    confidence: float
    historical_priors: dict[str, float]
    historical_samples: dict[str, int]
    features: SiteFeatures
    base_plan: dict[str, Any]
    diagnosis: FailureDiagnosis | None
    learning_mode: str = "deterministic-feedback"


@dataclass(slots=True)
class RankedSelector:
    selector: str
    selector_type: str
    score: float
    heuristic_score: float
    historical_prior: float | None
    historical_samples: int
    evidence: list[str]


class ExperienceStore:
    







    SCHEMA_VERSION = 1

    def __init__(self, path: Path, *, max_strategy_rows: int = 100_000, max_selector_rows: int = 100_000) -> None:
        self.path = path
        self.max_strategy_rows = max(1_000, min(2_000_000, int(max_strategy_rows)))
        self.max_selector_rows = max(1_000, min(2_000_000, int(max_selector_rows)))
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._initialize()
        except (sqlite3.DatabaseError, RuntimeError):
                                                                                          
                                                                                             
                                                                                
            self._quarantine_corrupt_store()
            self._initialize()

    def _quarantine_corrupt_store(self) -> None:
        if not self.path.exists():
            return
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        counter = 1
        while target.exists():
            target = self.path.with_name(f"{self.path.name}.corrupt-{stamp}-{counter}")
            counter += 1
        os.replace(self.path, target)
                                                                                             
                                                                                
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists():
                sidecar.unlink(missing_ok=True)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        






        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.executescript(
                """
                    CREATE TABLE IF NOT EXISTS strategy_outcomes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        site_key TEXT NOT NULL,
                        engine TEXT NOT NULL,
                        success INTEGER NOT NULL CHECK(success IN (0, 1)),
                        latency_ms REAL,
                        peak_memory_mb REAL,
                        completeness REAL,
                        failure_code TEXT,
                        features_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_strategy_site_engine
                    ON strategy_outcomes(site_key, engine, id);

                    CREATE TABLE IF NOT EXISTS selector_outcomes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        site_key TEXT NOT NULL,
                        candidate_key TEXT NOT NULL,
                        success INTEGER NOT NULL CHECK(success IN (0, 1)),
                        heuristic_score REAL NOT NULL,
                        features_json TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS ix_selector_site_candidate
                    ON selector_outcomes(site_key, candidate_key, id);
                """
            )
            current = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current not in {0, self.SCHEMA_VERSION}:
                raise RuntimeError(f"Unsupported Autopilot experience schema version: {current}")
            connection.execute(sqlite_pragma_user_version(self.SCHEMA_VERSION))

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat(timespec="seconds")

    def record_strategy(
        self,
        features: SiteFeatures,
        engine: str,
        *,
        success: bool,
        latency_ms: float | None = None,
        peak_memory_mb: float | None = None,
        completeness: float | None = None,
        failure_code: str | None = None,
    ) -> None:
        engine = str(engine).casefold()
        if engine not in _ALLOWED_ENGINES:
            raise ValueError(f"Unsupported engine: {engine}")
        latency = None if latency_ms is None else max(0.0, min(86_400_000.0, float(latency_ms)))
        memory = None if peak_memory_mb is None else max(0.0, min(4_194_304.0, float(peak_memory_mb)))
        complete = None if completeness is None else max(0.0, min(1.0, float(completeness)))
        safe_failure = (failure_code or "")[:80] or None
        safe_features = self._feature_payload(features)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO strategy_outcomes
                    (created_at, site_key, engine, success, latency_ms, peak_memory_mb,
                     completeness, failure_code, features_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._now(), features.site_key, engine, 1 if success else 0, latency,
                        memory, complete, safe_failure, json.dumps(safe_features, sort_keys=True, separators=(",", ":")),
                    ),
                )
                self._prune_table(connection, "strategy_outcomes", self.max_strategy_rows)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def record_selector(
        self,
        *,
        site_key: str,
        candidate_key: str,
        success: bool,
        heuristic_score: float,
        feature_flags: Mapping[str, bool] | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{24}", site_key):
            raise ValueError("Invalid site key")
        if not candidate_key or len(candidate_key) > 120:
            raise ValueError("Invalid selector candidate key")
        score = max(0.0, min(1.0, float(heuristic_score)))
        flags = {str(key)[:40]: bool(value) for key, value in (feature_flags or {}).items()}
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """
                    INSERT INTO selector_outcomes
                    (created_at, site_key, candidate_key, success, heuristic_score, features_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (self._now(), site_key, candidate_key, 1 if success else 0, score, json.dumps(flags, sort_keys=True, separators=(",", ":"))),
                )
                self._prune_table(connection, "selector_outcomes", self.max_selector_rows)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _prune_table(connection: sqlite3.Connection, table: str, maximum: int) -> None:
        allowed = {"strategy_outcomes", "selector_outcomes"}
        quoted = sql_identifier(table, allowed=allowed)
        count = int(connection.execute("SELECT COUNT(*) FROM " + quoted).fetchone()[0])
        excess = count - maximum
        if excess <= 0:
            return
        statement = "DELETE FROM " + quoted + " WHERE id IN (SELECT id FROM " + quoted + " ORDER BY id ASC LIMIT ?)"
        connection.execute(statement, (excess,))

    def strategy_priors(self, site_key: str) -> tuple[dict[str, float], dict[str, int]]:
        if not re.fullmatch(r"[0-9a-f]{24}", site_key):
            return {}, {}
        try:
            with self._lock, self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT engine, COUNT(*) AS n, SUM(success) AS wins
                    FROM strategy_outcomes
                    WHERE site_key = ?
                    GROUP BY engine
                    """,
                    (site_key,),
                ).fetchall()
        except sqlite3.DatabaseError:
            return {}, {}
        priors: dict[str, float] = {}
        samples: dict[str, int] = {}
        for row in rows:
            engine = str(row["engine"])
            n = int(row["n"])
            wins = int(row["wins"] or 0)
                                                                                               
            priors[engine] = round((wins + 2.0) / (n + 4.0), 4)
            samples[engine] = n
        return priors, samples

    def selector_prior(self, site_key: str, candidate_key: str) -> tuple[float | None, int]:
        try:
            with self._lock, self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS n, SUM(success) AS wins
                    FROM selector_outcomes
                    WHERE site_key = ? AND candidate_key = ?
                    """,
                    (site_key, candidate_key),
                ).fetchone()
        except sqlite3.DatabaseError:
            return None, 0
        n = int(row["n"] if row is not None else 0)
        if n == 0:
            return None, 0
        wins = int(row["wins"] or 0)
        return round((wins + 2.0) / (n + 4.0), 4), n

    def stats(self) -> dict[str, int]:
        with self._lock, self._connect() as connection:
            strategy = int(connection.execute("SELECT COUNT(*) FROM strategy_outcomes").fetchone()[0])
            selectors = int(connection.execute("SELECT COUNT(*) FROM selector_outcomes").fetchone()[0])
            sites = int(connection.execute("SELECT COUNT(DISTINCT site_key) FROM strategy_outcomes").fetchone()[0])
        return {"strategy_outcomes": strategy, "selector_outcomes": selectors, "sites": sites}

    def export_training_jsonl(self, destination: Path, *, limit: int = 100_000) -> Path:
        




        cap = max(1, min(1_000_000, int(limit)))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as connection:
            strategy = connection.execute(
                """
                SELECT created_at, site_key, engine, success, latency_ms, peak_memory_mb,
                       completeness, failure_code, features_json
                FROM strategy_outcomes ORDER BY id DESC LIMIT ?
                """,
                (cap,),
            ).fetchall()
            selectors = connection.execute(
                """
                SELECT created_at, site_key, candidate_key, success, heuristic_score, features_json
                FROM selector_outcomes ORDER BY id DESC LIMIT ?
                """,
                (cap,),
            ).fetchall()
        lines: list[str] = []
        for row in reversed(strategy):
            payload = {
                "kind": "strategy",
                "created_at": row["created_at"],
                "site_key": row["site_key"],
                "engine": row["engine"],
                "success": bool(row["success"]),
                "latency_ms": row["latency_ms"],
                "peak_memory_mb": row["peak_memory_mb"],
                "completeness": row["completeness"],
                "failure_code": row["failure_code"],
                "features": json.loads(str(row["features_json"])),
            }
            lines.append(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        for row in reversed(selectors):
            payload = {
                "kind": "selector",
                "created_at": row["created_at"],
                "site_key": row["site_key"],
                "candidate_key": row["candidate_key"],
                "success": bool(row["success"]),
                "heuristic_score": row["heuristic_score"],
                "features": json.loads(str(row["features_json"])),
            }
            lines.append(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        data = (("\n".join(lines) + "\n") if lines else "").encode("utf-8")
        fd, raw_temp = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        temp = Path(raw_temp)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)
        return destination

    @staticmethod
    def _feature_payload(features: SiteFeatures) -> dict[str, Any]:
        payload = asdict(features)
                                                                                                
        payload.pop("site_key", None)
        return payload


class FailureClassifier:
    





    def classify(
        self,
        *,
        response: FetchResponse | None = None,
        exception_name: str | None = None,
        selector_matches: int | None = None,
        schema_changes: int = 0,
        quality_drop: float = 0.0,
    ) -> FailureDiagnosis | None:
        status = response.status if response is not None else None
        error = (exception_name or "").casefold()
        if status == 429:
            return FailureDiagnosis("RATE_LIMIT", 0.99, ["HTTP 429"], ["adaptive-rate-limit", "retry-after", "smartpath-replan"])
        if status in {401, 403}:
            return FailureDiagnosis("AUTH_OR_ACCESS", 0.94, [f"HTTP {status}"], ["refresh-session", "browser-profile", "verify-access-policy"])
        if status is not None and status >= 500:
            return FailureDiagnosis("ORIGIN_UNSTABLE", 0.90, [f"HTTP {status}"], ["retry-backoff", "fallback-engine"])
        if "timeout" in error or "timedout" in error:
            return FailureDiagnosis("TIMEOUT", 0.92, [exception_name or "timeout"], ["increase-timeout", "reduce-concurrency", "fallback-engine"])
        if "ssl" in error or "tls" in error or "certificate" in error:
            return FailureDiagnosis("TLS_FAILURE", 0.90, [exception_name or "TLS error"], ["tls-inspector", "verify-system-time", "verify-certificate-chain"])
        if selector_matches == 0:
            return FailureDiagnosis("SELECTOR_DRIFT", 0.91, ["旧选择器匹配 0 个元素"], ["selector-self-heal", "shadow-validation"])
        if schema_changes > 0:
            return FailureDiagnosis("SCHEMA_DRIFT", min(0.98, 0.78 + 0.03 * schema_changes), [f"Schema 变化字段 {schema_changes}"], ["schema-diff", "field-remap", "shadow-validation"])
        if quality_drop >= 0.20:
            return FailureDiagnosis("QUALITY_REGRESSION", min(0.95, 0.72 + quality_drop / 2), [f"质量下降 {quality_drop:.0%}"], ["data-quality", "smartpath-replan", "shadow-validation"])
        return None


class SelectorRecoveryRanker:
    def __init__(self, store: ExperienceStore) -> None:
        self.store = store

    def rank(self, site_key: str, candidates: Sequence[Mapping[str, Any]]) -> list[RankedSelector]:
        output: list[RankedSelector] = []
        for raw in candidates:
            selector = str(raw.get("selector", ""))
            selector_type = str(raw.get("selector_type", "css"))
            heuristic = max(0.0, min(1.0, float(raw.get("confidence", raw.get("score", 0.0)) or 0.0)))
            evidence = [str(item)[:160] for item in raw.get("evidence", raw.get("reasons", [])) if isinstance(item, (str, int, float))]
            candidate_key, flags = self.candidate_key(selector, selector_type)
            prior, samples = self.store.selector_prior(site_key, candidate_key)
                                                                                                
                                                                          
            history_weight = min(0.18, 0.03 * samples)
            score = heuristic if prior is None else heuristic * (1.0 - history_weight) + prior * history_weight
            if prior is not None:
                evidence.append(f"历史成功先验 {prior:.0%} / {samples} 样本")
            output.append(RankedSelector(selector, selector_type, round(score, 4), heuristic, prior, samples, evidence))
        return sorted(output, key=lambda item: (-item.score, -item.historical_samples, item.selector))

    def record(self, site_key: str, candidate: Mapping[str, Any], *, success: bool) -> None:
        selector = str(candidate.get("selector", ""))
        selector_type = str(candidate.get("selector_type", "css"))
        heuristic = max(0.0, min(1.0, float(candidate.get("confidence", candidate.get("score", 0.0)) or 0.0)))
        candidate_key, flags = self.candidate_key(selector, selector_type)
        self.store.record_selector(
            site_key=site_key,
            candidate_key=candidate_key,
            success=success,
            heuristic_score=heuristic,
            feature_flags=flags,
        )

    @staticmethod
    def candidate_key(selector: str, selector_type: str) -> tuple[str, dict[str, bool]]:
        lowered = selector.casefold()
        flags = {
            "stable_attr": any(token in lowered for token in ("data-testid", "data-test", "data-qa", "aria-label", "itemprop")),
            "id": "#" in selector and selector_type == "css",
            "text": "normalize-space" in lowered or "text=" in lowered,
            "class": "." in selector and selector_type == "css",
            "structural": "nth-" in lowered or selector.startswith("/html") or selector.startswith("//"),
        }
        category = next((key for key in ("stable_attr", "id", "text", "class", "structural") if flags[key]), "generic")
        return f"{selector_type.casefold()}:{category}", flags


class AutopilotEngine:
    

    def __init__(self, planner: PlannerProtocol, store: ExperienceStore) -> None:
        self.planner = planner
        self.store = store
        self.failures = FailureClassifier()
        self.selectors = SelectorRecoveryRanker(store)

    def analyze(self, response: FetchResponse | None, events: Sequence[NetworkEvent]) -> AutopilotPlan:
        features = self.features(response, events)
        priors, samples = self.store.strategy_priors(features.site_key)
        plan = self.planner.analyze(response, events, priors)
        diagnosis = self.failures.classify(response=response)
        return AutopilotPlan(
            site_key=features.site_key,
            recommended_engine=str(plan.recommended_engine),
            confidence=float(plan.confidence),
            historical_priors=priors,
            historical_samples=samples,
            features=features,
            base_plan=self._plan_payload(plan),
            diagnosis=diagnosis,
        )

    def record_strategy_outcome(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        engine: str,
        *,
        success: bool,
        latency_ms: float | None = None,
        peak_memory_mb: float | None = None,
        completeness: float | None = None,
        failure_code: str | None = None,
    ) -> None:
        features = self.features(response, events)
        self.store.record_strategy(
            features,
            engine,
            success=success,
            latency_ms=latency_ms,
            peak_memory_mb=peak_memory_mb,
            completeness=completeness,
            failure_code=failure_code,
        )

    def rank_selector_candidates(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        candidates: Sequence[Mapping[str, Any]],
    ) -> list[RankedSelector]:
        site_key = self.features(response, events).site_key
        return self.selectors.rank(site_key, candidates)

    def record_selector_outcome(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        candidate: Mapping[str, Any],
        *,
        success: bool,
    ) -> None:
        site_key = self.features(response, events).site_key
        self.selectors.record(site_key, candidate, success=success)

    @staticmethod
    def features(response: FetchResponse | None, events: Sequence[NetworkEvent]) -> SiteFeatures:
        candidate_url = (response.final_url if response is not None else "") or next((item.url for item in events if item.url), "")
        hostname = (urlparse(candidate_url).hostname or "unknown").casefold().strip(".")
        site_key = hashlib.sha256(hostname.encode("utf-8", errors="ignore")).hexdigest()[:24]
        content_type = response.content_type.casefold() if response is not None else ""
        body = response.body if response is not None else b""
        text = ""
        if response is not None and "html" in content_type:
            text = body[:2_000_000].decode(response.encoding, errors="ignore")
        framework = "unknown"
        for name, pattern in _FRAMEWORK_PATTERNS:
            if pattern.search(text):
                framework = name
                break
        has_graphql = any(item.url and "graphql" in item.url.casefold() for item in events)
        has_api = any(
            item.url and (
                "/api/" in item.url.casefold()
                or "json" in " ".join(item.response_headers.values()).casefold()
                or "graphql" in item.url.casefold()
            )
            for item in events
        )
        has_session = any(
            key.casefold() in {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
            for item in events
            for key in item.request_headers
        )
        script_count = len(re.findall(r"<script\b", text, re.I))
        return SiteFeatures(
            site_key=site_key,
            framework=framework,
            has_html="html" in content_type,
            has_json="json" in content_type,
            has_graphql=has_graphql,
            has_api_events=has_api,
            has_session_state=has_session,
            js_heavy=script_count >= 20,
            event_count=min(10_000_000, len(events)),
            response_status=response.status if response is not None else None,
            response_bytes=min(2_147_483_647, len(body)),
        )

    @staticmethod
    def _plan_payload(plan: Any) -> dict[str, Any]:
        if hasattr(plan, "__dataclass_fields__"):
            raw = asdict(plan)
            return raw if isinstance(raw, dict) else {"value": raw}
        return {
            "recommended_engine": str(getattr(plan, "recommended_engine", "unknown")),
            "confidence": float(getattr(plan, "confidence", 0.0)),
            "ranking": list(getattr(plan, "ranking", [])),
            "reasons": list(getattr(plan, "reasons", [])),
        }
