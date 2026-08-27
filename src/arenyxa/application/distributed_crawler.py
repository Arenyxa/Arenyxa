"""Durable distributed crawling on Arenyxa's Enterprise queue.

Phase 5 deliberately reuses DurableDistributedQueue rather than inventing a second
cluster runtime.  Every URL is an idempotent leased job, so the existing Worker
heartbeat, lease fencing, failover/recovery and SQLite/PostgreSQL backends apply to
crawler work as well.

Security notes:
* Raw authorization/cookie/API-key headers are not serialized into distributed jobs.
* Credential-bearing proxy URLs are rejected; deployments should use an approved
  secret indirection at the worker boundary instead of putting credentials in the queue.
* robots.txt and NetworkUseGuard remain enforced by CrawlerEngine.fetch_one().
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from urllib.parse import urlsplit

from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine, canonicalize_url, normalize_domain
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CleanerStep, FieldSpec, ValidationRule, new_id
from arenyxa.enterprise.distributed_protocol import DistributedLease
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue

LOGGER = logging.getLogger(__name__)

DISTRIBUTED_CRAWL_JOB_KIND = "crawler.fetch.v1"
DISTRIBUTED_CRAWL_SCHEMA = "arenyxa.distributed-crawl/v1"
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token",
    "x-access-token", "x-csrf-token", "x-xsrf-token",
}


@dataclass(slots=True)
class DistributedCrawlPolicy:
    max_pending_jobs: int = 2_000
    max_result_links: int = 512
    job_max_attempts: int = 3
    priority_base: int = 100

    def normalized(self) -> "DistributedCrawlPolicy":
        return DistributedCrawlPolicy(
            max_pending_jobs=max(1, min(100_000, int(self.max_pending_jobs))),
            max_result_links=max(1, min(2_000, int(self.max_result_links))),
            job_max_attempts=max(1, min(20, int(self.job_max_attempts))),
            priority_base=max(-1000, min(1000, int(self.priority_base))),
        )


@dataclass(slots=True)
class DistributedCrawlSnapshot:
    crawl_id: str
    jobs_total: int
    queued: int
    leased: int
    running: int
    completed: int
    failed: int
    review_required: int
    storage_backend: str
    multi_host_writers: bool
    backpressure_active: bool
    postgresql_recommended: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _field_from_dict(raw: Mapping[str, Any]) -> FieldSpec:
    payload = dict(raw)
    payload["cleaners"] = [
        item if isinstance(item, CleanerStep) else CleanerStep(**dict(item))
        for item in list(payload.get("cleaners") or [])
        if isinstance(item, (CleanerStep, Mapping))
    ]
    payload["validators"] = [
        item if isinstance(item, ValidationRule) else ValidationRule(**dict(item))
        for item in list(payload.get("validators") or [])
        if isinstance(item, (ValidationRule, Mapping))
    ]
    return FieldSpec(**payload)


def crawler_config_from_snapshot(raw: Mapping[str, Any]) -> CrawlerConfig:
    payload = dict(raw)
    payload["fields"] = [
        item if isinstance(item, FieldSpec) else _field_from_dict(item)
        for item in list(payload.get("fields") or [])
        if isinstance(item, (FieldSpec, Mapping))
    ]
    return CrawlerConfig(**payload).normalized()


def _validate_distributed_config(config: CrawlerConfig) -> CrawlerConfig:
    item = config.normalized()
    for name in item.request_headers:
        if str(name).strip().casefold() in _SENSITIVE_HEADERS:
            raise ValueError(
                "Distributed crawler does not persist credential-bearing request headers; "
                "inject approved secrets at the Worker boundary"
            )
    for proxy in item.proxies:
        parsed = urlsplit(proxy)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(
                "Distributed crawler does not persist credential-bearing proxy URLs; "
                "use worker-local secret indirection"
            )
    return item


def _namespace(crawl_id: str) -> str:
    value = str(crawl_id).strip()
    if not value or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("crawl_id is invalid")
    return f"crawl:{value}:"


def _url_identity(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="strict")).hexdigest()


def _bounded_page_payload(page: Mapping[str, Any], *, max_chars: int = 96_000) -> dict[str, Any]:
    """Keep one distributed result below the queue's bounded result envelope."""
    payload = dict(page)
    extracted = payload.get("extracted")
    if isinstance(extracted, Mapping):
        # Extraction output can contain arbitrarily large page data.  Preserve a
        # bounded JSON-safe projection and mark truncation instead of overflowing
        # the durable queue result limit.
        projected: dict[str, Any] = {}
        used = 0
        for key, value in list(extracted.items())[:256]:
            encoded = json.dumps(value, ensure_ascii=False, default=str)
            if used + len(encoded) > max_chars:
                payload.setdefault("quality_flags", []).append("distributed:extraction_truncated")
                break
            projected[str(key)[:256]] = value
            used += len(encoded)
        payload["extracted"] = projected
    return payload


def _fit_distributed_result(result: dict[str, Any], *, max_bytes: int = 220 * 1024) -> dict[str, Any]:
    """Shrink only optional discovery detail until the durable result fits safely."""
    payload = dict(result)
    deferred = list(payload.get("deferred_links") or [])
    while True:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) <= max_bytes:
            return payload
        if deferred:
            deferred = deferred[: max(0, len(deferred) // 2)]
            payload["deferred_links"] = deferred
            payload["deferred_links_truncated"] = True
            continue
        page = dict(payload.get("page") or {})
        if page.get("extracted"):
            page["extracted"] = {}
            page.setdefault("quality_flags", []).append("distributed:result_size_truncated")
            payload["page"] = page
            continue
        payload["warnings"] = list(payload.get("warnings") or [])[:8]
        if len(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")) <= max_bytes:
            return payload
        raise ArenyxaError(
            "DISTRIBUTED_CRAWL_RESULT_TOO_LARGE",
            "Distributed crawl result could not be bounded safely",
            domain="CRAWLER",
        )


class DistributedCrawlerCoordinator:
    """Durable global frontier implemented as idempotent Enterprise queue jobs."""

    def __init__(
        self,
        queue: DurableDistributedQueue,
        config: CrawlerConfig,
        *,
        crawl_id: str = "",
        policy: DistributedCrawlPolicy | None = None,
        resource_id: str = "",
        permission: str = "crawler.execute",
    ) -> None:
        self.queue = queue
        self.config = _validate_distributed_config(config)
        self.crawl_id = str(crawl_id).strip() or new_id("crawl")
        self.namespace = _namespace(self.crawl_id)
        self.policy = (policy or DistributedCrawlPolicy()).normalized()
        self.resource_id = str(resource_id).strip() or f"crawler:{self.crawl_id}"
        self.permission = str(permission).strip() or "crawler.execute"
        self._seed_hosts = {normalize_domain(urlsplit(url).hostname or "") for url in self.config.seeds}
        self._seed_hosts.discard("")

    def _payload(self, url: str, depth: int, parent_url: str) -> dict[str, Any]:
        return {
            "schema": DISTRIBUTED_CRAWL_SCHEMA,
            "crawl_id": self.crawl_id,
            "url": url,
            "depth": int(depth),
            "parent_url": str(parent_url),
            "config": self.config.snapshot(),
            "policy": asdict(self.policy),
            "resource_id": self.resource_id,
            "permission": self.permission,
        }

    def enqueue_url(self, url: str, *, depth: int = 0, parent_url: str = "") -> tuple[str | None, str]:
        target = canonicalize_url(str(url).strip())
        if not target:
            return None, "invalid"
        depth_value = int(depth)
        if depth_value < 0 or depth_value > self.config.max_depth:
            return None, "depth"
        if depth_value > 0 and not CrawlerEngine._in_scope(target, self.config, self._seed_hosts):
            return None, "scope"
        current = self.queue.count_jobs_by_idempotency_prefix(self.namespace)
        if current >= self.config.max_pages:
            return None, "max-pages"
        queued = self.queue.count_jobs_by_idempotency_prefix(self.namespace, state="queued")
        if queued >= self.policy.max_pending_jobs:
            return None, "backpressure"
        key = self.namespace + _url_identity(target)
        payload = self._payload(target, depth_value, parent_url)
        try:
            job_id = self.queue.enqueue(
                DISTRIBUTED_CRAWL_JOB_KIND,
                payload,
                resource_id=self.resource_id,
                permission=self.permission,
                idempotency_key=key,
                side_effect_mode="idempotent",
                max_attempts=self.policy.job_max_attempts,
                priority=max(-1000, self.policy.priority_base - depth_value),
                idempotency_prefix=self.namespace,
                idempotency_prefix_limit=self.config.max_pages,
            )
            return job_id, "enqueued"
        except ArenyxaError as exc:
            if exc.code == "DISTRIBUTED_IDEMPOTENCY_COLLISION":
                return None, "duplicate"
            if exc.code == "DISTRIBUTED_PREFIX_LIMIT":
                return None, "max-pages"
            raise

    def start(self) -> dict[str, Any]:
        states: dict[str, int] = {}
        jobs: list[str] = []
        for url in self.config.seeds:
            job_id, state = self.enqueue_url(url, depth=0)
            states[state] = states.get(state, 0) + 1
            if job_id:
                jobs.append(job_id)
        return {"crawl_id": self.crawl_id, "job_ids": jobs, "states": states, "snapshot": self.snapshot().to_dict()}

    def reconcile_completed(self, *, limit: int = 2000) -> dict[str, int]:
        """Requeue discovery deferred by backpressure or transient queue pressure."""
        counts: dict[str, int] = {}
        for row in self.queue.list_jobs_by_idempotency_prefix(self.namespace, state="completed", limit=limit):
            result = row.get("result") if isinstance(row.get("result"), Mapping) else {}
            parent = str((result or {}).get("final_url") or "")
            next_depth = int((result or {}).get("depth", -1)) + 1
            for link in list((result or {}).get("deferred_links") or [])[: self.policy.max_result_links]:
                _job, state = self.enqueue_url(str(link), depth=next_depth, parent_url=parent)
                counts[state] = counts.get(state, 0) + 1
                if state == "backpressure":
                    return counts
        return counts

    def snapshot(self) -> DistributedCrawlSnapshot:
        states = {
            name: self.queue.count_jobs_by_idempotency_prefix(self.namespace, state=name)
            for name in ("queued", "leased", "running", "completed", "failed", "review_required")
        }
        health = self.queue.health()
        storage = dict(health.get("storage") or {})
        deployment = dict(health.get("deployment_profile") or {})
        return DistributedCrawlSnapshot(
            crawl_id=self.crawl_id,
            jobs_total=self.queue.count_jobs_by_idempotency_prefix(self.namespace),
            queued=states["queued"], leased=states["leased"], running=states["running"],
            completed=states["completed"], failed=states["failed"], review_required=states["review_required"],
            storage_backend=str(storage.get("backend", "unknown")),
            multi_host_writers=bool(storage.get("multi_host_writers", False)),
            backpressure_active=states["queued"] >= self.policy.max_pending_jobs,
            postgresql_recommended=bool(deployment.get("postgresql_recommended", False)),
        )


class DistributedCrawlerWorker:
    """Executes one distributed crawl URL under Enterprise lease fencing."""

    def __init__(self, engine: CrawlerEngine, worker_id: str) -> None:
        self.engine = engine
        self.worker_id = str(worker_id).strip()
        if not self.worker_id:
            raise ValueError("worker_id is required")

    def install(self, runtime: Any) -> None:
        """Register this crawler worker with an EnterpriseWorkerRuntime instance."""
        register = getattr(runtime, "register_job_handler", None)
        if not callable(register):
            raise TypeError("runtime does not support distributed job handlers")
        register(DISTRIBUTED_CRAWL_JOB_KIND, self.execute_lease)

    def execute_lease(self, queue: DurableDistributedQueue, lease: DistributedLease) -> dict[str, Any]:
        if lease.worker_id != self.worker_id:
            raise ArenyxaError("DISTRIBUTED_LEASE_STALE", "Crawler lease belongs to another worker", domain="CRAWLER")
        if lease.kind != DISTRIBUTED_CRAWL_JOB_KIND:
            raise ArenyxaError("DISTRIBUTED_JOB_KIND_UNSUPPORTED", "Crawler worker cannot execute this job kind", domain="CRAWLER")
        payload = dict(lease.payload)
        if payload.get("schema") != DISTRIBUTED_CRAWL_SCHEMA:
            raise ArenyxaError("DISTRIBUTED_CRAWL_SCHEMA_INVALID", "Distributed crawler payload schema is invalid", domain="CRAWLER")
        config_raw = payload.get("config")
        if not isinstance(config_raw, Mapping):
            raise ArenyxaError("DISTRIBUTED_CRAWL_CONFIG_INVALID", "Distributed crawler config is missing", domain="CRAWLER")
        config = _validate_distributed_config(crawler_config_from_snapshot(config_raw))
        policy_raw = payload.get("policy") if isinstance(payload.get("policy"), Mapping) else {}
        policy = DistributedCrawlPolicy(**dict(policy_raw)).normalized()
        url = canonicalize_url(str(payload.get("url", "")))
        if not url:
            raise ArenyxaError("DISTRIBUTED_CRAWL_URL_INVALID", "Distributed crawler URL is invalid", domain="CRAWLER")
        depth = int(payload.get("depth", 0))
        parent = str(payload.get("parent_url", ""))
        crawl_id = str(payload.get("crawl_id", ""))
        namespace = _namespace(crawl_id)

        queue.start_job(lease.job_id, self.worker_id, lease.lease_token)
        try:
            unit = self.engine.fetch_one(config, url, depth=depth, parent_url=parent)
            queue.checkpoint(
                lease.job_id,
                self.worker_id,
                lease.lease_token,
                {
                    "schema": "arenyxa.distributed-crawl-checkpoint/v1",
                    "url": unit.page.final_url,
                    "depth": depth,
                    "status": unit.page.status,
                    "links_discovered": len(unit.links),
                    "robots_denied": unit.robots_denied,
                },
            )

            deferred: list[str] = []
            enqueued_children = 0
            if not unit.robots_denied and depth < config.max_depth and 200 <= unit.page.status < 400:
                seed_hosts = {normalize_domain(urlsplit(seed).hostname or "") for seed in config.seeds}
                seed_hosts.discard("")
                for link in unit.links[: policy.max_result_links]:
                    if not CrawlerEngine._in_scope(link, config, seed_hosts):
                        continue
                    queued = queue.count_jobs_by_idempotency_prefix(namespace, state="queued")
                    if queued >= policy.max_pending_jobs:
                        deferred.append(link)
                        continue
                    key = namespace + _url_identity(link)
                    child_payload = {
                        **payload,
                        "url": link,
                        "depth": depth + 1,
                        "parent_url": unit.page.final_url,
                    }
                    try:
                        queue.enqueue(
                            DISTRIBUTED_CRAWL_JOB_KIND,
                            child_payload,
                            resource_id=str(payload.get("resource_id") or lease.resource_id),
                            permission=str(payload.get("permission") or lease.permission),
                            idempotency_key=key,
                            side_effect_mode="idempotent",
                            max_attempts=policy.job_max_attempts,
                            priority=max(-1000, policy.priority_base - (depth + 1)),
                            idempotency_prefix=namespace,
                            idempotency_prefix_limit=config.max_pages,
                        )
                        enqueued_children += 1
                    except ArenyxaError as exc:
                        if exc.code in {"DISTRIBUTED_IDEMPOTENCY_COLLISION", "DISTRIBUTED_PREFIX_LIMIT"}:
                            continue
                        deferred.append(link)

            page_payload = _bounded_page_payload(unit.page.snapshot())
            result = {
                "schema": "arenyxa.distributed-crawl-result/v1",
                "crawl_id": crawl_id,
                "requested_url": unit.page.requested_url,
                "final_url": unit.page.final_url,
                "depth": depth,
                "status": unit.page.status,
                "page": page_payload,
                "links_discovered": len(unit.links),
                "children_enqueued": enqueued_children,
                "deferred_links": deferred[: policy.max_result_links],
                "robots_denied": unit.robots_denied,
                "warnings": list(unit.warnings)[:64],
            }
            result = _fit_distributed_result(result)
            queue.complete(lease.job_id, self.worker_id, lease.lease_token, result)
            return result
        except ArenyxaError as exc:
            if exc.code not in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
                try:
                    queue.fail(
                        lease.job_id, self.worker_id, lease.lease_token,
                        exc.code or "CRAWLER_WORKER_FAILED", retryable=bool(exc.retryable),
                    )
                except ArenyxaError as fail_exc:
                    LOGGER.warning(
                        "Distributed crawler could not persist ArenyxaError failure state for %s: %s",
                        lease.job_id, fail_exc,
                    )
            raise
        except (OSError, RuntimeError, ValueError, TypeError, TimeoutError) as exc:
            try:
                queue.fail(
                    lease.job_id, self.worker_id, lease.lease_token,
                    "CRAWLER_WORKER_EXECUTION_FAILED", retryable=True,
                )
            except ArenyxaError as fail_exc:
                LOGGER.warning(
                    "Distributed crawler could not persist worker failure state for %s: %s",
                    lease.job_id, fail_exc,
                )
            raise ArenyxaError(
                "CRAWLER_WORKER_EXECUTION_FAILED",
                f"Distributed crawler worker failed: {type(exc).__name__}: {exc}",
                domain="CRAWLER",
                retryable=True,
            ) from exc
