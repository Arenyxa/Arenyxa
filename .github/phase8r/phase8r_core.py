from __future__ import annotations

MAX_WORKERS_FROZEN = 4096
WORKERS = 64
WARM_RUNS = 60
EXPECTED_FINAL_WORKERS = (1 + WARM_RUNS) * WORKERS
EXPECTED_MARGIN = MAX_WORKERS_FROZEN - EXPECTED_FINAL_WORKERS


def expected_worker_registry_count(gate_ordinal: int) -> int:
    """Exact registry cardinality after gate ordinal on one fresh DB.

    gate_ordinal is 1 for retained first run, 2 for warm-001, ...
    Every gate invocation registers exactly WORKERS unique worker ids.
    """
    if gate_ordinal < 1:
        raise ValueError("gate_ordinal must be >= 1")
    return gate_ordinal * WORKERS


def assert_phase8r_worker_budget(*, warm_runs: int = WARM_RUNS, max_workers: int = MAX_WORKERS_FROZEN) -> dict[str, int]:
    if warm_runs != WARM_RUNS:
        raise RuntimeError(f"Phase8R warm-run contract changed: {warm_runs} != {WARM_RUNS}")
    total = (1 + warm_runs) * WORKERS
    margin = max_workers - total
    if max_workers != MAX_WORKERS_FROZEN:
        raise RuntimeError(f"MAX_WORKERS contract changed: {max_workers} != {MAX_WORKERS_FROZEN}")
    if total != EXPECTED_FINAL_WORKERS or margin != EXPECTED_MARGIN:
        raise RuntimeError("Phase8R worker budget arithmetic changed")
    if total >= max_workers:
        raise RuntimeError(f"Phase8R worker registry budget unsafe: {total} >= {max_workers}")
    return {"retained_first_plus_warm_gate_invocations": 1 + warm_runs,
            "expected_final_worker_count": total,
            "max_workers": max_workers,
            "margin_workers": margin}


def expected_pool_geometry() -> dict[str, int]:
    # 1 coordinator + 16 independent clients, all frozen at pool min/max 8.
    return {"instances": 17, "pool_min": 8, "pool_max": 8, "total_pool_size": 136}
