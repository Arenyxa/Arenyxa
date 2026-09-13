from phase8r_core import (
    MAX_WORKERS_FROZEN, WORKERS, WARM_RUNS, EXPECTED_FINAL_WORKERS, EXPECTED_MARGIN,
    expected_worker_registry_count, assert_phase8r_worker_budget, expected_pool_geometry,
)


def test_frozen_horizon_is_admissible_below_worker_limit():
    x = assert_phase8r_worker_budget()
    assert WARM_RUNS == 60
    assert x["retained_first_plus_warm_gate_invocations"] == 61
    assert EXPECTED_FINAL_WORKERS == 3904
    assert EXPECTED_MARGIN == 192
    assert x["expected_final_worker_count"] < MAX_WORKERS_FROZEN


def test_worker_registry_progression_exact():
    assert expected_worker_registry_count(1) == 64
    assert expected_worker_registry_count(2) == 128
    assert expected_worker_registry_count(61) == 3904


def test_phase8_invalid_horizon_would_hit_limit():
    assert (1 + 63) * WORKERS == MAX_WORKERS_FROZEN
    assert (1 + 64) * WORKERS > MAX_WORKERS_FROZEN


def test_pool_geometry_frozen():
    assert expected_pool_geometry() == {"instances":17,"pool_min":8,"pool_max":8,"total_pool_size":136}
