import pytest
from phase8_core import (
    quantile_nearest, rolling_robust,
    best_l1_change_point, paired_boundary_calibration,
    delta_counter, classify_replication_axis,
)


def test_gate_quantile_nearest():
    xs=list(range(1,101))
    assert quantile_nearest(xs,.50)==51
    assert quantile_nearest(xs,.99)==99


def test_rolling_robust_median_mad():
    rows=rolling_robust([1,1,1,10,10], window=3)
    assert rows[2]['median']==1
    assert rows[2]['mad']==0
    assert rows[4]['median']==10


def test_change_point_finds_large_slow_to_fast_shift():
    xs=[700,710,690,705,695,715,700,708,420,410,430,415,425,405,418,422]
    cp=best_l1_change_point(xs,min_segment=6, permutations=300, seed=1)
    assert cp['split_index']==8
    assert cp['post_over_pre_median'] < .7
    assert cp['cost_reduction_fraction'] > .5
    assert cp['direction']=='slow_to_fast'


def test_change_point_rejects_flat_series():
    xs=[400,405,397,403,399,402,401,398,404,400,399,403,401,402,398,400]
    cp=best_l1_change_point(xs,min_segment=6, permutations=200, seed=2)
    assert cp['meaningful'] is False


def test_paired_calibration_is_direction_balanced_and_two_sided():
    recs=[]
    pair_specs=[('OFF',100),('ON',102),('ON',99),('OFF',100),('OFF',101),('ON',102),('ON',100),('OFF',101)]
    for mode,p99 in pair_specs:
        recs.append(dict(mode=mode,p50=100,p95=150,p99=p99,p999=p99*1.1,throughput=500,
                         lease_p99=p99*.6,start_p99=p99*.4,complete_p99=p99*.4,recovery_calls=2))
    v=paired_boundary_calibration(recs)
    assert v['accepted'] is True
    assert v['pair_count']==4


def test_paired_calibration_rejects_tail_or_recovery_perturbation():
    recs=[]
    specs=[('OFF',400,1),('ON',650,12),('ON',650,12),('OFF',400,1),
           ('OFF',400,1),('ON',650,12),('ON',650,12),('OFF',400,1)]
    for mode,p999,rec in specs:
        recs.append(dict(mode=mode,p50=100,p95=150,p99=200,p999=p999,throughput=500,
                         lease_p99=150,start_p99=100,complete_p99=100,recovery_calls=rec))
    v=paired_boundary_calibration(recs)
    assert v['accepted'] is False
    assert v['tail_safe'] is False or v['recovery_safe'] is False


def test_delta_counter_handles_reset():
    assert delta_counter(12,20)==8
    assert delta_counter(20,12) is None


def test_replication_axis_prefers_workload_when_run_index_stable_but_elapsed_not():
    reps=[
      {'transition_run':12,'transition_elapsed_s':100,'transition_cumulative_jobs':12288},
      {'transition_run':13,'transition_elapsed_s':145,'transition_cumulative_jobs':13312},
      {'transition_run':12,'transition_elapsed_s':80,'transition_cumulative_jobs':12288},
    ]
    c=classify_replication_axis(reps)
    assert c['most_stable_axis'] in {'run_index','cumulative_jobs'}
