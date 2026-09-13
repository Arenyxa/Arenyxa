from __future__ import annotations

import math
import random
import statistics
from typing import Iterable, Any


def quantile_nearest(values: Iterable[float], q: float) -> float | None:
    vals=sorted(float(x) for x in values)
    if not vals:
        return None
    if not 0 <= q <= 1:
        raise ValueError('q out of range')
    return vals[min(len(vals)-1,max(0,round((len(vals)-1)*q)))]


def distribution(values: Iterable[float]) -> dict[str, float|int|None]:
    vals=[float(x) for x in values]
    return {
        'count':len(vals),
        'mean':statistics.fmean(vals) if vals else None,
        'p50':quantile_nearest(vals,.50),
        'p95':quantile_nearest(vals,.95),
        'p99':quantile_nearest(vals,.99),
        'p999':quantile_nearest(vals,.999),
        'max':max(vals) if vals else None,
        'min':min(vals) if vals else None,
    }


def _mad(vals: list[float]) -> float | None:
    if not vals:
        return None
    m=statistics.median(vals)
    return statistics.median(abs(x-m) for x in vals)


def rolling_robust(values: Iterable[float], window: int=5) -> list[dict[str,float|int|None]]:
    vals=[float(x) for x in values]
    if window < 1:
        raise ValueError('window must be >=1')
    out=[]
    for i in range(len(vals)):
        lo=max(0,i-window+1); seg=vals[lo:i+1]
        out.append({'index':i+1,'window_start':lo+1,'count':len(seg),
                    'median':statistics.median(seg),'mad':_mad(seg)})
    return out


def _l1_cost(vals: list[float]) -> float:
    if not vals: return 0.0
    m=statistics.median(vals)
    return sum(abs(x-m) for x in vals)


def _best_split_no_perm(vals: list[float], min_segment: int) -> tuple[int|None,float,float]:
    base=_l1_cost(vals)
    if len(vals) < min_segment*2:
        return None,base,base
    best_k=None;best_cost=math.inf
    for k in range(min_segment,len(vals)-min_segment+1):
        c=_l1_cost(vals[:k])+_l1_cost(vals[k:])
        if c < best_cost:
            best_cost=c;best_k=k
    return best_k,base,best_cost


def best_l1_change_point(values: Iterable[float], *, min_segment: int=8,
                          permutations: int=1000, seed: int=20260913,
                          min_cost_reduction: float=.25,
                          meaningful_ratio_low: float=.80,
                          meaningful_ratio_high: float=1.25) -> dict[str,Any]:
    vals=[float(x) for x in values]
    k,base,best=_best_split_no_perm(vals,min_segment)
    if k is None:
        return {'split_index':None,'meaningful':False,'reason':'insufficient_samples'}
    pre=vals[:k];post=vals[k:]
    pre_m=statistics.median(pre);post_m=statistics.median(post)
    ratio=post_m/pre_m if pre_m else None
    reduction=(base-best)/base if base>0 else 0.0
    rng=random.Random(seed)
    exceed=0
    if permutations>0:
        for _ in range(permutations):
            p=vals[:];rng.shuffle(p)
            _,pb,pbest=_best_split_no_perm(p,min_segment)
            pred=(pb-pbest)/pb if pb>0 else 0.0
            if pred >= reduction-1e-15:
                exceed += 1
        pvalue=(exceed+1)/(permutations+1)
    else:
        pvalue=None
    if ratio is None:
        direction='unknown'
    elif ratio < 1:
        direction='slow_to_fast'
    elif ratio > 1:
        direction='fast_to_slow'
    else:
        direction='flat'
    ratio_effect=ratio is not None and (ratio <= meaningful_ratio_low or ratio >= meaningful_ratio_high)
    meaningful=bool(reduction >= min_cost_reduction and ratio_effect and (pvalue is None or pvalue <= .05))
    return {
        'split_index':k,
        'pre_n':len(pre),'post_n':len(post),
        'pre_median':pre_m,'post_median':post_m,
        'post_over_pre_median':ratio,
        'base_l1_cost':base,'split_l1_cost':best,
        'cost_reduction_fraction':reduction,
        'permutation_pvalue':pvalue,
        'permutations':permutations,
        'direction':direction,
        'meaningful':meaningful,
        'criteria':{
            'min_segment':min_segment,
            'min_cost_reduction':min_cost_reduction,
            'meaningful_ratio_low':meaningful_ratio_low,
            'meaningful_ratio_high':meaningful_ratio_high,
            'pvalue_max':.05,
        }
    }


def _paired_on_off_ratios(records: list[dict[str,Any]], key: str) -> list[float]:
    if len(records)%2:
        raise ValueError('calibration records must form adjacent pairs')
    ratios=[]
    for i in range(0,len(records),2):
        a,b=records[i],records[i+1]
        if {a['mode'],b['mode']} != {'OFF','ON'}:
            raise ValueError('each adjacent pair must contain one OFF and one ON')
        on=a if a['mode']=='ON' else b
        off=b if a['mode']=='ON' else a
        ov=float(on[key]);fv=float(off[key])
        ratios.append(ov/fv if fv else math.inf)
    return ratios


def paired_boundary_calibration(records: list[dict[str,Any]]) -> dict[str,Any]:
    if len(records) < 8 or len(records)%2:
        raise ValueError('need >=8 records in adjacent OFF/ON pairs')
    keys=('p50','p95','p99','p999','throughput','lease_p99','start_p99','complete_p99')
    rs={k:_paired_on_off_ratios(records,k) for k in keys}
    med={k:statistics.median(v) for k,v in rs.items()}
    primary_keys=('p50','p95','p99','throughput')
    primary_safe=all(.90 <= med[k] <= 1.10 for k in primary_keys)
    tail_keys=('p999','lease_p99','start_p99','complete_p99')
    tail_safe=all(.80 <= med[k] <= 1.20 for k in tail_keys)
    recovery_diffs=[]
    for i in range(0,len(records),2):
        a,b=records[i],records[i+1]
        on=a if a['mode']=='ON' else b;off=b if a['mode']=='ON' else a
        recovery_diffs.append(float(on['recovery_calls'])-float(off['recovery_calls']))
    recovery_median_abs=statistics.median(abs(x) for x in recovery_diffs)
    recovery_safe=recovery_median_abs <= 6.0
    return {
        'accepted':bool(primary_safe and tail_safe and recovery_safe),
        'pair_count':len(records)//2,
        'pair_ratios':rs,'median_ratios':med,
        'recovery_pair_differences':recovery_diffs,
        'recovery_median_absolute_difference':recovery_median_abs,
        'primary_safe':primary_safe,'tail_safe':tail_safe,'recovery_safe':recovery_safe,
        'limits':{
            'primary_two_sided_ratio':[.90,1.10],
            'tail_two_sided_ratio':[.80,1.20],
            'recovery_median_abs_delta_max':6.0,
        }
    }


def delta_counter(before: float|int|None, after: float|int|None) -> float|None:
    if before is None or after is None:
        return None
    a=float(after);b=float(before)
    if a < b:
        return None
    return a-b


def _cv(vals: list[float]) -> float:
    if not vals: return math.inf
    m=statistics.fmean(vals)
    if m == 0: return math.inf
    return statistics.pstdev(vals)/abs(m)


def classify_replication_axis(replicas: list[dict[str,Any]]) -> dict[str,Any]:
    axes={
        'run_index':[float(r['transition_run']) for r in replicas if r.get('transition_run') is not None],
        'elapsed_time':[float(r['transition_elapsed_s']) for r in replicas if r.get('transition_elapsed_s') is not None],
        'cumulative_jobs':[float(r['transition_cumulative_jobs']) for r in replicas if r.get('transition_cumulative_jobs') is not None],
    }
    cvs={k:_cv(v) if len(v)>=2 else math.inf for k,v in axes.items()}
    best=min(cvs,key=cvs.get) if any(math.isfinite(v) for v in cvs.values()) else None
    return {'axis_values':axes,'coefficient_of_variation':cvs,'most_stable_axis':best}
