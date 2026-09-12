"""Diagnostic arithmetic. Intervals are seconds; output is exclusive milliseconds."""
import math
import statistics

PRIORITY = (
    ('health_probe', 'health_probe_ms'), ('health', 'health_other_ms'),
    ('checkout', 'checkout_other_ms'), ('execute', 'execute_ms'),
    ('fetch', 'fetch_ms'), ('postprocess', 'postprocess_ms'),
    ('checkin', 'checkin_ms'), ('due', 'due_ms'),
    ('facade', 'facade_other_ms'),
)

def percentile(values, q):
    if not values:
        return None
    s = sorted(values)
    return float(s[min(len(s)-1, max(0, round((len(s)-1)*q)))])

def distribution(values):
    return dict(count=len(values), p50=percentile(values,.5), p95=percentile(values,.95),
                p99=percentile(values,.99), p999=percentile(values,.999),
                max=max(values) if values else None)

def ledger(begin, end, spans):
    if end < begin:
        raise ValueError('negative total interval')
    prepared=[]
    for kind, start, finish in spans:
        if finish < start:
            raise ValueError('negative child interval')
        start, finish = max(begin, start), min(end, finish)
        if finish > start:
            prepared.append((kind,start,finish))
    points=sorted({begin,end,*[t for _,a,b in prepared for t in (a,b)]})
    result={key:0.0 for _,key in PRIORITY};result['unattributed_ms']=0.0
    for start,finish in zip(points,points[1:]):
        covering={kind for kind,a,b in prepared if a <= start and b >= finish}
        key=next((key for kind,key in PRIORITY if kind in covering),'unattributed_ms')
        result[key]+=(finish-start)*1000.
    if not math.isclose(sum(result.values()),(end-begin)*1000.,abs_tol=1e-5):
        raise ValueError('ledger fails conservation')
    return result

def correlation(xs,ys):
    pairs=[(float(x),float(y)) for x,y in zip(xs,ys) if x is not None and y is not None]
    if len(pairs)<3:
        return None
    x,y=zip(*pairs)
    if statistics.pstdev(x)==0 or statistics.pstdev(y)==0:
        return None
    return statistics.correlation(x,y)
