"""Offline analyzer for Arenyxa P99 Phase 7 artifacts. No SQL/application code."""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import statistics
from typing import Any, Iterable


def pct(v: Iterable[float], q: float) -> float | None:
    xs = sorted(float(x) for x in v if x is not None and math.isfinite(float(x)))
    if not xs:
        return None
    return xs[min(len(xs)-1, max(0, int(round((len(xs)-1)*q))))]


def dist(v: Iterable[float]) -> dict[str, float | int | None]:
    xs = [float(x) for x in v if x is not None and math.isfinite(float(x))]
    if not xs:
        return {"n": 0, "mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {"n": len(xs), "mean": statistics.fmean(xs), "p50": pct(xs,.5),
            "p95": pct(xs,.95), "p99": pct(xs,.99), "max": max(xs)}


def corr(xs, ys):
    pairs=[(float(x),float(y)) for x,y in zip(xs,ys) if x is not None and y is not None]
    if len(pairs)<3:return None
    x=[p[0] for p in pairs];y=[p[1] for p in pairs]
    mx=statistics.fmean(x);my=statistics.fmean(y)
    num=sum((a-mx)*(b-my) for a,b in pairs)
    dx=sum((a-mx)**2 for a in x);dy=sum((b-my)**2 for b in y)
    return num/math.sqrt(dx*dy) if dx>0 and dy>0 else None


def sql_classes(row):
    return [x[0] for x in row.get("sql",[])]


def is_ordinary(row):
    c=sql_classes(row)
    return bool(row.get("success")) and not row.get("recovery_yes") and c.count("lease_fast")==1 and "other_business" not in c


def attr_record(row, run_no:int, run_p99:float) -> dict[str,Any] | None:
    p7=row.get("phase7_executes") or []
    if len(p7)!=1:return None
    x=p7[0]
    exchanges=x.get("exchanges") or []
    business=[e for e in exchanges if e.get("kind") in ("query_unprepared","query_prepared")]
    if len(business)!=1:return None
    be=business[0]
    send_ops=[s for s in (x.get("send_ops") or []) if s.get("kind") in ("query_unprepared","query_prepared")]
    if len(send_ops)!=1:return None
    so=send_ops[0]
    t0=x.get("t0");t1=so.get("begin");t2=be.get("flush_end");t3=be.get("first_driver_read_ready");t5=be.get("end");t6=x.get("t6")
    if any(t is None for t in (t0,t1,t2,t5,t6)):return None
    pre=(t1-t0)*1000;send=(t2-t1)*1000;prefull=(t5-t2)*1000;post=(t6-t5)*1000;total=(t6-t0)*1000
    first_wait=(t3-t2)*1000 if t3 is not None else None
    after_read=(t5-t3)*1000 if t3 is not None else None
    cons=(pre+send+prefull+post)-total
    extra_after=sum(1 for e in exchanges if e.get("begin") is not None and e.get("begin")>t5)
    prepare_ex=[e for e in exchanges if e.get("kind")=="prepare"]
    return {
        "run":run_no,"cycle_ms":float(row.get("cycle_ms",0)),"run_p99":run_p99,
        "run_gate":"FAIL" if run_p99>500 else "PASS","client":row.get("client_id"),"worker":row.get("worker"),
        "backend_pid":x.get("backend_pid"),"tid":x.get("native_tid"),"lease_ms":float(row.get("lease_ms",0)),
        "execute_wall_ms":float(row.get("ledger",{}).get("execute_ms",total)),"phase7_execute_ms":total,
        "pre_business_send_ms":pre,"business_send_ms":send,"send_to_full_result_ms":prefull,
        "full_result_to_return_ms":post,"driver_first_read_wait_ms":first_wait,
        "first_read_to_full_result_ms":after_read,"first_driver_read_ready_observed":t3 is not None,
        "read_ready_events":int(be.get("read_ready_events",0)),"write_ready_events":int(be.get("write_ready_events",0)),
        "thread_cpu_ms":x.get("thread_cpu_ms"),"thread_vcsw":x.get("thread_vcsw"),"thread_ivcsw":x.get("thread_ivcsw"),
        "sched_cpu_ms":x.get("sched_cpu_ms"),"sched_runqueue_ms":x.get("sched_runqueue_ms"),"sched_timeslices":x.get("sched_timeslices"),
        "health_probe_yes":bool(row.get("health_probe_yes")),"prepare_exchange_count":len(prepare_ex),
        "all_exchange_count":len(exchanges),"extra_exchanges_after_business":extra_after,
        "business_exchange_kind":be.get("kind"),"business_result_count":be.get("result_count"),
        "conservation_error_ms":cons,
    }


def group_summary(rows:list[dict[str,Any]]) -> dict[str,Any]:
    fields=("execute_wall_ms","phase7_execute_ms","pre_business_send_ms","business_send_ms","send_to_full_result_ms",
            "driver_first_read_wait_ms","first_read_to_full_result_ms","full_result_to_return_ms","thread_cpu_ms",
            "thread_vcsw","thread_ivcsw","sched_runqueue_ms","sched_timeslices")
    out={"n":len(rows),"first_read_observed_n":sum(bool(r["first_driver_read_ready_observed"]) for r in rows)}
    for f in fields:out[f]=dist(r.get(f) for r in rows)
    total=sum(r["phase7_execute_ms"] for r in rows)
    out["sum_shares"]={
        "pre_business_send":sum(r["pre_business_send_ms"] for r in rows)/total if total else None,
        "business_send":sum(r["business_send_ms"] for r in rows)/total if total else None,
        "send_to_full_result":sum(r["send_to_full_result_ms"] for r in rows)/total if total else None,
        "full_result_to_return":sum(r["full_result_to_return_ms"] for r in rows)/total if total else None,
        "sched_runqueue":(sum(r["sched_runqueue_ms"] for r in rows if r.get("sched_runqueue_ms") is not None)/total
                          if total and any(r.get("sched_runqueue_ms") is not None for r in rows) else None),
        "thread_cpu":(sum(r["thread_cpu_ms"] for r in rows if r.get("thread_cpu_ms") is not None)/total if total else None),
    }
    out["prepare_fraction"]=sum(r["prepare_exchange_count"]>0 for r in rows)/len(rows) if rows else None
    out["post_business_extra_exchange_fraction"]=sum(r["extra_exchanges_after_business"]>0 for r in rows)/len(rows) if rows else None
    out["max_abs_conservation_error_ms"]=max((abs(r["conservation_error_ms"]) for r in rows),default=None)
    return out


def write_csv(path:Path, rows:list[dict[str,Any]]):
    if not rows:return
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--in-dir",type=Path,required=True);ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    verdict=json.loads((args.in_dir/"verdict.json").read_text())
    calibrations=json.loads((args.in_dir/"calibrations.json").read_text())
    warm_files=sorted(args.in_dir.glob("warm-*.json"))
    rows=[]; recovery=[]; warm=[]
    coverage={"ordinary":0,"attributed":0,"bad_phase7_execute_count":0,"bad_business_exchange_count":0}
    for p in warm_files:
        payload=json.loads(p.read_text());run_no=int(p.stem.split("-")[-1]);off=payload["official"];trace=payload["trace"]
        run_p99=float(off["latency_ms"]["p99"]);warm.append({"run":run_no,"p99":run_p99,"throughput":off["throughput_jobs_per_second"],"gate":"FAIL" if run_p99>500 else "PASS"})
        for row in trace.get("cycles",[]):
            if row.get("recovery_yes"):
                rec=attr_record(row,run_no,run_p99)
                if rec: recovery.append(rec)
            if not is_ordinary(row):continue
            coverage["ordinary"]+=1
            if len(row.get("phase7_executes") or [])!=1:
                coverage["bad_phase7_execute_count"]+=1;continue
            rec=attr_record(row,run_no,run_p99)
            if rec is None:
                coverage["bad_business_exchange_count"]+=1;continue
            coverage["attributed"]+=1;rows.append(rec)
    rows.sort(key=lambda r:r["lease_ms"])
    leases=[r["lease_ms"] for r in rows]
    q50=pct(leases,.5);q99=pct(leases,.99);q999=pct(leases,.999)
    groups={
        "FAST": [r for r in rows if r["lease_ms"]<=q50],
        "MID": [r for r in rows if q50<r["lease_ms"]<=q99],
        "TOP1": [r for r in rows if r["lease_ms"]>q99],
        "TOP0.1": [r for r in rows if r["lease_ms"]>q999],
    }
    summaries={k:group_summary(v) for k,v in groups.items()}
    top100=sorted(rows,key=lambda r:r["lease_ms"],reverse=True)[:100]
    fast100=rows[:100]
    fail_top1=[r for r in groups["TOP1"] if r["run_gate"]=="FAIL"]
    pass_top1=[r for r in groups["TOP1"] if r["run_gate"]=="PASS"]
    health_top1=[r for r in groups["TOP1"] if r["health_probe_yes"]]
    nohealth_top1=[r for r in groups["TOP1"] if not r["health_probe_yes"]]
    controls={
        "FAST_vs_TOP1":{"FAST":summaries["FAST"],"TOP1":summaries["TOP1"]},
        "PASS_TOP1_vs_FAIL_TOP1":{"PASS_TOP1":group_summary(pass_top1),"FAIL_TOP1":group_summary(fail_top1)},
        "HEALTH_vs_NO_HEALTH_TOP1":{"HEALTH":group_summary(health_top1),"NO_HEALTH":group_summary(nohealth_top1)},
        "RECOVERY_CONTROL":group_summary(recovery),
    }
    correlations={
        "execute_vs_send_to_full":corr([r["phase7_execute_ms"] for r in rows],[r["send_to_full_result_ms"] for r in rows]),
        "execute_vs_post_result":corr([r["phase7_execute_ms"] for r in rows],[r["full_result_to_return_ms"] for r in rows]),
        "execute_vs_sched_runqueue":corr([r["phase7_execute_ms"] for r in rows],[r["sched_runqueue_ms"] for r in rows]),
        "execute_vs_thread_cpu":corr([r["phase7_execute_ms"] for r in rows],[r["thread_cpu_ms"] for r in rows]),
        "execute_vs_vcsw":corr([r["phase7_execute_ms"] for r in rows],[r["thread_vcsw"] for r in rows]),
    }
    top=summaries["TOP1"];shares=top["sum_shares"]
    if not rows:
        initial="D"
    elif shares["full_result_to_return"] is not None and shares["full_result_to_return"]>=.50:
        initial="B"
    elif shares["full_result_to_return"] is not None and shares["full_result_to_return"]<=.20:
        initial="A"
    else:
        initial="C"
    out={
        "verdict_capture":verdict,"calibrations":calibrations,"warm_runs":warm,
        "warm_failure_count":sum(r["gate"]=="FAIL" for r in warm),"coverage":coverage,
        "thresholds_ms":{"q50":q50,"q99":q99,"q999":q999},"groups":summaries,"controls":controls,
        "correlations":correlations,"initial_boundary_class":initial,
        "semantic_limits":{
            "T3_kernel_first_readable":"NOT DIRECTLY OBSERVABLE",
            "T3_driver_observed_read_ready":"MEASURED when wait_c returns read-ready to proxy",
            "T4_PQconsumeInput":"NOT DIRECTLY OBSERVABLE",
            "T5_full_results_collected":"MEASURED at psycopg generators.execute return",
            "T6_Connection_execute_return":"MEASURED",
        },
    }
    (args.out/"PHASE7_SUMMARY.json").write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding="utf-8")
    write_csv(args.out/"PHASE7_TOP100_SLOW.csv",top100);write_csv(args.out/"PHASE7_FAST100_CONTROL.csv",fast100)
    write_csv(args.out/"PHASE7_ALL_ATTRIBUTED.csv",rows)
    print(json.dumps({
        "capture_status":verdict.get("status"),"accepted_profile":verdict.get("accepted_profile"),
        "warm_runs":len(warm),"warm_failures":sum(r["gate"]=="FAIL" for r in warm),"coverage":coverage,
        "top1_n":top["n"],"top01_n":summaries["TOP0.1"]["n"],"top1_sum_shares":shares,
        "top1_first_read_coverage":[top["first_read_observed_n"],top["n"]],
        "initial_boundary_class":initial,"correlations":correlations,
        "max_conservation_error_ms":max((abs(r["conservation_error_ms"]) for r in rows),default=None),
    },ensure_ascii=False),flush=True)

if __name__=="__main__":main()
