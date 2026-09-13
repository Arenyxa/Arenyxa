from __future__ import annotations

import json
from pathlib import Path
import subprocess
import time
from typing import Any


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _proc_stat() -> dict[str, Any]:
    text=_read_text('/proc/stat') or ''
    out: dict[str,Any]={}
    for line in text.splitlines():
        parts=line.split()
        if not parts: continue
        if parts[0]=='cpu':
            keys=('user','nice','system','idle','iowait','irq','softirq','steal','guest','guest_nice')
            vals=[int(x) for x in parts[1:]]
            out['cpu']={k:(vals[i] if i<len(vals) else 0) for i,k in enumerate(keys)}
        elif parts[0] in {'ctxt','processes','procs_running','procs_blocked'} and len(parts)>1:
            out[parts[0]]=int(parts[1])
    return out


def _loadavg() -> dict[str,Any]:
    text=(_read_text('/proc/loadavg') or '').strip().split()
    if len(text)<4: return {}
    r,t=(text[3].split('/')+['0'])[:2]
    return {'load1':float(text[0]),'load5':float(text[1]),'load15':float(text[2]),
            'runnable':int(r),'threads':int(t),'last_pid':int(text[4]) if len(text)>4 else None}


def _selected_kv(path: str, keys: set[str]) -> dict[str,int|float]:
    text=_read_text(path) or ''
    out={}
    for line in text.splitlines():
        parts=line.replace(':',' ').split()
        if not parts or parts[0] not in keys or len(parts)<2: continue
        try: out[parts[0]]=int(parts[1])
        except ValueError:
            try: out[parts[0]]=float(parts[1])
            except ValueError: pass
    return out


def _psi(kind: str) -> dict[str,Any]:
    text=_read_text(f'/proc/pressure/{kind}') or ''
    out={}
    for line in text.splitlines():
        p=line.split()
        if not p: continue
        row={}
        for item in p[1:]:
            if '=' not in item: continue
            k,v=item.split('=',1)
            try: row[k]=float(v) if '.' in v else int(v)
            except ValueError: row[k]=v
        out[p[0]]=row
    return out


def _self_process() -> dict[str,Any]:
    try:
        import psutil
        p=psutil.Process()
        ct=p.cpu_times(); mi=p.memory_info(); cs=p.num_ctx_switches(); io=p.io_counters()
        return {'pid':p.pid,'cpu_user_s':ct.user,'cpu_system_s':ct.system,'rss':mi.rss,'vms':mi.vms,
                'threads':p.num_threads(),'vcsw':cs.voluntary,'ivcsw':cs.involuntary,
                'read_bytes':getattr(io,'read_bytes',None),'write_bytes':getattr(io,'write_bytes',None)}
    except Exception as exc:
        return {'error':type(exc).__name__}


def _parse_cgroup_file(path: Path) -> dict[str,Any]:
    text=_read_text(str(path))
    if text is None: return {}
    out={}
    for line in text.splitlines():
        p=line.split()
        if len(p)==2:
            try: out[p[0]]=int(p[1])
            except ValueError: out[p[0]]=p[1]
    return out


def _container_cgroup(container_name: str) -> dict[str,Any]:
    try:
        pid=int(subprocess.check_output(['docker','inspect','-f','{{.State.Pid}}',container_name],text=True,timeout=5).strip())
        cg=(_read_text(f'/proc/{pid}/cgroup') or '').splitlines()
        rel=None
        for line in cg:
            if line.startswith('0::'):
                rel=line[3:]; break
        if not rel:
            return {'pid':pid,'error':'cgroup_v2_path_unavailable'}
        base=Path('/sys/fs/cgroup')/rel.lstrip('/')
        cpu=_parse_cgroup_file(base/'cpu.stat')
        memstat=_parse_cgroup_file(base/'memory.stat')
        io_text=_read_text(str(base/'io.stat')) or ''
        io_tot={'rbytes':0,'wbytes':0,'rios':0,'wios':0,'dbytes':0,'dios':0}
        for line in io_text.splitlines():
            for kv in line.split()[1:]:
                if '=' not in kv: continue
                k,v=kv.split('=',1)
                if k in io_tot:
                    try: io_tot[k]+=int(v)
                    except ValueError: pass
        cur=_read_text(str(base/'memory.current')); peak=_read_text(str(base/'memory.peak'))
        pressure={}
        for k in ('cpu','memory','io'):
            txt=_read_text(str(base/f'{k}.pressure'))
            if txt is not None: pressure[k]=txt.strip()
        return {'pid':pid,'cgroup':rel,'cpu_stat':cpu,
                'memory_current':int(cur.strip()) if cur and cur.strip().isdigit() else None,
                'memory_peak':int(peak.strip()) if peak and peak.strip().isdigit() else None,
                'memory_stat':{k:memstat.get(k) for k in ('anon','file','kernel','pagetables','sock','shmem','pgfault','pgmajfault')},
                'io_stat':io_tot,'pressure_raw':pressure}
    except Exception as exc:
        return {'error':type(exc).__name__+':'+str(exc)[:160]}


def host_snapshot(container_name: str|None=None) -> dict[str,Any]:
    began=time.perf_counter()
    snap={'wall_ns':time.time_ns(),'perf_counter':began,
          'loadavg':_loadavg(),'proc_stat':_proc_stat(),
          'meminfo_kb':_selected_kv('/proc/meminfo',{'MemTotal','MemFree','MemAvailable','Buffers','Cached','SwapTotal','SwapFree','Dirty','Writeback','Committed_AS'}),
          'vmstat':_selected_kv('/proc/vmstat',{'pgfault','pgmajfault','pgpgin','pgpgout','pswpin','pswpout','nr_dirty','nr_writeback'}),
          'psi':{k:_psi(k) for k in ('cpu','memory','io')},
          'python_process':_self_process()}
    if container_name:
        snap['postgres_container']=_container_cgroup(container_name)
    snap['snapshot_duration_ms']=(time.perf_counter()-began)*1000.0
    return snap


def _one_json(cur, sql: str):
    row=cur.execute(sql).fetchone()
    if not row: return None
    value=row[0]
    if isinstance(value,str):
        try:return json.loads(value)
        except json.JSONDecodeError:return value
    return value


def pg_snapshot(dsn: str) -> dict[str,Any]:
    began=time.perf_counter()
    out: dict[str,Any]={'wall_ns':time.time_ns(),'perf_counter':began}
    try:
        import psycopg
        with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
            with conn.cursor() as cur:
                out['database']=_one_json(cur,"SELECT row_to_json(d)::text FROM pg_stat_database d WHERE datname=current_database()")
                out['wal']=_one_json(cur,"SELECT row_to_json(w)::text FROM pg_stat_wal w")
                out['bgwriter']=_one_json(cur,"SELECT row_to_json(b)::text FROM pg_stat_bgwriter b")
                out['tables']=[]
                for (payload,) in cur.execute("""
                    SELECT json_build_object(
                      'relid',relid,'schemaname',schemaname,'relname',relname,
                      'seq_scan',seq_scan,'idx_scan',idx_scan,
                      'n_tup_ins',n_tup_ins,'n_tup_upd',n_tup_upd,'n_tup_del',n_tup_del,
                      'n_live_tup',n_live_tup,'n_dead_tup',n_dead_tup,
                      'vacuum_count',vacuum_count,'autovacuum_count',autovacuum_count,
                      'analyze_count',analyze_count,'autoanalyze_count',autoanalyze_count,
                      'heap_bytes',pg_relation_size(relid),'total_bytes',pg_total_relation_size(relid)
                    )::text
                    FROM pg_stat_user_tables ORDER BY relid
                """).fetchall():
                    out['tables'].append(json.loads(payload))
                out['indexes']=[]
                for (payload,) in cur.execute("""
                    SELECT json_build_object(
                      'relid',relid,'indexrelid',indexrelid,'schemaname',schemaname,
                      'relname',relname,'indexrelname',indexrelname,
                      'idx_scan',idx_scan,'idx_tup_read',idx_tup_read,'idx_tup_fetch',idx_tup_fetch,
                      'index_bytes',pg_relation_size(indexrelid)
                    )::text
                    FROM pg_stat_user_indexes ORDER BY indexrelid
                """).fetchall():
                    out['indexes'].append(json.loads(payload))
                out['activity']=dict(cur.execute("""
                    SELECT COALESCE(state,'<null>'),count(*)
                    FROM pg_stat_activity WHERE datname=current_database()
                    GROUP BY COALESCE(state,'<null>') ORDER BY 1
                """).fetchall())
                try:
                    out['io']=[json.loads(r[0]) for r in cur.execute("SELECT row_to_json(i)::text FROM pg_stat_io i").fetchall()]
                except Exception as exc:
                    out['io_error']=type(exc).__name__
        out['ok']=True
    except Exception as exc:
        out['ok']=False;out['error']=type(exc).__name__+':'+str(exc)[:240]
    out['snapshot_duration_ms']=(time.perf_counter()-began)*1000.0
    return out


def combined_snapshot(*, dsn: str|None, container_name: str|None,
                      enable_os: bool, enable_pg: bool) -> dict[str,Any]:
    began=time.perf_counter();out={'wall_ns':time.time_ns(),'enable_os':enable_os,'enable_pg':enable_pg}
    if enable_os: out['host']=host_snapshot(container_name)
    if enable_pg and dsn: out['postgres']=pg_snapshot(dsn)
    out['snapshot_duration_ms']=(time.perf_counter()-began)*1000.0
    return out
