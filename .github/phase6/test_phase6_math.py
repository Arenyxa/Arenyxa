from pathlib import Path
import pytest
from phase6_math import ledger, percentile
from phase6_trace import Recorder, clock_sites, verify
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[2]

def test_nested_health_is_not_double_counted():
    spans=[('checkout',1.,4.),('health',2.,3.),('health_probe',2.25,2.75),('execute',5.,9.),('facade',4.8,9.1),('fetch',9.2,9.5)]
    x=ledger(0.,10.,spans)
    assert sum(x.values())==pytest.approx(10000)
    assert x['checkout_other_ms']==pytest.approx(2000)
    assert x['health_other_ms']==pytest.approx(500)
    assert x['health_probe_ms']==pytest.approx(500)
    assert x['execute_ms']==pytest.approx(4000)
    assert x['facade_other_ms']==pytest.approx(300)

def test_empty_spans():
    x=ledger(1,1.5,[])
    assert x['unattributed_ms']==pytest.approx(500)

def test_reject_invalid_span():
    with pytest.raises(ValueError):ledger(1,2,[('execute',1.8,1.2)])

def test_frozen_percentile():
    assert percentile(list(range(1024)),.99)==1013
    assert percentile(list(range(1024)),.999)==1022

def test_clipping():
    x=ledger(1,2,[('execute',.9,1.5)])
    assert x['execute_ms']==pytest.approx(500)
    assert sum(x.values())==pytest.approx(1000)

def test_frozen_source_and_boundaries():
    assert len(verify(ROOT))==4
    sites=clock_sites(ROOT/'scripts/postgresql_32_worker_gate.py')
    assert sites['elapsed']>sites['operation_start']

def test_inherited_method_restore():
    class Parent:
        def value(self):return 1
    class Child(Parent):pass
    fake=SimpleNamespace(__file__=str(ROOT/'scripts/postgresql_32_worker_gate.py'))
    rec=Recorder(fake,None,None,None,True)
    rec.patch(Child,'value',lambda self:2)
    assert Child().value()==2
    rec.restore()
    assert Child().value()==1 and 'value' not in Child.__dict__
