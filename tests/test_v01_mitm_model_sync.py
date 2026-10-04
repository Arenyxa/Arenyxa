from dataclasses import replace

from arenyxa.infrastructure.capture.mitm_engine import MitmEvent
from arenyxa.presentation.pages.mitm_proxy import MitmEventModel
from arenyxa.qt_compat.QtCore import QPersistentModelIndex


def event(sequence):
    return MitmEvent(sequence, float(sequence), 'message', str(sequence), 'tcp', 'data')


def test_sliding_event_window_preserves_selected_event(qapp):
    model = MitmEventModel()
    resets = []
    model.modelReset.connect(lambda: resets.append(True))
    rows = [event(n) for n in range(1, 5)]
    model.sync(rows[:3])
    selected = QPersistentModelIndex(model.index(1, 0))
    model.sync(rows[1:])
    assert selected.isValid() and selected.row() == 0
    assert selected.data() == 2
    assert [row.sequence for row in model.rows] == [2, 3, 4]
    assert not resets


def test_filter_replacement_and_changed_event_are_visible(qapp):
    model = MitmEventModel()
    changed = []
    model.dataChanged.connect(lambda *args: changed.append(True))
    model.sync([event(1), event(2)])
    model.sync([replace(event(1), method='UPDATED'), event(2)])
    assert model.index(0, 3).data() == 'UPDATED' and changed
    model.sync([event(7)])
    assert model.rowCount() == 1 and model.index(0, 0).data() == 7
    model.sync([])
    assert model.rowCount() == 0
