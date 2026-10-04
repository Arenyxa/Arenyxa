import threading
import time
from types import SimpleNamespace

import pytest

from arenyxa.presentation import background
from arenyxa.presentation.pages.proxy import ProxyPage
from arenyxa.qt_compat.QtWidgets import QPushButton


@pytest.mark.parametrize('fails', [False, True])
def test_repeater_io_leaves_gui_thread_and_completes_on_gui(qapp, monkeypatch, fails):
    monkeypatch.setattr(background, '_SHUTTING_DOWN', False)
    gui_thread = threading.get_ident()
    release = threading.Event()
    started = threading.Event()
    worker_threads, callback_threads, outputs = [], [], []

    def repeat(*args):
        worker_threads.append(threading.get_ident())
        started.set()
        assert release.wait(2)
        if fails:
            raise OSError('controlled transport failure')
        return b'HTTP/1.1 200 OK'

    def show(text):
        callback_threads.append(threading.get_ident())
        outputs.append(text)

    page = SimpleNamespace(
        engine=SimpleNamespace(repeat_raw=repeat),
        repeater_scheme=SimpleNamespace(currentText=lambda: 'http'),
        repeater_host=SimpleNamespace(text=lambda: '127.0.0.1'),
        repeater_port=SimpleNamespace(value=lambda: 8080),
        repeater_request=SimpleNamespace(toPlainText=lambda: 'GET / HTTP/1.1'),
        repeater_response=SimpleNamespace(setPlainText=show),
        repeater_send=QPushButton(),
    )
    try:
        ProxyPage.send_repeater(page)
        assert started.wait(1) and not page.repeater_send.isEnabled()
        assert worker_threads[0] != gui_thread
    finally:
        release.set()
    deadline = time.monotonic() + 2
    while not outputs and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(0.005)
    assert callback_threads == [gui_thread]
    assert page.repeater_send.isEnabled()
    assert ('Request failed' if fails else '200 OK') in outputs[0]
    qapp.processEvents()
