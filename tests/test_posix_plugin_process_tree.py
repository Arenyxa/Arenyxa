from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.plugins import PluginSandbox, SandboxBudget


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group sandbox contract")
def test_plugin_timeout_terminates_descendant_process_group(tmp_path: Path) -> None:
    plugin = tmp_path / "process-tree"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(
        json.dumps({
            "id": "process-tree",
            "name": "Process Tree",
            "version": "1.0.0",
            "entry": "plugin.py",
            "permissions": {"process": True},
        }),
        encoding="utf-8",
    )
    (plugin / "plugin.py").write_text(
        "import subprocess, sys, time\n"
        "def handle(request):\n"
        "    marker = request['marker']\n"
        "    code = \"import time, pathlib; time.sleep(0.8); pathlib.Path(%r).write_text('survived')\" % marker\n"
        "    subprocess.Popen([sys.executable, '-c', code])\n"
        "    time.sleep(5)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    marker = tmp_path / "descendant-survived.txt"
    with pytest.raises(ArenyxaError) as captured:
        PluginSandbox().invoke(
            plugin,
            {"marker": str(marker)},
            {"process": True},
            SandboxBudget(timeout_seconds=0.2, max_processes=2),
        )
    assert captured.value.code in {"PLUGIN_BUDGET_EXCEEDED", "PLUGIN_EXECUTION_FAILED"}
    time.sleep(1.0)
    assert not marker.exists(), "a descendant process survived the plugin sandbox timeout"
