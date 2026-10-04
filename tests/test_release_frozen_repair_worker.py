from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows GUI executable process contract')
@pytest.mark.parametrize(('exit_code', 'relaunch'), [(0, False), (7, False), (0, True)])
def test_powershell_waits_for_windowed_repair_worker_and_propagates_exit(tmp_path: Path, exit_code: int, relaunch: bool):
    system = Path(os.environ['SystemRoot'])
    compiler = system / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    shell = system / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    if not compiler.is_file() or not shell.is_file():
        pytest.skip('Requires Windows PowerShell and the Windows .NET Framework compiler')
    install = tmp_path / 'candidate with spaces'
    data = tmp_path / 'test data with spaces'
    install.mkdir()
    data.mkdir()
    plan = data / 'repair plan.json'
    plan.write_text(json.dumps({'categories': ['settings_ui'], 'detected_findings': []}), encoding='utf-8')
    program = tmp_path / 'worker.cs'
    program.write_text('''
using System;
using System.IO;
using System.Threading;
using System.Diagnostics;
class Worker {
    static int Main(string[] args) {
        if (args[0] == "--hold-child") {
            DateTime deadline = DateTime.UtcNow.AddSeconds(15);
            while (!File.Exists(Path.Combine(args[1], "release-child.txt")) && DateTime.UtcNow < deadline)
                Thread.Sleep(50);
            File.WriteAllText(Path.Combine(args[1], "child-finished.txt"), "complete");
            return 0;
        }
        Thread.Sleep(3500);
        string folder = Path.GetDirectoryName(args[1]);
        File.WriteAllText(Path.Combine(folder, "worker-finished.txt"), "complete");
        if (RELAUNCH) {
            var start = new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName);
            start.Arguments = "--hold-child " + (char)34 + folder + (char)34;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            Process.Start(start);
        }
        return EXIT_CODE;
    }
}
'''.replace('EXIT_CODE', str(exit_code)).replace('RELAUNCH', str(relaunch).lower()), encoding='utf-8')
    compiled = subprocess.run(
        [str(compiler), '/nologo', '/target:winexe', '/out:' + str(install / 'Arenyxa.exe'), str(program)],
        capture_output=True, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    parent = subprocess.Popen([sys.executable, '-B', '-c', 'pass'])
    parent.wait(timeout=10)
    script = Path(__file__).resolve().parents[1] / 'src/arenyxa/resources/repair/repair_worker.ps1'
    result = subprocess.run(
        [str(shell), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
         '-File', str(script), '-InstallRoot', str(install), '-DataRoot', str(data),
         '-PlanPath', str(plan), '-WaitPid', str(parent.pid)],
        capture_output=True, timeout=30,
    )
    try:
        assert result.returncode == exit_code, result.stdout + result.stderr
        assert (data / 'worker-finished.txt').read_text() == 'complete'
        log = (data / 'repair/external-repair.log').read_text(encoding='utf-8-sig')
        if exit_code:
            assert 'exit code 7' in log
            assert 'Repair worker completed successfully.' not in log
        else:
            assert 'Repair worker completed successfully.' in log
        if relaunch:
            assert not (data / 'child-finished.txt').exists(), 'Repair terminal waited for the relaunched application'
    finally:
        (data / 'release-child.txt').write_text('release', encoding='utf-8')
