import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import urlopen
from urllib.error import URLError
ROOT = Path(__file__).resolve().parents[1]
from servercommon.osrules import classify_line
from serverlog.oslog import classify_line as analyze_line

class StandaloneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='standalone tools ')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.log = ROOT
        self.install = ROOT

    def run_python(self, script, *args):
        return subprocess.run([sys.executable, '-E', str(script)]+list(args), cwd=str(self.work),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', timeout=20)


    def test_log_cli_and_launcher_help_outside_source(self):
        p = self.run_python(self.log/'serverlog.py', '--formats')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('lenovo_xcc', p.stdout)
        p = self.run_python(self.log/'launch_log_analyzer.py', '--help')
        self.assertEqual(p.returncode, 0, p.stderr)


    def test_shared_classification_stays_identical(self):
        self.assertIs(classify_line, analyze_line)
        self.assertEqual(classify_line('kernel','Kernel panic - not syncing'), ('cause','kernel','E'))


    def test_isolated_web_launcher_serves_its_own_reports(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        command = [sys.executable, '-E', str(self.log/'launch_log_analyzer.py'),
                   '--port', str(port), '--no-browser', '--no-idle-exit']
        process = subprocess.Popen(command, cwd=str(self.work), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            end = time.monotonic()+10
            ping = None
            while time.monotonic() < end:
                if process.poll() is not None:
                    out, err = process.communicate()
                    self.fail('web launcher exited: %r %r' % (out, err))
                try:
                    with urlopen('http://127.0.0.1:%d/api/ping' % port, timeout=0.5) as r:
                        ping = json.loads(r.read().decode('utf-8'))
                    break
                except (URLError, OSError):
                    time.sleep(0.05)
            self.assertIsNotNone(ping, 'web launcher startup timed out')
            self.assertEqual(ping['app'], 'serverlog_web')
            self.assertTrue((self.log/'reports').is_dir())
            self.assertFalse((self.work/'reports').exists())
        finally:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.communicate()
