import ast
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]

from serverlog import flow

class IncidentTests(unittest.TestCase):
    def ev(self, minute, msg, sev='I'):
        return {"ts": datetime(2026, 10, 29, tzinfo=timezone.utc)+timedelta(minutes=minute),
                "sev": sev, "id": "demo", "msg": msg, "kind": "event"}
    def test_separate_reboots_inside_thirty_minutes(self):
        rows = [self.ev(0,'Host Power has been turned off'), self.ev(2,'Host Power has been turned on'),
                self.ev(10,'Host Power has been turned off'), self.ev(12,'Host Power has been turned on')]
        self.assertEqual(len(flow.analyze_flow(rows)['incidents']), 2)
    def test_related_down_events_without_boot_still_merge(self):
        rows = [self.ev(0,'Host Power has been turned off'), self.ev(1,'System was reset')]
        self.assertEqual(len(flow.analyze_flow(rows)['incidents']), 1)
    def test_thermal_fault_has_cause_and_recovery(self):
        rows = [self.ev(0,'CPU 1 OverTemp', 'E'), self.ev(1,'Host Power has been turned off'),
                self.ev(5,'Host Power has been turned on')]
        incident = flow.analyze_flow(rows)['incidents'][0]
        self.assertEqual(incident['kind'], 'fault'); self.assertEqual(incident['downtime'], 240)
    def test_no_evidence_is_not_fault(self):
        rows = [self.ev(0,'Host Power has been turned off'), self.ev(1,'Host Power has been turned on')]
        self.assertEqual(flow.analyze_flow(rows)['incidents'][0]['kind'], 'unexplained')


class CLITests(unittest.TestCase):
    def test_invalid_timezone_is_rejected(self):
        for value in ('+24:00', '+09:99'):
            p = subprocess.run([sys.executable, str(ROOT/'serverlog.py'), '--os-tz', value, '--formats'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(p.returncode, 2)
