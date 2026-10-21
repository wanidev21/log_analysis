"""Lenovo/IBM IMM2 서비스 데이터 (System x, Flex System 등).

덤프 구조 예: <type>_<serial>_imm2_<YYYYMMDD>_<HHMMSS>/{tmp,var,etc,...}
"""

import os
import re

from . import _lenovo

KEY = "lenovo_imm2"
VENDOR = "Lenovo"
NAME = "IMM2 서비스 데이터"
PRODUCTS = "System x / Flex System (IMM2)"
KNOWLEDGE = []

CEM_FILES = [
    ("var/log/cem_eventlog.1", "event"), ("var/log/cem_eventlog", "event"),
    ("var/log/cem_auditlog.1", "audit"), ("var/log/cem_auditlog", "audit"),
]
SENSOR_FILE = "tmp/ffdc_live_dbg/sensor.log"
SYSLOG_FILES = [
    "tmp/system.log",
    "tmp/user.log",
    "var/log/bmc-error.log",
    "var/preserved_logs/bmc-error.log",
    "var/log/syshealth.log",
    "var/preserved_logs/syshealth.log",
]
# 분석에 쓰는 파일 (덤프 루트 기준, '*' 는 경로 구분자를 넘지 않는 와일드카드)
INPUT_FILES = ["tmp/service.txt"] + [f for f, _ in CEM_FILES] + [SENSOR_FILE] + SYSLOG_FILES


def detect(root):
    """이 형식이면 양수(확신할수록 큼), 아니면 0."""
    head = _lenovo.service_head(root)
    score = 0
    if "Service Support Personnel" in head and "IMM2(" in head:
        score += 10
    if os.path.isfile(_lenovo.p(root, "var/log/cem_eventlog")):
        score += 5
    if re.search(r"_imm2_\d{8}_\d{6}$", os.path.basename(os.path.normpath(root))):
        score += 2
    return score if score >= 5 else 0


def parse(root, name):
    return _lenovo.build_dump(root, name, CEM_FILES, SENSOR_FILE, SYSLOG_FILES,
                              (r"(\d{8})_(\d{6})$", "%Y%m%d%H%M%S"))
