"""Lenovo XClarity Controller(XCC) 서비스 데이터 (ThinkSystem, ThinkAgile 등).

XCC 웹에서 내려받은 <type>_<serial>_xcc_<YYMMDD>-<HHMMSS>.tzz 는 tar 를 lzop 으로 압축한 것이다.
core 가 압축을 풀어 주므로 여기서는 풀린 폴더만 다룬다.
"""

import os
import re

from . import _lenovo

KEY = "lenovo_xcc"
VENDOR = "Lenovo"
NAME = "XCC 서비스 데이터"
PRODUCTS = "ThinkSystem / ThinkAgile (XCC)"
KNOWLEDGE = []

CEM_FILES = [
    ("var/volatile/log/cem_eventlog.last.gz", "event"), ("var/volatile/log/cem_eventlog", "event"),
    ("var/volatile/log/cem_auditlog.last.gz", "audit"), ("var/volatile/log/cem_auditlog", "audit"),
]
SENSOR_FILE = "tmp/ffdc_live_dbg/sensor.log"
SYSLOG_FILES = [
    "var/volatile/log/bmc-err.log",
    "var/volatile/log/kernel-err.log",
    "var/volatile/log/syshealth.log",
    "var/log/bmc_log_flush/bmc_log_error.log",
    "var/log/bmc_log_flush/bmc_log_warn.log",
    "tmp/bmc-warn.log",
]
# 분석에 쓰는 파일. '*.tzz' 는 폴더째 올릴 때 안에 든 XCC 압축 덤프를 함께 받기 위한 것.
INPUT_FILES = (["tmp/service.txt"] + [f for f, _ in CEM_FILES] + [SENSOR_FILE] + SYSLOG_FILES
               + ["*.tzz"])


def detect(root):
    """이 형식이면 양수(확신할수록 큼), 아니면 0."""
    head = _lenovo.service_head(root)
    score = 0
    if "Service Support Personnel" in head and "BMC(" in head:
        score += 10
    if os.path.isfile(_lenovo.p(root, "var/volatile/log/cem_eventlog")):
        score += 5
    if re.search(r"_xcc_\d{6}-\d{6}$", os.path.basename(os.path.normpath(root))):
        score += 2
    return score if score >= 5 else 0


def parse(root, name):
    return _lenovo.build_dump(root, name, CEM_FILES, SENSOR_FILE, SYSLOG_FILES,
                              (r"(\d{6})-(\d{6})$", "%y%m%d%H%M%S"))
