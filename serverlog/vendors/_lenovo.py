"""Lenovo/IBM 관리 컨트롤러(IMM2, XCC) 공통 파서.

두 세대 모두 tmp/service.txt, CEM 이벤트/감사 로그, ipmitool 형식 센서 덤프를 남긴다.
세대별 차이(파일 위치, 판별 조건)는 lenovo_imm2.py / lenovo_xcc.py 가 정한다.
"""

import gzip
import os
import re
from datetime import datetime, timedelta, timezone

from ..core import read_text, scan_syslogs, split_cols

CEM_SEV = {"1": "I", "2": "W", "3": "E"}
FQX_RE = re.compile(r"^FQX[A-Z]{2}[A-Z]{2}\d{4}[A-Z]$")

# 공장 기본 관리자 계정 이름
DEFAULT_ACCOUNTS = ["USERID"]


def p(root, rel):
    return os.path.join(root, *rel.split("/"))


def read_any(path):
    """.gz 이면 풀어서, 아니면 그대로 텍스트로 읽는다."""
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            data = f.read()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    return read_text(path)


def service_head(root):
    path = p(root, "tmp/service.txt")
    return read_text(path)[:4000] if os.path.isfile(path) else ""


# ---------------------------------------------------------------- service.txt

def parse_service_txt(path):
    info = {"system": {}, "datetime": "", "tz_offset": timedelta(0), "status": [],
            "firmware": [], "fru": [], "events": [], "vpd": {}}
    section = table = None
    for raw in read_text(path).splitlines():
        line = raw.rstrip()
        if not line:
            table = None
            continue
        if not raw.startswith((" ", "\t")):
            section = line.strip()
            table = None
            continue
        s = line.strip()
        if section == "System Information":
            if ":" in s:
                k, v = s.split(":", 1)
                info["system"][k.strip()] = v.strip()
        elif section == "Date Time Information":
            info["datetime"] = s
            m = re.search(r"(?:GMT|UTC)\s*([+-])(\d{1,2}):(\d\d)", s)
            if m:
                delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
                info["tz_offset"] = delta if m.group(1) == "+" else -delta
        elif section == "System Status":
            info["status"].append(s)
        elif section == "Vital Product Data":
            if set(s) <= set("- "):
                continue
            cols = split_cols(s)
            if cols[:2] == ["Type and Model", "Serial No"]:
                table = "vpd"
            elif cols[:2] == ["Type", "Version"]:
                table = "fw"
            elif cols[:2] == ["FRU Name", "FRU ID"]:
                table = "fru"
            elif table == "vpd" and len(cols) >= 2:
                info["vpd"] = {"type_model": cols[0], "serial": cols[1],
                               "uuid": cols[2] if len(cols) > 2 else ""}
            elif table == "fw" and len(cols) >= 2:
                cols += [""] * (4 - len(cols))
                info["firmware"].append(cols[:4])
            elif table == "fru" and len(cols) >= 4:
                info["fru"].append(cols[:4])
        elif section == "IMM Event Log":
            parts = s.split("\t")
            if len(parts) >= 4:
                try:
                    ts = datetime.strptime(parts[2].strip(), "%m/%d/%Y %H:%M:%S.%f")
                except ValueError:
                    continue
                info["events"].append({"local": ts, "sev": parts[1].strip()[:1],
                                       "msg": parts[3].strip()})
    for ev in info["events"]:
        ev["ts"] = (ev.pop("local") - info["tz_offset"]).replace(tzinfo=timezone.utc)
    return info


# ---------------------------------------------------------------- CEM / 센서

def parse_cem(path, kind):
    """CEM 이벤트/감사 로그 (세미콜론 구분, 2번째 필드가 epoch hex).

    XCC 는 Lenovo 메시지 ID(FQXSP...)를 뒤쪽 필드에 함께 남긴다. 있으면 그것을 ID 로 쓴다.
    """
    out = []
    for line in read_any(path).splitlines():
        f = line.split(";")
        if len(f) < 5:
            continue
        try:
            epoch = int(f[1].split(":")[0], 16)
        except ValueError:
            continue
        fqx = next((x for x in f[5:] if FQX_RE.match(x.strip())), "")
        out.append({
            "ts": datetime.fromtimestamp(epoch, tz=timezone.utc),
            "sev": CEM_SEV.get(f[0].strip(), "I"),
            "id": fqx.strip() or f[3].strip(),
            "msg": f[4].strip(),
            "kind": kind,
        })
    return out


def parse_sensors(path):
    """ipmitool 형식: 이름|값|단위|상태|LNR|LCR|LNC|UNC|UCR|UNR"""
    cols = ["name", "reading", "unit", "status", "lnr", "lcr", "lnc", "unc", "ucr", "unr"]
    out = []
    for line in read_text(path).splitlines():
        parts = [x.strip() for x in line.split("|")]
        if len(parts) < 10:
            continue
        row = dict(zip(cols, parts[:10]))
        if row["reading"] in ("na", ""):
            continue
        row["discrete"] = row["unit"] == "discrete"
        out.append(row)
    return out


def _norm(msg):
    return re.sub(r"\d+", "#", msg)


def merge_events(service_events, cem_events):
    """CEM(이벤트 ID 있음)과 service.txt 이벤트를 합치고 중복을 없앤다."""
    merged = {}
    known = {}  # 숫자를 지운 메시지 → (이벤트 ID, 종류)
    for ev in cem_events:
        merged[(int(ev["ts"].timestamp()), ev["msg"])] = dict(ev)
        known.setdefault(_norm(ev["msg"]), (ev["id"], ev["kind"]))
    for ev in service_events:
        sec = int(ev["ts"].timestamp())
        if any((sec + d, ev["msg"]) in merged for d in (0, -1, 1)):
            continue
        ev_id, kind = known.get(_norm(ev["msg"]), ("", ""))
        if not kind:
            kind = "audit" if re.search(r"\bLogin ID\b|logged off", ev["msg"]) else "event"
        merged[(sec, ev["msg"])] = {"ts": ev["ts"], "sev": ev["sev"], "id": ev_id,
                                    "msg": ev["msg"], "kind": kind}
    return list(merged.values())


# ---------------------------------------------------------------- 공통 형식으로 조립

def build_dump(root, name, cem_files, sensor_file, syslog_files, name_time):
    """cem_files: [(상대 경로, 'event'|'audit')], name_time: (정규식, strptime 형식)"""
    used = []

    def path(rel):
        full = p(root, rel)
        if os.path.isfile(full):
            used.append(rel)
            return full
        return None

    svc = {"system": {}, "datetime": "", "status": [], "firmware": [], "fru": [],
           "events": [], "vpd": {}, "tz_offset": timedelta(0)}
    sp = path("tmp/service.txt")
    if sp:
        svc = parse_service_txt(sp)

    cem = []
    for rel, kind in cem_files:
        cp = path(rel)
        if cp:
            cem += parse_cem(cp, kind)

    sp = path(sensor_file)
    sensors = parse_sensors(sp) if sp else []
    log_files, log_patterns = scan_syslogs(root, syslog_files)
    used += [f["file"] for f in log_files]

    events = merge_events(svc["events"], cem)

    collected = None
    rx, fmt = name_time
    m = re.search(rx, name or "")
    if m:
        collected = datetime.strptime("".join(m.groups()), fmt)
    elif svc["datetime"]:
        try:
            collected = datetime.strptime(svc["datetime"][:19], "%m/%d/%Y %H:%M:%S")
        except ValueError:
            pass
    if collected:
        collected = (collected - svc["tz_offset"]).replace(tzinfo=timezone.utc)

    model = bmc_host = ""
    for e in sorted(events, key=lambda x: x["ts"], reverse=True):  # 가장 최근 설정을 쓴다
        if not model:
            mm = re.search(r"The System System (.+?) encountered", e["msg"])
            model = mm.group(1) if mm else ""
        if not bmc_host:
            mm = re.search(r"HstName=([^,\s]+)", e["msg"])
            bmc_host = mm.group(1) if mm else ""
        if model and bmc_host:
            break

    firmware = []
    for typ, ver, build, date in svc["firmware"]:
        mm = re.match(r"(.+?)\((\w+)\)$", typ)
        firmware.append({"name": typ, "component": mm.group(1) if mm else typ,
                         "role": mm.group(2).lower() if mm else "",
                         "version": ver, "build": build, "date": date})

    sysinfo = svc["system"]
    vpd = svc["vpd"]
    return {
        "system": {
            # SystemName 이 비어 있으면 BMC 네트워크 설정의 호스트 이름을 쓴다
            "host": sysinfo.get("SystemName") or bmc_host,
            "model": model,
            "machine_type": vpd.get("type_model", ""),
            "serial": vpd.get("serial", ""),
            "uuid": vpd.get("uuid", ""),
            "power": " / ".join(svc["status"]),
            "location": " / ".join(x for x in (
                sysinfo.get("Location"),
                sysinfo.get("RackID") and "Rack " + sysinfo["RackID"],
                sysinfo.get("LowestU") not in (None, "", "0") and "U" + sysinfo["LowestU"]) if x),
            "collected": collected,
            "clock": svc["datetime"],
        },
        "firmware": firmware,
        "fru": [{"name": n, "id": i, "entity": e,
                 "present": st.upper() == "PRSENT", "status": st}
                for n, i, e, st in svc["fru"]],
        "events": events,
        "sensors": sensors,
        "log_files": log_files,
        "log_patterns": log_patterns,
        "files_used": used,
        "default_accounts": DEFAULT_ACCOUNTS,
    }
