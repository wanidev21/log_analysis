"""OS 로그 (Linux syslog, dmesg -T, sosreport) 읽기.

BMC 덤프와 같은 시간축(UTC)에 올려 흐름 분석에 쓰도록 이벤트로 바꾼다.

- syslog 형식: messages / secure / syslog / kern.log (+ 순환 파일, .gz) 와 이름이 달라도 내용이 syslog 인 파일
- dmesg -T 형식: "[Mon Jul 24 17:23:56 2023] ..." (syslog 가 없는 구간에만 쓴다)
- sosreport: 위 로그 + 호스트·시리얼·시간대·OS 버전 + last(부팅·세션 이력)

전통 syslog 에는 연도와 시간대가 없다. 연도는 수집 시점에서 거꾸로 따라가며 붙이고,
시간대는 sosreport 의 timedatectl → BMC 부팅 기록과의 정렬 → 이 PC 시간대 순으로 정한다.
"""

import gzip
import os
import re
from collections import Counter, OrderedDict
from datetime import date, datetime, timedelta, timezone

from .core import normalize_msg, read_text

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
DOW = {d: i for i, d in enumerate(["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])}

# 흐름 분석 역할 이름 (flow.py 와 같은 값)
from servercommon.osrules import (
    OUTCOME, CAUSE, RESOLVE, ACTION, BOOT, LOGIN,
    OS_RULES, OS_KEEP_EXTRA, CAT_LABEL, classify_line,
)

SYSLOG_CLASSIC = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$")
SYSLOG_RFC = re.compile(
    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?([+-]\d\d:\d\d|Z) (\S+) ([^:\[\s]+)(?:\[\d+\])?: ?(.*)$")
DMESG_T = re.compile(r"^\[(\w{3}) (\w{3}) +(\d{1,2}) (\d\d):(\d\d):(\d\d) (\d{4})\] ?(.*)$")
LAST_LINE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>system boot|\S+)\s+(?P<host>\S*)\s+"
    r"(?P<dow>Mon|Tue|Wed|Thu|Fri|Sat|Sun) (?P<mon>\w{3}) +(?P<day>\d{1,2}) (?P<h>\d\d):(?P<m>\d\d)\s+(?P<rest>.*)$")

# 웹 업로드에서 받는 OS 로그 파일 ('*' 는 경로 구분자를 넘지 않음, 경로 끝부분과 비교)
UPLOAD_PATTERNS = [
    "sosreport*.tar.xz", "sosreport*.tar.gz", "sosreport*.tar.bz2",
    "*messages*", "*secure*", "*syslog*", "*kern*log*", "*dmesg*",
    "sos_commands/systemd/timedatectl", "sos_commands/hardware/dmidecode", "sos_commands/general/hostname",
    "sos_commands/kernel/uname_-a", "sos_commands/last/last", "sos_commands/last/last_reboot",
    "etc/redhat-release", "etc/os-release", "etc/hostname", "version.txt",
]

AUTO_LOGIN_MIN = 50  # 분석 기간 안에 이보다 많이 반복된 (계정, 출발지) 접속은 자동화로 본다

OS_FILE_NAME = re.compile(r"(messages|syslog|kern\.?log|secure|auth\.log|dmesg)", re.I)
SOS_KEEP = re.compile(
    r"^[^/]+/(var/log/(messages|secure|syslog|kern\.log)[^/]*"
    r"|sos_commands/(systemd/timedatectl|hardware/dmidecode|general/hostname|kernel/uname_-a|last/last(_reboot)?)"
    r"|etc/(redhat-release|os-release|hostname)|version\.txt)$")

# ---------------------------------------------------------------- 파일 찾기

def _head(path, n=4096):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                return f.read(n).decode("latin-1")
        with open(path, "rb") as f:
            return f.read(n).decode("latin-1")
    except (OSError, EOFError):
        return ""


def sniff(path):
    """파일 앞부분으로 형식을 고른다: 'syslog' | 'dmesg_t' | None"""
    lines = [l for l in _head(path).splitlines()[:30] if l.strip()]
    if not lines:
        return None
    sys_hits = sum(1 for l in lines if SYSLOG_CLASSIC.match(l) or SYSLOG_RFC.match(l))
    dm_hits = sum(1 for l in lines if DMESG_T.match(l))
    if sys_hits >= max(2, len(lines) // 2):
        return "syslog"
    if dm_hits >= max(2, len(lines) // 2):
        return "dmesg_t"
    return None


def is_sosreport_dir(path):
    return os.path.isdir(os.path.join(path, "sos_commands")) and (
        os.path.isfile(os.path.join(path, "version.txt")) or os.path.basename(path).startswith("sosreport"))


def find_sources(root, skip_dirs=()):
    """root 아래의 OS 로그 출처: [{'type': 'sosreport'|'syslog'|'dmesg_t', 'path': ...}]"""
    skip = [os.path.normpath(d) for d in skip_dirs]
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        nd = os.path.normpath(dirpath)
        if any(nd == s or nd.startswith(s + os.sep) for s in skip):
            dirnames[:] = []
            continue
        if is_sosreport_dir(dirpath):
            out.append({"type": "sosreport", "path": dirpath})
            dirnames[:] = []
            continue
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            if not (OS_FILE_NAME.search(fn) or fn.lower().endswith((".log", ".txt"))):
                continue
            kind = sniff(p)
            if kind:
                out.append({"type": kind, "path": p})
    return out


# ---------------------------------------------------------------- 읽기

def _read(path):
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as f:
            data = f.read()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1")
    return read_text(path)


def _sos_meta(sos):
    def rd(rel):
        p = os.path.join(sos, *rel.split("/"))
        return read_text(p) if os.path.isfile(p) else ""
    meta = {"host": "", "serial": "", "product": "", "manufacturer": "", "release": "", "kernel": "",
            "tz_offset": None, "tz_name": "", "ref_local": None}
    meta["host"] = (rd("sos_commands/general/hostname") or rd("etc/hostname")).strip().split(".")[0]
    dmi = rd("sos_commands/hardware/dmidecode")
    m = re.search(r"System Information\s*\n(.*?)\n\s*\n", dmi, re.S)
    block = m.group(1) if m else dmi
    for key, field in (("serial", "Serial Number"), ("product", "Product Name"), ("manufacturer", "Manufacturer")):
        mm = re.search(r"%s:\s*(.+)" % field, block)
        if mm:
            meta[key] = mm.group(1).strip()
    rel = rd("etc/redhat-release").strip()
    if not rel:
        mm = re.search(r'PRETTY_NAME="([^"]+)"', rd("etc/os-release"))
        rel = mm.group(1) if mm else ""
    meta["release"] = rel
    mm = re.search(r"^Linux \S+ (\S+)", rd("sos_commands/kernel/uname_-a"))
    meta["kernel"] = mm.group(1) if mm else ""
    td = rd("sos_commands/systemd/timedatectl")
    mm = re.search(r"Time zone:\s*(\S+)\s*\(\S+,\s*([+-])(\d\d)(\d\d)\)", td)
    if mm:
        off = timedelta(hours=int(mm.group(3)), minutes=int(mm.group(4)))
        meta["tz_offset"] = off if mm.group(2) == "+" else -off
        meta["tz_name"] = mm.group(1)
    mm = re.search(r"Local time:\s*\w{3} (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", td)
    if mm:
        meta["ref_local"] = datetime.strptime(mm.group(1), "%Y-%m-%d %H:%M:%S")
    return meta


def _assign_years(entries, ref_local):
    """연도 없는 (월, 일, 시, 분, 초, ...) 들에 연도를 붙인다. entries 는 파일 안의 순서(오래된 → 최신)."""
    if not entries:
        return []
    year = ref_local.year
    out = [None] * len(entries)
    prev_month = None
    for i in range(len(entries) - 1, -1, -1):
        mon, day = entries[i][0], entries[i][1]
        if prev_month is None:
            # 마지막 줄이 수집 시점보다 (하루 넘게) 뒤라면 작년 기록이다
            try:
                if datetime(year, mon, day) > ref_local + timedelta(days=1):
                    year -= 1
            except ValueError:
                pass
        elif mon > prev_month:  # 거꾸로 가는데 월이 커지면 해가 바뀐 것
            year -= 1
        prev_month = mon
        out[i] = year
    return out


def _year_by_weekday(mon, day, dow, max_year):
    """요일이 맞는 가장 가까운 과거 연도 (last 출력처럼 요일은 있고 연도가 없을 때)."""
    for y in range(max_year, max_year - 12, -1):
        try:
            if date(y, mon, day).weekday() == dow:
                return y
        except ValueError:
            continue
    return max_year


def load(sources, ref_utc=None):
    """출처들을 읽어 호스트별 OsData 목록을 만든다. 시각은 아직 '현지 시각(naive)'."""
    groups = OrderedDict()

    def group_for(host, serial=""):
        key = (serial or "").upper() or (host or "").upper() or "?"
        for k, g in groups.items():
            if (serial and g["serial"].upper() == serial.upper()) or (host and g["host"].upper() == host.upper()):
                if host and not g["host"]:
                    g["host"] = host
                if serial and not g["serial"]:
                    g["serial"] = serial
                return g
        g = groups[key] = {"host": host or "", "serial": serial or "", "meta": {}, "files": [], "lines": [],
                           "boots_wtmp": [], "crash_sessions": []}
        return g

    sos_list = [s for s in sources if s["type"] == "sosreport"]
    files = [s for s in sources if s["type"] != "sosreport"]
    for s in sos_list:
        meta = _sos_meta(s["path"])
        g = group_for(meta["host"], meta["serial"])
        g["meta"] = meta
        logdir = os.path.join(s["path"], "var", "log")
        if os.path.isdir(logdir):
            for fn in sorted(os.listdir(logdir)):
                if re.match(r"(messages|secure|syslog|kern\.log)", fn):
                    files.append({"type": "syslog", "path": os.path.join(logdir, fn), "group": g,
                                  "label": "sosreport:var/log/" + fn})
        for rel in ("sos_commands/last/last_reboot", "sos_commands/last/last"):
            p = os.path.join(s["path"], *rel.split("/"))
            if os.path.isfile(p):
                files.append({"type": "last", "path": p, "group": g, "label": "sosreport:" + rel})

    ref_default = None
    if ref_utc:
        ref_default = ref_utc.replace(tzinfo=None) + timedelta(hours=14)  # 어느 시간대여도 미래가 되지 않게
    for f in files:
        f.setdefault("label", os.path.basename(f["path"]))

    # 파일별 호스트 추정: syslog 의 호스트 필드, 아니면 파일 이름에 든 호스트·시리얼
    for f in files:
        if "group" in f:
            continue
        host = ""
        if f["type"] == "syslog":
            hosts = Counter()
            for l in _head(f["path"], 65536).splitlines():
                m = SYSLOG_CLASSIC.match(l) or SYSLOG_RFC.match(l)
                if m:
                    hosts[m.group(6) if m.re is SYSLOG_CLASSIC else m.group(3)] += 1
            host = hosts.most_common(1)[0][0] if hosts else ""
        if host:
            f["group"] = group_for(host)
        else:
            name = os.path.basename(f["path"]).upper()
            f["group"] = next((g for g in groups.values()
                               if (g["host"] and g["host"].upper() in name) or
                               (g["serial"] and g["serial"].upper() in name)), None) or group_for("")

    for f in files:
        g = f["group"]
        ref = g["meta"].get("ref_local") or ref_default or datetime.fromtimestamp(os.path.getmtime(f["path"]))
        g["files"].append({"file": f["label"], "type": f["type"]})
        text = _read(f["path"])
        if f["type"] == "syslog":
            _parse_syslog(text, ref, f, g)
        elif f["type"] == "dmesg_t":
            _parse_dmesg(text, f, g)
        elif f["type"] == "last":
            _parse_last(text, ref, f, g)

    out = []
    for g in groups.values():
        if not g["lines"] and not g["boots_wtmp"]:
            continue
        out.append(_finish_group(g))
    return out


def _parse_syslog(text, ref, f, g):
    raw = []
    for line in text.splitlines():
        m = SYSLOG_CLASSIC.match(line)
        if m:
            raw.append(("c", m))
            continue
        m = SYSLOG_RFC.match(line)
        if m:
            raw.append(("r", m))
    years = _assign_years([(MONTHS.get(m.group(1), 1), int(m.group(2))) for t, m in raw if t == "c"], ref)
    yi = 0
    n = 0
    for t, m in raw:
        try:
            if t == "c":
                ts = datetime(years[yi], MONTHS.get(m.group(1), 1), int(m.group(2)),
                              int(m.group(3)), int(m.group(4)), int(m.group(5)))
                yi += 1
                host, proc, msg, utc = m.group(6), m.group(7), m.group(8), None
            else:
                aware = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
                off = m.group(2)
                delta = timedelta(0) if off == "Z" else timedelta(hours=int(off[1:3]), minutes=int(off[4:6]))
                delta = delta if off[:1] != "-" else -delta
                utc = (aware - delta).replace(tzinfo=timezone.utc)
                ts, host, proc, msg = aware, m.group(3), m.group(4), m.group(5)
        except (ValueError, IndexError):
            continue
        g["lines"].append({"local": ts, "utc": utc, "host": host, "proc": proc, "msg": msg,
                           "file": f["label"], "src": "syslog"})
        n += 1
    g["files"][-1]["lines"] = n


def _parse_dmesg(text, f, g):
    n = 0
    for line in text.splitlines():
        m = DMESG_T.match(line)
        if not m:
            continue
        try:
            ts = datetime(int(m.group(7)), MONTHS.get(m.group(2), 1), int(m.group(3)),
                          int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            continue
        g["lines"].append({"local": ts, "utc": None, "host": g["host"], "proc": "kernel", "msg": m.group(8),
                           "file": f["label"], "src": "dmesg"})
        n += 1
    g["files"][-1]["lines"] = n


def _parse_last(text, ref, f, g):
    year = ref.year
    prev = None
    n = 0
    for line in text.splitlines():
        m = LAST_LINE.match(line)
        if not m:
            continue
        mon = MONTHS.get(m.group("mon"))
        if not mon:
            continue
        day = int(m.group("day"))
        # last 는 최신 → 과거 순이므로 연도가 바뀌면 요일로 다시 맞춘다
        cand = _year_by_weekday(mon, day, DOW[m.group("dow")], year)
        if prev and datetime(cand, mon, day) > prev + timedelta(days=1):
            cand = _year_by_weekday(mon, day, DOW[m.group("dow")], cand - 1)
        year = cand
        try:
            ts = datetime(year, mon, day, int(m.group("h")), int(m.group("m")))
        except ValueError:
            continue
        prev = ts
        n += 1
        if m.group("user") == "reboot":
            g["boots_wtmp"].append(ts)
        elif "crash" in m.group("rest"):
            g["crash_sessions"].append({"start": ts, "user": m.group("user"), "from": m.group("host")})
    g["files"][-1]["lines"] = n


def _finish_group(g):
    # syslog 파일끼리(사본, sosreport 와 따로 받은 파일) 겹치는 줄을 없앤다
    seen = set()
    lines = []
    for l in sorted(g["lines"], key=lambda x: (x["local"], x["src"] != "syslog")):
        key = (l["local"], l["proc"], l["msg"])
        if key in seen:
            continue
        seen.add(key)
        lines.append(l)
    # dmesg 는 syslog 가 없는 구간에만 쓴다 (같은 커널 메시지가 시각만 조금 다르게 중복되므로)
    sys_ts = [l["local"] for l in lines if l["src"] == "syslog"]
    if sys_ts:
        lo, hi = sys_ts[0], sys_ts[-1]
        lines = [l for l in lines if l["src"] != "dmesg" or not (lo <= l["local"] <= hi + timedelta(minutes=5))]
    meta = g["meta"]
    return {"host": g["host"] or meta.get("host", ""), "serial": g["serial"] or meta.get("serial", ""),
            "meta": meta, "files": g["files"], "lines": lines,
            "boots_wtmp": sorted(set(g["boots_wtmp"])), "crash_sessions": g["crash_sessions"]}


# ---------------------------------------------------------------- 시간대와 이벤트화

def os_boot_times(osd):
    """현지 시각 기준 OS 부팅 시각들 (syslog 의 커널 부팅 줄 + wtmp)."""
    boots = [l["local"] for l in osd["lines"] if l["proc"] == "kernel" and l["msg"].startswith("Linux version")]
    for b in osd["boots_wtmp"]:
        if not any(abs((b - x).total_seconds()) <= 300 for x in boots):
            boots.append(b)
    return sorted(boots)


def resolve_tz(osd, bmc_boot_utc, override=None):
    """(UTC 와의 차이, 근거 문장, 일치한 부팅 수)"""
    boots = os_boot_times(osd)

    def matches(off):
        n = 0
        for b in boots:
            u = (b - off).replace(tzinfo=timezone.utc)
            if any(timedelta(0) <= u - t <= timedelta(minutes=10) for t in bmc_boot_utc):
                n += 1
        return n

    if override is not None:
        return override, "사용자 지정", matches(override)
    meta = osd["meta"]
    if meta.get("tz_offset") is not None:
        off = meta["tz_offset"]
        return off, "sosreport timedatectl (%s)" % meta.get("tz_name", ""), matches(off)
    if boots and bmc_boot_utc:
        scores = []
        for minutes in range(-720, 841, 30):
            off = timedelta(minutes=minutes)
            scores.append((matches(off), -abs(minutes - 540), off))  # 동점이면 KST 에 가까운 쪽
        scores.sort(reverse=True)
        best = scores[0]
        if best[0] >= 1 and (len(scores) < 2 or best[0] > scores[1][0] or best[0] >= 2):
            return best[2], "자동 추정 (BMC 부팅 기록과 OS 부팅 %d건이 맞음)" % best[0], best[0]
    local = datetime.now().astimezone().utcoffset() or timedelta(0)
    return local, "가정: 이 PC 시간대 (확인 필요)", matches(local)


def fmt_offset(off):
    total = int(off.total_seconds() // 60)
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return "UTC%s%02d:%02d" % (sign, total // 60, total % 60)


def to_events(osd, offset):
    """OS 줄들을 흐름 분석용 이벤트로 바꾼다 (역할이 있는 줄만)."""
    def utc(l):
        return l["utc"] or (l["local"] - offset).replace(tzinfo=timezone.utc)

    lines = osd["lines"]
    events = []
    shutdown_ts = []
    for l in lines:
        c = classify_line(l["proc"], l["msg"])
        if c is False:
            continue
        role, cat, sev = c
        if role == ACTION and cat == "os_shutdown":
            shutdown_ts.append(l["local"])
        events.append({"ts": utc(l), "sev": sev, "id": l["proc"], "msg": l["msg"], "kind": "os",
                       "role": (role, cat) if role else None, "file": l["file"], "local": l["local"]})

    # 같은 계정·출발지에서 수없이 반복되는 SSH 접속은 자동화(클러스터 노드 간 접속 등)로 보고 요약만 한다.
    # 드문 접속과 부팅 전후 1시간 안의 접속은 사람의 작업일 수 있으니 남긴다.
    def who(e):
        m = re.search(r"Accepted \S+ for (\S+) from (\S+)", e["msg"])
        return m.groups() if m else None
    logins = [e for e in events if e["role"] and e["role"][0] == LOGIN]
    freq = Counter(who(e) for e in logins)
    boot_local = [e["local"] for e in events if e["role"] and e["role"][1] == "os_boot"]
    auto = {k for k, n in freq.items() if n > AUTO_LOGIN_MIN}
    keep = []
    for e in events:
        if e["role"] and e["role"][0] == LOGIN and who(e) in auto and not any(
                abs((e["local"] - b).total_seconds()) <= 3600 for b in boot_local):
            continue
        keep.append(e)
    events = keep
    osd["auto_logins"] = sorted(((u, src, freq[(u, src)]) for u, src in auto), key=lambda x: -x[2])

    # 부팅마다 직전 OS 기록이 언제 끊겼는지, 정상 종료 절차가 있었는지 붙인다
    sys_lines = [l for l in lines if l["src"] in ("syslog", "dmesg")]
    boots = [e for e in events if e["role"] and e["role"][1] == "os_boot"]
    for b in boots:
        prev = [l for l in sys_lines if l["local"] < b["local"] - timedelta(seconds=5)]
        if not prev:
            continue
        last = prev[-1]["local"]
        if b["local"] - last > timedelta(days=60):
            continue  # 기록이 너무 오래 비어 있으면 판단하지 않는다
        b["prev_last"] = (last - offset).replace(tzinfo=timezone.utc)
        b["graceful"] = any(last - timedelta(minutes=15) <= t <= last for t in shutdown_ts)

    # wtmp(last) 에만 있는 부팅 (syslog 가 없는 과거 기간)
    for bt in osd["boots_wtmp"]:
        if any(abs((bt - e["local"]).total_seconds()) <= 300 for e in boots):
            continue
        crash = any(s["start"] < bt for s in osd["crash_sessions"]
                    if not any(s["start"] < x < bt for x in osd["boots_wtmp"] if x != bt))
        events.append({"ts": (bt - offset).replace(tzinfo=timezone.utc), "sev": "I", "id": "wtmp",
                       "msg": "OS 부팅 (last 기록)", "kind": "os", "role": (BOOT, "os_boot"),
                       "file": "last", "local": bt, "wtmp": True,
                       "graceful": False if crash else None})
    return events


def error_patterns(events):
    """OS 원인 후보 이벤트를 메시지 패턴별로 묶는다 (리포트 표용)."""
    groups = {}
    for e in events:
        if not e.get("role") or e["role"][0] != CAUSE:
            continue
        key = (e["id"], normalize_msg(e["msg"]))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"proc": e["id"], "pattern": key[1], "count": 0, "first": e["ts"], "last": e["ts"],
                               "sev": e["sev"], "cat": CAT_LABEL.get(e["role"][1], e["role"][1])}
        g["count"] += 1
        g["first"] = min(g["first"], e["ts"])
        g["last"] = max(g["last"], e["ts"])
    return sorted(groups.values(), key=lambda g: (g["sev"] != "E", -g["count"]))
