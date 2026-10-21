"""공통 엔진: 입력 처리, 벤더 판별, 공통 분석 규칙, 집계.

벤더 파서의 parse() 가 돌려주는 공통 형식 덤프:

    system:    {host, model, machine_type, serial, uuid, power, location,
                collected(datetime UTC|None), clock}
    firmware:  [{name, component, role('active'|'primary'|'backup'|''), version, build,
                 date('YYYY/MM/DD' 또는 'YYYY-MM-DD')}]
    fru:       [{name, id, entity, present(bool), status}]
    events:    [{ts(datetime UTC), sev('E'|'W'|'I'), id, msg, kind('event'|'audit')}]
    sensors:   [{name, reading, unit, status, lcr, lnc, unc, ucr, discrete(bool)}]
    log_files, log_patterns: scan_syslogs() 결과
    files_used: [분석에 쓴 파일의 상대 경로]
    default_accounts: [공장 기본 관리자 계정 이름] (선택)
"""

import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from . import __version__, knowledge  # noqa: F401

SEV_ORDER = {"E": 0, "W": 1, "I": 2}
SEV_LABEL = {"E": "Error", "W": "Warning", "I": "Info"}
LEVEL_RANK = {"critical": 0, "warning": 1, "info": 2}


class ArchiveError(ValueError):
    """맨 바깥 압축 파일을 풀 수 없을 때."""


class UnsupportedDump(ValueError):
    pass


# ---------------------------------------------------------------- 유틸

def read_text(path):
    with open(path, "rb") as f:
        data = f.read()
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def split_cols(line):
    return re.split(r"\s{2,}", line.strip())


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def normalize_msg(msg):
    m = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", msg)
    m = re.sub(r"\b0x[0-9a-fA-F]+\b", "<hex>", m)
    m = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<hex>", m)
    return re.sub(r"\d+", "#", m)


def pattern_regex(pattern):
    """INPUT_FILES 패턴 → 정규식. '*' 는 경로 구분자를 넘지 않는다."""
    return re.compile("^" + re.escape(pattern).replace(r"\*", "[^/]*") + "$")


def is_safe_relpath(rel):
    parts = rel.split("/")
    return bool(rel) and not rel.startswith("/") and "\\" not in rel and ":" not in rel \
        and all(p not in ("", ".", "..") for p in parts)


# ---------------------------------------------------------------- 입력 처리

ARCHIVE_EXTS = (".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar", ".zip", ".tzz", ".lzo")
MAX_NESTED_ARCHIVE = 2 * 1024 ** 3  # 이보다 큰 안쪽 압축 파일은 풀지 않는다
MAX_NESTED_DEPTH = 2
# 제어 문자, Windows 에서 쓸 수 없는 문자, 깨진 인코딩이 들어간 이름
BAD_NAME_RE = re.compile(r'[\x00-\x1f<>:"|?*\\]|[\udc80-\udcff]')


def strip_archive_ext(name):
    low = name.lower()
    for ext in ARCHIVE_EXTS:
        if low.endswith(ext):
            return name[: -len(ext)]
    return name


def is_archive_name(name):
    return name.lower().endswith(ARCHIVE_EXTS)


def extract_archive(path):
    """압축을 임시 폴더 안의 '<원래 이름에서 확장자를 뺀 폴더>' 에 푼다.

    돌려주는 값은 그 임시 폴더(최상위)다. 정리는 호출한 쪽에서 한다.
    폴더 이름을 원래 이름으로 맞춰 두면, 압축 안에 상위 폴더가 없어도
    덤프 이름(수집 시각 포함)을 그대로 얻을 수 있다.
    """
    from . import oslog
    top = tempfile.mkdtemp(prefix="serverlog_")
    base = os.path.basename(path)
    dest = os.path.join(top, strip_archive_ext(base) or "dump")
    os.makedirs(dest)
    # sosreport 는 파일이 수만 개라 분석에 쓰는 것만 골라 푼다
    keep = oslog.SOS_KEEP if base.lower().startswith("sosreport") else None
    try:
        _extract_into(path, dest, keep)
    except Exception:
        shutil.rmtree(top, ignore_errors=True)
        raise
    return top


def _extract_into(path, dest, keep=None):
    """keep: 정규식. 주어지면 tar 안에서 이름이 맞는 파일만 푼다."""
    from . import lzop
    real = os.path.realpath(dest) + os.sep
    if lzop.is_lzop(path):
        # .tzz/.lzo: lzop 을 풀면 tar 가 나온다
        tar_path = dest + ".tar"
        lzop.decompress_file(path, tar_path)
        try:
            _extract_into(tar_path, dest)
        finally:
            os.remove(tar_path)
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for m in z.namelist():
                if not os.path.realpath(os.path.join(dest, m)).startswith(real):
                    raise ValueError("압축 파일에 안전하지 않은 경로가 있습니다: %s" % m)
            z.extractall(dest)
        return
    kw = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
    with tarfile.open(path) as t:
        for m in t:
            if m.issym() or m.islnk() or m.isdev() or BAD_NAME_RE.search(m.name):
                continue
            if keep is not None and not (m.isfile() and keep.match(m.name)):
                continue
            if not os.path.realpath(os.path.join(dest, m.name)).startswith(real):
                continue
            try:
                t.extract(m, dest, **kw)
            except (OSError, tarfile.TarError):
                # BMC 덤프에는 Windows 에서 만들 수 없는 이름 등이 섞여 있다. 분석과 무관하니 건너뛴다.
                continue


def _scan(path, temps, depth=0):
    """path 아래의 덤프 [(루트, 파서)] 를 찾는다. 안쪽 압축 파일도 임시 폴더에 풀어서 찾는다."""
    from . import vendors
    found, archives = [], []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        parser = vendors.detect(dirpath)
        if parser:
            found.append((dirpath, parser))
            dirnames[:] = []  # 덤프 안쪽은 더 내려가지 않는다
            continue
        if dirpath[len(path):].count(os.sep) >= 4:
            dirnames[:] = []
        archives += [os.path.join(dirpath, f) for f in sorted(filenames) if is_archive_name(f)]
    if depth < MAX_NESTED_DEPTH:
        for arc in archives:
            if os.path.getsize(arc) > MAX_NESTED_ARCHIVE:
                continue
            try:
                top = extract_archive(arc)
            except Exception:  # 지원하지 않거나 깨진 압축은 건너뛴다
                continue
            temps.append(top)
            found += _scan(top, temps, depth + 1)
    return found


class DumpSource:
    """폴더나 압축 파일에서 BMC 덤프와 OS 로그를 찾는다. with 블록이 끝나면 임시 폴더를 지운다.

        with DumpSource(path) as src:
            src.dumps        # [(루트, 파서), ...]
            src.os_sources   # oslog.find_sources() 결과
    """

    def __init__(self, path):
        self.path = path
        self.temps = []
        self.dumps = []
        self.os_sources = []

    def __enter__(self):
        from . import oslog
        base = self.path
        if os.path.isfile(base):
            if not is_archive_name(base) and oslog.sniff(base):
                # 압축이 아닌 OS 로그 파일 하나
                self.os_sources = [{"type": oslog.sniff(base), "path": base}]
                return self
            try:
                base = extract_archive(base)
            except Exception as e:
                raise ArchiveError("압축을 풀 수 없습니다: %s" % e)
            self.temps.append(base)
        self.dumps = _scan(base, self.temps)
        skip = [root for root, _ in self.dumps]
        for top in [base] + [t for t in self.temps if t != base]:
            self.os_sources += oslog.find_sources(top, skip)
        return self

    def __exit__(self, *exc):
        for t in self.temps:
            shutil.rmtree(t, ignore_errors=True)
        return False


def unsupported_message():
    from . import vendors
    names = ", ".join("%s %s" % (p["vendor"], p["name"]) for p in vendors.supported())
    return "지원하는 서버 로그를 찾지 못했습니다. 현재 지원: %s, Linux OS 로그(sosreport, messages·secure·syslog·kern.log, dmesg -T)" % names


# ---------------------------------------------------------------- 공용 파서

# "시각 호스트 프로세스[pid]: 메시지" 와 "시각[우선순위] 프로세스: 메시지" 를 모두 받는다
SYSLOG_RE = re.compile(
    r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(?:[+-]\d\d:\d\d|Z)?(?:\[\d+\])?\s+"
    r"(?:[^\s:]+\s+)?([\w\-./]+?)(?:\[\d+\])?:\s*(.*)$"
)
ERROR_KW_RE = re.compile(
    r"\[ERR\]|\b(error|errors|fail|failed|failure|fatal|panic|critical|"
    r"timeout|timed out|abort|aborted|segfault|exception|crash|corrupt\w*)\b",
    re.IGNORECASE,
)


def scan_syslogs(root, rel_files):
    """RFC3339 시각으로 시작하는 syslog 파일에서 오류 키워드가 있는 줄을 패턴별로 묶는다."""
    seen = set()
    files = []
    groups = {}
    for rel in rel_files:
        p = os.path.join(root, *rel.split("/"))
        if not os.path.isfile(p):
            continue
        n_lines = n_err = 0
        first = last = None
        for line in read_text(p).splitlines():
            m = SYSLOG_RE.match(line)
            if not m:
                continue
            n_lines += 1
            ts = m.group(1)
            first = first or ts
            last = ts
            if line in seen:  # preserved_logs 등 같은 내용의 사본은 한 번만 센다
                continue
            seen.add(line)
            proc, msg = m.group(2), m.group(3)
            if not ERROR_KW_RE.search(msg):
                continue
            n_err += 1
            key = (proc, normalize_msg(msg))
            g = groups.get(key)
            if g is None:
                g = groups[key] = {"proc": proc, "pattern": key[1], "count": 0,
                                   "first": ts, "last": ts, "sample": msg, "files": set()}
            g["count"] += 1
            g["first"] = min(g["first"], ts)
            g["last"] = max(g["last"], ts)
            g["files"].add(rel)
        files.append({"file": rel, "lines": n_lines, "errors": n_err,
                      "first": first, "last": last})
    pats = sorted(groups.values(), key=lambda g: -g["count"])
    for g in pats:
        g["files"] = sorted(g["files"])
    return files, pats


# ---------------------------------------------------------------- 분석

def group_events(events):
    groups = {}
    for ev in events:
        key = (ev["sev"], ev["id"], ev["msg"])
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"sev": ev["sev"], "id": ev["id"], "msg": ev["msg"],
                               "count": 0, "first": ev["ts"], "last": ev["ts"],
                               "days": Counter()}
        g["count"] += 1
        g["first"] = min(g["first"], ev["ts"])
        g["last"] = max(g["last"], ev["ts"])
        g["days"][ev["ts"].date()] += 1
    return sorted(groups.values(), key=lambda g: (SEV_ORDER.get(g["sev"], 9), -g["count"]))


def _parse_date(s):
    for fmt in ("%Y/%m/%d", "%Y-%m-%d", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def build_findings(ctx, vendor_kb):
    findings = []
    groups = ctx["groups"]

    def add(level, title, detail, msg_for_hint=None, evidence=None):
        why, action = knowledge.lookup(msg_for_hint, vendor_kb) if msg_for_hint else (None, None)
        findings.append({"level": level, "title": title, "detail": detail,
                         "why": why, "action": action, "evidence": evidence or []})

    ref = ctx["system"]["collected"] or ctx["ev_last"]

    def age_note(last):
        # 수집 시점보다 오래전에 끝난 문제는 지금도 유효한지 따로 확인해야 한다
        if not ref or not last:
            return []
        days = (ref - last).days
        if days < 90:
            return []
        when = "약 %.1f년" % (days / 365.25) if days >= 365 else "약 %d개월" % (days // 30)
        return ["마지막 발생이 수집 시점보다 %s 전입니다. 현재도 해당하는지 확인하세요." % when]

    for g in groups:
        span = "%s ~ %s" % (fmt_ts(g["first"]), fmt_ts(g["last"]))
        idline = "이벤트 ID: %s" % (g["id"] or "-")
        if g["sev"] == "E":
            add("critical", g["msg"], "Error 이벤트 %d건 (%s)" % (g["count"], span), g["msg"],
                [idline] + age_note(g["last"]))
        elif g["sev"] == "W" and g["count"] >= 5:
            peak_day, peak = g["days"].most_common(1)[0]
            ev = [idline, "발생 일수: %d일, 최다 발생일: %s (%d건)" % (len(g["days"]), peak_day, peak)]
            # 같은 대상의 "no longer ..." 복구 이벤트가 있으면 상태가 반복해서 바뀌는 것(flapping)
            subject = g["msg"].lower().split(" is ")[0]
            recover = [x for x in groups if "no longer" in x["msg"].lower() and subject in x["msg"].lower()]
            if recover:
                ev.append("복구 이벤트 %d건이 함께 발생 → 상태가 반복적으로 바뀌고 있음(flapping)"
                          % sum(x["count"] for x in recover))
            add("warning", "반복 경고: " + g["msg"], "Warning %d건 (%s)" % (g["count"], span), g["msg"],
                ev + age_note(g["last"]))
        elif g["sev"] == "W":
            add("info", g["msg"], "Warning %d건 (%s)" % (g["count"], span), g["msg"],
                [idline] + age_note(g["last"]))

    for g in groups:
        if g["sev"] == "I" and re.search(r"(Event Log|SEL) is full|log is full", g["msg"], re.I):
            add("warning", "이벤트 로그가 가득 참",
                "%d회 (마지막 %s)" % (g["count"], fmt_ts(g["last"])), g["msg"],
                ["분석한 이벤트 기간: %s ~ %s" % (fmt_ts(ctx["ev_first"]), fmt_ts(ctx["ev_last"]))])

    # 공장 기본 관리자 계정으로 원격 로그인 (비밀번호가 기본값이라는 뜻은 아님)
    defaults = set(ctx.get("default_accounts") or [])
    logins = [e for e in ctx["events"] if re.search(r"Login Successful", e["msg"], re.I)]
    used = [e for e in logins
            if any(u in defaults for u in re.findall(r"Login ID: (\S+)", e["msg"]))]
    if used:
        accts = sorted({u for e in used for u in re.findall(r"Login ID: (\S+)", e["msg"])})
        ips = sorted({ip for e in used for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", e["msg"])})
        ev = ["계정: " + ", ".join(accts)]
        if ips:
            ev.append("접속 IP: " + ", ".join(ips))
        add("info", "공장 기본 관리자 계정(%s)으로 원격 로그인" % ", ".join(accts),
            "%d회 (%s ~ %s)" % (len(used), fmt_ts(min(e["ts"] for e in used)),
                               fmt_ts(max(e["ts"] for e in used))),
            evidence=ev + ["로그인 기록만으로는 비밀번호가 기본값인지 알 수 없습니다. "
                           "누가 작업했는지 추적할 수 있도록 개인별 계정을 쓰는 것을 권장합니다."])

    # 펌웨어: Primary/Backup 불일치, 오래된 릴리스
    by_comp = defaultdict(dict)
    for f in ctx["firmware"]:
        by_comp[f["component"]][f["role"]] = f
    for comp, roles in by_comp.items():
        p, b = roles.get("primary"), roles.get("backup")
        if p and b and (p["version"], p["build"]) != (b["version"], b["build"]):
            add("warning", "%s Primary/Backup 펌웨어 불일치" % comp,
                "Primary %s (%s) / Backup %s (%s)" % (p["version"], p["build"], b["version"], b["build"]),
                evidence=["백업 뱅크로 전환되면 동작이 달라질 수 있습니다. 백업도 같은 버전으로 맞추세요."])
    fw_ref = ctx["system"]["collected"] or datetime.now(timezone.utc)
    for f in ctx["firmware"]:
        if f["role"] in ("primary", "backup"):
            continue
        d = _parse_date(f["date"])
        if d is None:
            continue
        years = (fw_ref - d).days / 365.25
        if years >= 3:
            add("info", "%s 펌웨어가 오래됨 (%.1f년)" % (f["name"], years),
                "버전 %s, 빌드 %s, 릴리스 %s" % (f["version"], f["build"], f["date"]),
                evidence=["벤더 지원 사이트에서 최신 펌웨어를 확인하세요."])

    # 센서 (임계치 센서만. discrete 센서는 상태가 비트마스크라 판단하지 않음)
    for s in ctx["sensors"]:
        if s.get("discrete"):
            continue
        st = s["status"].lower()
        if st not in ("ok", "na", ""):
            add("critical" if st in ("cr", "nr") else "warning", "센서 이상: %s" % s["name"],
                "현재값 %s %s, 상태 %s" % (s["reading"], s["unit"], s["status"]))
            continue
        val = to_float(s["reading"])
        if val is None:
            continue
        unc = to_float(s.get("unc"))
        if unc and s["unit"].startswith("degrees") and val >= unc * 0.9:
            add("info", "임계치에 가까운 온도: %s" % s["name"], "현재 %.0f℃ / 경고 임계치 %.0f℃" % (val, unc))
        low = to_float(s.get("lnc"))
        if low is None:
            low = to_float(s.get("lcr"))
        if low and low > 0 and val <= low * 1.1:
            add("info", "하한 임계치에 가까운 값: %s" % s["name"],
                "현재 %s %s / 하한 %s" % (s["reading"], s["unit"], low))

    psus = [f for f in ctx["fru"] if re.match(r"(power supply|psu)", f["name"], re.I)]
    absent = [f["name"] for f in psus if not f["present"]]
    if psus and absent:
        add("warning", "전원 공급 장치 부재", ", ".join(absent) + " 가 감지되지 않습니다.",
            evidence=["전원 이중화가 동작하지 않을 수 있습니다."])

    findings.sort(key=lambda f: LEVEL_RANK[f["level"]])
    return findings


def bucket_events(events):
    """타임라인 막대용 집계. 기간에 따라 일/주/월 단위를 고른다."""
    if not events:
        return "day", []
    first = min(e["ts"] for e in events).date()
    last = max(e["ts"] for e in events).date()
    span = (last - first).days
    if span <= 120:
        unit, key = "day", (lambda d: d)
        step = lambda d: d + timedelta(days=1)  # noqa: E731
    elif span <= 730:
        unit, key = "week", (lambda d: d - timedelta(days=d.weekday()))
        step = lambda d: d + timedelta(days=7)  # noqa: E731
    else:
        unit, key = "month", (lambda d: d.replace(day=1))
        step = lambda d: (d.replace(day=28) + timedelta(days=4)).replace(day=1)  # noqa: E731
    counts = defaultdict(Counter)
    for e in events:
        counts[key(e["ts"].date())][e["sev"]] += 1
    out = []
    d = key(first)
    while d <= last:
        nxt = step(d)
        c = counts.get(d, {})
        out.append({"start": d.isoformat(), "end": (nxt - timedelta(days=1)).isoformat(),
                    "E": c.get("E", 0), "W": c.get("W", 0), "I": c.get("I", 0)})
        d = nxt
    return unit, out


def parse_dump(root, parser, name=None):
    """BMC 덤프 하나를 읽어 공통 형식 + 이름·벤더 정보를 돌려준다."""
    name = name or os.path.basename(os.path.normpath(root))
    dump = parser.parse(root, name)
    dump.update({"name": name, "vendor": parser.VENDOR, "format": parser.NAME, "parser": parser.KEY,
                 "knowledge": getattr(parser, "KNOWLEDGE", [])})
    return dump


def _os_only_dump(osd):
    """BMC 덤프 없이 OS 로그만 있을 때의 공통 형식."""
    meta = osd["meta"]
    ref = meta.get("ref_local")
    return {
        "name": osd["host"] or osd["serial"] or "os-logs",
        "vendor": meta.get("manufacturer", ""),
        "format": "OS 로그" + (" (%s)" % meta["release"] if meta.get("release") else ""),
        "parser": "os", "knowledge": [],
        "system": {"host": osd["host"], "model": meta.get("product", ""), "machine_type": "",
                   "serial": osd["serial"], "uuid": "", "power": "", "location": "",
                   "collected": None, "clock": ref.strftime("%Y-%m-%d %H:%M:%S") + " (현지)" if ref else ""},
        "firmware": [], "fru": [], "events": [], "sensors": [], "log_files": [], "log_patterns": [],
        "files_used": [], "default_accounts": [],
        "_ref_local": ref,
    }


def build_ctx(dump, osd=None, pair_note="", tz_override=None):
    """BMC 덤프(없으면 OS 로그만)와 OS 로그를 합쳐 분석한다."""
    from . import flow, oslog
    ctx = dict(dump)
    bmc_events = list(dump["events"])
    os_events = []
    if osd:
        bmc_boot = [e["ts"] for e in bmc_events if flow.is_bmc_boot_marker(e)]
        offset, tz_src, tz_matches = oslog.resolve_tz(osd, bmc_boot, tz_override)
        os_events = oslog.to_events(osd, offset)
        lines = osd["lines"]
        meta = osd["meta"]
        ctx["os"] = {
            "host": osd["host"], "serial": osd["serial"], "release": meta.get("release", ""),
            "kernel": meta.get("kernel", ""), "product": meta.get("product", ""),
            "tz": oslog.fmt_offset(offset), "tz_offset": offset, "tz_source": tz_src, "tz_matches": tz_matches,
            "files": osd["files"], "pair_note": pair_note,
            "first_local": lines[0]["local"] if lines else None,
            "last_local": lines[-1]["local"] if lines else None,
            "n_lines": len(lines), "auto_logins": osd.get("auto_logins", []),
            "patterns": oslog.error_patterns(os_events),
            "boots": sorted([e for e in os_events if e.get("role") and e["role"][1] == "os_boot"],
                            key=lambda e: e["ts"], reverse=True),
        }
        if dump["system"].get("collected") is None and dump.get("_ref_local"):
            ctx["system"] = dict(dump["system"], collected=(dump["_ref_local"] - offset).replace(tzinfo=timezone.utc))
    events = sorted(bmc_events + os_events, key=lambda e: e["ts"], reverse=True)
    ctx.update({
        "events": events,
        # 개별 발견 사항 규칙은 BMC 이벤트에만 적용한다 (OS 는 흐름 분석과 OS 섹션에서 다룸)
        "groups": group_events([e for e in bmc_events if e["kind"] == "event" or e["sev"] != "I"]),
        "ev_first": min((e["ts"] for e in events), default=None),
        "ev_last": max((e["ts"] for e in events), default=None),
    })
    ctx["flow"] = flow.analyze_flow(events, ctx["system"]["collected"])
    event_findings = build_findings(ctx, dump.get("knowledge", []))
    flow.link_findings(event_findings, ctx["flow"])  # 각 이벤트 뒤에 무엇이 이어졌는지 덧붙임
    # 흐름 분석에서 나온 사건을 같은 등급 안에서 맨 앞에 둔다 (정렬은 안정 정렬)
    findings = flow.flow_findings(ctx["flow"]) + event_findings
    findings.sort(key=lambda f: LEVEL_RANK[f["level"]])
    ctx["findings"] = findings
    chart = [e for e in events if e["kind"] == "event"] or [e for e in os_events if e.get("role")]
    ctx["bucket_unit"], ctx["buckets"] = bucket_events(chart)
    return ctx


def analyze_dump(root, parser, name=None):
    """BMC 덤프 하나만 분석한다."""
    return build_ctx(parse_dump(root, parser, name))


def _pair(dumps, os_groups):
    """OS 로그 묶음을 시리얼·호스트 이름으로 BMC 덤프와 짝짓는다. [(dump, osd|None, 메모)]"""
    pairs = [[d, None, ""] for d in dumps]
    left = []
    for g in os_groups:
        hit = None
        for p in pairs:
            ds = p[0]["system"]
            if p[1] is None and g["serial"] and ds.get("serial") and g["serial"].upper() == ds["serial"].upper():
                hit, note = p, "시리얼 번호(%s)가 같아 짝지음" % g["serial"]
                break
        if hit is None:
            for p in pairs:
                ds = p[0]["system"]
                if p[1] is None and g["host"] and ds.get("host") and g["host"].upper() == ds["host"].upper():
                    hit, note = p, "호스트 이름(%s)이 같아 짝지음" % g["host"]
                    break
        if hit is not None:
            hit[1], hit[2] = g, note
        else:
            left.append(g)
    free = [p for p in pairs if p[1] is None]
    if len(free) == 1 and len(left) == 1:
        free[0][1] = left.pop()
        free[0][2] = "함께 올라온 BMC 덤프가 하나뿐이라 짝지음 (시리얼·호스트로는 확인 못 함)"
    return pairs, left


def analyze_all(path, tz_override=None):
    """폴더나 압축 파일 안의 BMC 덤프와 OS 로그를 서버별로 묶어 분석하고 [ctx, ...] 를 돌려준다."""
    from . import oslog
    with DumpSource(path) as src:
        if not src.dumps and not src.os_sources:
            raise UnsupportedDump(unsupported_message())
        # 파서가 필요한 내용을 모두 메모리로 읽으므로 이 블록이 끝나면 임시 폴더를 지워도 된다
        dumps = [parse_dump(root, parser) for root, parser in src.dumps]
        os_groups = oslog.load(src.os_sources) if src.os_sources else []
    if not dumps and not os_groups:
        raise UnsupportedDump(unsupported_message())
    pairs, left = _pair(dumps, os_groups)
    out = [build_ctx(d, g, note, tz_override) for d, g, note in pairs]
    out += [build_ctx(_os_only_dump(g), g, "", tz_override) for g in left]
    return out
