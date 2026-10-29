"""흐름 분석: 이벤트들의 앞뒤 관계로 '무슨 일이 왜 일어났는지' 재구성한다.

1. 이벤트마다 역할을 붙인다 (결과 / 원인 후보 / 복구 / 사용자 조작 / 부팅 / BMC 재시작 / 로그 삭제).
2. 결과 이벤트(전원 꺼짐, 재시작, OS 장애, 사용자 재시작 요청)를 사건으로 묶고,
   직전 LOOKBACK 동안의 원인 후보·사용자 조작과, 다시 켜질 때까지의 과정을 붙인다.
3. 사건마다 '장애 추정 / 계획된 작업 / 원인 기록 없음' 을 판정하고 근거를 문장으로 남긴다.
4. 사건과 무관하게 지나간 경고 묶음(서비스 영향 없는 이상 구간)도 정리한다.

규칙은 특정 벤더 문구에 묶이지 않도록 일반적인 표현 위주로 둔다.
"""

import bisect
import re
from collections import Counter, OrderedDict
from datetime import timedelta

from .core import fmt_ts, normalize_msg

LOOKBACK = timedelta(minutes=60)       # 사건 직전 원인을 찾는 범위
POST_BOOT = timedelta(minutes=15)      # 다시 올라온 뒤 문제를 찾는 범위
LOGIN_LOOKBACK = timedelta(minutes=30)
MERGE_GAP = timedelta(minutes=30)      # 이 간격 안의 결과 이벤트는 한 사건으로 본다
CLUSTER_GAP = timedelta(minutes=30)    # 경고 묶음을 나누는 간격
AFTER_LIMIT = timedelta(days=90)       # 다시 켜지는 시점을 찾는 최대 범위
RESOLVE_LIMIT = timedelta(days=1)

OUTCOME, CAUSE, RESOLVE, ACTION, BOOT, BMC_RESTART, MARK, LOGIN = (
    "outcome", "cause", "resolve", "action", "boot", "bmc", "mark", "login")

# 원인 후보 분류. 위에서부터 먼저 맞는 것을 쓴다 ("CPU 1 OverTemp" 는 CPU 가 아니라 과열).
CAUSE_CATS = [
    ("thermal", "과열", re.compile(r"OverTemp|over.?temp|\bTemp\b|temperature|thermal|PROCHOT", re.I)),
    ("fan", "팬", re.compile(r"\bFan\b", re.I)),
    ("power", "전원", re.compile(r"Power Supply|\bPSU|lost input|Redundan|\bVol(t|tage)?\b|power (fault|resource|unit)|AC lost", re.I)),
    ("memory", "메모리", re.compile(r"DIMM|Memory|\bECC\b", re.I)),
    ("storage", "디스크", re.compile(r"\bDrive\b|\bDisk|\bRAID\b|\bArray\b|\bHDD|\bSSD|NVMe", re.I)),
    ("pcie", "PCIe", re.compile(r"\bPCI|bus error|SERR|PERR", re.I)),
    ("cpu", "CPU", re.compile(r"processor|\bCPU|IERR|CATERR|Machine Check|\bMCE\b|\bQPI|\bUPI", re.I)),
    ("fw", "펌웨어", re.compile(r"firmware|BIOS|UEFI|\bBMC\b|\bIMM|\bXCC", re.I)),
]
CAT_LABEL = dict((k, v) for k, v, _ in CAUSE_CATS)
CAT_LABEL.update({"other": "기타 경고", "kernel": "커널", "hw": "하드웨어(MCE)", "oom": "메모리 부족(OOM)",
                  "network": "네트워크", "app": "애플리케이션"})

CAT_VERDICT = {
    "thermal": "과열 보호 동작에 의한 차단으로 추정됩니다.",
    "fan": "팬 이상으로 냉각이 부족해져 보호 차단됐을 가능성이 있습니다.",
    "power": "전원 공급 이상과 관련된 중단으로 추정됩니다.",
    "memory": "메모리 오류에 따른 중단으로 추정됩니다.",
    "storage": "디스크 이상 뒤에 일어났습니다. OS 쪽 영향(부팅 디스크, 파일시스템)을 확인하세요.",
    "pcie": "PCIe 장치 오류에 따른 중단으로 추정됩니다.",
    "cpu": "CPU 이상에 따른 중단으로 추정됩니다.",
    "fw": "펌웨어 이상과 관련됐을 수 있습니다.",
    "other": "직전 경고와의 관련성을 확인하세요.",
    "kernel": "커널 장애(패닉·멈춤 등)에 따른 중단으로 추정됩니다.",
    "hw": "하드웨어 오류(Machine Check)에 따른 중단으로 추정됩니다.",
    "oom": "메모리 부족(OOM)에 따른 중단으로 추정됩니다.",
    "network": "네트워크 이상 뒤에 일어났습니다. 클러스터 노드라면 펜싱(fencing)에 의한 재시작인지 확인하세요.",
    "app": "애플리케이션(GPFS 등) 이상 뒤에 일어났습니다.",
}

OUTCOME_LABEL = {"power_off": "전원 꺼짐", "power_cycle": "전원 재투입", "reset": "재시작",
                 "os_fail": "OS 장애", "user_power": "재시작 요청", "os_down": "OS 중단", "os_reboot": "OS 재부팅"}
# 이 결과들은 '꺼졌다가 다시 켜지는' 구간을 만든다 (다시 켜지는 시점을 찾는다)
DOWN_OUTCOMES = ("power_off", "power_cycle", "os_fail", "os_down", "os_reboot")

R_LOG_CLEAR = re.compile(r"Event Log has been cleared|log (has been |was )?cleared", re.I)
R_USER_POWER = re.compile(
    r"(Reset|Restart|Shut ?Down|Power(ed)?[ -]?(Off|On|Cycle)|powered-?up).*"
    r"(by user (?!system)|pushbutton|power button|chassis control)|Attempting to .* by user", re.I)
R_BMC_RESET_USER = re.compile(r"Management Controller .*reset was initiated by user", re.I)
R_PHYSICAL = re.compile(r"Phy(sical)? Presence", re.I)
R_POWER_ON_ACTION = re.compile(r"powered-?up|Power(ed)? ?On", re.I)
R_EXPLICIT_ON = re.compile(r"Host Power has been turned on|powered-?up|powered on", re.I)
R_FW_UPDATE = re.compile(r"Flash of .* succeeded|firmware (update|flash)|update of .*firmware", re.I)
R_RESOLVE = re.compile(r"no longer|returned to|deasserted|\bdeassert|recovered|back to normal|"
                       r"transitioned to (OK|normal)", re.I)
OUTCOME_RULES = [
    ("power_cycle", re.compile(r"Power Cycled|power cycle", re.I)),
    ("power_off", re.compile(r"Host Power has been turned off|(server|system) was powered off|powered off", re.I)),
    ("reset", re.compile(r"(server|system) (was|is|has been) (\w+ )?(restarted|reset)|warm reset|cold reset", re.I)),
    ("os_fail", re.compile(r"watchdog|OS (Timeout|stop|hang)|blue screen|kernel panic|\bNMI\b|"
                           r"critical stop|operating system .*(fail|halt)", re.I)),
]
R_BOOT = re.compile(r"Host Power has been turned on|powered-?up|encountered firmware progress|system boot", re.I)
R_BMC_RESTART = re.compile(r"Management Controller .*(Network Initialization Complete|has been reset)", re.I)
R_LOGIN = re.compile(r"Remote Login Successful", re.I)
R_PSU_LOST = re.compile(r"Power Supply (\d+) has lost input", re.I)
R_PSU_BACK = re.compile(r"Power Supply (\d+) has returned to a Normal Input", re.I)


def cause_cat(msg):
    for key, _, rx in CAUSE_CATS:
        if rx.search(msg):
            return key
    return "other"


def classify(e):
    """(역할, 세부 분류) 또는 None(흐름과 무관)."""
    if e.get("kind") == "os":  # OS 이벤트는 oslog 가 읽을 때 이미 분류했다
        return e.get("role")
    m = e["msg"]
    if R_LOG_CLEAR.search(m):
        return MARK, "log_clear"
    if R_BMC_RESET_USER.search(m):
        return ACTION, "bmc_reset"
    if R_USER_POWER.search(m):
        # 전원 '켜기' 조작은 사건의 시작이 아니라 복구 과정이다
        return ACTION, "power_on" if R_POWER_ON_ACTION.search(m) else "user_power"
    if R_PHYSICAL.search(m) and not R_RESOLVE.search(m):
        return ACTION, "physical"
    if R_FW_UPDATE.search(m):
        return ACTION, "fw_update"
    if R_LOGIN.search(m):
        return LOGIN, "login"
    if R_RESOLVE.search(m):
        cat = cause_cat(m)
        return (RESOLVE, cat) if cat != "other" else None
    for key, rx in OUTCOME_RULES:
        if rx.search(m):
            return OUTCOME, key
    if R_BOOT.search(m):
        return BOOT, "boot"
    if R_BMC_RESTART.search(m):
        return BMC_RESTART, "bmc"
    if e["sev"] in ("E", "W"):
        return CAUSE, cause_cat(m)
    return None


def is_bmc_boot_marker(e):
    """OS 시간대 추정에 쓰는 BMC 쪽 '부팅이 시작된' 표시."""
    c = classify(e)
    return bool(c) and (c[0] == BOOT or (c[0] == OUTCOME and c[1] in ("reset", "power_cycle")))


# ---------------------------------------------------------------- 표시 도우미

def fmt_dur(sec):
    sec = int(abs(sec))
    if sec < 60:
        return "%d초" % sec
    if sec < 3600:
        return "%d분" % (sec // 60)
    if sec < 86400:
        h, m = divmod(sec // 60, 60)
        return "%d시간 %d분" % (h, m) if m else "%d시간" % h
    d, h = divmod(sec // 3600, 24)
    return "%d일 %d시간" % (d, h) if h and d < 7 else "%d일" % d


def fmt_rel(sec):
    if abs(sec) < 1:
        return "기준"
    return ("-" if sec < 0 else "+") + fmt_dur(sec)


def short(msg, n=70):
    return msg if len(msg) <= n else msg[: n - 1] + "…"


def subject(msg):
    """'Sensor CPU 1 OverTemp has transitioned to non-recoverable ...' → 'CPU 1 OverTemp (복구 불가)'"""
    msg = re.sub(r"^\[[A-Z]\]\s*(Event raised:\s*)?", "", msg)  # GPFS mmsysmon 접두어
    w = re.match(r"^WARNING: CPU: \d+ PID: \d+ at (\S+)", msg)
    if w:
        return "커널 WARNING (%s)" % w.group(1)
    m = re.match(r"^(?:Sensor\s+)?(.+?)\s+(?:has|is|was|have)\b", msg)
    # 'The node is not able to ...' 처럼 주어만으로는 뜻이 안 통하면 문장을 줄여 쓴다
    state = re.search(r"transitioned|asserted|lost input|Degraded|returned to|Configuration Mismatch", msg)
    subj = short(m.group(1), 48) if m and state else short(msg.rstrip("."), 60)
    if re.search(r"lost input", msg, re.I):
        subj += " 입력 상실"
    elif re.search(r"non-recoverable", msg, re.I):
        subj += " (복구 불가)"
    elif re.search(r"\bcritical\b", msg, re.I) and not re.search(r"non-critical", msg, re.I):
        subj += " (위험)"
    elif re.search(r"Degraded", msg, re.I):
        subj += " (성능 저하)"
    return subj


# ---------------------------------------------------------------- 분석

def analyze_flow(events, collected=None):
    ev = sorted(events, key=lambda e: e["ts"])
    if not ev:
        return {"incidents": [], "patterns": [], "notes": [], "summary": {}}
    ev = ev + _synthetic_os_outcomes(ev)
    ev.sort(key=lambda e: e["ts"])
    tagged = [(e, classify(e)) for e in ev]
    times = [e["ts"] for e in ev]

    def between(lo, hi, roles=None, lo_incl=True):
        i = bisect.bisect_left(times, lo) if lo_incl else bisect.bisect_right(times, lo)
        j = bisect.bisect_right(times, hi)
        return [(e, c) for e, c in tagged[i:j] if c and (roles is None or c[0] in roles)]

    # 1) 결과 이벤트(+사용자 재시작 요청)를 사건으로 묶는다
    explicit_on = any(R_EXPLICIT_ON.search(e["msg"]) for e in ev if e.get("kind") != "os")
    anchors = [(e, c) for e, c in tagged
               if c and (c[0] == OUTCOME or (c[0] == ACTION and c[1] == "user_power"))]
    episodes = []
    for e, c in anchors:
        previous = episodes[-1][-1][0]["ts"] if episodes else None
        boot_between = previous is not None and any(
            c0[0] == BOOT and previous < ev0["ts"] < e["ts"]
            for ev0, c0 in between(previous, e["ts"], roles={BOOT}))
        if episodes and e["ts"] - previous <= MERGE_GAP and not boot_between:
            episodes[-1].append((e, c))
        else:
            episodes.append([(e, c)])

    incidents = []
    covered = []  # 사건이 설명하는 시간 구간 (이상 구간 분석에서 제외)
    for idx, anc in enumerate(episodes):
        nxt_start = episodes[idx + 1][0][0]["ts"] if idx + 1 < len(episodes) else None
        incidents.append(_build_incident(anc, between, ev, nxt_start, explicit_on))
        # 재시작 직후 문제는 사건에 붙였으므로 그 구간까지 이상 구간 분석에서 뺀다
        covered.append((anc[0][0]["ts"] - LOOKBACK, max(anc[-1][0]["ts"], incidents[-1].get("post_until") or anc[-1][0]["ts"])))

    patterns = _patterns(tagged, covered, between, incidents)

    notes = []
    clears = [e for e, c in tagged if c and c[0] == MARK]
    if clears:
        notes.append("이벤트 로그가 %d회 삭제됐습니다 (처음 %s, 마지막 %s). 삭제 이전의 기록은 남아 있지 않아 "
                     "그 무렵의 흐름은 끊겨 있을 수 있습니다."
                     % (len(clears), fmt_ts(clears[0]["ts"]), fmt_ts(clears[-1]["ts"])))
    by_day = Counter(i["start"].date() for i in incidents)
    out_day = Counter(e["ts"].date() for e, c in anchors)
    clear_day = Counter(e["ts"].date() for e in clears)
    busy = sorted(d for d in set(by_day) | set(clear_day)
                  if by_day[d] >= 3 or out_day[d] >= 4 or (by_day[d] and clear_day[d] >= 2))
    if busy:
        notes.append("%s 에는 전원 사건이 몰려 있거나 로그 삭제가 겹칩니다 → 설치·점검 같은 작업 기간으로 보입니다. "
                     "이 기간의 '원인 기록 없음' 사건은 작업 중 조작일 가능성이 큽니다 (작업 이력으로 확인)."
                     % ", ".join(d.isoformat() for d in busy))
        for i in incidents:
            if i["start"].date() in busy:
                i["work_period"] = True
                if i["kind"] == "unexplained":
                    i["notes"].insert(0, "작업이 몰린 날의 사건입니다 → 작업 중 조작일 가능성이 큽니다.")
    notes.append("흐름 분석 기간: %s ~ %s (UTC). 이보다 앞선 일은 로그에 없습니다."
                 % (fmt_ts(ev[0]["ts"]), fmt_ts(ev[-1]["ts"])))

    kinds = Counter(i["kind"] for i in incidents)
    summary = {
        "incidents": len(incidents),
        "fault": kinds["fault"], "planned": kinds["planned"], "unexplained": kinds["unexplained"],
        "ac_loss": sum(1 for i in incidents if i["ac_loss"]),
        "downtime": sum(i["downtime"] or 0 for i in incidents),
        "patterns": len(patterns),
    }
    return {"incidents": incidents, "patterns": patterns, "notes": notes, "summary": summary}


def _synthetic_os_outcomes(ev):
    """OS 부팅마다 '그 전에 OS 가 멈춘 시점'을 결과 이벤트로 만든다.

    - syslog 로 확인되는 부팅: 직전 마지막 OS 기록 시각에 'OS 중단'
    - wtmp(last) 에만 있는 부팅: 앞 12시간 안에 BMC 결과 이벤트가 없을 때만 부팅 시각에 'OS 재부팅'
      (BMC 가 이미 전원 꺼짐 등을 남겼다면 그 사건의 복구 과정으로 본다)
    """
    out = []
    bmc_out = [e["ts"] for e in ev if e.get("kind") != "os" and (classify(e) or ("",))[0] == OUTCOME]
    for b in ev:
        if b.get("kind") != "os" or not b.get("role") or b["role"][1] != "os_boot":
            continue
        g = b.get("graceful")
        how = "정상 종료 절차 있음" if g else ("정상 종료 기록 없음" if g is False else "종료 방식 알 수 없음")
        if b.get("prev_last"):
            out.append({"ts": b["prev_last"], "sev": "I", "id": "OS", "kind": "os", "role": (OUTCOME, "os_down"),
                        "msg": "OS 기록 끊김 → %s 뒤 다시 부팅 (%s)" % (
                            fmt_dur((b["ts"] - b["prev_last"]).total_seconds()), how),
                        "graceful": g, "boot_ts": b["ts"]})
        elif b.get("wtmp") and not any(timedelta(0) <= b["ts"] - t <= timedelta(hours=12) for t in bmc_out):
            out.append({"ts": b["ts"] - timedelta(seconds=1), "sev": "I", "id": "wtmp", "kind": "os",
                        "role": (OUTCOME, "os_reboot"), "graceful": g, "boot_ts": b["ts"],
                        "msg": "OS 재부팅 (last 기록, BMC 전원 기록 없음 → 전원은 켜진 채 OS 만 재시작, %s)" % how})
    return out


def _build_incident(anc, between, ev, nxt_start, explicit_on):
    start, end = anc[0][0]["ts"], anc[-1][0]["ts"]
    before = between(start - LOOKBACK, start, lo_incl=True)
    before = [(e, c) for e, c in before if e["ts"] < start]
    during = between(start, end)

    causes = [(e, c) for e, c in before if c[0] == CAUSE]
    actions = [(e, c) for e, c in before + during if c[0] == ACTION]
    # OS 로그인은 자동 접속이 많아 판정에는 쓰지 않고 흐름표에만 보여준다
    logins = [(e, c) for e, c in before if c[0] == LOGIN and start - e["ts"] <= LOGIN_LOOKBACK
              and e.get("kind") != "os"]

    # 마지막 '꺼짐' 이후 다시 켜지는 시점과 그 사이의 일
    offs = [e for e, c in anc if c[0] == OUTCOME and c[1] in DOWN_OUTCOMES]
    off_ts = offs[-1]["ts"] if offs else end
    limit = min(off_ts + AFTER_LIMIT, nxt_start) if nxt_start else off_ts + AFTER_LIMIT
    after_all = [(e, c) for e, c in between(off_ts, limit) if e["ts"] > off_ts]
    # XCC 처럼 꺼진 직후에도 'firmware progress' 를 남기는 장비가 있어서,
    # 명시적인 '전원 켜짐' 기록이 있는 장비는 그것만 부팅으로 본다
    boot = next((e for e, c in after_all
                 if c[0] == BOOT and (c[1] == "os_boot" or not explicit_on or R_EXPLICIT_ON.search(e["msg"]))),
                None)
    os_boot = next((e for e, c in after_all if c[0] == BOOT and c[1] == "os_boot"), None)
    after_end = boot["ts"] if boot else (off_ts + timedelta(hours=1))
    after = [(e, c) for e, c in after_all if e["ts"] <= after_end]
    # AC 가 다시 들어오면 BMC 부팅과 서버 부팅이 거의 같이 일어나므로 부팅 뒤 10분까지 본다
    bmc_restart = next((e for e, c in after_all if c[0] == BMC_RESTART
                        and e["ts"] <= after_end + timedelta(minutes=10)), None)
    planned_bmc = any(c[1] in ("fw_update", "bmc_reset") for e, c in actions + after if c[0] == ACTION)
    ac_loss = bool(offs and bmc_restart and not planned_bmc)
    downtime = (boot["ts"] - off_ts).total_seconds() if (offs and boot) else None
    after_actions = [(e, c) for e, c in after if c[0] == ACTION]
    resolves = [(e, c) for e, c in after_all
                if c[0] == RESOLVE and c[1] in {cc[1] for _, cc in causes}
                and e["ts"] - off_ts <= RESOLVE_LIMIT]

    # 원인 후보 평가: 심각도와 결과까지의 시간 간격
    def strength(e):
        dt = (start - e["ts"]).total_seconds()
        if classify(e)[1] == "other":  # 무엇인지 모르는 경고는 원인으로 단정하지 않는다
            return 1
        if e["sev"] == "E":
            return 3 if dt <= 600 else 2
        return 3 if dt <= 120 else (2 if dt <= 600 else 1)

    best = None
    if causes:
        # 강도가 같으면 Error 를, 그다음엔 먼저 일어난 것(연쇄의 시작)을 원인으로 본다
        best = max(causes, key=lambda ec: (strength(ec[0]), ec[0]["sev"] == "E", -ec[0]["ts"].timestamp()))
    best_s = strength(best[0]) if best else 0
    real_actions = [(e, c) for e, c in actions if c[1] != "login"]

    os_downs = [e for e, c in anc if c[1] in ("os_down", "os_reboot")]
    abrupt = any(e.get("graceful") is False for e in os_downs)
    graceful = any(e.get("graceful") for e in os_downs)

    if best and (best_s >= 2 or not real_actions):
        kind = "fault"
        conf = {3: "높음", 2: "중간", 1: "낮음"}[best_s]
    elif real_actions:
        # 작업 흔적은 있지만 OS 정상 종료 기록이 없으면 강제 재부팅이라 확신을 낮춘다
        kind, conf = "planned", "중간" if abrupt else "높음"
    elif logins:
        kind, conf = "planned", "낮음"
    else:
        kind, conf = "unexplained", ""

    outcome_keys = [c[1] for e, c in anc]
    first_out = next((k for k in outcome_keys if k != "user_power"), outcome_keys[0])
    out_label = OUTCOME_LABEL[first_out]
    if len(anc) > 1:
        out_label += " 외 %d건" % (len(anc) - 1)

    notes = []
    if kind == "fault":
        be, bc = best
        dt = (start - be["ts"]).total_seconds()
        headline = "%s ← %s: %s" % (out_label, CAT_LABEL[bc[1]], subject(be["msg"]))
        verdict = "%s %s 뒤 %s. %s" % (
            short(be["msg"], 90), fmt_dur(dt), "전원이 꺼졌습니다" if offs else "시스템이 재시작됐습니다",
            CAT_VERDICT[bc[1]])
        others = Counter(normalize_msg(e["msg"]) for e, c in causes)
        sample = dict((normalize_msg(e["msg"]), e["msg"]) for e, c in causes)
        rep = [(sample[k], n) for k, n in others.items() if n >= 3]
        if rep:
            verdict += " 직전 %d분 동안 반복된 경고: %s." % (
                LOOKBACK.seconds // 60,
                ", ".join("'%s' %d회" % (short(m, 60), n) for m, n in sorted(rep, key=lambda x: -x[1])))
        if real_actions:
            notes.append("사용자 조작도 함께 기록돼 있습니다: %s" % _action_summary(real_actions))
    elif kind == "planned":
        if real_actions:
            headline = "%s ← 사용자 작업" % out_label
            verdict = "사용자 조작에 이어 일어난 것으로 보입니다: %s." % _action_summary(real_actions)
            if abrupt:
                headline = "%s ← 관리자 작업 중 강제 재시작" % out_label
                verdict += " 다만 OS 정상 종료 기록이 없어, 정상 종료 절차 없이 강제로 재시작한 것으로 보입니다."
        else:
            e = logins[-1][0]
            headline = "%s ← 사용자 접속 중" % out_label
            verdict = ("%s 전에 원격 로그인이 있었고 다른 이상 징후는 없습니다. 접속한 사용자가 종료했을 가능성이 "
                       "있습니다 (%s)." % (fmt_dur((start - e["ts"]).total_seconds()), short(e["msg"], 80)))
        if best:
            notes.append("직전에 경고도 있었습니다: %s (%s 전)."
                         % (short(best[0]["msg"], 80), fmt_dur((start - best[0]["ts"]).total_seconds())))
    elif ac_loss:
        headline = "%s — AC 전원 끊김 추정 (선행 이상 없음)" % out_label
        verdict = ("직전 %d분 안에 이상 징후도 사용자 조작 기록도 없이 꺼졌고, 그 뒤 BMC까지 새로 시작됐습니다. "
                   "서버로 들어오는 전원 자체가 끊긴 것으로 보입니다. 정전, 전원 케이블, 랙·PDU 작업 이력을 "
                   "확인하세요." % (LOOKBACK.seconds // 60))
    elif all(c[1] == "os_reboot" for e, c in anc):
        headline = "%s — 전원 유지된 채 OS만 재시작 (원인 기록 없음)" % out_label
        verdict = ("OS 부팅 이력(last)에는 재부팅이 있지만 BMC에는 전원 꺼짐 없이 POST만 남았습니다 → OS 안에서 "
                   "재부팅한 것(reboot 명령, 또는 커널 장애 뒤 자동 재시작)으로 보입니다. 이 시기의 OS 로그가 없어 "
                   "원인은 알 수 없습니다.")
    else:
        headline = "%s — 원인 기록 없음" % out_label
        verdict = ("직전 %d분 안에 이상 징후도, BMC에 기록된 사용자 조작도 없습니다. OS에서의 종료·재부팅, "
                   "전원 버튼, 외부 전원 차단 여부를 OS 로그와 작업 기록으로 확인하세요." % (LOOKBACK.seconds // 60))
        if downtime is not None and downtime <= 900 and not ac_loss:
            notes.append("%s 만에 다시 켜졌고 BMC는 계속 동작했습니다 → OS 재부팅이나 전원 버튼 조작일 가능성이 큽니다."
                         % fmt_dur(downtime))

    # OS 쪽 종료 방식과 다시 올라온 시점
    last_os = next((e for e in reversed(os_downs)), None)
    wtmp_only = bool(os_downs) and all(c[1] == "os_reboot" for e, c in anc)
    if graceful:
        notes.append("OS가 정상 종료 절차(서비스 중지, 로그 종료)를 거쳤습니다.")
    elif abrupt and wtmp_only:
        notes.append("부팅 직전 로그인 세션이 로그아웃 없이 끝났습니다(last 의 'crash') → 정상 종료 절차 없이 "
                     "재시작된 것으로 보입니다.")
    elif abrupt and last_os:
        notes.append("OS 정상 종료 기록 없이 로그가 끊겼습니다 (마지막 OS 기록 %s) → 강제 재부팅(reboot -f, 리셋), "
                     "OS 멈춤, 전원 차단 중 하나입니다." % fmt_ts(last_os["ts"]))
        bmc_reset = [e for e, c in anc if c[1] == "reset" and e.get("kind") != "os"]
        bmc_off = [e for e, c in anc if c[1] in ("power_off", "power_cycle") and e.get("kind") != "os"]
        if bmc_reset and not bmc_off:
            notes.append("BMC에는 전원이 꺼지지 않은 재시작(%s)으로 남았습니다 → 전원은 유지된 채 시스템만 리셋됐습니다."
                         % short(bmc_reset[0]["msg"], 50))
        elif not bmc_off and not bmc_reset:
            notes.append("BMC에는 전원 꺼짐·리셋 기록이 없습니다 → OS 안에서 강제로 재시작했을 가능성이 큽니다.")
    if os_boot and offs and not wtmp_only:  # 부팅 시각만 아는 경우 중단 시간은 알 수 없다
        down_from = offs[0]["ts"]
        notes.append("OS가 다시 올라온 시각: %s → 서비스 중단(OS 기준) 약 %s."
                     % (fmt_ts(os_boot["ts"]), fmt_dur((os_boot["ts"] - down_from).total_seconds())))
    post = []
    if os_boot or boot:
        b_ts = (os_boot or boot)["ts"]
        post = [(e, c) for e, c in between(b_ts, b_ts + POST_BOOT) if c[0] == CAUSE]
        if post:
            # 심각한 분류(커널·하드웨어)와 Error 를 먼저, 같은 문구는 한 번만
            rank = {"kernel": 0, "hw": 0, "memory": 1, "storage": 1, "thermal": 1}
            items = []
            for e, c in sorted(post, key=lambda ec: (rank.get(ec[1][1], 2), ec[0]["sev"] != "E", ec[0]["ts"])):
                txt = "%s: %s" % (CAT_LABEL.get(c[1], c[1]), subject(e["msg"]))
                if txt not in items:
                    items.append(txt)
            notes.append("다시 올라온 뒤 %d분 안에 문제가 있었습니다: %s%s." % (
                POST_BOOT.seconds // 60, "; ".join(items[:4]),
                " 외 %d건" % (len(items) - 4) if len(items) > 4 else ""))
        for e in ev:
            if b_ts <= e["ts"] <= b_ts + POST_BOOT:
                m = re.search(r"DUP_OF_DIR: .*oops-(\d{4}-\d\d-\d\d)", e["msg"])
                if m:
                    notes.append("abrt 기록: 같은 커널 경고가 %s에도 있었습니다 → 재시작 때마다 반복되는 알려진 증상일 수 "
                                 "있습니다." % m.group(1))
                    break

    mid = [e for e, c in during if c[0] == CAUSE]
    if mid:
        notes.append("사건 도중에도 오류·경고가 기록됐습니다: %s."
                     % ", ".join(sorted({"%s(%s)" % (subject(e["msg"]), e["sev"]) for e in mid})))
    if ac_loss and kind != "unexplained":
        notes.append("다시 켜지기 전에 BMC(관리 컨트롤러)도 새로 시작됐습니다 (%s) → 서버로 들어오는 AC 전원 자체가 "
                     "끊겼던 것으로 보입니다 (전원 케이블 분리, 정전, 랙 전원 작업 등)."
                     % fmt_ts(bmc_restart["ts"]))
    if offs and not wtmp_only:
        if downtime is not None:
            notes.append("다시 켜지기까지 %s 걸렸습니다 (%s)." % (fmt_dur(downtime), fmt_ts(boot["ts"])))
        elif nxt_start:
            notes.append("다음 사건(%s) 전까지 다시 켜진 기록이 없습니다. 그 사이 기록이 빠졌을 수 있습니다."
                         % fmt_ts(nxt_start))
        else:
            notes.append("이 뒤로 다시 켜진 기록이 없습니다.")
    for e, c in after_actions:
        if re.search(r"pushbutton|power button", e["msg"], re.I):
            notes.append("전원 버튼으로 켰습니다 (%s) → 현장에서 직접 조치한 것으로 보입니다." % fmt_ts(e["ts"]))
            break
    phys = [e for e, c in actions if c[1] == "physical"]
    if phys:
        notes.append("직전에 장비에서 직접 하는 조작(Physical Presence)이 있었습니다 → 현장 작업 중이었을 수 있습니다.")
    for e, c in resolves[:3]:
        notes.append("원인 후보가 복구됐습니다: %s (%s)." % (short(e["msg"], 70), fmt_ts(e["ts"])))
    if ev and ev[0]["ts"] >= start - timedelta(minutes=10):
        notes.append("로그 기록이 이 무렵부터 시작돼 그 이전 상황은 알 수 없습니다.")
    clears = [e for e, c in between(start - LOOKBACK, after_end, roles=(MARK,))]
    if clears:
        notes.append("이 무렵 이벤트 로그가 삭제됐습니다 (%s). 빠진 기록이 있을 수 있습니다." % fmt_ts(clears[0]["ts"]))

    chain = _chain(before + during + after + post, start)
    return {
        "start": start, "end": end, "kind": kind, "confidence": conf, "forced": abrupt and not wtmp_only,
        "post_until": ((os_boot or boot)["ts"] + POST_BOOT) if (os_boot or boot) else None,
        "headline": headline, "verdict": verdict, "notes": notes, "chain": chain,
        "cause_cat": best[1][1] if best else None, "downtime": downtime, "ac_loss": ac_loss,
        "cause_msg": best[0]["msg"] if best else None,
        "cause_gap": (start - best[0]["ts"]).total_seconds() if best else None,
        "out_label": out_label, "mid_msgs": {e["msg"] for e in mid},
        "cause_msgs": {e["msg"] for e, c in causes},
        "cause_sigs": {normalize_msg(e["msg"]) for e, c in causes},
    }


ACTION_LABELS = [
    (re.compile(r"Hard Reset", re.I), "강제 재시작(Hard Reset)"),
    (re.compile(r"Restart \(Soft\)|Soft", re.I), "OS 재시작 요청(Soft)"),
    (re.compile(r"Power ?Cycle", re.I), "전원 재투입 요청"),
    (re.compile(r"Shut ?Down|Power(ed)? ?Off", re.I), "전원 끄기 요청"),
    (re.compile(r"pushbutton|power button", re.I), "전원 버튼"),
    (re.compile(r"powered-?up|Power(ed)? ?On", re.I), "전원 켜기 요청"),
    (re.compile(r"Phy(sical)? Presence", re.I), "현장 물리 조작(Physical Presence)"),
]


def _action_summary(actions):
    cnt = OrderedDict()
    users, ips = set(), set()
    for e, c in actions:
        if re.search(r"chassis control", e["msg"], re.I):
            continue  # 리셋 명령의 결과로 남는 기록이라 따로 세지 않는다
        label = {"fw_update": "펌웨어 업데이트", "bmc_reset": "BMC 리셋", "os_shutdown": "OS 정상 종료",
                 "os_reboot_cmd": "재부팅 명령(sudo)"}.get(c[1])
        if c[1] == "service_stop":
            m = re.search(r"Stopping (.+?)\.*$", e["msg"])
            label = "서비스 중지: %s" % (m.group(1) if m else short(e["msg"], 30))
        if not label:
            label = next((lab for rx, lab in ACTION_LABELS if rx.search(e["msg"])), short(e["msg"], 40))
        cnt[label] = cnt.get(label, 0) + 1
        users.update(re.findall(r"(?:by|for) user (\w+)", e["msg"]))
        ips.update(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", e["msg"]))
    parts = ["%s%s" % (k, " %d회" % v if v > 1 else "") for k, v in cnt.items()]
    who = []
    if users - {"system"}:
        who.append("사용자 " + ", ".join(sorted(users - {"system"})))
    if ips:
        who.append("접속 IP " + ", ".join(sorted(ips)))
    return ", ".join(parts) + (" (%s)" % "; ".join(who) if who else "")


ROLE_LABEL = {OUTCOME: "결과", CAUSE: "원인 후보", RESOLVE: "복구", ACTION: "사용자 조작",
              BOOT: "부팅", BMC_RESTART: "BMC 재시작", MARK: "로그 삭제", LOGIN: "로그인"}


def _chain(items, anchor):
    """사건 전후 이벤트를 같은 메시지끼리 묶어 시간순 행으로 만든다."""
    rows = OrderedDict()
    for e, c in sorted(items, key=lambda ec: ec[0]["ts"]):
        key = (c[0], normalize_msg(e["msg"]), e.get("kind") == "os")
        r = rows.get(key)
        if r is None:
            rows[key] = {"role": c[0], "role_label": ROLE_LABEL[c[0]],
                         "src": "OS" if e.get("kind") == "os" else "BMC",
                         "cat": CAT_LABEL.get(c[1], ""), "sev": e["sev"], "id": e["id"],
                         "msg": e["msg"], "first": e["ts"], "last": e["ts"], "count": 1}
        else:
            r["count"] += 1
            r["last"] = e["ts"]
    out = sorted(rows.values(), key=lambda r: r["first"])
    for r in out:
        r["rel"] = fmt_rel((r["first"] - anchor).total_seconds())
        r["is_anchor"] = r["first"] == anchor
    if len(out) > 18:  # 너무 길면 가운데를 줄인다
        out = out[:9] + [{"gap": len(out) - 17}] + out[-8:]
    return out


def _patterns(tagged, covered, between, incidents):
    """사건으로 이어지지 않은 경고 묶음을 정리한다."""
    def in_covered(ts):
        return any(lo <= ts <= hi for lo, hi in covered)

    causes = [(e, c) for e, c in tagged if c and c[0] == CAUSE and not in_covered(e["ts"])]
    clusters = []
    for e, c in causes:
        if clusters and e["ts"] - clusters[-1][-1][0]["ts"] <= CLUSTER_GAP:
            clusters[-1].append((e, c))
        else:
            clusters.append([(e, c)])

    groups = OrderedDict()
    for cl in clusters:
        sig = frozenset(normalize_msg(e["msg"]) for e, c in cl)
        groups.setdefault(sig, []).append(cl)

    rows = []
    for sig, cls in groups.items():
        evs = [ec for cl in cls for ec in cl]
        cats = sorted({CAT_LABEL[c[1]] for e, c in evs})
        top = Counter(e["msg"] for e, c in evs).most_common(1)[0][0]
        unresolved = 0
        for e, c in evs:
            res = between(e["ts"], e["ts"] + RESOLVE_LIMIT, roles=(RESOLVE,))
            if not any(cc[1] == c[1] and ee["ts"] > e["ts"] for ee, cc in res):
                unresolved += 1
        exact = {e["msg"] for e, c in evs}  # 숫자까지 같은 메시지만 같은 증상으로 본다
        linked = sorted({fmt_ts(i["start"])[:16] for i in incidents if exact & i["cause_msgs"]})
        if len(cls) <= 5:
            for cl in cls:
                rows.append(_pattern_row(cl, 1, cats, top, between, linked))
        else:
            row = _pattern_row(evs, len(cls), cats, top, between, linked)
            row["interp"] = ("서비스 중단 없이 %d개 구간에서 반복됐습니다 (총 %d건). 오래 이어지는 증상이므로 근본 원인을 "
                             "점검하세요." % (len(cls), len(evs)))
            if unresolved:
                row["interp"] += " 복구 기록이 없는 경우가 %d건 있습니다." % unresolved
            if linked:
                row["interp"] += " 같은 증상이 %s 사건 직전에도 나타났습니다." % ", ".join(linked)
            rows.append(row)
    # 하나의 PSU 만 끊긴 구간이 가까운 시기에 다른 PSU 로 이어지면 순차 작업으로 본다
    single = sorted([r for r in rows if r.get("psus") and len(r["psus"]) == 1], key=lambda r: r["first"])
    for x, y in zip(single, single[1:]):
        if x["psus"] != y["psus"] and y["first"] - x["last"] <= timedelta(hours=48):
            msg = (" %s PSU %s → %s PSU %s 순서로 하나씩 입력을 잃었습니다 → 전원 경로를 한쪽씩 작업한 것으로 "
                   "보입니다." % (fmt_ts(x["first"])[:16], x["psus"][0], fmt_ts(y["first"])[:16], y["psus"][0]))
            for r in (x, y):
                if msg not in r["interp"]:
                    r["interp"] += msg
    rows.sort(key=lambda r: (-r["severity"], -r["last"].timestamp()))
    return rows


def _pattern_row(evs, occurrences, cats, top, between, linked):
    first, last = evs[0][0]["ts"], evs[-1][0]["ts"]
    sev = max(2 if e["sev"] == "E" else 1 for e, c in evs)
    interp = _interpret_cluster(evs, between)
    if linked:
        interp += " 같은 증상이 %s 사건 직전에도 나타났습니다." % ", ".join(linked)
    psus = sorted({m.group(1) for e, c in evs for m in [R_PSU_LOST.search(e["msg"])] if m})
    return {"first": first, "last": last, "count": len(evs), "occurrences": occurrences,
            "cats": cats, "title": top, "interp": interp, "severity": sev, "psus": psus}


def _interpret_cluster(evs, between):
    first, last = evs[0][0]["ts"], evs[-1][0]["ts"]
    lost = [(e, R_PSU_LOST.search(e["msg"]).group(1)) for e, c in evs if R_PSU_LOST.search(e["msg"])]
    if lost:
        back = {}
        for e, c in between(first, last + RESOLVE_LIMIT, roles=(RESOLVE,)):
            m = R_PSU_BACK.search(e["msg"])
            if m:
                back.setdefault(m.group(1), []).append(e["ts"])
        spans = []
        for e, n in lost:
            rt = next((t for t in back.get(n, []) if t > e["ts"]), None)
            spans.append((n, e["ts"], rt))
        psus = sorted({n for n, _, _ in spans})
        never = [n for n, _, rt in spans if rt is None]
        overlap = any(a[0] != b[0] and a[1] < (b[2] or b[1] + RESOLVE_LIMIT) and b[1] < (a[2] or a[1] + RESOLVE_LIMIT)
                      for i, a in enumerate(spans) for b in spans[i + 1:])
        dur = ", ".join("PSU %s %s" % (n, fmt_dur((rt - t).total_seconds()) if rt else "복구 기록 없음")
                        for n, t, rt in spans)
        if len(psus) >= 2 and not overlap:
            txt = ("PSU %s가 번갈아 입력 전원을 잃었다가 복구됐습니다 (%s). 이중화로 서비스는 유지됐고, "
                   "한쪽씩 차례로 전원을 내린 작업(PDU·UPS 점검 등) 패턴입니다." % (", ".join(psus), dur))
        elif len(psus) >= 2:
            txt = ("두 PSU의 입력이 동시에 끊긴 구간이 있습니다 (%s). 그런데도 전원 꺼짐 기록이 없으므로, "
                   "기록 누락 여부를 확인하세요." % dur)
        else:
            txt = ("PSU %s 입력 전원이 끊겼습니다 (%s). 이중화로 서비스는 유지됐지만, 그동안 전원 이중화가 없는 "
                   "상태였습니다. 해당 전원 경로(PDU, 케이블)를 점검하세요." % (psus[0], dur))
        if never:
            txt += " 복구 기록이 없는 PSU가 있으니 현재 상태를 확인하세요."
        return txt
    paths = [e for e, c in evs if re.search(r"Failing path|path is down|checker failed path", e["msg"])]
    if paths:
        maps = sorted({m.group(1) for e in paths for m in [re.search(r"(\w+): \w+ - ", e["msg"])] if m})
        back = [e for e, c in between(first, last + timedelta(hours=1), roles=(RESOLVE,)) if c[1] == "storage"]
        zero = any(re.search(r"remaining active paths: 0", e["msg"]) for e, c in evs)
        span = fmt_dur((back[0]["ts"] - first).total_seconds()) if back else "복구 기록 없음"
        txt = "스토리지 경로가 끊겼습니다%s (%s)." % (" (%s)" % ", ".join(maps) if maps else "", span)
        if zero:
            txt += " 남은 경로가 0개가 된 순간이 있어 I/O가 멈췄을 수 있습니다."
        else:
            txt += " 다른 경로로 서비스는 유지됐습니다(경로 이중화)."
        return txt + " 반복되면 케이블, HBA, 스토리지 컨트롤러를 점검하세요."
    cats = Counter(c[1] for e, c in evs)
    main = CAT_LABEL[cats.most_common(1)[0][0]]
    span = fmt_dur((last - first).total_seconds()) if last > first else "순간"
    res = between(first, last + RESOLVE_LIMIT, roles=(RESOLVE,))
    ok = any(cc[1] in cats for ee, cc in res)
    return "%s 경고 %d건 (%s 동안), 서비스 중단 기록 없음%s." % (
        main, len(evs), span, ", 복구 기록 있음" if ok else ", 복구 기록 없음")


def link_findings(findings, flow):
    """개별 이벤트 발견 사항에 흐름 분석 결과를 덧붙인다 (이 이벤트 뒤에 무엇이 일어났는지)."""
    for f in findings:
        if f.get("flow"):
            continue
        msg = f["title"].replace("반복 경고: ", "")
        for i in flow["incidents"]:
            when = "%s 사건" % fmt_ts(i["start"])[:16]
            if i.get("cause_msg") == msg:
                f["evidence"].append("흐름 분석: 이 이벤트 %s 뒤 %s → %s (사건 흐름 분석 참고)"
                                     % (fmt_dur(i["cause_gap"]), i["out_label"], i["headline"]))
            elif msg in i.get("mid_msgs", ()):
                f["evidence"].append("흐름 분석: %s 도중에 기록됐습니다%s."
                                     % (when, " (작업 기간)" if i.get("work_period") else ""))
            elif msg in i.get("cause_msgs", ()):  # 숫자까지 같아야 같은 대상 (processor 1 ≠ 2)
                f["evidence"].append("흐름 분석: %s 직전에도 나타났습니다." % when)


def flow_findings(flow):
    """흐름 분석 결과 중 발견 사항으로 올릴 것."""
    out = []
    for i in flow["incidents"]:
        if i["kind"] == "fault":
            level = "critical" if i["confidence"] in ("높음", "중간") else "warning"
            out.append({"level": level, "title": "흐름: %s (%s)" % (i["headline"], fmt_ts(i["start"])),
                        "detail": i["verdict"], "why": None, "action": None,
                        "evidence": ["판정 신뢰도: %s" % i["confidence"]] + i["notes"], "flow": True})
    unexplained = [i for i in flow["incidents"] if i["kind"] == "unexplained" and not i.get("work_period")]
    if unexplained:
        out.append({"level": "warning", "title": "흐름: 원인 기록 없는 서비스 중단 %d건" % len(unexplained),
                    "detail": ", ".join(fmt_ts(i["start"]) for i in unexplained[-5:])
                              + (" 외" if len(unexplained) > 5 else ""),
                    "why": None, "action": "OS 로그와 작업 기록으로 원인을 확인하세요.",
                    "evidence": [n for i in unexplained[-3:] for n in i["notes"][:1]], "flow": True})
    return out
