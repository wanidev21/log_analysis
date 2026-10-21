"""분석 결과 → 단일 HTML 리포트 (외부 파일 없이 열림)."""

import html
import json
from collections import Counter
from datetime import datetime

from . import APP_NAME, __version__
from .core import SEV_LABEL, fmt_ts

LEVEL_META = {
    "critical": ("심각", "!"),
    "warning": ("주의", "▲"),
    "info": ("참고", "i"),
}


def esc(v):
    return html.escape(str(v if v is not None else ""))


def render_html(ctx, src_name, nav=""):
    """nav: 헤더 위에 넣을 HTML (웹 화면에서 '새 분석' 링크 등)."""
    sysi = ctx["system"]
    events = ctx["events"]
    sev_count = Counter(e["sev"] for e in events if e["kind"] in ("event", "os"))
    lvl_count = Counter(f["level"] for f in ctx["findings"])

    title_host = sysi.get("host") or sysi.get("serial") or src_name
    model = sysi.get("model", "")
    if sysi.get("machine_type"):
        model = "%s (%s)" % (model, sysi["machine_type"]) if model else sysi["machine_type"]

    def kv(label, value):
        return '<div class="kv"><dt>%s</dt><dd>%s</dd></div>' % (esc(label), esc(value or "-"))

    fw_kv = "".join(kv(f["component"], "%s (%s)" % (f["version"], f["build"]) if f["build"] else f["version"])
                    for f in ctx["firmware"] if f["role"] in ("active", ""))
    collected = sysi.get("collected")
    head_kv = "".join([
        kv("벤더 / 형식", ("%s %s" % (ctx["vendor"], ctx["format"])).strip()),
        kv("모델", model),
        kv("시리얼", sysi.get("serial")),
        kv("UUID", sysi.get("uuid")),
        kv("시스템 상태", sysi.get("power")),
        kv("수집 시각", fmt_ts(collected) + " UTC" if collected else sysi.get("clock")),
        kv("위치", sysi.get("location")),
    ]) + fw_kv
    osi = ctx.get("os")
    if osi:
        head_kv += "".join([
            kv("OS", " / ".join(x for x in (osi["release"], osi["kernel"]) if x)),
            kv("OS 호스트", osi["host"]),
            kv("OS 시간대", "%s (%s)" % (osi["tz"], osi["tz_source"])),
        ])

    def tile(label, value, sub="", cls=""):
        return ('<div class="tile %s"><div class="tile-label">%s</div>'
                '<div class="tile-value">%s</div><div class="tile-sub">%s</div></div>'
                % (cls, esc(label), esc(value), esc(sub)))

    period = ""
    if ctx["ev_first"]:
        period = "%s ~ %s" % (ctx["ev_first"].strftime("%Y-%m-%d"), ctx["ev_last"].strftime("%Y-%m-%d"))
    tiles = "".join([
        tile("발견 사항", len(ctx["findings"]),
             "심각 %d · 주의 %d · 참고 %d" % (lvl_count["critical"], lvl_count["warning"], lvl_count["info"])),
        tile("Error 이벤트", sev_count["E"], "", "t-crit" if sev_count["E"] else ""),
        tile("Warning 이벤트", sev_count["W"], "", "t-warn" if sev_count["W"] else ""),
        tile("Info 이벤트", sev_count["I"]),
        tile("이벤트 기간", "%d일" % ((ctx["ev_last"] - ctx["ev_first"]).days + 1)
             if ctx["ev_first"] else "-", period + " (UTC)" if period else ""),
    ])

    if ctx["findings"]:
        items = []
        for f in ctx["findings"]:
            label, icon = LEVEL_META[f["level"]]
            extra = ""
            if f["why"]:
                extra += '<p class="why"><b>해설</b> %s</p>' % esc(f["why"])
            if f["action"]:
                extra += '<p class="why"><b>권장 조치</b> %s</p>' % esc(f["action"])
            if f["evidence"]:
                extra += "<ul>%s</ul>" % "".join("<li>%s</li>" % esc(x) for x in f["evidence"])
            items.append(
                '<li class="finding f-%s"><span class="badge b-%s"><span class="ico">%s</span>%s</span>'
                '<div class="f-body"><div class="f-title">%s</div><div class="f-detail">%s</div>%s</div></li>'
                % (f["level"], f["level"], icon, label, esc(f["title"]), esc(f["detail"]), extra))
        findings_html = '<ul class="findings">%s</ul>' % "".join(items)
    else:
        findings_html = '<p class="empty">자동 규칙으로 찾은 이상 징후가 없습니다.</p>'

    grp_rows = "".join(
        '<tr><td><span class="sev s-%s">%s</span></td><td class="mono">%s</td><td>%s</td>'
        '<td class="num">%d</td><td class="mono">%s</td><td class="mono">%s</td></tr>'
        % (g["sev"], SEV_LABEL.get(g["sev"], g["sev"]), esc(g["id"] or "-"), esc(g["msg"]),
           g["count"], fmt_ts(g["first"]), fmt_ts(g["last"]))
        for g in ctx["groups"])

    def sensor_cls(s):
        st = s["status"].lower()
        if s.get("discrete") or st in ("ok", "na", ""):
            return ""
        return "row-crit" if st in ("cr", "nr") else "row-warn"

    sensor_rows = "".join(
        '<tr class="%s"><td>%s</td><td class="num">%s</td><td>%s</td><td>%s</td>'
        '<td class="num">%s</td><td class="num">%s</td><td class="num">%s</td><td class="num">%s</td></tr>'
        % (sensor_cls(s), esc(s["name"]), esc(s["reading"]), esc(s["unit"]), esc(s["status"]),
           esc(s.get("lcr")), esc(s.get("lnc")), esc(s.get("unc")), esc(s.get("ucr")))
        for s in ctx["sensors"])

    fw_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td></tr>"
        % (esc(f["name"]), esc(f["version"]), esc(f["build"]), esc(f["date"])) for f in ctx["firmware"])

    fru_rows = "".join(
        "<tr class='%s'><td>%s</td><td class='mono'>%s</td><td class='mono'>%s</td><td>%s</td></tr>"
        % ("" if f["present"] else "row-muted", esc(f["name"]), esc(f["id"]), esc(f["entity"]),
           "장착" if f["present"] else "미장착")
        for f in ctx["fru"])

    sys_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td class="num">%d</td><td class="mono">%s</td><td class="mono">%s</td>'
        '<td class="mono small">%s</td></tr>'
        % (esc(g["proc"]), esc(g["pattern"]), g["count"], esc(g["first"].replace("T", " ")),
           esc(g["last"].replace("T", " ")), esc(", ".join(g["files"])))
        for g in ctx["log_patterns"][:100])
    sys_files = "".join(
        '<tr><td class="mono">%s</td><td class="num">%d</td><td class="num">%d</td><td class="mono">%s</td>'
        '<td class="mono">%s</td></tr>'
        % (esc(f["file"]), f["lines"], f["errors"], esc((f["first"] or "").replace("T", " ")),
           esc((f["last"] or "").replace("T", " "))) for f in ctx["log_files"])

    data = {
        "unit": ctx["bucket_unit"],
        "buckets": ctx["buckets"],
        "incidents": [{"d": i["start"].strftime("%Y-%m-%d"), "k": i["kind"], "h": i["headline"]}
                      for i in (ctx.get("flow") or {}).get("incidents", [])],
        "events": [{"t": fmt_ts(e["ts"]), "s": e["sev"], "id": e["id"], "m": e["msg"], "k": e["kind"]}
                   for e in events],
    }
    data_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    files_used = "".join("<li class='mono'>%s</li>" % esc(f) for f in sorted(set(ctx["files_used"])))

    return HTML_TEMPLATE.format(
        nav=nav,
        flow_section=render_flow(ctx.get("flow"), (ctx.get("os") or {}).get("tz_offset")),
        os_section=render_os(ctx.get("os")),
        title=esc("%s 로그 분석" % title_host),
        host=esc(title_host),
        src=esc(src_name),
        gen=esc(datetime.now().strftime("%Y-%m-%d %H:%M")),
        app=esc(APP_NAME),
        version=__version__,
        head_kv=head_kv,
        tiles=tiles,
        findings=findings_html,
        unit_label={"day": "일별", "week": "주별", "month": "월별"}[ctx["bucket_unit"]],
        grp_rows=grp_rows or '<tr><td colspan="6" class="empty">이벤트 없음</td></tr>',
        n_events=len(events),
        sensor_rows=sensor_rows or '<tr><td colspan="8" class="empty">센서 데이터 없음</td></tr>',
        fw_rows=fw_rows or '<tr><td colspan="4" class="empty">-</td></tr>',
        fru_rows=fru_rows or '<tr><td colspan="4" class="empty">-</td></tr>',
        fru_summary=esc("장착 %d / 전체 %d" % (sum(f["present"] for f in ctx["fru"]), len(ctx["fru"]))),
        sys_rows=sys_rows or '<tr><td colspan="6" class="empty">오류 패턴 없음</td></tr>',
        sys_files=sys_files or '<tr><td colspan="5" class="empty">-</td></tr>',
        n_patterns=len(ctx["log_patterns"]),
        files_used=files_used,
        data_json=data_json,
    )


KIND_META = {
    "fault": ("장애 추정", "var(--crit)"),
    "unexplained": ("원인 미상", "var(--serious)"),
    "planned": ("계획 작업", "var(--accent)"),
}


def _local(ts, off):
    if off is None:
        return ""
    from .oslog import fmt_offset
    return " · 현지 %s (%s)" % ((ts + off).strftime("%m-%d %H:%M:%S"), fmt_offset(off))


def _incident_card(i, open_chain, off=None):
    label, color = KIND_META[i["kind"]]
    conf = '<span>판정 신뢰도 %s</span>' % esc(i["confidence"]) if i["confidence"] else ""
    work = "<span>· 작업 기간</span>" if i.get("work_period") else ""
    notes = "".join("<li>%s</li>" % esc(n) for n in i["notes"])
    rows = []
    for r in i["chain"]:
        if "gap" in r:
            rows.append('<tr><td colspan="5" class="small">… %d행 생략 …</td></tr>' % r["gap"])
            continue
        extra = ""
        if r["count"] > 1:
            extra = ' <span class="small">×%d (%s ~ %s)</span>' % (
                r["count"], fmt_ts(r["first"])[5:], fmt_ts(r["last"])[5:])
        rows.append(
            '<tr class="%s"><td class="mono num">%s</td><td><span class="src src-%s">%s</span></td>'
            '<td><span class="role role-%s">%s</span></td>'
            '<td><span class="sev s-%s"></span></td><td>%s%s</td></tr>'
            % ("anchor" if r["is_anchor"] else "", esc(r["rel"]), r.get("src", "BMC").lower(), r.get("src", "BMC"),
               r["role"], esc(r["role_label"]), r["sev"], esc(r["msg"]), extra))
    chain = ('<details %s><summary>사건 전후 흐름 (%d행, 기준 = %s)</summary><div class="tbl-wrap">'
             '<table class="chain"><tbody>%s</tbody></table></div></details>'
             % ("open" if open_chain else "", len(i["chain"]), esc(fmt_ts(i["start"])), "".join(rows)))
    return ('<div class="inc k-%s" style="--kc:%s"><div class="inc-head"><span class="kbadge">%s</span>'
            '<span class="mono">%s UTC%s</span>%s%s</div><div class="inc-title">%s</div>'
            '<p class="inc-verdict">%s</p>%s%s</div>'
            % (i["kind"], color, esc(label), esc(fmt_ts(i["start"])), esc(_local(i["start"], off)), conf, work,
               esc(i["headline"]),
               esc(i["verdict"]), '<ul class="inc-notes">%s</ul>' % notes if notes else "", chain))


def render_flow(flow, off=None):
    if not flow:
        return ""
    from .flow import fmt_dur
    sm = flow["summary"]
    incs = flow["incidents"]
    order = {"fault": 0, "unexplained": 1, "planned": 2}
    # 계획 작업이라도 정상 종료 없이 강제로 재시작했다면 펼쳐서 보여준다
    main = [i for i in incs if (i["kind"] != "planned" or i.get("forced")) and not i.get("work_period")]
    side = [i for i in incs if i not in main]
    main.sort(key=lambda i: (order[i["kind"]], -i["start"].timestamp()))
    side.sort(key=lambda i: -i["start"].timestamp())

    chips = [
        "서비스 중단 %d건" % sm.get("incidents", 0),
        "장애 추정 %d" % sm.get("fault", 0),
        "원인 미상 %d" % sm.get("unexplained", 0),
        "계획 작업 %d" % sm.get("planned", 0),
    ]
    if sm.get("ac_loss"):
        chips.append("AC 전원 끊김 추정 %d" % sm["ac_loss"])
    if sm.get("downtime"):
        chips.append("기록상 꺼져 있던 시간 합계 %s" % fmt_dur(sm["downtime"]))
    out = ['<section id="flow"><h2>사건 흐름 분석 <small>결과 이벤트(전원 꺼짐·재시작 등)를 기준으로 '
           '직전 원인과 이후 복구 과정을 엮어 판정</small></h2>',
           '<div class="flow-sum">%s</div>' % "".join('<span class="chip">%s</span>' % esc(c) for c in chips)]
    if flow["notes"]:
        out.append('<ul class="flow-notes">%s</ul>' % "".join("<li>%s</li>" % esc(n) for n in flow["notes"]))
    if not incs:
        out.append('<p class="empty">전원 꺼짐·재시작 같은 서비스 중단 기록이 없습니다.</p>')
    for i in main:
        out.append(_incident_card(i, open_chain=i["kind"] == "fault", off=off))
    if side:
        out.append('<details class="more"><summary>계획 작업·작업 기간 사건 %d건 펼치기</summary>%s</details>'
                   % (len(side), "".join(_incident_card(i, False, off) for i in side)))
    if flow["patterns"]:
        rows = "".join(
            '<tr><td class="mono">%s<br>~ %s</td><td>%s</td><td class="num">%d</td>'
            '<td>%s<div class="small">%s</div></td></tr>'
            % (esc(fmt_ts(p["first"])), esc(fmt_ts(p["last"])), esc(", ".join(p["cats"])), p["count"],
               esc(p["interp"]), esc(p["title"]))
            for p in flow["patterns"])
        out.append('<h2 style="margin-top:20px">서비스 영향 없는 이상 구간 '
                   '<small>사건으로 이어지지 않은 경고 묶음</small></h2>'
                   '<div class="tbl-wrap"><table><thead><tr><th>기간 (UTC)</th><th>분류</th>'
                   '<th class="num">건수</th><th>해석</th></tr></thead><tbody>%s</tbody></table></div>' % rows)
    out.append("</section>")
    return "\n".join(out)


def render_os(osi):
    if not osi:
        return ""
    from .oslog import fmt_offset
    off = osi["tz_offset"]

    def loc(ts):
        return (ts + off).strftime("%Y-%m-%d %H:%M") if ts else "-"

    period = "%s ~ %s (현지)" % (osi["first_local"].strftime("%Y-%m-%d %H:%M"),
                                osi["last_local"].strftime("%Y-%m-%d %H:%M")) if osi["first_local"] else "-"
    info = [
        ("OS", " / ".join(x for x in (osi["release"], osi["kernel"]) if x) or "-"),
        ("호스트 / 시리얼", "%s / %s" % (osi["host"] or "-", osi["serial"] or "-")),
        ("시간대", "%s · 근거: %s · BMC 부팅 기록과 맞은 OS 부팅 %d건"
         % (fmt_offset(off), osi["tz_source"], osi["tz_matches"])),
        ("syslog 기간", "%s · %s줄" % (period, format(osi["n_lines"], ","))),
    ]
    if osi["pair_note"]:
        info.append(("BMC 덤프와 짝", osi["pair_note"]))
    kv = "".join('<div class="kv"><dt>%s</dt><dd>%s</dd></div>' % (esc(k), esc(v)) for k, v in info)

    how = {True: "정상 종료", False: "비정상(정상 종료 기록 없음)", None: "알 수 없음"}
    boot_rows = "".join(
        '<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td><td class="mono">%s</td><td class="small">%s</td></tr>'
        % (esc(loc(b["ts"])), esc(fmt_ts(b["ts"])), esc(how[b.get("graceful")]),
           esc(loc(b.get("prev_last"))), "last(wtmp)" if b.get("wtmp") else "syslog")
        for b in osi["boots"][:30])
    pat_rows = "".join(
        '<tr><td><span class="sev s-%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td><td class="num">%d</td>'
        '<td class="mono">%s</td><td class="mono">%s</td></tr>'
        % (p["sev"], SEV_LABEL.get(p["sev"], p["sev"]), esc(p["cat"]), esc(p["proc"]), esc(p["pattern"]),
           p["count"], esc(loc(p["first"])), esc(loc(p["last"])))
        for p in osi["patterns"][:60])
    files = "".join('<tr><td class="mono">%s</td><td>%s</td><td class="num">%s</td></tr>'
                    % (esc(f["file"]), esc(f["type"]), esc(f.get("lines", "-"))) for f in osi["files"])
    auto = ""
    if osi["auto_logins"]:
        auto = ('<p class="hint">반복되는 자동 SSH 접속은 흐름에서 뺐습니다 (부팅 전후 1시간은 남김): %s</p>'
                % esc(", ".join("%s@%s %d회" % (u, h, n) for u, h, n in osi["auto_logins"][:6])))
    return ('<section id="oslog"><h2>OS 로그 <small>BMC 로그와 같은 시간축(UTC)으로 맞춰 흐름 분석에 함께 사용</small></h2>'
            '<dl class="grid">%s</dl>%s'
            '<h2 style="margin-top:18px">OS 부팅 이력 <small>최근 30건 · 직전 종료 방식</small></h2>'
            '<div class="tbl-wrap"><table><thead><tr><th>부팅 (현지)</th><th>부팅 (UTC)</th><th>직전 종료</th>'
            '<th>직전 마지막 OS 기록 (현지)</th><th>출처</th></tr></thead><tbody>%s</tbody></table></div>'
            '<h2 style="margin-top:18px">OS 오류·경고 패턴</h2>'
            '<div class="tbl-wrap scroll"><table><thead><tr><th>등급</th><th>분류</th><th>프로세스</th><th>패턴</th>'
            '<th class="num">건수</th><th>최초 (현지)</th><th>최근 (현지)</th></tr></thead><tbody>%s</tbody></table></div>'
            '<details><summary>읽은 OS 로그 파일 %d개</summary><div class="tbl-wrap"><table><thead><tr><th>파일</th>'
            '<th>형식</th><th class="num">줄 수</th></tr></thead><tbody>%s</tbody></table></div></details></section>'
            % (kv, auto, boot_rows or '<tr><td colspan="5" class="empty">부팅 기록 없음</td></tr>',
               pat_rows or '<tr><td colspan="7" class="empty">오류·경고 없음</td></tr>', len(osi["files"]), files))


HTML_TEMPLATE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --crit: #d03b3b; --warn: #fab219; --serious: #ec835a; --good: #0ca30c; --info: #898781;
  --crit-bg: rgba(208,59,59,0.08); --warn-bg: rgba(250,178,25,0.12); --accent: #2a78d6;
  --accent-bg: rgba(42,120,214,0.08);
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --crit-bg: rgba(208,59,59,0.16); --warn-bg: rgba(250,178,25,0.12); --accent: #3987e5;
  }}
}}
:root[data-theme="dark"] {{
  --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
  --crit-bg: rgba(208,59,59,0.16); --warn-bg: rgba(250,178,25,0.12); --accent: #3987e5;
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.55 "Pretendard", "Malgun Gothic", "Apple SD Gothic Neo", system-ui, sans-serif; }}
.wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px 64px; }}
header h1 {{ font-size: 24px; margin: 0 0 4px; }}
header .sub {{ color: var(--ink-2); font-size: 13px; }}
section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 20px; margin-top: 20px; }}
h2 {{ font-size: 17px; margin: 0 0 12px; }}
h2 small {{ font-weight: normal; color: var(--muted); font-size: 13px; margin-left: 6px; }}
dl.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 10px 24px; margin: 0; }}
.kv dt {{ color: var(--muted); font-size: 12px; }}
.kv dd {{ margin: 0; word-break: break-all; }}
.tiles {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px;
  margin-top: 20px; }}
.tile {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
.tile-label {{ color: var(--ink-2); font-size: 12px; }}
.tile-value {{ font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; }}
.tile-sub {{ color: var(--muted); font-size: 12px; min-height: 1em; }}
.tile.t-crit {{ border-left: 4px solid var(--crit); }}
.tile.t-warn {{ border-left: 4px solid var(--warn); }}
.findings {{ list-style: none; margin: 0; padding: 0; }}
.finding {{ display: flex; gap: 12px; padding: 12px 0; border-top: 1px solid var(--grid); }}
.finding:first-child {{ border-top: 0; }}
.badge {{ flex: none; display: inline-flex; align-items: center; gap: 4px; height: 24px; padding: 0 8px;
  border-radius: 12px; font-size: 12px; font-weight: 600; border: 1px solid var(--border); }}
.badge .ico {{ display: inline-grid; place-items: center; width: 16px; height: 16px; border-radius: 50%;
  font-size: 10px; color: #fff; }}
.b-critical .ico {{ background: var(--crit); }}
.b-warning .ico {{ background: var(--warn); color: #0b0b0b; }}
.b-info .ico {{ background: var(--info); }}
.f-critical {{ background: var(--crit-bg); margin: 0 -20px; padding: 12px 20px; }}
.f-title {{ font-weight: 600; }}
.f-detail {{ color: var(--ink-2); font-size: 13px; }}
.why {{ margin: 6px 0 0; font-size: 13px; }}
.why b {{ color: var(--ink-2); margin-right: 6px; }}
.finding ul {{ margin: 6px 0 0; padding-left: 18px; color: var(--ink-2); font-size: 13px; }}
.legend {{ display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--ink-2); margin-bottom: 8px; }}
.legend span.mk::before {{ width: 0; height: 0; border-radius: 0; background: none;
  border-left: 5px solid transparent; border-right: 5px solid transparent; border-top: 8px solid var(--c); }}
.flow-sum {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }}
.flow-sum .chip {{ font-size: 13px; padding: 3px 10px; border-radius: 12px; border: 1px solid var(--border); }}
.flow-notes {{ margin: 0 0 14px; padding: 10px 14px 10px 30px; background: var(--page); border-radius: 8px;
  color: var(--ink-2); font-size: 13px; }}
.inc {{ border: 1px solid var(--border); border-left: 4px solid var(--kc); border-radius: 8px;
  padding: 12px 14px; margin-bottom: 12px; }}
.inc-head {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; font-size: 12px; color: var(--ink-2); }}
.kbadge {{ font-weight: 700; font-size: 12px; padding: 1px 8px; border-radius: 10px; color: #fff; background: var(--kc); }}
.k-unexplained .kbadge {{ color: #0b0b0b; }}
.inc-title {{ font-weight: 700; margin: 6px 0 4px; }}
.inc-verdict {{ margin: 0 0 6px; }}
.inc-notes {{ margin: 0 0 6px; padding-left: 18px; color: var(--ink-2); font-size: 13px; }}
table.chain td {{ padding: 4px 8px; }}
table.chain .sev {{ min-width: 0; }}
table.chain td:nth-child(1) {{ width: 1%; white-space: nowrap; }}
table.chain td:nth-child(2), table.chain td:nth-child(3) {{ width: 1%; }}
table.chain tr.anchor td {{ background: var(--accent-bg); font-weight: 600; }}
.role {{ display: inline-block; font-size: 11px; padding: 0 6px; border-radius: 8px; border: 1px solid var(--border);
  white-space: nowrap; color: var(--ink-2); }}
.role-cause {{ border-color: var(--warn); }}
.role-outcome {{ border-color: var(--crit); color: var(--ink); }}
.role-action, .role-login {{ border-color: var(--accent); }}
.role-resolve, .role-boot {{ border-color: var(--good); }}
.src {{ display: inline-block; font-size: 10px; font-weight: 700; padding: 0 5px; border-radius: 4px;
  color: var(--ink-2); background: var(--page); border: 1px solid var(--border); }}
.src-os {{ color: var(--accent); }}
details.more > summary {{ margin-top: 6px; }}
.legend span::before {{ content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 2px;
  margin-right: 6px; vertical-align: -1px; background: var(--c); }}
.chart {{ position: relative; }}
.chart svg {{ display: block; width: 100%; height: 240px; }}
.chart .grid line {{ stroke: var(--grid); }}
.chart .axis text {{ fill: var(--muted); font-size: 11px; }}
.chart .baseline {{ stroke: var(--axis); }}
.chart .hit {{ fill: transparent; cursor: pointer; }}
.chart .hit:hover {{ fill: var(--grid); fill-opacity: .5; }}
.tip {{ position: absolute; pointer-events: none; background: var(--surface); color: var(--ink);
  border: 1px solid var(--border); border-radius: 8px; padding: 8px 10px; font-size: 12px;
  box-shadow: 0 4px 16px rgba(0,0,0,.12); white-space: nowrap; display: none; z-index: 2; }}
.tip .row {{ display: flex; justify-content: space-between; gap: 16px; }}
.tip .row i {{ display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 6px; }}
.hint {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
.tbl-wrap {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }}
th {{ color: var(--ink-2); font-weight: 600; position: sticky; top: 0; background: var(--surface); }}
td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono {{ font-family: Consolas, "D2Coding", ui-monospace, monospace; font-size: 12px; white-space: nowrap; }}
.small {{ font-size: 11px; color: var(--muted); }}
.sev {{ display: inline-block; min-width: 62px; font-size: 12px; font-weight: 600; white-space: nowrap; }}
th {{ white-space: nowrap; }}.sev::before {{ content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 50%;
  margin-right: 6px; background: var(--info); }}
.s-E::before {{ background: var(--crit); }}
.s-W::before {{ background: var(--warn); }}
.row-crit td {{ background: var(--crit-bg); }}
.row-warn td {{ background: var(--warn-bg); }}
.row-muted td {{ color: var(--muted); }}
.controls {{ display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin-bottom: 10px; }}
.controls input[type=search] {{ flex: 1 1 260px; padding: 7px 10px; border-radius: 8px; border: 1px solid var(--axis);
  background: var(--page); color: var(--ink); font: inherit; }}
.controls label {{ font-size: 13px; color: var(--ink-2); white-space: nowrap; }}
.controls button {{ padding: 6px 10px; border-radius: 8px; border: 1px solid var(--axis); background: var(--page);
  color: var(--ink); font: inherit; font-size: 13px; cursor: pointer; }}
.scroll {{ max-height: 520px; overflow: auto; border: 1px solid var(--grid); border-radius: 8px; }}
.cols-2 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }}
details summary {{ cursor: pointer; color: var(--ink-2); margin: 4px 0 8px; }}
.empty {{ color: var(--muted); }}
footer {{ color: var(--muted); font-size: 12px; margin-top: 24px; }}
footer ul {{ columns: 2; padding-left: 18px; }}
.theme-btn {{ float: right; }}
@media (max-width: 640px) {{ footer ul {{ columns: 1; }} .f-critical {{ margin: 0 -12px; padding: 12px; }} section {{ padding: 16px 12px; }} }}
@media print {{ .controls, .theme-btn {{ display: none; }} .scroll {{ max-height: none; }} }}
</style>
</head>
<body>
<div class="wrap">
{nav}
<header>
  <div class="controls theme-btn"><button type="button" id="themeBtn">테마 전환</button></div>
  <h1>{host} 로그 분석 리포트</h1>
  <div class="sub">원본: <span class="mono">{src}</span> · 생성: {gen} · {app} v{version}</div>
</header>

<section>
  <h2>시스템 정보</h2>
  <dl class="grid">{head_kv}</dl>
</section>

<div class="tiles">{tiles}</div>

<section>
  <h2>발견 사항 <small>자동 규칙 기반 · 최종 판단은 엔지니어가 확인</small></h2>
  {findings}
</section>

{flow_section}

{os_section}

<section>
  <h2>이벤트 타임라인 <small>{unit_label} 이벤트 수 · UTC</small></h2>
  <div class="legend">
    <span style="--c: var(--crit)">Error</span>
    <span style="--c: var(--warn)">Warning</span>
    <span style="--c: var(--info)">Info</span>
    <span class="mk" style="--c: var(--crit)">장애 추정 사건</span>
    <span class="mk" style="--c: var(--serious)">원인 미상 사건</span>
    <span class="mk" style="--c: var(--accent)">계획 작업 사건</span>
  </div>
  <div class="chart" id="chart"><svg id="chartSvg" role="img" aria-label="기간별 이벤트 수 누적 막대 차트"></svg>
    <div class="tip" id="tip"></div></div>
  <div class="hint">막대를 클릭하면 아래 전체 이벤트 표가 그 기간으로 필터링됩니다.</div>
</section>

<section>
  <h2>이벤트 유형별 요약</h2>
  <div class="tbl-wrap"><table>
    <thead><tr><th>등급</th><th>이벤트 ID</th><th>메시지</th><th class="num">건수</th><th>최초 (UTC)</th><th>최근 (UTC)</th></tr></thead>
    <tbody>{grp_rows}</tbody>
  </table></div>
</section>

<section id="events">
  <h2>전체 이벤트 <small>총 {n_events}건 · 이벤트 로그 + 감사 로그 통합</small></h2>
  <div class="controls">
    <input type="search" id="q" placeholder="메시지, 이벤트 ID 검색">
    <label><input type="checkbox" class="sevf" value="E" checked> Error</label>
    <label><input type="checkbox" class="sevf" value="W" checked> Warning</label>
    <label><input type="checkbox" class="sevf" value="I" checked> Info</label>
    <label><input type="checkbox" id="audit" checked> 감사 로그 포함</label>
    <label><input type="checkbox" id="osbox" checked> OS 로그 포함</label>
    <button type="button" id="reset">필터 초기화</button>
    <span class="small" id="count"></span>
  </div>
  <div class="scroll"><table>
    <thead><tr><th>시각 (UTC)</th><th>등급</th><th>ID</th><th>메시지</th></tr></thead>
    <tbody id="evBody"></tbody>
  </table></div>
</section>

<section>
  <h2>센서 <small>수집 시점 값</small></h2>
  <div class="tbl-wrap scroll"><table>
    <thead><tr><th>센서</th><th class="num">값</th><th>단위</th><th>상태</th><th class="num">하한 위험</th><th class="num">하한 경고</th><th class="num">상한 경고</th><th class="num">상한 위험</th></tr></thead>
    <tbody>{sensor_rows}</tbody>
  </table></div>
</section>

<div class="cols-2">
<section>
  <h2>펌웨어</h2>
  <div class="tbl-wrap"><table>
    <thead><tr><th>구분</th><th>버전</th><th>빌드</th><th>릴리스</th></tr></thead>
    <tbody>{fw_rows}</tbody>
  </table></div>
</section>
<section>
  <h2>부품(FRU) <small>{fru_summary}</small></h2>
  <details><summary>부품 목록 펼치기</summary>
  <div class="tbl-wrap"><table>
    <thead><tr><th>이름</th><th>FRU ID</th><th>Entity</th><th>상태</th></tr></thead>
    <tbody>{fru_rows}</tbody>
  </table></div></details>
</section>
</div>

<section>
  <h2>BMC 시스템 로그 오류 패턴 <small>오류 키워드가 들어간 줄을 묶음 · {n_patterns}개 패턴 (상위 100개 표시)</small></h2>
  <div class="tbl-wrap scroll"><table>
    <thead><tr><th>프로세스</th><th>패턴 (숫자→#, 16진수→&lt;hex&gt;)</th><th class="num">건수</th><th>최초</th><th>최근</th><th>파일</th></tr></thead>
    <tbody>{sys_rows}</tbody>
  </table></div>
  <details><summary>분석한 시스템 로그 파일</summary>
  <div class="tbl-wrap"><table>
    <thead><tr><th>파일</th><th class="num">줄 수</th><th class="num">오류 줄</th><th>처음</th><th>끝</th></tr></thead>
    <tbody>{sys_files}</tbody>
  </table></div></details>
</section>

<footer>
  분석에 사용한 파일
  <ul>{files_used}</ul>
</footer>
</div>

<script>
const DATA = {data_json};
(function () {{
  const root = document.documentElement;
  document.getElementById('themeBtn').addEventListener('click', () => {{
    const dark = root.dataset.theme ? root.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
  }});

  // ---------- 이벤트 표
  const body = document.getElementById('evBody');
  const q = document.getElementById('q');
  const auditBox = document.getElementById('audit');
  const osBox = document.getElementById('osbox');
  const countEl = document.getElementById('count');
  const SEV = {{E: 'Error', W: 'Warning', I: 'Info'}};
  let range = null;
  const escH = s => String(s).replace(/[&<>"]/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}}[c]));

  function render() {{
    const sev = new Set([...document.querySelectorAll('.sevf:checked')].map(x => x.value));
    const term = q.value.trim().toLowerCase();
    const rows = DATA.events.filter(e =>
      sev.has(e.s) && (auditBox.checked || e.k !== 'audit') && (osBox.checked || e.k !== 'os') &&
      (!term || e.m.toLowerCase().includes(term) || e.id.toLowerCase().includes(term)) &&
      (!range || (e.t.slice(0, 10) >= range[0] && e.t.slice(0, 10) <= range[1])));
    const shown = rows.slice(0, 2000);
    body.innerHTML = shown.map(e =>
      `<tr><td class="mono">${{e.t}}</td><td><span class="sev s-${{e.s}}">${{SEV[e.s]}}</span></td>` +
      `<td class="mono">${{escH(e.id || '-')}}</td><td>${{escH(e.m)}}${{e.k === 'audit' ? ' <span class="small">[감사]</span>' : e.k === 'os' ? ' <span class="src src-os">OS</span>' : ''}}</td></tr>`
    ).join('') || '<tr><td colspan="4" class="empty">조건에 맞는 이벤트가 없습니다.</td></tr>';
    countEl.textContent = `${{rows.length}}건` + (rows.length > shown.length ? ' (처음 2000건 표시)' : '') +
      (range ? ` · 기간 ${{range[0]}} ~ ${{range[1]}}` : '');
  }}
  q.addEventListener('input', render);
  auditBox.addEventListener('change', render);
  osBox.addEventListener('change', render);
  document.querySelectorAll('.sevf').forEach(x => x.addEventListener('change', render));
  document.getElementById('reset').addEventListener('click', () => {{
    q.value = ''; range = null; auditBox.checked = true; osBox.checked = true;
    document.querySelectorAll('.sevf').forEach(x => x.checked = true);
    render();
  }});
  render();

  // ---------- 타임라인 차트 (누적 막대)
  const svg = document.getElementById('chartSvg');
  const tip = document.getElementById('tip');
  const B = DATA.buckets;
  const NS = 'http://www.w3.org/2000/svg';
  const STACK = [['E', 'var(--crit)'], ['W', 'var(--warn)'], ['I', 'var(--info)']];
  function el(name, attrs, parent) {{
    const n = document.createElementNS(NS, name);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    parent.appendChild(n); return n;
  }}
  function niceMax(v) {{
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }}
  function topPath(x, y, w, h, r) {{
    r = Math.min(r, w / 2, h);
    return `M${{x}},${{y + h}}V${{y + r}}Q${{x}},${{y}} ${{x + r}},${{y}}H${{x + w - r}}Q${{x + w}},${{y}} ${{x + w}},${{y + r}}V${{y + h}}Z`;
  }}
  function draw() {{
    svg.innerHTML = '';
    if (!B.length) {{ el('text', {{x: 10, y: 20, fill: 'var(--muted)'}}, svg).textContent = '이벤트 없음'; return; }}
    const W = svg.clientWidth || 800, H = 250, L = 40, R = 8, T = 20, Bm = 26;
    svg.setAttribute('viewBox', `0 0 ${{W}} ${{H}}`);
    const max = niceMax(Math.max(...B.map(b => b.E + b.W + b.I)));
    const pw = W - L - R, ph = H - T - Bm, bw = pw / B.length;
    const y = v => T + ph - v / max * ph;
    const g = el('g', {{class: 'grid'}}, svg), ax = el('g', {{class: 'axis'}}, svg);
    for (let i = 0; i <= 4; i++) {{
      const v = max * i / 4, yy = y(v);
      if (i) el('line', {{x1: L, x2: W - R, y1: yy, y2: yy}}, g);
      el('text', {{x: L - 6, y: yy + 4, 'text-anchor': 'end'}}, ax).textContent = Math.round(v);
    }}
    const step = Math.max(1, Math.ceil(B.length / Math.max(2, Math.floor(pw / 80))));
    B.forEach((b, i) => {{
      if (i % step === 0) el('text', {{x: L + i * bw + bw / 2, y: H - 8, 'text-anchor': 'middle'}}, ax)
        .textContent = DATA.unit === 'month' ? b.start.slice(0, 7) : b.start.slice(5);
    }});
    const gap = bw > 6 ? 2 : 0, barW = Math.max(1, bw - Math.min(bw * 0.3, 8));
    B.forEach((b, i) => {{
      const x = L + i * bw + (bw - barW) / 2;
      let acc = 0;
      const segs = STACK.filter(([k]) => b[k] > 0);
      segs.forEach(([k, c], j) => {{
        const y0 = y(acc), y1 = y(acc + b[k]);
        acc += b[k];
        let h = y0 - y1 - (j ? gap : 0);
        if (h < 1) h = 1;
        const top = y0 - (j ? gap : 0) - h;
        if (j === segs.length - 1) el('path', {{d: topPath(x, top, barW, h, 4), fill: c}}, svg);
        else el('rect', {{x, y: top, width: barW, height: h, fill: c}}, svg);
      }});
      const inc = incidentsIn(b);
      if (inc.length) {{
        const k = ['fault', 'unexplained', 'planned'].find(k => inc.some(x => x.k === k));
        const cx = L + i * bw + bw / 2;
        el('path', {{d: `M${{cx - 5}},4H${{cx + 5}}L${{cx}},12Z`, fill: KCOLOR[k]}}, svg);
      }}
      const hit = el('rect', {{class: 'hit', x: L + i * bw, y: 0, width: bw, height: ph + T}}, svg);
      hit.addEventListener('mousemove', ev => showTip(ev, b));
      hit.addEventListener('mouseleave', () => tip.style.display = 'none');
      hit.addEventListener('click', () => {{
        range = [b.start, b.end]; render();
        document.getElementById('events').scrollIntoView({{behavior: 'smooth'}});
      }});
    }});
    el('line', {{class: 'baseline', x1: L, x2: W - R, y1: T + ph, y2: T + ph}}, svg);
  }}
  const KCOLOR = {{fault: 'var(--crit)', unexplained: 'var(--serious)', planned: 'var(--accent)'}};
  const KLABEL = {{fault: '장애 추정', unexplained: '원인 미상', planned: '계획 작업'}};
  function incidentsIn(b) {{
    return (DATA.incidents || []).filter(x => x.d >= b.start && x.d <= b.end);
  }}
  function showTip(ev, b) {{
    const label = b.start === b.end ? b.start : `${{b.start}} ~ ${{b.end}}`;
    tip.innerHTML = `<b>${{label}}</b>` + STACK.map(([k, c]) =>
      `<div class="row"><span><i style="background:${{c}}"></i>${{SEV[k]}}</span><b>${{b[k]}}</b></div>`).join('') +
      `<div class="row"><span>합계</span><b>${{b.E + b.W + b.I}}</b></div>` +
      incidentsIn(b).slice(0, 4).map(x =>
        `<div class="row"><span><i style="background:${{KCOLOR[x.k]}}"></i>${{KLABEL[x.k]}}</span><span>${{escH(x.h)}}</span></div>`).join('');
    tip.style.display = 'block';
    const box = svg.parentNode.getBoundingClientRect();
    let x = ev.clientX - box.left + 12;
    if (x + tip.offsetWidth > box.width) x = ev.clientX - box.left - tip.offsetWidth - 12;
    tip.style.left = Math.max(0, x) + 'px';
    tip.style.top = (ev.clientY - box.top - 10) + 'px';
  }}
  draw();
  addEventListener('resize', draw);
}})();
</script>
</body>
</html>
"""
