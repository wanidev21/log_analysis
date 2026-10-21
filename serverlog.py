#!/usr/bin/env python3
"""서버 로그 분석기 - 명령줄 실행 (BMC 덤프 + OS 로그).

    python serverlog.py <덤프 폴더 또는 압축 파일> [-o report.html] [--open] [--os-tz +09:00]

폴더/압축 안에 덤프가 여러 개 있으면 덤프마다 <덤프이름>_report.html 을 만든다.
지원 형식은 serverlog/vendors/ 의 파서가 정한다 (--formats 로 확인).
"""

import argparse
import os
import re
import sys
import webbrowser
from collections import Counter
from datetime import timedelta

from serverlog import APP_NAME, __version__, core, report, vendors


def main(argv=None):
    ap = argparse.ArgumentParser(description="%s v%s - 서버 로그 덤프 → HTML 리포트" % (APP_NAME, __version__))
    ap.add_argument("source", nargs="?", help="덤프 폴더 또는 압축 파일 (.tgz/.tar.gz/.zip/.tzz)")
    ap.add_argument("-o", "--output",
                    help="출력 HTML 경로. 덤프가 여러 개면 폴더로 보고 그 안에 만든다 (기본: 현재 폴더)")
    ap.add_argument("--open", action="store_true", help="생성 후 브라우저로 열기")
    ap.add_argument("--formats", action="store_true", help="지원 형식 목록 보기")
    ap.add_argument("--os-tz", metavar="+09:00",
                    help="OS 로그 시간대 (UTC 기준). 지정하지 않으면 sosreport → BMC 부팅 기록 정렬 순으로 자동 판단")
    for stream in (sys.stdout, sys.stderr):
        if not stream.isatty() and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = ap.parse_args(argv)
    tz_override = None
    if args.os_tz:
        m = re.fullmatch(r"(?:UTC)?([+-])(\d{1,2}):?(\d\d)?", args.os_tz.strip(), re.I)
        if not m:
            ap.error("--os-tz 는 +09:00 처럼 지정하세요.")
        tz_override = timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
        if m.group(1) == "-":
            tz_override = -tz_override

    if args.formats:
        for p in vendors.supported():
            print("%-12s %-7s %s (%s)" % (p["key"], p["vendor"], p["name"], p["products"]))
        return 0
    if not args.source:
        ap.error("덤프 폴더나 압축 파일을 지정하세요.")

    src = os.path.abspath(args.source)
    if not os.path.exists(src):
        ap.error("경로를 찾을 수 없습니다: %s" % src)
    try:
        results = core.analyze_all(src, tz_override)
    except (core.UnsupportedDump, core.ArchiveError) as e:
        print("오류: %s" % e, file=sys.stderr)
        return 2

    for ctx in results:
        if args.output and len(results) == 1 and not os.path.isdir(args.output):
            out = os.path.abspath(args.output)
        else:
            out = os.path.abspath(os.path.join(args.output or ".", "%s_report.html" % ctx["name"]))
        with open(out, "w", encoding="utf-8") as f:
            f.write(report.render_html(ctx, ctx["name"]))

        lv = Counter(x["level"] for x in ctx["findings"])
        print("리포트 생성: %s" % out)
        print("  형식: %s, 이벤트 %d건, 발견 사항: 심각 %d / 주의 %d / 참고 %d"
              % (("%s %s" % (ctx["vendor"], ctx["format"])).strip(), len(ctx["events"]),
                 lv["critical"], lv["warning"], lv["info"]))
        for x in ctx["findings"]:
            if x["level"] != "info":
                print("  [%s] %s" % (report.LEVEL_META[x["level"]][0], x["title"]))
        if args.open:
            webbrowser.open("file:///" + out.replace(os.sep, "/"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
