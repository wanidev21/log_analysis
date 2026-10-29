#!/usr/bin/env python3
"""서버 로그 분석기 - 웹 화면.

브라우저에 덤프 폴더나 .tgz/.zip 을 끌어다 놓으면 분석해서 리포트를 보여준다.
리포트는 reports/ 폴더에 쌓인다.

    python serverlog_web.py                  # 내 PC 전용 (127.0.0.1), 브라우저 자동 실행
    python serverlog_web.py --host 0.0.0.0   # 팀 공유 (사내망에서 접속)

표준 라이브러리만 사용한다.
"""

import argparse
import base64
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

APP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, APP_DIR)
from serverlog import APP_NAME, __version__, core, oslog, report, vendors  # noqa: E402
from serverlog.ui import CSS as UI_CSS, BRAND  # noqa: E402

APP_ID = "serverlog_web"
DEFAULT_PORT = 8765
MAX_UPLOAD = 1024 * 1024 * 1024  # 1GB
IDLE_EXIT_SEC = 30 * 60

REPORT_DIR = os.path.join(APP_DIR, "reports")
INDEX_PATH = os.path.join(REPORT_DIR, "index.json")
LOG_PATH = os.path.join(APP_DIR, "serverlog_web.log")
# 업로드로 받는 파일: BMC 파서가 쓰는 파일 + OS 로그. 경로 '끝부분'이 패턴과 맞으면 받는다.
UPLOAD_PATTERNS = vendors.input_patterns() + oslog.UPLOAD_PATTERNS
INPUT_RX = [re.compile(r"(?:^|/)" + re.escape(p).replace(r"\*", "[^/]*") + "$") for p in UPLOAD_PATTERNS]
index_lock = threading.Lock()
last_activity = time.time()


def log(msg):
    line = "%s %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass
    if sys.stdout and not sys.stdout.closed:
        try:
            sys.stdout.write(line)
        except (OSError, ValueError, UnicodeEncodeError):
            pass


# ---------------------------------------------------------------- 리포트 보관

def load_index():
    try:
        with open(INDEX_PATH, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def save_index(items):
    tmp = INDEX_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=1)
    os.replace(tmp, INDEX_PATH)


def safe_name(name):
    name = re.sub(r"[^\w.\-]+", "_", name, flags=re.UNICODE).strip("._")
    return name[:80] or "dump"


NAV_HTML = ('<div style="margin-bottom:12px"><a href="/" style="color:var(--accent);'
            'text-decoration:none;font-size:13px">&larr; 새 분석 / 리포트 목록</a></div>')


def save_report(ctx):
    """분석 결과로 리포트를 저장하고 목록 항목을 돌려준다."""
    name = ctx["name"]
    rid = datetime.now().strftime("%Y%m%d_%H%M%S_") + safe_name(name)
    with open(os.path.join(REPORT_DIR, rid + ".html"), "w", encoding="utf-8") as f:
        f.write(report.render_html(ctx, name, nav=NAV_HTML))
    lv = {"critical": 0, "warning": 0, "info": 0}
    for x in ctx["findings"]:
        lv[x["level"]] += 1
    sysi = ctx["system"]
    item = {
        "id": rid,
        "name": name,
        "vendor": ctx["vendor"],
        "format": ctx["format"],
        "host": sysi.get("host", ""),
        "model": sysi.get("model") or sysi.get("machine_type", ""),
        "serial": sysi.get("serial", ""),
        "dump_time": core.fmt_ts(sysi.get("collected")),
        "created": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "events": len(ctx["events"]),
        "findings": lv,
        "top": [x["title"] for x in ctx["findings"] if x["level"] != "info"][:3],
    }
    with index_lock:
        items = [i for i in load_index() if i["id"] != rid]
        items.insert(0, item)
        save_index(items)
    log("분석 완료: %s (%s %s) → %s" % (name, ctx["vendor"], ctx["format"], rid))
    return item


def accepted(rel):
    """올라온 파일을 받을지. 등록된 패턴이거나, 묶음 바로 아래(한 단계까지)의 압축 파일이면 받는다."""
    if not core.is_safe_relpath(rel):
        return False
    if any(rx.search(rel) for rx in INPUT_RX):
        return True
    return core.is_archive_name(rel) and rel.count("/") <= 1


def analyze_folder(payload):
    """브라우저가 골라 보낸 파일들로 폴더를 다시 만들어 분석한다 (BMC 덤프와 OS 로그를 함께)."""
    name = safe_name(payload.get("name") or "dump")
    files = payload.get("files") or {}
    tmp = tempfile.mkdtemp(prefix="serverlog_web_")
    root = os.path.join(tmp, name)  # 폴더 이름에 수집 시각이 들어 있으므로 그대로 살린다
    try:
        for rel, b64 in files.items():
            if not accepted(rel):  # 정해진 파일만 받는다 (경로 조작 방지)
                continue
            dest = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(base64.b64decode(b64))
        return [save_report(ctx) for ctx in core.analyze_all(root)]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def analyze_archive(filename, data):
    work = tempfile.mkdtemp(prefix="serverlog_web_")
    try:
        # 원래 파일 이름을 살려 저장해야 압축 안에 상위 폴더가 없어도 덤프 이름을 알 수 있다
        arc = os.path.join(work, safe_name(os.path.basename(filename)))
        with open(arc, "wb") as f:
            f.write(data)
        try:
            results = core.analyze_all(arc)
        except core.ArchiveError as e:
            log("압축 해제 실패 (%s): %r" % (filename, e))
            raise ValueError("압축을 풀 수 없습니다. .tgz / .tar.gz / .tar.xz / .zip / .tzz 파일이 맞는지 확인하세요.")
        return [save_report(ctx) for ctx in results]
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "ServerLog/" + __version__
    local_only = True

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        # 내 PC 전용 모드에서는 다른 사이트가 localhost 로 접근하는 것(DNS rebinding)을 막는다
        if not self.local_only:
            return True
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in ("127.0.0.1", "localhost", "::1")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            raise ValueError("업로드가 너무 큽니다 (최대 1GB).")
        return self.rfile.read(n)

    def do_GET(self):
        global last_activity
        last_activity = time.time()
        if not self._host_ok():
            return self._send(403, {"error": "forbidden"})
        path = urlparse(self.path).path
        if path == "/":
            cfg = json.dumps({"files": UPLOAD_PATTERNS, "local": self.local_only,
                              "version": __version__, "app": APP_NAME,
                              "formats": vendors.supported()}, ensure_ascii=False)
            return self._send(200, INDEX_HTML.replace("__CONFIG__", cfg), "text/html; charset=utf-8")
        if path == "/api/ping":
            return self._send(200, {"app": APP_ID, "version": __version__})
        if path == "/api/reports":
            return self._send(200, load_index())
        m = re.fullmatch(r"/reports/([\w.\-]+)\.html", path)
        if m:
            p = os.path.join(REPORT_DIR, m.group(1) + ".html")
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    data = f.read()
                q = parse_qs(urlparse(self.path).query)
                extra = {}
                if "download" in q:
                    extra["Content-Disposition"] = 'attachment; filename="%s.html"' % m.group(1)
                return self._send(200, data, "text/html; charset=utf-8", extra)
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        global last_activity
        last_activity = time.time()
        # 본문을 먼저 받아야 거부 응답을 보내도 클라이언트 연결이 끊기지 않는다
        try:
            body = self._body()
        except ValueError as e:
            self.close_connection = True
            return self._send(413, {"error": str(e)})
        # 사용자 지정 헤더를 요구해 다른 사이트의 단순 POST(CSRF)를 막는다
        if not self._host_ok() or self.headers.get("X-ServerLog") != "1":
            return self._send(403, {"error": "forbidden"})
        path = urlparse(self.path).path
        try:
            if path == "/api/analyze/folder":
                return self._send(200, {"items": analyze_folder(json.loads(body.decode("utf-8")))})
            if path == "/api/analyze/archive":
                fn = parse_qs(urlparse(self.path).query).get("name", ["dump.tgz"])[0]
                return self._send(200, {"items": analyze_archive(fn, body)})
            if path == "/api/reports/delete":
                rid = json.loads(body.decode("utf-8")).get("id", "")
                if not re.fullmatch(r"[\w.\-]+", rid):
                    return self._send(400, {"error": "잘못된 ID"})
                with index_lock:
                    save_index([i for i in load_index() if i["id"] != rid])
                try:
                    os.remove(os.path.join(REPORT_DIR, rid + ".html"))
                except OSError:
                    pass
                return self._send(200, {"ok": True})
            if path == "/api/shutdown":
                if not self.local_only:
                    return self._send(403, {"error": "공유 모드에서는 화면에서 종료할 수 없습니다."})
                self._send(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                log("화면에서 종료")
                return None
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:  # 분석 중 예상하지 못한 오류
            log("오류: %r" % e)
            return self._send(500, {"error": "분석 중 오류가 발생했습니다: %s" % e})
        return self._send(404, {"error": "not found"})


def idle_watchdog(server):
    while True:
        time.sleep(60)
        if time.time() - last_activity > IDLE_EXIT_SEC:
            log("%d분 동안 사용하지 않아 종료" % (IDLE_EXIT_SEC // 60))
            server.shutdown()
            return


def already_running(port):
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/ping" % port, timeout=1) as r:
            return json.loads(r.read().decode()).get("app") == APP_ID
    except Exception:
        return False


def port_free(host, port):
    with socket.socket() as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="%s - 웹 화면" % APP_NAME)
    ap.add_argument("--host", default="127.0.0.1",
                    help="접속을 받을 주소. 팀 공유 시 0.0.0.0 (기본: 127.0.0.1, 내 PC 전용)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true", help="브라우저를 자동으로 열지 않음")
    ap.add_argument("--no-idle-exit", action="store_true", help="30분 미사용 시 자동 종료하지 않음")
    args = ap.parse_args(argv)

    local = args.host in ("127.0.0.1", "localhost", "::1")
    url = "http://127.0.0.1:%d/" % args.port

    if already_running(args.port):
        if not args.no_browser:
            webbrowser.open(url)
        return 0
    if not port_free(args.host, args.port):
        log("포트 %d 가 다른 프로그램에서 사용 중입니다. --port 로 바꾸세요." % args.port)
        return 1

    os.makedirs(REPORT_DIR, exist_ok=True)
    Handler.local_only = local
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    log("시작: http://%s:%d/ (%s)" % (args.host, args.port, "내 PC 전용" if local else "공유 모드"))
    if local and not args.no_idle_exit:
        threading.Thread(target=idle_watchdog, args=(server,), daemon=True).start()
    if not args.no_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>서버 로그 분석기</title>
<style>
:root {
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10); --accent: #2a78d6;
  --accent-bg: rgba(42,120,214,0.08); --crit: #d03b3b; --warn: #fab219; --info: #898781;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10); --accent: #3987e5;
    --accent-bg: rgba(57,135,229,0.12);
  }
}
:root[data-theme="dark"] {
  --page: #0d0d0d; --surface: #1a1a19; --ink: #f0efec; --ink-2: #c3c2b7;
  --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10); --accent: #3987e5;
  --accent-bg: rgba(57,135,229,0.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink);
  font: 14px/1.55 "Pretendard", "Malgun Gothic", "Apple SD Gothic Neo", system-ui, sans-serif; }
.wrap { max-width: 960px; margin: 0 auto; padding: 32px 16px 64px; }
header { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
h1 { font-size: 22px; margin: 0; }
.sub { color: var(--ink-2); font-size: 13px; }
button { font: inherit; font-size: 13px; padding: 7px 12px; border-radius: 8px; cursor: pointer;
  border: 1px solid var(--axis); background: var(--surface); color: var(--ink); }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
button:disabled { opacity: .5; cursor: default; }
.drop { margin-top: 20px; border: 2px dashed var(--axis); border-radius: 14px; background: var(--surface);
  padding: 44px 20px; text-align: center; transition: background .15s, border-color .15s; }
.drop.over { border-color: var(--accent); background: var(--accent-bg); }
.drop .big { font-size: 18px; font-weight: 600; margin-bottom: 6px; }
.drop .btns { margin-top: 16px; display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; }
.status { margin-top: 14px; min-height: 22px; font-size: 13px; }
.status.err { color: var(--crit); }
.spin { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--grid);
  border-top-color: var(--accent); border-radius: 50%; animation: s 0.8s linear infinite; vertical-align: -2px; margin-right: 6px; }
@keyframes s { to { transform: rotate(360deg); } }
section { margin-top: 28px; }
h2 { font-size: 16px; margin: 0 0 10px; }
.list { display: grid; gap: 10px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px;
  display: grid; grid-template-columns: 1fr auto; gap: 6px 16px; align-items: start; }
.card a.title { color: var(--ink); font-weight: 600; text-decoration: none; font-size: 15px; }
.card a.title:hover { color: var(--accent); }
.meta { color: var(--muted); font-size: 12px; }
.mono { font-family: Consolas, "D2Coding", ui-monospace, monospace; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.chip { font-size: 12px; padding: 1px 8px; border-radius: 10px; border: 1px solid var(--border); white-space: nowrap; }
.chip::before { content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; background: var(--c); }
.top { font-size: 12px; color: var(--ink-2); margin: 4px 0 0; padding-left: 16px; }
.actions { display: flex; gap: 6px; }
.actions a, .actions button { font-size: 12px; padding: 5px 9px; }
.actions a { border: 1px solid var(--axis); border-radius: 8px; color: var(--ink); text-decoration: none; }
.empty { color: var(--muted); }
footer { margin-top: 36px; color: var(--muted); font-size: 12px; }
@media (max-width: 560px) { .card { grid-template-columns: 1fr; } }
__UI_CSS__
</style>
<script>try { const t=localStorage.getItem('serverlog-theme'); if(t==='light'||t==='dark')document.documentElement.dataset.theme=t; } catch(e) {}</script>
</head>
<body>
<aside class="app-sidebar" aria-label="메뉴">
  <a class="app-brand" href="#upload">__BRAND__<span>ServerLog</span></a>
  <div class="sidebar-caption">SERVER DIAGNOSTICS</div>
  <div class="side-label">워크스페이스</div>
  <nav class="side-links"><a class="active" href="#upload"><b>01</b> 새 분석</a><a href="#history"><b>02</b> 분석 기록</a></nav>
  <div class="side-label">지원 자료</div>
  <div class="side-note">Lenovo IMM2 · XCC<br>Linux OS 로그 · sosreport<br><br>BMC와 OS 기록을 함께 확인</div>
  <div class="side-bottom"><span class="local-dot"></span><span id="modeLabel">로컬 분석</span><br>로그는 실행 중인 PC에서 분석합니다.</div>
</aside>
<main class="app-main">
<div class="wrap">
  <div class="topbar">
    <div class="breadcrumb">워크스페이스 &nbsp;/&nbsp; <b>새 분석</b></div>
    <div class="toolbar"><span class="version" id="versionLabel"></span>
      <button type="button" id="theme" aria-label="밝은 테마와 어두운 테마 전환">테마 전환</button>
      <button type="button" id="quit">종료</button>
    </div>
  </div>
  <header class="page-heading" id="upload"><div class="eyebrow">BMC + OS LOG ANALYSIS</div>
    <h1>서버 로그 분석기</h1>
    <div class="sub">BMC와 OS 기록을 연결해, 장애 발생 전후의 흐름을 확인하세요.</div>
  </header>
  <div class="upload-grid">
  <div class="drop" id="drop">
    <div class="upload-icon" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 16V3m-5 5 5-5 5 5M4 15v5h16v-5"/></svg></div>
    <div class="big">분석할 로그를 여기에 놓으세요</div>
    <div class="sub">BMC 덤프와 OS 로그를 함께 선택하면 같은 서버의 자료를 연결합니다.<br>폴더 또는 압축 파일을 선택할 수 있습니다.</div>
    <div class="btns">
      <button type="button" class="primary" id="pickDir">폴더 선택</button>
      <button type="button" id="pickFile">파일 선택</button>
    </div>
    <input type="file" id="dirInput" webkitdirectory multiple hidden>
    <input type="file" id="fileInput" multiple hidden>
    <div class="format-tags" aria-label="지원 자료"><span>IMM2 / XCC</span><span>SOSREPORT</span><span>SYSLOG / DMESG</span></div>
    <div class="status" id="status" role="status" aria-live="polite"></div>
  </div>
  <aside class="workflow-card" aria-label="분석 순서"><h2>분석은 이렇게 진행됩니다</h2>
    <div class="workflow-step"><span>1</span><div><b>자료 연결</b><p>서버와 로그 형식을 식별합니다.</p></div></div>
    <div class="workflow-step"><span>2</span><div><b>시간축 정리</b><p>BMC·OS 기록을 UTC 기준으로 맞춥니다.</p></div></div>
    <div class="workflow-step"><span>3</span><div><b>사건 흐름 확인</b><p>원인 후보와 결과·복구 기록을 함께 봅니다.</p></div></div>
  </aside>
  </div>
  <section class="history-panel" id="history">
    <div class="section-head"><h2>분석 기록 <span class="count-pill" id="reportCount">0</span></h2>
      <div class="list-controls"><input id="historySearch" type="search" placeholder="호스트명, 시리얼, 파일 검색" aria-label="분석 기록 검색">
        <select id="historyFilter" aria-label="분석 기록 필터"><option value="all">전체 리포트</option><option value="critical">심각 항목 포함</option><option value="warning">주의 항목 포함</option></select></div>
    </div>
    <div class="list" id="list"><div class="empty">불러오는 중…</div></div>
  </section>

  <footer id="foot"></footer>
</div>
</main>
<script>
const CFG = __CONFIG__;
const $ = id => document.getElementById(id);
const statusEl = $('status');
const H = {'X-ServerLog': '1'};
const escH = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let busy = false;
let reportItems = [];
$('versionLabel').textContent = `v${CFG.version}`;
$('modeLabel').textContent = CFG.local ? '내 PC 전용' : '공유 모드';

$('foot').textContent = `${CFG.app} v${CFG.version} · 지원 형식: ` +
  CFG.formats.map(f => `${f.vendor} ${f.name}`).join(', ') + ' · ' +
  (CFG.local ? '내 PC 전용 모드 · 30분 동안 사용하지 않으면 자동 종료' : '공유 모드');
if (!CFG.local) $('quit').hidden = true;

$('theme').onclick = () => {
  const r = document.documentElement;
  const dark = r.dataset.theme ? r.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  r.dataset.theme = dark ? 'light' : 'dark';
  try { localStorage.setItem('serverlog-theme',r.dataset.theme); } catch(e) {}
};
$('quit').onclick = async () => {
  try { await fetch('/api/shutdown', {method: 'POST', headers: H}); } catch (e) {}
  document.body.innerHTML = '<div class="wrap"><h1>분석기를 종료했습니다.</h1>' +
    '<p class="sub">다시 쓰려면 바로가기를 더블클릭하세요. 이 탭은 닫아도 됩니다.</p></div>';
};

function setStatus(html, err) {
  statusEl.className = 'status' + (err ? ' err' : '');
  statusEl.innerHTML = html;
}

// ---------- 리포트 목록
async function loadList() {
  try {
    const response = await fetch('/api/reports');
    if (!response.ok) throw new Error('load failed');
    reportItems = await response.json();
    renderList();
  } catch(e) {
    $('list').innerHTML = '<div class="empty-state"><strong>분석 기록을 불러오지 못했습니다.</strong>연결 상태를 확인하고 다시 열어주세요.</div>';
  }
}
function renderList() {
  const q = $('historySearch').value.trim().toLowerCase();
  const filter = $('historyFilter').value;
  const items = reportItems.filter(i => [i.host,i.serial,i.name,i.model].join(' ').toLowerCase().includes(q) &&
    (filter === 'all' || (i.findings || {})[filter] > 0));
  $('reportCount').textContent = q || filter !== 'all' ? `${items.length} / ${reportItems.length}` : reportItems.length;
  const list = $('list');
  if (!items.length) { list.innerHTML = reportItems.length
    ? '<div class="empty-state"><strong>조건에 맞는 분석 기록이 없습니다.</strong>검색어나 필터를 변경해 보세요.</div>'
    : '<div class="empty-state"><strong>첫 번째 분석을 시작해 보세요.</strong>로그를 선택하면 분석 결과가 여기에 보관됩니다.</div>'; return; }
  list.innerHTML = items.map(i => {
    const f = i.findings || {};
    const chip = (n, label, c) => `<span class="chip ${n ? label === '심각' ? 'chip-critical' : '' : 'chip-zero'}" style="--c:${c}">${label} ${n}</span>`;
    return `<div class="card">
      <div>
        <a class="title" href="/reports/${encodeURIComponent(i.id)}.html">${escH(i.host || i.serial || i.name)}</a>
        <span class="meta">${escH([i.vendor, i.model].filter(Boolean).join(' '))} · S/N ${escH(i.serial || '-')}</span>
        <div class="meta mono">${escH(i.name)}</div>
        <div class="chips">${chip(f.critical || 0, '심각', 'var(--crit)')}${chip(f.warning || 0, '주의', 'var(--warn)')}${chip(f.info || 0, '참고', 'var(--info)')}
          <span class="meta">이벤트 ${i.events}건 · 수집 ${escH(i.dump_time || '-')} UTC · 분석 ${escH(i.created)}</span></div>
        ${(i.top || []).length ? '<ul class="top">' + i.top.slice(0,2).map(t => `<li>${escH(t)}</li>`).join('') + '</ul>' : ''}
      </div>
      <div class="actions">
        <a href="/reports/${encodeURIComponent(i.id)}.html">열기</a>
        <a href="/reports/${encodeURIComponent(i.id)}.html?download=1">저장</a>
        <button type="button" data-del="${escH(i.id)}">삭제</button>
      </div>
    </div>`;
  }).join('');
  list.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
    b.disabled = true;
    await fetch('/api/reports/delete', {method: 'POST', headers: {...H, 'Content-Type': 'application/json'},
      body: JSON.stringify({id: b.dataset.del})});
    loadList();
  });
}
$('historySearch').addEventListener('input',renderList);
$('historyFilter').addEventListener('change',renderList);

// ---------- 업로드
const isArchive = n => /\.(tgz|tar\.gz|tar\.xz|txz|tar\.bz2|tbz2|tar|zip|tzz|lzo)$/i.test(n);
// 서버가 받는 파일 패턴 ('*' 는 경로 구분자를 넘지 않음). 경로 '끝부분'이 맞으면 올린다.
const PATTERNS = CFG.files.map(p => new RegExp('(?:^|/)' +
  p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '$'));
const wanted = rel => PATTERNS.some(rx => rx.test(rel)) || (isArchive(rel) && rel.split('/').length <= 2);

// 끌어다 놓은 항목(폴더) 하나가 한 묶음. 낱개 파일들은 모두 한 묶음으로 합친다.
function groupItems(entries) {
  const groups = new Map();
  for (const {path, file} of entries) {
    const cut = path.indexOf('/');
    const name = cut < 0 ? '' : path.slice(0, cut);
    const rel = cut < 0 ? path : path.slice(cut + 1);
    if (!wanted(rel)) continue;
    if (!groups.has(name)) groups.set(name, {});
    groups.get(name)[rel] = file;
  }
  return [...groups.entries()].map(([name, files]) => ({name: name || 'upload', files}));
}

function toB64(file) {
  return new Promise((ok, fail) => {
    const r = new FileReader();
    r.onload = () => ok(String(r.result).split(',', 2)[1] || '');
    r.onerror = () => fail(r.error);
    r.readAsDataURL(file);
  });
}

async function post(url, body, json) {
  const res = await fetch(url, {method: 'POST', body,
    headers: json ? {...H, 'Content-Type': 'application/json'} : {...H, 'Content-Type': 'application/octet-stream'}});
  const data = await res.json().catch(() => ({error: '서버 응답을 읽을 수 없습니다.'}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function processAll(entries) {
  if (busy) return;
  const loose = entries.filter(e => !e.path.includes('/'));
  let jobs;
  if (loose.length === 1 && entries.length === 1 && isArchive(loose[0].file.name)) {
    // 압축 파일 하나만 놓았으면 그대로 보낸다 (큰 파일도 부담 없이)
    const a = loose[0];
    jobs = [{label: a.file.name, run: () =>
      post('/api/analyze/archive?name=' + encodeURIComponent(a.file.name), a.file, false)}];
  } else {
    jobs = groupItems(entries).map(g => ({label: g.name === 'upload' ? Object.keys(g.files).join(', ') : g.name,
      run: async () => {
        const files = {};
        for (const [rel, f] of Object.entries(g.files)) files[rel] = await toB64(f);
        return post('/api/analyze/folder', JSON.stringify({name: g.name, files}), true);
      }}));
  }
  if (!jobs.length) {
    setStatus('지원하는 BMC 덤프나 OS 로그를 찾지 못했습니다. 지원 형식: ' +
      escH(CFG.formats.map(f => `${f.vendor} ${f.name}`).join(', ')) + ', Linux OS 로그(sosreport, messages, dmesg)', true);
    return;
  }
  busy = true;
  const done = [], errors = [];
  for (const [i, job] of jobs.entries()) {
    setStatus(`<span class="spin"></span>${i + 1}/${jobs.length} 분석 중: ${escH(job.label)}`);
    try { done.push(...(await job.run()).items); }
    catch (e) { errors.push(`${escH(job.label)}: ${escH(e.message)}`); }
  }
  busy = false;
  await loadList();
  if (done.length === 1 && !errors.length) { location.href = `/reports/${encodeURIComponent(done[0].id)}.html`; return; }
  setStatus((done.length ? `${done.length}건 분석 완료. 아래 목록에서 여세요.` : '') +
    (errors.length ? '<br>실패: ' + errors.join('<br>') : ''), errors.length > 0);
}

// 끌어다 놓은 폴더를 재귀로 펼친다
function readEntry(entry, path) {
  return new Promise(resolve => {
    if (entry.isFile) {
      entry.file(f => resolve([{path: path + f.name, file: f}]), () => resolve([]));
    } else if (entry.isDirectory) {
      const reader = entry.createReader(), all = [];
      const next = () => reader.readEntries(async batch => {
        if (!batch.length) {
          const nested = await Promise.all(all.map(e => readEntry(e, path + entry.name + '/')));
          resolve(nested.flat());
        } else { all.push(...batch); next(); }
      }, () => resolve([]));
      next();
    } else resolve([]);
  });
}

const drop = $('drop');
['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove('over'); }));
addEventListener('dragover', e => e.preventDefault());
addEventListener('drop', e => e.preventDefault());
drop.addEventListener('drop', async e => {
  const items = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  setStatus('<span class="spin"></span>파일 목록을 읽는 중…');
  const entries = (await Promise.all(items.map(it => readEntry(it, '')))).flat();
  processAll(entries);
});
$('pickDir').onclick = () => $('dirInput').click();
$('pickFile').onclick = () => $('fileInput').click();
$('dirInput').onchange = e => { processAll([...e.target.files].map(f => ({path: f.webkitRelativePath, file: f}))); e.target.value = ''; };
$('fileInput').onchange = e => { processAll([...e.target.files].map(f => ({path: f.name, file: f}))); e.target.value = ''; };

loadList();
</script>
</body>
</html>
"""

INDEX_HTML = INDEX_HTML.replace('__UI_CSS__', UI_CSS).replace('__BRAND__', BRAND)


if __name__ == "__main__":
    sys.exit(main())
