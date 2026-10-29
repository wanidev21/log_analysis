"""웹 화면과 독립 HTML 리포트가 공유하는 화면 스타일. 외부 자원 없이 동작한다."""

CSS = r"""
:root {
 --page:#f1f5f8;--surface:#fff;--ink:#152b3c;--ink-2:#4d6475;--muted:#687f90;
 --grid:#e3eaf0;--axis:#c4d1db;--border:#dde6ed;--accent:#087f8c;--accent-bg:#e8f5f4;
 --crit:#cf4555;--warn:#bd7a14;--good:#168268;--info:#7991a1;--serious:#b57932;
 --crit-bg:#fdf0f2;--warn-bg:#fff7e8;--nav:#132c3e;--shadow:0 8px 30px rgba(20,46,64,.04);
}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){
 --page:#101e29;--surface:#192c39;--ink:#e2edf3;--ink-2:#b0c4d1;--muted:#94acbc;
 --grid:#2b4352;--axis:#506b7d;--border:#304957;--accent:#56cccb;--accent-bg:#183c43;
 --crit:#fa8291;--warn:#edbd70;--good:#6bd1ad;--info:#91aab9;--serious:#e5b170;
 --crit-bg:#3a2631;--warn-bg:#382f23;--nav:#0e1d28;--shadow:none;
}}
:root[data-theme=dark]{
 --page:#101e29;--surface:#192c39;--ink:#e2edf3;--ink-2:#b0c4d1;--muted:#94acbc;
 --grid:#2b4352;--axis:#506b7d;--border:#304957;--accent:#56cccb;--accent-bg:#183c43;
 --crit:#fa8291;--warn:#edbd70;--good:#6bd1ad;--info:#91aab9;--serious:#e5b170;
 --crit-bg:#3a2631;--warn-bg:#382f23;--nav:#0e1d28;--shadow:none;
}
html{scroll-behavior:smooth;scroll-padding-top:84px}
body{font-family:'Segoe UI','Malgun Gothic','Apple SD Gothic Neo',sans-serif;line-height:1.65;letter-spacing:-.02em}
button,input,select{font:inherit}button,a,input,select{touch-action:manipulation}
button,a,input,select,summary{-webkit-tap-highlight-color:transparent}
:focus-visible{outline:3px solid var(--accent);outline-offset:3px}
button{transition:border-color .15s;min-height:36px}
button:hover:not(:disabled),.actions a:hover{border-color:var(--accent);background:var(--accent-bg)}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--surface);font-weight:600}
button.primary:hover:not(:disabled){background:var(--ink);border-color:var(--ink);color:var(--surface)}
.app-sidebar{position:fixed;inset:0 auto 0 0;width:212px;background:var(--nav);color:#ecf5f8;display:flex;flex-direction:column;padding:29px 18px;z-index:10}
.app-brand{display:flex;align-items:center;gap:11px;text-decoration:none;color:inherit;font-size:18px;font-weight:700;letter-spacing:.01em}
.brand-mark{display:grid;gap:4px;width:27px;flex:none}.brand-mark i{height:7px;border:1.5px solid #70d6d2;border-radius:2px;position:relative}.brand-mark i:after{content:'';position:absolute;width:4px;height:2px;right:3px;top:1px;background:#70d6d2}
.sidebar-caption{font-size:10px;letter-spacing:.15em;color:#9cb8c9;margin:8px 0 37px 38px}
.side-label{font-size:10px;letter-spacing:.12em;color:#9cb8c9;margin:23px 12px 9px}
.side-links{display:grid;gap:5px}.side-links a{display:flex;gap:10px;align-items:center;color:#c7d9e3;text-decoration:none;padding:11px 12px;border-radius:7px;font-size:13px}
.side-links a:hover{background:#233f50;color:white}.side-links a.active{background:#254957;color:#8ee3dc;box-shadow:inset 3px 0 #70d6d2}
.side-links a b{font-family:Consolas,monospace;font-size:11px;color:#8facbe;font-weight:400}
.side-note{padding:13px 12px;border:1px solid #365264;border-radius:7px;color:#b7ceda;font-size:11px;line-height:1.9}
.side-bottom{margin-top:auto;padding-top:24px;font-size:11px;color:#a1bdcb}
.local-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#70d6b0;margin-right:7px}
.app-main{margin-left:212px;min-width:0}.wrap{max-width:1260px;margin:0 auto;padding:28px 38px 52px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:30px;min-height:35px}
.breadcrumb{font-size:12px;color:var(--muted)}.breadcrumb b{color:var(--ink);font-weight:600}
.toolbar{display:flex;gap:7px;align-items:center}.toolbar button{background:var(--surface);border:1px solid var(--border);border-radius:7px;color:var(--ink-2);padding:5px 11px;font-size:12px}
.version{font:11px Consolas,monospace;background:var(--surface);border:1px solid var(--border);border-radius:5px;padding:4px 7px;color:var(--muted)}
.eyebrow{font-size:10px;font-weight:700;letter-spacing:.16em;color:var(--accent);margin-bottom:8px}
.page-heading{display:block;margin:0 0 25px}.page-heading h1{font-size:30px;line-height:1.35;letter-spacing:-.045em;margin:0 0 10px;color:var(--ink)}
.page-heading .sub{font-size:13px;color:var(--ink-2);max-width:750px}
.upload-grid{display:grid;grid-template-columns:minmax(0,1fr) 240px;gap:18px;align-items:stretch}
.drop{margin:0;padding:26px 24px 15px;border:1.5px dashed var(--axis);border-radius:12px;background:var(--surface);box-shadow:var(--shadow);transition:border-color .15s}
.upload-icon{display:grid;place-items:center;margin:0 auto 13px;width:44px;height:44px;border-radius:12px;background:var(--accent-bg);color:var(--accent)}
.drop .big{font-size:18px;font-weight:650;line-height:1.5;margin:0 0 7px}.drop .sub{font-size:12px;line-height:1.8;max-width:520px;margin:auto}
.drop .btns{margin-top:20px;gap:9px}.drop .btns button{padding:8px 17px;border-radius:7px;font-size:12px}
.drop .status{min-height:19px;margin-top:10px;font-size:12px;overflow-wrap:anywhere}
.format-tags{display:flex;justify-content:center;gap:7px;flex-wrap:wrap;margin-top:15px}.format-tags span{font:10px Consolas,monospace;color:var(--muted);background:var(--page);border:1px solid var(--grid);padding:2px 7px;border-radius:4px}
.workflow-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:21px 21px 12px;box-shadow:var(--shadow)}
.workflow-card h2{font-size:13px;margin:0 0 16px}.workflow-step{display:grid;grid-template-columns:24px 1fr;gap:10px;padding-bottom:18px;position:relative}
.workflow-step:not(:last-child):before{content:'';position:absolute;left:11px;top:26px;bottom:4px;border-left:1px solid var(--grid)}
.workflow-step>span{font:11px Consolas,monospace;display:grid;place-items:center;background:var(--accent-bg);color:var(--accent);width:24px;height:24px;border-radius:50%}
.workflow-step b{font-size:12px;font-weight:600}.workflow-step p{font-size:11px;color:var(--muted);margin:3px 0 0;line-height:1.7}
.history-panel{margin-top:30px}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px;flex-wrap:wrap}
.section-head h2{font-size:16px;margin:0}.count-pill{display:inline-flex;align-items:center;justify-content:center;min-width:23px;border-radius:5px;font:11px Consolas,monospace;background:var(--accent-bg);color:var(--accent);padding:3px 6px;margin-left:6px}
.list-controls{display:flex;gap:8px;flex-wrap:wrap}.list-controls input,.list-controls select{background:var(--surface);border:1px solid var(--border);border-radius:7px;padding:8px 11px;color:var(--ink);font-size:12px;max-width:100%}.list-controls input{width:230px}
.list{gap:9px}.card{border-radius:9px;box-shadow:0 2px 7px rgba(20,46,64,.02);padding:17px 18px;min-width:0}.card:has(.chip-critical){border-left:3px solid var(--crit)}
.card a.title{font-size:15px;letter-spacing:-.01em;display:inline-block;margin-right:9px}.card .meta{font-size:11px;overflow-wrap:anywhere}.card .mono{margin-top:3px;white-space:normal;font-size:10px}.card .chips{align-items:center;gap:7px;margin-top:10px}
.chip{border-radius:5px;font-size:10px;padding:2px 7px}.chip::before{width:5px;height:5px}.chip-zero{opacity:.65}.top{font-size:11px;line-height:1.8;margin-top:8px}.actions a,.actions button{border-radius:6px;font-size:11px;padding:5px 9px;min-height:30px}.actions a:first-child{background:var(--accent-bg);color:var(--accent);border-color:transparent;font-weight:600}
.empty-state{text-align:center;border:1px dashed var(--axis);border-radius:10px;padding:35px 18px;background:var(--surface);color:var(--muted);font-size:12px}.empty-state strong{display:block;color:var(--ink-2);font-size:14px;margin-bottom:6px}
.report-heading h1{font:700 29px/1.3 'Segoe UI','Malgun Gothic',sans-serif;overflow-wrap:anywhere}.report-heading .sub{overflow-wrap:anywhere}.report-heading .mono{white-space:normal;font-size:11px}
.report-nav{display:flex;gap:6px;flex-wrap:wrap;margin:20px 0 23px}.report-nav a{text-decoration:none;color:var(--ink-2);background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:6px 11px;font-size:11px}.report-nav a:hover{color:var(--accent);border-color:var(--accent)}
.incident-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.incident-metric{background:var(--surface);border:1px solid var(--border);border-radius:9px;padding:16px 18px;position:relative;box-shadow:var(--shadow)}.incident-metric label{font-size:11px;color:var(--ink-2)}.incident-metric strong{display:block;font:500 30px/1.3 Consolas,monospace;margin-top:8px;color:var(--mc,var(--ink))}.incident-metric:before{content:'';position:absolute;top:17px;right:15px;width:6px;height:6px;border-radius:50%;background:var(--mc,var(--accent))}
.report-main section{border-radius:11px;padding:23px 24px;margin-top:20px;box-shadow:var(--shadow);min-width:0}.report-main h2{font-size:16px;line-height:1.65;margin-bottom:16px}.report-main h2 small{display:block;margin:3px 0 0;font-size:11px;line-height:1.8}
.report-main .flow-sum .chip{font-size:11px;border-radius:5px;background:var(--page)}.report-main .flow-notes{font-size:11px;background:var(--page);padding:12px 15px 12px 30px;line-height:1.85}.inc{border-radius:7px;padding:16px 18px;margin-bottom:14px}.inc-title{font-size:15px;margin:9px 0 7px;line-height:1.6}.inc-head{font-size:11px;gap:7px}.kbadge{border-radius:4px;font-size:10px;padding:2px 7px}.inc-verdict{font-size:13px;line-height:1.9}.inc-notes{font-size:11px;line-height:1.85}.report-main details summary{font-size:12px;color:var(--accent);padding:5px 0}
.report-main .finding{padding-top:16px;padding-bottom:16px}.report-main .f-critical{margin-left:-24px;margin-right:-24px;padding-left:24px;padding-right:24px}.f-body{min-width:0;overflow-wrap:anywhere}.f-title{font-size:13px}.f-detail,.why,.finding ul{font-size:12px}.badge{border-radius:5px;font-size:10px}.kbadge{color:var(--surface)}.report-main .tile{border-radius:7px;box-shadow:none;padding:13px}.report-main .tiles{margin-top:0;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:9px}.tile-value{font:500 26px Consolas,monospace;margin:6px 0}.tile-sub,.tile-label{font-size:10px}
.report-main th{font-size:11px;padding:9px 10px;background:var(--page)}.report-main td{padding:9px 10px;font-size:12px}.report-main .mono{font-size:11px}.report-main .chart svg{height:210px}.report-main .scroll{border-radius:7px}.report-main .cols-2{grid-template-columns:repeat(2,minmax(0,1fr))}.system-info{margin-top:20px;border:1px solid var(--border);background:var(--surface);border-radius:9px;padding:12px 20px}.system-info>section{box-shadow:none;border:0;margin:0;padding:12px 0}.report-main .grid{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}.report-main .kv dt{font-size:10px}.report-main .kv dd{font-size:12px}.report-main footer{font-size:11px;overflow-wrap:anywhere}
footer{margin-top:26px;font-size:11px;color:var(--muted);line-height:1.8}.report-nav-print{display:none}
@media(max-width:1100px){.upload-grid{grid-template-columns:minmax(0,1fr) 210px}.wrap{padding:24px}.incident-metric{padding:13px}.app-sidebar{width:190px;padding:25px 14px}.app-main{margin-left:190px}}
@media(max-width:900px){.app-sidebar{display:none}.app-main{margin-left:0}.upload-grid{grid-template-columns:minmax(0,1fr) 220px}.topbar{margin-bottom:23px}.page-heading h1{font-size:27px}}
@media(max-width:620px){.wrap{padding:18px 16px 35px}.upload-grid{grid-template-columns:1fr}.workflow-card{display:none}.page-heading h1{font-size:24px}.page-heading .sub{font-size:12px}.topbar{gap:8px;margin-bottom:22px}.version{display:none}.breadcrumb{font-size:11px}.toolbar{gap:5px}.toolbar button{font-size:11px;padding:5px 9px}.drop{padding:24px 16px 13px}.drop .big{font-size:16px}.section-head{align-items:stretch}.list-controls{width:100%}.list-controls input{flex:1;width:150px;min-width:0}.list-controls select{max-width:140px}.card{grid-template-columns:1fr;padding:15px}.actions{margin-top:6px}.incident-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.incident-metric strong{font-size:26px}.report-heading h1{font-size:23px}.report-main section{padding:18px 15px}.report-main .cols-2{grid-template-columns:minmax(0,1fr)}.report-main .f-critical{margin-left:-15px;margin-right:-15px;padding-left:15px;padding-right:15px}.report-main .finding{gap:8px}.report-main .flow-notes{padding-left:25px}.inc{padding:13px 12px}.inc-title{font-size:13px}.inc-verdict{font-size:12px}.report-main .controls input[type=search]{min-width:0}.report-main .tip{white-space:normal;max-width:260px}.report-main .grid{grid-template-columns:minmax(0,1fr)}.report-main .mono{font-size:10px}.report-nav{gap:5px}.report-nav a{font-size:10px;padding:5px 8px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*,*:before,*:after{animation:none!important;transition:none!important}}
@media print{.app-sidebar,.topbar,.report-nav{display:none!important}.app-main{margin:0}.wrap{max-width:none;padding:0}.report-main section,.incident-metric{box-shadow:none}.system-info{display:block}.system-info>section{display:block!important}body{background:white;color:black}}
"""

BRAND = '<span class="brand-mark" aria-hidden="true"><i></i><i></i><i></i></span>'
