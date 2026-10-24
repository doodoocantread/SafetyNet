const {useState, useEffect, useRef} = React;

/* ---------- i18n: Vietnamese (default) / English ----------
   The language is fixed per page load: LangToggle stores it in localStorage and reloads, so plain
   module-level constants below can call tr() at definition time. tr(vi, en) picks one string. */
const LANG = (() => {
  try { const l = localStorage.getItem("sn-lang"); if (l === "en" || l === "vi") return l; } catch {}
  return "vi";
})();
const tr = (vi, en) => LANG === "en" ? en : vi;
const LOCALE = LANG === "en" ? "en-GB" : "vi-VN";
document.documentElement.lang = LANG;

/* Strings the Python backend sends in Vietnamese (system notes, mode reasons, log lines, ...).
   Matched exactly or by pattern so the English UI never mixes languages; unknown strings pass through. */
const BE_EXACT = {
  "Chưa ánh xạ OWASP": "No OWASP mapping",
  "Không tìm thấy lệnh pentestgpt-agent (xem README).": "pentestgpt-agent command not found (see README).",
  "Chưa đặt ANTHROPIC_API_KEY — nhãn do bộ luật heuristic offline gán.":
    "ANTHROPIC_API_KEY is not set — labels come from the offline heuristic rules.",
  "Đã đặt ANTHROPIC_API_KEY nhưng chưa cài package `anthropic` — mọi finding đang âm thầm rơi về heuristic.":
    "ANTHROPIC_API_KEY is set but the `anthropic` package is not installed — every finding silently falls back to the heuristic.",
  "Đã hủy theo yêu cầu người dùng": "Cancelled at the user's request",
  "Docker (cô lập)": "Docker (isolated)",
  "Trực tiếp trên máy (không cô lập)": "Directly on this machine (not isolated)",
};
const BE_PATTERNS = [
  [/^Server chưa bật\. Khởi động với (\S+)\.$/, "Not enabled on the server. Start it with $1."],
  [/^Đang chờ slot quét \(tối đa (\d+) song song\)…$/, "Waiting for a scan slot (max $1 in parallel)…"],
  [/^Bắt đầu quét · /, "Scan started · "],
  [/ · model=mặc định · /, " · model=default · "],
  [/^Quét xong — /, "Scan finished — "],
  [/^LỖI: /, "ERROR: "],
  [/^Người dùng đã hủy quét$/, "Scan cancelled by the user"],
];
function be(s) {
  if (LANG !== "en" || typeof s !== "string") return s;
  if (BE_EXACT[s]) return BE_EXACT[s];
  let out = s;
  for (const [re, to] of BE_PATTERNS) out = out.replace(re, to);
  return out;
}

const SEV = {
  critical: {label: "CRITICAL", color: "var(--crit)", bg: "var(--crit-bg)"},
  high:     {label: "HIGH",     color: "var(--high)", bg: "var(--high-bg)"},
  medium:   {label: "MEDIUM",   color: "var(--med)",  bg: "var(--med-bg)"},
  low:      {label: "LOW",      color: "var(--low)",  bg: "var(--low-bg)"},
  info:     {label: "INFO",     color: "var(--info)", bg: "var(--info-bg)"},
};
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

async function api(path, opt) {
  const r = await fetch(path, opt);
  if (!r.ok) {
    const d = await r.json().catch(() => ({detail: r.statusText}));
    throw new Error(d.detail || r.statusText);
  }
  return r.json();
}

const MODE_LABEL = {docker: tr("Docker (cô lập)", "Docker (isolated)"), direct: tr("Trực tiếp trên máy", "Directly on this machine")};
const AGENT_LABEL = {pentestgpt: "PentestGPT", hackingbuddy: "hackingBuddyGPT (web)"};
const STATUS = {
  completed:   {label: tr("Hoàn tất", "Completed"),      color: "var(--ok)",   bg: "var(--ok-bg)"},
  queued:      {label: tr("Đang chờ", "Queued"),          color: "var(--low)",  bg: "var(--low-bg)"},
  running:     {label: tr("Đang chạy", "Running"),        color: "var(--low)",  bg: "var(--low-bg)"},
  failed:      {label: tr("Thất bại", "Failed"),          color: "var(--crit)", bg: "var(--crit-bg)"},
  error:       {label: tr("Lỗi", "Error"),                color: "var(--crit)", bg: "var(--crit-bg)"},
  interrupted: {label: tr("Bị gián đoạn", "Interrupted"), color: "var(--high)", bg: "var(--high-bg)"},
  cancelled:   {label: tr("Đã hủy", "Cancelled"),         color: "var(--high)", bg: "var(--high-bg)"},
};

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString(LOCALE, {hour12: false});
}


function fmtDur(sec) {
  sec = Math.round(sec || 0);
  if (sec < 60) return sec + "s";
  const m = Math.floor(sec / 60);
  return m < 60 ? `${m}${tr("p", "m")} ${sec % 60}s` : `${Math.floor(m / 60)}${tr("g", "h")} ${m % 60}${tr("p", "m")}`;
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  return n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";
}

/* Decision the user records on a vulnerability (runs/triage.json). */
const TRIAGE = {
  open:           {label: tr("Mới", "New"),                        color: "var(--high)", bg: "var(--high-bg)"},
  fixing:         {label: tr("Đang sửa", "Fixing"),                color: "var(--low)",  bg: "var(--low-bg)"},
  fixed:          {label: tr("Đã sửa", "Fixed"),                   color: "var(--ok)",   bg: "var(--ok-bg)"},
  false_positive: {label: "False positive",                       color: "var(--info)", bg: "var(--info-bg)"},
  accepted:       {label: tr("Chấp nhận rủi ro", "Risk accepted"), color: "var(--info)", bg: "var(--info-bg)"},
};

function TriagePill({status}) {
  const t = TRIAGE[status] || TRIAGE.open;
  return <span className="badge" style={{background: t.bg, color: t.color}}>{t.label}</span>;
}

/* Severity distribution from a {severity: count} map (the page-level cousin of <Counts>). */
function SevDist({counts}) {
  const total = SEV_ORDER.reduce((n, s) => n + (counts[s] || 0), 0);
  const present = SEV_ORDER.filter(s => counts[s]);
  if (!total) return <div className="hint">{tr("Chưa có lỗ hổng nào đang mở.", "No open vulnerabilities.")}</div>;
  return <div>
    <div className="sevbar">
      {present.map(s => <div key={s} title={`${SEV[s].label}: ${counts[s]}`}
        style={{width: `${(counts[s] / total) * 100}%`, background: SEV[s].color}} />)}
    </div>
    <div className="sevlegend">
      {present.map(s => <span key={s}>
        <span className="sw" style={{background: SEV[s].color}} />{SEV[s].label} · {counts[s]}</span>)}
    </div>
  </div>;
}

/* Horizontal bars for [{label, count}] — used for the OWASP spread. */
function BarList({items, color}) {
  const max = Math.max(1, ...items.map(i => i.count));
  return <div className="barlist">
    {items.map(i => <div key={i.label} className="barrow">
      <span className="bl" title={i.label}>{i.label}</span>
      <span className="bt"><span className="bf" style={{width: `${(i.count / max) * 100}%`, background: color || "var(--accent)"}} /></span>
      <span className="bn">{i.count}</span>
    </div>)}
  </div>;
}

/* Page title block shared by the new pages. */
function Hero({title, children}) {
  return <div className="hero"><h1>{title}</h1><p>{children}</p></div>;
}

const FOOTER = tr("SafetyNet · dự án khoa học · AI tổng hợp kết quả scan, không tự quyết định tấn công",
                  "SafetyNet · science project · AI summarizes scan results, never decides to attack on its own");

/* ---------- small components ---------- */
function StatusPill({status}) {
  const s = STATUS[status] || {label: status || "—", color: "var(--info)", bg: "var(--info-bg)"};
  return <span className="badge" style={{background: s.bg, color: s.color}}>{s.label}</span>;
}

function Badge({sev}) {
  const s = SEV[sev] || SEV.info;
  return <span className="badge" style={{background: s.bg, color: s.color}}>{s.label}</span>;
}

function ThemeToggle() {
  const [dark, setDark] = useState(() =>
    (localStorage.getItem("sn-theme") ||
     (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light")) === "dark");
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    try { localStorage.setItem("sn-theme", dark ? "dark" : "light"); } catch {}
  }, [dark]);
  return <button className="icon-btn" title={tr("Đổi giao diện", "Toggle theme")} onClick={() => setDark(d => !d)}>
    {dark ? "☾" : "☀"}</button>;
}

/* Shows the language you would switch TO; the choice is remembered and the page reloads. */
function LangToggle() {
  const next = LANG === "vi" ? "en" : "vi";
  const tip = LANG === "vi" ? "Switch to English" : "Chuyển sang tiếng Việt";
  return <button className="icon-btn lang-btn" title={tip} aria-label={tip}
    onClick={() => { try { localStorage.setItem("sn-lang", next); } catch {} location.reload(); }}>
    {next.toUpperCase()}</button>;
}

function Counts({findings}) {
  const counts = {};
  findings.forEach(f => { const s = (f.label || {}).severity || "info"; counts[s] = (counts[s] || 0) + 1; });
  const total = findings.length || 1;
  const present = SEV_ORDER.filter(s => counts[s]);
  return <div>
    <div className="sevbar">
      {present.map(s => <div key={s} title={`${SEV[s].label}: ${counts[s]}`}
        style={{width: `${(counts[s] / total) * 100}%`, background: SEV[s].color}} />)}
    </div>
    <div className="sevlegend">
      {present.map(s => <span key={s}>
        <span className="sw" style={{background: SEV[s].color}} />{SEV[s].label} · {counts[s]}</span>)}
    </div>
  </div>;
}

function Kpis({rep}) {
  const c = {};
  rep.findings.forEach(f => { const s = (f.label || {}).severity || "info"; c[s] = (c[s] || 0) + 1; });
  const tiles = [
    {n: rep.findings.length, l: "Findings"},
    {n: c.critical || 0, l: "Critical", cls: "crit"},
    {n: c.high || 0, l: "High", cls: "high"},
    {n: "$" + (rep.cost_usd || 0).toFixed(2), l: tr("Chi phí", "Cost")},
    {n: Math.round(rep.wall_duration_s || 0) + "s", l: tr("Thời gian", "Duration")},
  ];
  return <div className="kpis">
    {tiles.map((t, i) => <div key={i} className={"kpi " + (t.cls || "")}>
      <div className="n">{t.n}</div><div className="l">{t.l}</div></div>)}
  </div>;
}

// Why this finding was flagged: the labeler's concrete signals, plus the scanning
// agent's own note (an unverified claim — labeled as such).
function WhyFlagged({rationale, agentNote}) {
  if (!(rationale && rationale.length) && !agentNote) return null;
  return <div className="kv why">
    <b>{tr("Vì sao bắt lỗi này.", "Why this was flagged.")}</b>
    {rationale && rationale.length > 0 && <ul>{rationale.map((r, k) => <li key={k}>{r}</li>)}</ul>}
    {agentNote && <details>
      <summary>{tr("Nhận xét của agent (chưa kiểm chứng)", "Agent's note (unverified)")}</summary>
      <p>{agentNote}</p>
    </details>}
  </div>;
}

function Finding({f, i}) {
  const L = f.label || {};
  return <div className={"finding " + (L.severity || "info")}>
    <h3><span className="num">{i}.</span> {L.vuln_class || "Observation"} <Badge sev={L.severity}/></h3>
    <div className="chips">
      {L.cwe && <span className="chip mono">{L.cwe}</span>}
      {L.owasp && <span className="chip">{L.owasp}</span>}
      <span className="chip">confidence: {L.confidence}</span>
      <span className="chip">task: {f.task_kind || "—"}</span>
    </div>
    {L.explanation && <div className="kv"><b>{tr("Giải thích.", "Explanation.")}</b> {L.explanation}</div>}
    <WhyFlagged rationale={L.rationale} agentNote={f.agent_note} />
    {L.remediation && <div className="kv"><b>{tr("Khắc phục.", "Remediation.")}</b> {L.remediation}</div>}
    {(f.request || f.response) &&
      <details>
        <summary>{tr("Bằng chứng — request & response", "Evidence — request & response")}</summary>
        {f.request && <pre>{"$ " + f.request}</pre>}
        {f.response && <pre>{f.response.slice(0, 1400)}</pre>}
      </details>}
  </div>;
}

function ScanMeta({meta, typeLabel}) {
  return <>
    <div className="meta-cell"><b>{tr("Dự án", "Project")}</b><span>{meta.project || "—"}</span></div>
    <div className="meta-cell"><b>{tr("Loại scan", "Scan type")}</b><span>{typeLabel(meta.scan_type)}</span></div>
    <div className="meta-cell"><b>Agent</b><span>{AGENT_LABEL[meta.agent] || meta.agent || "—"}</span></div>
    <div className="meta-cell"><b>{tr("Chế độ chạy", "Run mode")}</b><span>{MODE_LABEL[meta.mode] || meta.mode || "—"}</span></div>
    <div className="meta-cell"><b>{tr("Model agent", "Agent model")}</b><span>{meta.model || tr("mặc định", "default")}</span></div>
    <div className="meta-cell"><b>Timeout</b><span>{meta.timeout_s ? meta.timeout_s + "s" : "—"}</span></div>
    <div className="meta-cell"><b>{tr("Bắt đầu", "Started")}</b><span>{fmtTime(meta.created_at)}</span></div>
    <div className="meta-cell"><b>{tr("Kết thúc", "Finished")}</b><span>{fmtTime(meta.finished_at)}</span></div>
  </>;
}

function Report({rep, src, meta, typeLabel}) {
  return <div className="card">
    <div className="card-b">
      <div className="rep-head">
        <h2>{rep.run_id}</h2>
        <div className="rep-actions no-print">
          <button className="btn ghost sm" onClick={() => window.print()}>{tr("⎙ In / PDF", "⎙ Print / PDF")}</button>
          <a href={`/api/report/${src}/${rep.run_id}/markdown`}>
            <button className="btn ghost sm">↓ Markdown</button></a>
        </div>
      </div>

      <Kpis rep={rep} />
      {rep.findings.length > 0 && <Counts findings={rep.findings} />}

      <div className="meta-grid">
        <div className="meta-cell"><b>Goal</b><span>{rep.goal || "—"}</span></div>
        <div className="meta-cell"><b>Target</b><span>{(rep.targets || []).join(", ") || "—"}</span></div>
        <div className="meta-cell"><b>Engine</b><span>{rep.engine}</span></div>
        <div className="meta-cell"><b>{tr("Trạng thái", "Status")}</b><span>{rep.status}</span></div>
        <div className="meta-cell"><b>{tr("Phân loại bởi", "Labeled by")}</b><span>{rep.labeled_by}</span></div>
        {meta && <ScanMeta meta={meta} typeLabel={typeLabel} />}
      </div>

      {rep.status !== "completed" &&
        <div className="warnbox">
          <span>⚠️</span>
          <div>{tr(<><b>Run không hoàn tất</b> — kết quả không kết luận được ("không tìm thấy" khác "run lỗi").</>,
                   <><b>Run did not complete</b> — the result is inconclusive ("nothing found" is not the same as "run failed").</>)}
            <br/><code>{be(rep.error) || "unknown"}</code></div>
        </div>}

      {rep.findings.map((f, i) => <Finding key={f.id} f={f} i={i + 1} />)}
      {rep.findings.length === 0 &&
        <p className="hint">{tr("Run này không có observation nào để phân loại.", "This run has no observations to classify.")}</p>}
    </div>
  </div>;
}

/* A scan with no report: still running, or it died before the agent wrote a summary. */
function RunWithoutReport({meta, typeLabel}) {
  const active = meta.status === "queued" || meta.status === "running";
  const cancelled = meta.status === "cancelled";
  return <div className="card">
    <div className="card-b">
      <div className="rep-head">
        <h2>{meta.run_id}</h2>
        <StatusPill status={meta.status} />
      </div>
      <div className="meta-grid" style={{marginTop: 16}}>
        <div className="meta-cell"><b>Target</b><span>{meta.target || "—"}</span></div>
        <ScanMeta meta={meta} typeLabel={typeLabel} />
      </div>
      <div className={"warnbox" + (cancelled ? " neutral" : "")}>
        <span>{active ? "⏳" : cancelled ? "🛑" : "⚠️"}</span>
        <div>{active
          ? tr(<><b>Scan chưa xong</b> — báo cáo sẽ có khi agent hoàn tất. Mở trang <a href="/history">Lịch sử</a> để theo dõi.</>,
               <><b>Scan not finished</b> — the report appears once the agent completes. Follow it on the <a href="/history">History</a> page.</>)
          : cancelled
          ? tr(<><b>Đã hủy quét</b> theo yêu cầu của bạn — agent/container đã được dừng, không có báo cáo cho lần quét này.</>,
               <><b>Scan cancelled</b> at your request — the agent/container was stopped, so there is no report for this scan.</>)
          : <>{tr(<><b>Scan không tạo ra báo cáo</b> — kết quả không kết luận được ("không tìm thấy" khác "scan lỗi").</>,
                  <><b>The scan produced no report</b> — the result is inconclusive ("nothing found" is not the same as "scan failed").</>)}
              <br/><code>{be(meta.error) || tr("Không có thông tin lỗi (server có thể đã khởi động lại giữa chừng).", "No error details (the server may have restarted mid-scan).")}</code></>}
        </div>
      </div>
    </div>
  </div>;
}

/* Real-time agent terminal: tails /api/scan/{job_id}/log while a scan runs, so
   "quét mới" shows what the agent is doing (and where it fails) live instead of
   a spinner. Stops polling once the job's own status turns done/error. */
function ScanTerminal({jobId}) {
  const [lines, setLines] = useState([]);
  const cursorRef = useRef(0);
  const boxRef = useRef(null);

  useEffect(() => {
    setLines([]); cursorRef.current = 0;
    if (!jobId) return;
    let stopped = false;
    let timer = null;
    const poll = async () => {
      if (stopped) return;
      try {
        const r = await api(`/api/scan/${jobId}/log?after=${cursorRef.current}`);
        if (r.lines.length) {
          cursorRef.current = r.cursor;
          setLines(prev => [...prev, ...r.lines]);
        }
        if (r.status === "done" || r.status === "error" || r.status === "cancelled") return;
      } catch (e) { /* transient poll error — keep trying */ }
      timer = setTimeout(poll, 700);
    };
    poll();
    return () => { stopped = true; if (timer) clearTimeout(timer); };
  }, [jobId]);

  useEffect(() => {
    if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight;
  }, [lines]);

  return <div className="term" ref={boxRef}>
    {lines.length === 0 && <div className="term-line term-empty">{tr("Đang khởi động agent…", "Starting agent…")}</div>}
    {lines.map((l, i) => <div key={i} className={"term-line " + (l.level || "info")}>
      <span className="term-ts">{new Date(l.ts * 1000).toLocaleTimeString(LOCALE, {hour12: false})}</span>
      {be(l.text)}
    </div>)}
  </div>;
}

/* ---------- header menu (dùng chung cho mọi trang React; about.html có bản tĩnh tương đương — sửa cả hai) ---------- */
const NAV = [
  {key: "overview", href: "/",        label: tr("Tổng quan", "Overview")},
  {key: "scan",     href: "/scan",    label: tr("Quét mới", "New scan")},
  {key: "history",  href: "/history", label: tr("Lịch sử", "History")},
  {key: "vulns",    href: "/vulns",   label: tr("Lỗ hổng", "Vulnerabilities")},
  {key: "about",    href: "/about",   label: tr("Phương pháp & Đóng góp", "Method & Contributions")},
  {key: "system",   href: "/system",  label: tr("Hệ thống", "System")},
];

function AppBar({active}) {
  return <header className="appbar">
    <a className="brand" href="/"><span className="logo">🛡</span> SafetyNet <span className="ver">v0.1</span></a>
    <nav className="mainnav" aria-label={tr("Menu chính", "Main menu")}>
      {NAV.map(n => <a key={n.key} href={n.href} className={n.key === active ? "on" : ""}
        aria-current={n.key === active ? "page" : undefined}>{n.label}</a>)}
    </nav>
    <div className="spacer" />
    <span className="scopebadge"><span className="dot" /> Local-only scope</span>
    <LangToggle />
    <ThemeToggle />
  </header>;
}
