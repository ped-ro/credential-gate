"""Web dashboard for Credential Gate.

A lightweight, self-contained HTML dashboard served at GET /dashboard.
No external dependencies — all HTML, CSS, and JS inline in a single template.
Auto-refreshes by polling /stats and /leases every 10 seconds.

Phase 8 implementation.
"""

DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Credential Gate</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;
  --fg:#e6edf3;--fg2:#8b949e;--green:#3fb950;--red:#f85149;
  --yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;
  --font:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
}
body{background:var(--bg);color:var(--fg);font-family:var(--font);font-size:14px;line-height:1.5}
a{color:var(--blue);text-decoration:none}
.container{max-width:1200px;margin:0 auto;padding:16px}

/* Status bar */
.status-bar{display:flex;flex-wrap:wrap;gap:8px;padding:12px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;align-items:center}
.status-bar .title{font-weight:600;font-size:16px;margin-right:auto}
.status-item{display:flex;align-items:center;gap:4px;font-size:12px;color:var(--fg2)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block}
.dot.green{background:var(--green)}.dot.yellow{background:var(--yellow)}.dot.red{background:var(--red)}

/* Cards row */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}
.card .label{font-size:12px;color:var(--fg2);text-transform:uppercase;letter-spacing:0.5px}
.card .value{font-size:28px;font-weight:700;margin:4px 0}
.card .trend{font-size:12px;color:var(--fg2)}
.card .trend.up{color:var(--green)}.card .trend.down{color:var(--red)}

/* Lock banner */
.lock-banner{background:#f8514944;border:2px solid var(--red);border-radius:8px;padding:16px 20px;margin-bottom:16px;display:none;text-align:center}
.lock-banner.visible{display:block}
.lock-banner h2{color:var(--red);font-size:18px;margin-bottom:8px}
.lock-banner .lock-details{font-size:13px;color:var(--fg);margin-bottom:12px}
.lock-banner .lock-duration{font-size:12px;color:var(--fg2)}

/* Panic / Unlock buttons */
.panic-controls{display:flex;gap:12px;justify-content:center;margin-bottom:16px}
.btn-panic{background:var(--red);color:#fff;border:none;padding:10px 24px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font);text-transform:uppercase;letter-spacing:1px}
.btn-panic:hover{opacity:0.85}
.btn-unlock{background:var(--green);color:#fff;border:none;padding:10px 24px;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font);text-transform:uppercase;letter-spacing:1px;display:none}
.btn-unlock:hover{opacity:0.85}
.btn-unlock.visible{display:inline-block}

/* Anomaly banner */
.anomaly-banner{background:#f8514922;border:1px solid var(--red);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:none}
.anomaly-banner.visible{display:block}
.anomaly-banner h3{color:var(--red);font-size:14px;margin-bottom:8px}
.anomaly-item{font-size:13px;margin-bottom:4px}

/* Tables */
.section{background:var(--bg2);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;overflow:hidden}
.section-header{padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;font-size:14px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 16px;font-size:12px;color:var(--fg2);text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid var(--border)}
td{padding:8px 16px;font-size:13px;border-bottom:1px solid var(--border)}
tr:last-child td{border-bottom:none}
tr.approved td{border-left:3px solid var(--green)}
tr.denied td{border-left:3px solid var(--red)}
tr.timeout td{border-left:3px solid var(--yellow)}
tr.error td{border-left:3px solid var(--yellow)}
tr.info td{border-left:3px solid var(--blue)}

/* Agent cards */
.agent-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-bottom:16px}
.agent-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:16px}
.agent-card .agent-name{font-weight:600;font-size:15px;margin-bottom:8px}
.agent-card .agent-stat{display:flex;justify-content:space-between;font-size:13px;padding:2px 0}
.agent-card .agent-stat .stat-label{color:var(--fg2)}

/* Lease table */
.btn-revoke{background:var(--red);color:#fff;border:none;padding:4px 10px;border-radius:4px;font-size:12px;cursor:pointer;font-family:var(--font)}
.btn-revoke:hover{opacity:0.8}

/* Footer */
.footer{text-align:center;color:var(--fg2);font-size:12px;padding:16px 0}

/* Responsive */
@media(max-width:600px){
  .cards{grid-template-columns:repeat(2,1fr)}
  .agent-cards{grid-template-columns:1fr}
  td,th{padding:6px 10px;font-size:12px}
}
</style>
</head>
<body>
<div class="container">

<!-- Status Bar -->
<div class="status-bar">
  <span class="title">Credential Gate</span>
  <div class="status-item"><span class="dot" id="dot-bw"></span><span id="st-bw">Bitwarden</span></div>
  <div class="status-item"><span class="dot" id="dot-fido"></span><span id="st-fido">FIDO2</span></div>
  <div class="status-item"><span class="dot" id="dot-notif"></span><span id="st-notif">Notifications</span></div>
  <div class="status-item"><span class="dot" id="dot-mcp"></span><span id="st-mcp">MCP</span></div>
  <div class="status-item"><span class="dot" id="dot-proxy"></span><span id="st-proxy">Proxy</span></div>
  <div class="status-item"><span class="dot" id="dot-obs"></span><span id="st-obs">Observability</span></div>
  <div class="status-item" style="color:var(--fg2);font-size:11px" id="last-update"></div>
</div>

<!-- Lock Banner (Phase 10) -->
<div class="lock-banner" id="lock-banner">
  <h2>GATE LOCKED</h2>
  <div class="lock-details" id="lock-details"></div>
  <div class="lock-duration" id="lock-duration"></div>
</div>

<!-- Panic / Unlock Controls (Phase 10) -->
<div class="panic-controls">
  <button class="btn-panic" id="btn-panic" onclick="triggerPanic()">PANIC LOCK</button>
  <button class="btn-unlock" id="btn-unlock" onclick="triggerUnlock()">UNLOCK GATE</button>
</div>

<!-- Live Counters -->
<div class="cards">
  <div class="card"><div class="label">Requests (24h)</div><div class="value" id="c-requests">—</div><div class="trend" id="c-requests-trend"></div></div>
  <div class="card"><div class="label">Approval Rate</div><div class="value" id="c-approval">—</div><div class="trend" id="c-approval-trend"></div></div>
  <div class="card"><div class="label">Active Leases</div><div class="value" id="c-leases">—</div><div class="trend" id="c-leases-trend"></div></div>
  <div class="card"><div class="label">Proxy Executions</div><div class="value" id="c-proxy">—</div><div class="trend" id="c-proxy-trend"></div></div>
</div>

<!-- Anomaly Banner -->
<div class="anomaly-banner" id="anomaly-banner">
  <h3>Anomalies Detected</h3>
  <div id="anomaly-list"></div>
</div>

<!-- Recent Activity -->
<div class="section">
  <div class="section-header">Recent Activity</div>
  <table><thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Credential</th><th>Result</th><th>Response</th></tr></thead>
  <tbody id="events-body"></tbody></table>
</div>

<!-- Agent Breakdown -->
<div class="section-header" style="margin-bottom:8px">Agents</div>
<div class="agent-cards" id="agent-cards"></div>

<!-- Active Leases -->
<div class="section">
  <div class="section-header">Active Leases</div>
  <table><thead><tr><th>Lease ID</th><th>Agent</th><th>Credential</th><th>Expires</th><th>Renewable</th><th></th></tr></thead>
  <tbody id="leases-body"></tbody></table>
</div>

<div class="footer">Credential Gate &mdash; Phase 10</div>

</div>

<script>
const BASE = window.location.origin;
let prevStats = null;

function relTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60) return diff + "s ago";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
  return Math.floor(diff / 86400) + "d ago";
}

function countdown(iso) {
  if (!iso) return "—";
  const d = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  const diff = Math.floor((d.getTime() - Date.now()) / 1000);
  if (diff <= 0) return "expired";
  if (diff < 60) return diff + "s";
  if (diff < 3600) return Math.floor(diff / 60) + "m " + (diff % 60) + "s";
  return Math.floor(diff / 3600) + "h " + Math.floor((diff % 3600) / 60) + "m";
}

function trendArrow(curr, prev) {
  if (prev === null || prev === undefined) return "";
  if (curr > prev) return "\\u2191";
  if (curr < prev) return "\\u2193";
  return "\\u2192";
}

function statusDot(id, color, text) {
  document.getElementById("dot-" + id).className = "dot " + color;
  document.getElementById("st-" + id).textContent = text;
}

function rowClass(status) {
  if (status === "approved" || status === "proxy_executed" || status === "panic_unlocked") return "approved";
  if (status === "denied" || status === "proxy_failed" || status === "panic_locked") return "denied";
  if (status === "timeout") return "timeout";
  if (status === "error") return "error";
  return "info";
}

function actionLabel(status, purpose) {
  if (status === "panic_locked") return "PANIC LOCK";
  if (status === "panic_unlocked") return "UNLOCK";
  if (status === "lease_renewed") return "Lease Renew";
  if (status === "lease_revoked") return "Lease Revoke";
  if (status === "lease_expired") return "Lease Expired";
  if (status === "lease_revoke_all") return "Revoke All";
  if (status === "proxy_executed" || status === "proxy_failed") return "Proxy";
  if (purpose && purpose.startsWith("proxy:")) return "Proxy";
  if (purpose && purpose.startsWith("identity_violation")) return "Identity";
  return "Credential";
}

async function fetchJSON(path) {
  try {
    const r = await fetch(BASE + path);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

async function refresh() {
  const [stats, health, events, leases] = await Promise.all([
    fetchJSON("/stats"),
    fetchJSON("/health"),
    fetchJSON("/events?limit=20"),
    fetchJSON("/leases/active"),
  ]);

  // Status bar
  if (health) {
    statusDot("bw", health.bitwarden === "active" ? "green" : "red", "BW: " + health.bitwarden);
    statusDot("fido", health.fido2 === "ready" ? "green" : "yellow", "FIDO2: " + health.fido2);
    const nc = health.notifications;
    statusDot("notif", nc === "ntfy_connected" ? "green" : nc === "disabled" ? "yellow" : "red", "Ntfy: " + nc);
    statusDot("mcp", health.mcp === "enabled" ? "green" : "yellow", "MCP: " + health.mcp);
    statusDot("proxy", health.proxy === "enabled" ? "green" : "yellow", "Proxy: " + health.proxy);
    const obs = health.observability;
    statusDot("obs", obs === "enabled" ? "green" : "yellow", "Obs: " + (obs || "unknown"));

    // Lock banner (Phase 10)
    const panic = health.panic || {};
    const lockBanner = document.getElementById("lock-banner");
    const btnPanic = document.getElementById("btn-panic");
    const btnUnlock = document.getElementById("btn-unlock");
    if (panic.locked) {
      lockBanner.classList.add("visible");
      document.getElementById("lock-details").textContent = "Reason: " + (panic.reason || "unknown");
      const dur = panic.locked_for_seconds || 0;
      const durMin = Math.floor(dur / 60);
      const durSec = dur % 60;
      document.getElementById("lock-duration").textContent = "Locked for " + durMin + "m " + durSec + "s";
      btnPanic.style.display = "none";
      btnUnlock.classList.add("visible");
    } else {
      lockBanner.classList.remove("visible");
      btnPanic.style.display = "";
      btnUnlock.classList.remove("visible");
    }
  }
  document.getElementById("last-update").textContent = "Updated " + new Date().toLocaleTimeString();

  // Cards
  if (stats) {
    const rq = stats.requests || {};
    const ls = stats.leases || {};
    const px = stats.proxy || {};

    document.getElementById("c-requests").textContent = rq.total ?? "—";
    document.getElementById("c-approval").textContent = rq.total > 0 ? (rq.approval_rate * 100).toFixed(1) + "%" : "—";
    document.getElementById("c-leases").textContent = ls.active ?? "—";
    document.getElementById("c-proxy").textContent = px.executions_today ?? "—";

    // Trends vs previous fetch
    if (prevStats) {
      const prq = prevStats.requests || {};
      const pls = prevStats.leases || {};
      const ppx = prevStats.proxy || {};
      document.getElementById("c-requests-trend").textContent = trendArrow(rq.total, prq.total);
      document.getElementById("c-leases-trend").textContent = trendArrow(ls.active, pls.active);
      document.getElementById("c-proxy-trend").textContent = trendArrow(px.executions_today, ppx.executions_today);
    }
    prevStats = stats;

    // Agent breakdown
    const agentDiv = document.getElementById("agent-cards");
    const byAgent = rq.by_agent || {};
    const agentNames = Object.keys(byAgent);
    if (agentNames.length === 0) {
      agentDiv.innerHTML = '<div class="agent-card"><div class="agent-name">No agent activity</div></div>';
    } else {
      agentDiv.innerHTML = agentNames.map(aid => {
        const a = byAgent[aid];
        const rate = a.total > 0 ? ((a.approved / a.total) * 100).toFixed(0) + "%" : "—";
        return '<div class="agent-card">' +
          '<div class="agent-name">' + aid + '</div>' +
          '<div class="agent-stat"><span class="stat-label">Requests</span><span>' + a.total + '</span></div>' +
          '<div class="agent-stat"><span class="stat-label">Approved</span><span>' + a.approved + '</span></div>' +
          '<div class="agent-stat"><span class="stat-label">Denied</span><span>' + a.denied + '</span></div>' +
          '<div class="agent-stat"><span class="stat-label">Approval Rate</span><span>' + rate + '</span></div>' +
          '</div>';
      }).join("");
    }

    // Anomaly banner
    const anomalies = stats.anomalies || [];
    const banner = document.getElementById("anomaly-banner");
    if (anomalies.length > 0) {
      banner.classList.add("visible");
      document.getElementById("anomaly-list").innerHTML = anomalies.map(a =>
        '<div class="anomaly-item"><strong>' + a.severity.toUpperCase() + '</strong>: ' +
        a.agent_id + " — " + a.metric + " = " + a.value + " (threshold: " + a.threshold + ")</div>"
      ).join("");
    } else {
      banner.classList.remove("visible");
    }
  }

  // Events table
  if (events && Array.isArray(events)) {
    const tbody = document.getElementById("events-body");
    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--fg2)">No events</td></tr>';
    } else {
      tbody.innerHTML = events.map(e => {
        const cls = rowClass(e.status);
        const respTime = e.response_time_ms != null ? e.response_time_ms + "ms" : "—";
        return '<tr class="' + cls + '">' +
          '<td>' + relTime(e.timestamp) + '</td>' +
          '<td>' + (e.agent_id || "—") + '</td>' +
          '<td>' + actionLabel(e.status, e.purpose) + '</td>' +
          '<td>' + (e.credential_name || "—") + '</td>' +
          '<td>' + (e.status || "—") + '</td>' +
          '<td>' + respTime + '</td></tr>';
      }).join("");
    }
  }

  // Leases table
  if (leases && Array.isArray(leases)) {
    const tbody = document.getElementById("leases-body");
    if (leases.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--fg2)">No active leases</td></tr>';
    } else {
      tbody.innerHTML = leases.map(l => {
        const shortId = l.lease_id ? l.lease_id.substring(0, 12) + "\\u2026" : "—";
        const expires = countdown(l.expires_at);
        const renewable = l.ttl_seconds != null ? "Yes" : "No";
        return '<tr>' +
          '<td><code>' + shortId + '</code></td>' +
          '<td>' + (l.agent_id || "—") + '</td>' +
          '<td>' + (l.credential_name || "—") + '</td>' +
          '<td>' + expires + '</td>' +
          '<td>' + renewable + '</td>' +
          '<td><button class="btn-revoke" onclick="revokeLease(\\'' + l.lease_id + '\\')">Revoke</button></td></tr>';
      }).join("");
    }
  }
}

async function revokeLease(leaseId) {
  if (!confirm("Revoke lease " + leaseId.substring(0, 12) + "...?")) return;
  try {
    const r = await fetch(BASE + "/dashboard/revoke/" + leaseId, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({"reason": "dashboard revoke"})
    });
    if (r.ok) { refresh(); }
    else { alert("Revoke failed: " + r.status); }
  } catch (e) { alert("Revoke error: " + e); }
}

async function triggerPanic() {
  const reason = prompt("Panic reason (required):");
  if (!reason) return;
  if (!confirm("LOCK THE GATE? This will revoke ALL leases and block ALL credential requests.\\n\\nYou will need to touch your YubiKey.")) return;
  try {
    const r = await fetch(BASE + "/panic", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({"reason": reason})
    });
    const data = await r.json();
    if (r.ok) {
      alert("Gate LOCKED. Leases revoked: " + (data.leases_revoked || 0));
      refresh();
    } else {
      alert("Panic failed: " + (data.detail || r.status));
    }
  } catch (e) { alert("Panic error: " + e); }
}

async function triggerUnlock() {
  const reason = prompt("Unlock reason (required):");
  if (!reason) return;
  if (!confirm("UNLOCK the gate? You will need to touch your YubiKey.")) return;
  try {
    const r = await fetch(BASE + "/unlock", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({"reason": reason})
    });
    const data = await r.json();
    if (r.ok) {
      alert("Gate UNLOCKED. Was locked for " + (data.was_locked_for_seconds || 0) + "s.");
      refresh();
    } else {
      alert("Unlock failed: " + (data.detail || r.status));
    }
  } catch (e) { alert("Unlock error: " + e); }
}

// Initial load + 10s interval
refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""


def get_dashboard_html() -> str:
    """Return the complete dashboard HTML page."""
    return DASHBOARD_HTML
