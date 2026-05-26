const API = "https://threat-scanner-saas-2.onrender.com";

// =========================
// Helpers
// =========================
function $(id) {
  return document.getElementById(id);
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getToken() {
  return localStorage.getItem("token");
}

function showMessage(msg, type = "info") {
  const out = $("out") || $("container");
  if (!out) {
    alert(msg);
    return;
  }

  const color = type === "error" ? "#ef4444" : type === "success" ? "#22c55e" : "#60a5fa";

  out.innerHTML = `
    <div class="result-card" style="border-left:5px solid ${color};">
      <h2>${type === "error" ? "❌" : type === "success" ? "✅" : "ℹ️"} ${esc(msg)}</h2>
    </div>
  `;
}

function safeList(items, empty = "None") {
  if (!items) return empty;
  if (Array.isArray(items)) return items.length ? items.map(esc).join(", ") : empty;
  return esc(items);
}

function riskClass(risk) {
  const r = String(risk || "UNKNOWN").toUpperCase();
  if (r === "CRITICAL") return "critical";
  if (r === "HIGH") return "high";
  if (r === "MEDIUM") return "medium";
  if (r === "LOW") return "low";
  return "unknown";
}


// =========================
// Professional Evidence Helpers
// =========================
function extractFirstUrl(text) {
  const value = String(text || "");
  const match = value.match(/https?:\/\/[^\s"'<>]+/i);
  return match ? match[0] : null;
}

function getAffectedUrl(item) {
  return item?.affected_url || item?.url || extractFirstUrl(item?.evidence) || null;
}

function cvssFromSeverity(severity) {
  const s = String(severity || "INFO").toUpperCase();
  if (s === "CRITICAL") return "9.8";
  if (s === "HIGH") return "8.1";
  if (s === "MEDIUM") return "5.6";
  if (s === "LOW") return "3.1";
  return "0.0";
}

function confidencePercent(confidence) {
  const c = String(confidence || "MEDIUM").toUpperCase();
  if (c === "HIGH") return "90%";
  if (c === "LOW") return "45%";
  return "70%";
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    alert("Copied");
  } catch (e) {
    const t = document.createElement("textarea");
    t.value = text;
    document.body.appendChild(t);
    t.select();
    document.execCommand("copy");
    document.body.removeChild(t);
    alert("Copied");
  }
}

function openUrl(url) {
  if (!url) return;
  window.open(url, "_blank", "noopener,noreferrer");
}

function renderUrlActions(url) {
  if (!url) return "";
  const safe = esc(url);
  return `
    <div class="affected-box">
      <div class="affected-label">🔗 Affected URL</div>
      <a class="affected-link" href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a>
      <div class="affected-actions">
        <button type="button" onclick="openUrl('${safe}')">Open</button>
        <button type="button" onclick="copyText('${safe}')">Copy</button>
      </div>
    </div>
  `;
}

function renderMetaBadges(item) {
  const severity = esc(item?.severity || "INFO");
  const cvss = esc(item?.cvss || item?.score || cvssFromSeverity(item?.severity));
  const confidence = esc(item?.confidence_percent || item?.confidence || confidencePercent(item?.confidence));
  const status = esc(item?.status || "INFO");

  return `
    <div class="meta-badges">
      <span class="meta-badge severity-${severity.toLowerCase()}">Severity: ${severity}</span>
      <span class="meta-badge">CVSS: ${cvss}</span>
      <span class="meta-badge">Confidence: ${confidence}</span>
      <span class="meta-badge">Status: ${status}</span>
    </div>
  `;
}

function buildSeverityCounts(items) {
  const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0};
  (items || []).forEach(item => {
    const s = String(item?.severity || "INFO").toUpperCase();
    if (counts[s] !== undefined) counts[s]++;
    else counts.INFO++;
  });
  return counts;
}

function renderSeverityBars(items) {
  const counts = buildSeverityCounts(items);
  const total = Math.max(Object.values(counts).reduce((a,b)=>a+b,0), 1);

  return `
    <div class="severity-bars">
      ${Object.keys(counts).map(k => {
        const percent = Math.round((counts[k] / total) * 100);
        return `
          <div class="sev-row">
            <span>${k}</span>
            <div class="sev-track"><div class="sev-fill ${k.toLowerCase()}" style="width:${percent}%"></div></div>
            <b>${counts[k]}</b>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function renderProgressSteps() {
  return `
    <div class="progress-steps">
      <div class="step done">✓ Target normalization</div>
      <div class="step done">✓ DNS analysis</div>
      <div class="step done">✓ SSL/TLS analysis</div>
      <div class="step active">⟳ Port scanning</div>
      <div class="step">• WAF detection</div>
      <div class="step">• CVE enumeration</div>
      <div class="step">• Validation engine</div>
    </div>
  `;
}

function renderThreatIntel(data) {
  const ti = data.ip_intelligence || data.whois_asn || data.asn_info || data.geoip || {};
  if (!ti || Object.keys(ti).length === 0) {
    return `<p class="muted">No threat intelligence data returned.</p>`;
  }

  return `
    <div class="intel-grid">
      <div class="mini-result"><b>ASN</b><span>${esc(ti.asn || "Unknown")}</span></div>
      <div class="mini-result"><b>ISP</b><span>${esc(ti.isp || ti.provider || "Unknown")}</span></div>
      <div class="mini-result"><b>Organization</b><span>${esc(ti.organization || ti.org || "Unknown")}</span></div>
      <div class="mini-result"><b>Country</b><span>${esc(ti.country || "Unknown")}</span></div>
      <div class="mini-result"><b>City</b><span>${esc(ti.city || "Unknown")}</span></div>
      <div class="mini-result"><b>Reverse DNS</b><span>${esc(ti.reverse_dns || "Unknown")}</span></div>
    </div>
  `;
}

function renderAttackSurface(data) {
  const endpoints = data.api_endpoints || data.discovered_endpoints || [];
  const subdomains = Array.isArray(data.subdomains) ? data.subdomains : [];
  const ports = Array.isArray(data.open_ports) ? data.open_ports : [];
  const exposures = data.advanced_exposures || data.exposures || [];

  return `
    <div class="attack-grid">
      <div class="mini-result"><b>API Endpoints</b><span>${endpoints.length || 0}</span></div>
      <div class="mini-result"><b>Subdomains</b><span>${subdomains.length || 0}</span></div>
      <div class="mini-result"><b>Open Ports</b><span>${ports.length || 0}</span></div>
      <div class="mini-result"><b>Exposures</b><span>${exposures.length || 0}</span></div>
    </div>
    ${
      endpoints.length
      ? `<h4>Discovered APIs</h4>${endpoints.slice(0,20).map(e => {
          const endpoint = e.endpoint || e.url || e;
          return `<div class="mini-result"><b>${esc(endpoint)}</b><span>${esc(e.severity || "INFO")}</span></div>`;
        }).join("")}`
      : `<p class="muted">No API endpoints returned.</p>`
    }
  `;
}


// =========================
// LOGIN
// =========================
async function login() {
  const username = $("u")?.value?.trim();
  const password = $("p")?.value?.trim();

  if (!username || !password) {
    alert("Enter username and password");
    return;
  }

  try {
    const res = await fetch(API + "/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username, password})
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok || !data.access_token) {
      alert(data.detail || "Login failed");
      return;
    }

    localStorage.setItem("token", data.access_token);
    window.location.href = "dashboard.html";

  } catch (err) {
    console.error(err);
    alert("Backend connection failed");
  }
}

// =========================
// REGISTER
// =========================
async function register() {
  const username =
    $("ru")?.value?.trim() ||
    $("r_user")?.value?.trim() ||
    $("user")?.value?.trim();

  const password =
    $("rp")?.value?.trim() ||
    $("r_pass")?.value?.trim() ||
    $("pass")?.value?.trim();

  const confirm = $("rp2")?.value?.trim();

  if (!username || !password) {
    alert("Enter username and password");
    return;
  }

  if (confirm !== undefined && confirm && confirm !== password) {
    alert("Passwords do not match");
    return;
  }

  try {
    const res = await fetch(API + "/register", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({username, password})
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      alert(data.detail || "Register failed");
      return;
    }

    alert("Account created. Login now.");

    if ($("u")) $("u").value = username;
    if ($("p")) $("p").value = "";
    if (typeof switchTab === "function") switchTab("login");

  } catch (err) {
    console.error(err);
    alert("Backend connection failed");
  }
}

// =========================
// LOGOUT
// =========================
function logout() {
  localStorage.removeItem("token");
  window.location.href = "index.html";
}

// =========================
// START SCAN
// Supports inputs: target OR t
// Supports output: out OR container
// =========================
async function scan() {
  const token = getToken();

  if (!token) {
    alert("Login first");
    window.location.href = "index.html";
    return;
  }

  const targetInput = $("target") || $("t") || $("searchBox");
  const profileInput = $("scan_profile") || $("profile");

  if (!targetInput || !targetInput.value.trim()) {
    alert("Enter target");
    return;
  }

  const target = targetInput.value.trim();
  const profile = profileInput ? profileInput.value : "full";
  const out = $("out") || $("container");

  if (out) {
    out.innerHTML = `
      <div class="result-card scanning-card">
        <div class="scan-loader"></div>
        <h2>🔍 Scanning Target...</h2>
        <p><b>Target:</b> ${esc(target)}</p>
        <p><b>Profile:</b> ${esc(profile)}</p>
        <p class="muted">Please wait while the scanner checks ports, SSL, DNS, headers, WAF, CVEs, and findings.</p>${renderProgressSteps()}
      </div>
    `;
  }

  try {
    const res = await fetch(API + "/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({
        target: target,
        profile: profile
      })
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      showMessage(data.detail || "Scan failed: HTTP " + res.status, "error");
      return;
    }

    console.log("SCAN RESULT:", data);
    renderScanResult(data);

  } catch (err) {
    console.error(err);
    showMessage("Cannot connect to backend", "error");
  }
}

// =========================
// Render Scan Results
// =========================
function renderScanResult(data) {
  const out = $("out") || $("container");

  if (!out) {
    console.log(data);
    return;
  }

  const openPorts = Array.isArray(data.open_ports) ? data.open_ports : [];
  const nmapPorts = Array.isArray(data.nmap_scan?.ports) ? data.nmap_scan.ports : [];
  const allPorts = openPorts.length ? openPorts : nmapPorts;

  const findings = Array.isArray(data.findings) ? data.findings : [];
  const vulns = Array.isArray(data.vulnerability_checks) ? data.vulnerability_checks : [];
  const allFindings = [...findings, ...vulns];

  const cveGroups = Array.isArray(data.cve_results) ? data.cve_results : [];
  const technologies = Array.isArray(data.technologies) ? data.technologies : [];
  const subdomains = Array.isArray(data.subdomains) ? data.subdomains : [];

  const cveCount = cveGroups.reduce((sum, group) => sum + ((group.cves || []).length), 0);

  const portHTML = allPorts.length
    ? allPorts.map(p => `
      <div class="mini-result">
        <b>Port ${esc(p.port)}</b>
        <span>${esc(p.service || "Unknown")} · ${esc(p.protocol || "tcp")} · ${esc(p.state || "open")}</span>
        ${p.banner ? `<small>Banner: ${esc(p.banner)}</small>` : ""}
        ${p.product || p.version ? `<small>Product: ${esc(p.product || "")} ${esc(p.version || "")}</small>` : ""}
        ${p.risk ? `<small>Risk: ${esc(p.risk)}</small>` : ""}
      </div>
    `).join("")
    : "<p class='muted'>No open ports returned</p>";

  const findingHTML = allFindings.length
    ? allFindings.map(f => {
        const affectedUrl = getAffectedUrl(f);
        return `
          <div class="finding ${riskClass(f.severity)}">
            <div class="finding-head">
              <h4>${esc(f.title || f.name || f.type || "Finding")}</h4>
              <span class="finding-status">${esc(f.status || "INFO")}</span>
            </div>
            ${renderMetaBadges(f)}
            <p><b>Category:</b> ${esc(f.category || "General")}</p>
            <p><b>Description:</b> ${esc(f.description || f.impact || "N/A")}</p>
            <p><b>Evidence:</b> ${esc(f.evidence || "N/A")}</p>
            ${renderUrlActions(affectedUrl)}
            ${f.fix_location ? `<p><b>Fix Location:</b> ${esc(f.fix_location)}</p>` : ""}
            <div class="fix-box"><b>Recommended Fix</b><p>${esc(f.fix || "Review manually")}</p></div>
          </div>
        `;
      }).join("")
    : "<p class='muted'>No findings returned</p>";

  const cveHTML = cveGroups.length
    ? cveGroups.map(group => `
      <div class="finding">
        <h4>🧬 ${esc(group.technology || "Technology")}</h4>
        ${
          group.cves && group.cves.length
          ? group.cves.map(c => `
            <div class="mini-result">
              <b>${esc(c.id || c.cve_id || "CVE")}</b>
              <span>${esc(c.severity || "UNKNOWN")} · CVSS ${esc(c.score || c.cvss || "N/A")}</span>
              <small>${esc(c.description || "")}</small>
              ${c.url ? renderUrlActions(c.url) : ""}
            </div>
          `).join("")
          : "<p class='muted'>No CVEs found</p>"
        }
      </div>
    `).join("")
    : "<p class='muted'>No CVE results available</p>";

  const subdomainHTML = subdomains.length
    ? subdomains.map(s => `
      <div class="mini-result">
        <b>${esc(s.subdomain)}</b>
        <span>Status: ${esc(s.status_code || "N/A")} · HTTPS: ${s.https ? "Yes" : "No"}</span>
        <small>${esc(s.final_url || "")}</small>
        ${s.final_url ? renderUrlActions(s.final_url) : ""}
      </div>
    `).join("")
    : "<p class='muted'>No subdomains returned</p>";

  out.innerHTML = `
    <section class="scan-result-shell">

      <div class="result-header ${riskClass(data.risk)}">
        <div>
          <h2>🛡️ Scan Result</h2>
          <p>${esc(data.target || data.host || "Unknown target")}</p>
        </div>
        <div class="risk-pill">${esc(data.risk || "UNKNOWN")}</div>
      </div>

      <div class="result-grid">
        <div class="box"><span>Risk</span><h3>${esc(data.risk || "UNKNOWN")}</h3></div>
        <div class="box"><span>Score</span><h3>${esc(data.score ?? 0)}/100</h3></div>
        <div class="box"><span>Target Type</span><h3>${esc(data.target_type || "domain")}</h3></div>
        <div class="box"><span>Open Ports</span><h3>${allPorts.length}</h3></div>
        <div class="box"><span>CVEs</span><h3>${cveCount}</h3></div>
        <div class="box"><span>Findings</span><h3>${allFindings.length}</h3></div>
      </div>

      <div class="result-card wide">
        <h3>📊 Severity Overview</h3>
        ${renderSeverityBars(allFindings)}
      </div>

      <div class="result-panels">

        <div class="result-card">
          <h3>🌐 Target Information</h3>
          <p><b>Target:</b> ${esc(data.target || "-")}</p>
          <p><b>Host:</b> ${esc(data.host || "-")}</p>
          <p><b>IP:</b> ${esc(data.ip || "-")}</p>
          <p><b>Final URL:</b> ${esc(data.final_url || "-")}</p>
          <p><b>Status:</b> ${esc(data.status_code || "-")}</p>
          ${data.final_url ? renderUrlActions(data.final_url) : ""}
        </div>

        <div class="result-card">
          <h3>🛰️ Nmap Scan</h3>
          <p><b>Enabled:</b> ${data.nmap_scan?.enabled ? "✅ Yes" : "❌ No"}</p>
          <p><b>Host:</b> ${esc(data.nmap_scan?.host || data.host || "-")}</p>
          <p><b>Error:</b> ${esc(data.nmap_scan?.error || "None")}</p>
        </div>

        <div class="result-card">
          <h3>🚪 Open Ports</h3>
          ${portHTML}
        </div>

        <div class="result-card">
          <h3>🔒 SSL / TLS</h3>
          <p><b>Valid:</b> ${data.ssl?.valid ? "✅ Yes" : "❌ No"}</p>
          <p><b>TLS:</b> ${esc(data.ssl?.tls_version || "-")}</p>
          <p><b>Cipher:</b> ${esc(data.ssl?.cipher_name || "-")}</p>
          <p><b>Expires:</b> ${esc(data.ssl?.info || data.ssl?.expires || "-")}</p>
        </div>

        <div class="result-card">
          <h3>🌍 DNS Security</h3>
          <p><b>SPF:</b> ${data.dns_security?.spf ? "✅ Found" : "❌ Missing"}</p>
          <p><b>DMARC:</b> ${data.dns_security?.dmarc ? "✅ Found" : "❌ Missing"}</p>
          <p><b>A Records:</b> ${safeList(data.dns_security?.a_records)}</p>
          <p><b>Issues:</b> ${safeList(data.dns_security?.issues)}</p>
        </div>

        <div class="result-card">
          <h3>🛡️ WAF Detection</h3>
          <p><b>Name:</b> ${esc(data.waf?.name || data.waf || "Unknown")}</p>
          <p><b>Confidence:</b> ${esc(data.waf?.confidence || "0%")}</p>
          <p><b>Evidence:</b> ${safeList(data.waf?.evidence)}</p>
        </div>

        <div class="result-card wide">
          <h3>🧠 Technologies</h3>
          <p>${safeList(technologies, "Unknown")}</p>
        </div>

        <div class="result-card wide">
          <h3>🌍 Threat Intelligence / ASN</h3>
          ${renderThreatIntel(data)}
        </div>

        <div class="result-card wide">
          <h3>🕸️ Attack Surface Map</h3>
          ${renderAttackSurface(data)}
        </div>

        <div class="result-card wide">
          <h3>🧬 CVE Results</h3>
          ${cveHTML}
        </div>

        <div class="result-card wide">
          <h3>🌐 Subdomains</h3>
          ${subdomainHTML}
        </div>

        <div class="result-card wide">
          <h3>🚨 Findings & Evidence</h3>
          ${findingHTML}
        </div>

        <div class="result-card wide">
          <h3>🧾 Raw JSON</h3>
          <pre>${esc(JSON.stringify(data, null, 2))}</pre>
        </div>

      </div>
    </section>
  `;
}
// =========================
// Add dashboard styles dynamically
// Works even if dashboard.html CSS is old
// =========================
(function injectDashboardStyles() {
  if (document.getElementById("pro-dashboard-style")) return;

  const style = document.createElement("style");
  style.id = "pro-dashboard-style";
  style.textContent = `
    body{
      background:
        radial-gradient(circle at 20% 0%, rgba(255,255,255,.08), transparent 26%),
        linear-gradient(135deg,#000,#111 45%,#222) !important;
      color:#f8fafc !important;
    }

    header{
      background:rgba(0,0,0,.86) !important;
      border-bottom:1px solid rgba(255,255,255,.12) !important;
      backdrop-filter:blur(18px) !important;
    }

    .card,.result-card,.panel{
      background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.03)) !important;
      border:1px solid rgba(255,255,255,.14) !important;
      border-radius:18px !important;
      box-shadow:0 18px 45px rgba(0,0,0,.38) !important;
      backdrop-filter:blur(16px) !important;
    }

    button,a.btn{
      background:linear-gradient(180deg,rgba(255,255,255,.20),rgba(255,255,255,.08)) !important;
      color:#fff !important;
      border:1px solid rgba(255,255,255,.18) !important;
      border-radius:12px !important;
    }

    button:hover,a.btn:hover{
      transform:translateY(-1px);
      box-shadow:0 0 24px rgba(255,255,255,.08);
    }

    .danger{
      background:linear-gradient(180deg,rgba(239,68,68,.9),rgba(127,29,29,.9)) !important;
    }

    input,select{
      background:#080808 !important;
      color:#fff !important;
      border:1px solid rgba(255,255,255,.16) !important;
      border-radius:12px !important;
    }

    .scan-result-shell{
      display:block;
      width:100%;
    }

    .result-header{
      display:flex;
      justify-content:space-between;
      align-items:center;
      gap:14px;
      padding:20px;
      border-radius:20px;
      margin-bottom:16px;
      background:linear-gradient(180deg,rgba(255,255,255,.08),rgba(255,255,255,.03));
      border:1px solid rgba(255,255,255,.14);
      box-shadow:0 18px 45px rgba(0,0,0,.4);
    }

    .result-header h2{margin:0;font-size:28px}
    .result-header p{margin:6px 0 0;color:#a3a3a3}

    .risk-pill{
      padding:10px 16px;
      border-radius:999px;
      font-weight:900;
      background:#111;
      border:1px solid rgba(255,255,255,.16);
    }

    .result-grid{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
      gap:12px;
      margin-bottom:16px;
    }

    .box{
      background:linear-gradient(180deg,rgba(255,255,255,.075),rgba(255,255,255,.025));
      border:1px solid rgba(255,255,255,.14);
      border-radius:16px;
      padding:16px;
    }

    .box span{
      display:block;
      color:#a3a3a3;
      font-size:13px;
      margin-bottom:8px;
    }

    .box h3{
      margin:0;
      font-size:24px;
    }

    .result-panels{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:14px;
    }

    .result-card{
      padding:18px;
      overflow:auto;
    }

    .result-card h3{
      margin-top:0;
    }

    .result-card.wide{
      grid-column:1 / -1;
    }

    .mini-result{
      padding:12px;
      margin:10px 0;
      background:#070707;
      border:1px solid rgba(255,255,255,.10);
      border-radius:12px;
    }

    .mini-result b{
      display:block;
      margin-bottom:5px;
    }

    .mini-result span,.mini-result small{
      display:block;
      color:#a3a3a3;
      line-height:1.5;
    }

    .finding{
      padding:13px;
      margin:10px 0;
      background:#070707;
      border:1px solid rgba(255,255,255,.10);
      border-left:4px solid #60a5fa;
      border-radius:12px;
    }

    .finding.high,.finding.critical{border-left-color:#ef4444}
    .finding.medium{border-left-color:#f59e0b}
    .finding.low{border-left-color:#22c55e}

    pre{
      background:#050505 !important;
      color:#e5e7eb !important;
      border:1px solid rgba(255,255,255,.12) !important;
      border-radius:14px !important;
      padding:14px !important;
      max-height:420px;
      overflow:auto;
      white-space:pre-wrap;
      word-break:break-word;
    }

    .scanning-card{
      text-align:center;
      padding:35px !important;
    }

    .scan-loader{
      width:70px;
      height:70px;
      border-radius:50%;
      border:3px solid rgba(255,255,255,.12);
      border-top-color:#fff;
      margin:0 auto 18px;
      animation:spin 1s linear infinite;
    }

    @keyframes spin{
      to{transform:rotate(360deg)}
    }

    .muted{color:#a3a3a3}


    .meta-badges{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin:10px 0;
    }

    .meta-badge{
      display:inline-flex;
      align-items:center;
      gap:5px;
      padding:6px 9px;
      border-radius:999px;
      background:#111;
      border:1px solid rgba(255,255,255,.12);
      color:#d4d4d4;
      font-size:12px;
      font-weight:800;
    }

    .severity-critical,.severity-high{border-color:rgba(239,68,68,.5);color:#fecaca}
    .severity-medium{border-color:rgba(245,158,11,.5);color:#fde68a}
    .severity-low{border-color:rgba(34,197,94,.5);color:#bbf7d0}

    .finding-head{
      display:flex;
      align-items:flex-start;
      justify-content:space-between;
      gap:10px;
      margin-bottom:8px;
    }

    .finding-head h4{margin:0}

    .finding-status{
      padding:5px 9px;
      border-radius:999px;
      font-size:11px;
      font-weight:900;
      background:rgba(255,255,255,.08);
      border:1px solid rgba(255,255,255,.12);
      color:#fff;
    }

    .affected-box{
      margin:12px 0;
      padding:12px;
      border-radius:14px;
      background:rgba(96,165,250,.08);
      border:1px solid rgba(96,165,250,.28);
    }

    .affected-label{
      font-size:12px;
      color:#93c5fd;
      font-weight:900;
      margin-bottom:6px;
    }

    .affected-link{
      display:block;
      word-break:break-all;
      color:#dbeafe;
      line-height:1.45;
      margin-bottom:10px;
      text-decoration:underline;
      text-underline-offset:3px;
    }

    .affected-actions{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
    }

    .affected-actions button{
      padding:8px 10px !important;
      font-size:12px !important;
    }

    .fix-box{
      margin-top:12px;
      padding:12px;
      background:rgba(34,197,94,.07);
      border:1px solid rgba(34,197,94,.22);
      border-radius:14px;
    }

    .fix-box b{
      color:#bbf7d0;
    }

    .fix-box p{
      margin:7px 0 0;
    }

    .severity-bars{
      display:grid;
      gap:10px;
    }

    .sev-row{
      display:grid;
      grid-template-columns:80px 1fr 32px;
      align-items:center;
      gap:10px;
      color:#d4d4d4;
      font-size:13px;
      font-weight:800;
    }

    .sev-track{
      height:10px;
      border-radius:999px;
      background:#080808;
      border:1px solid rgba(255,255,255,.08);
      overflow:hidden;
    }

    .sev-fill{
      height:100%;
      border-radius:999px;
      background:#60a5fa;
    }

    .sev-fill.critical,.sev-fill.high{background:#ef4444}
    .sev-fill.medium{background:#f59e0b}
    .sev-fill.low{background:#22c55e}
    .sev-fill.info{background:#60a5fa}

    .progress-steps{
      display:grid;
      gap:8px;
      max-width:420px;
      margin:18px auto 0;
      text-align:left;
    }

    .step{
      padding:9px 11px;
      background:#070707;
      border:1px solid rgba(255,255,255,.09);
      border-radius:12px;
      color:#a3a3a3;
      font-weight:800;
      font-size:13px;
    }

    .step.done{color:#bbf7d0;border-color:rgba(34,197,94,.25)}
    .step.active{color:#dbeafe;border-color:rgba(96,165,250,.35)}

    .intel-grid,.attack-grid{
      display:grid;
      grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
      gap:10px;
    }


    @media(max-width:850px){
      .result-panels{grid-template-columns:1fr}
      .result-header{align-items:flex-start;flex-direction:column}
    }
  `;

  document.head.appendChild(style);
})();
