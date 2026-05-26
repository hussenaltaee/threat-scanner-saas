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
        <p class="muted">Please wait while the scanner checks ports, SSL, DNS, headers, WAF, and findings.</p>
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
      </div>
    `).join("")
    : "<p class='muted'>No open ports returned</p>";

  const findingHTML = [...findings, ...vulns].length
    ? [...findings, ...vulns].map(f => `
      <div class="finding ${riskClass(f.severity)}">
        <h4>${esc(f.title || f.name || "Finding")}</h4>
        <p><b>Severity:</b> ${esc(f.severity || "INFO")}</p>
        <p><b>Evidence:</b> ${esc(f.evidence || "N/A")}</p>
        <p><b>Fix:</b> ${esc(f.fix || "Review manually")}</p>
      </div>
    `).join("")
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
        <div class="box"><span>Findings</span><h3>${findings.length + vulns.length}</h3></div>
      </div>

      <div class="result-panels">

        <div class="result-card">
          <h3>🌐 Target Information</h3>
          <p><b>Target:</b> ${esc(data.target || "-")}</p>
          <p><b>Host:</b> ${esc(data.host || "-")}</p>
          <p><b>IP:</b> ${esc(data.ip || "-")}</p>
          <p><b>Final URL:</b> ${esc(data.final_url || "-")}</p>
          <p><b>Status:</b> ${esc(data.status_code || "-")}</p>
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
          <h3>🧬 CVE Results</h3>
          ${cveHTML}
        </div>

        <div class="result-card wide">
          <h3>🌐 Subdomains</h3>
          ${subdomainHTML}
        </div>

        <div class="result-card wide">
          <h3>🚨 Findings</h3>
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

    @media(max-width:850px){
      .result-panels{grid-template-columns:1fr}
      .result-header{align-items:flex-start;flex-direction:column}
    }
  `;

  document.head.appendChild(style);
})();
