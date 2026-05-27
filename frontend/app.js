const API = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") ? "http://127.0.0.1:8000" : "https://threat-scanner-saas-2.onrender.com";
let historyItems = [];
let autoRefreshTimer = null;
let lastReport = null;

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

function token(){ return getToken(); }

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
// Enterprise Sections Helpers
// =========================
function normalizeFindingList(list) {
  return Array.isArray(list) ? list : [];
}

function classifyFindingFrontend(f) {
  const status = String(f?.status || "").toUpperCase();
  const severity = String(f?.severity || "INFO").toUpperCase();
  const category = String(f?.category || "").toLowerCase();
  const title = String(f?.title || f?.name || f?.type || "").toLowerCase();

  if (status === "CONFIRMED") return "confirmed";
  if (status === "POSSIBLE") return "possible";
  if (status === "HARDENING") return "hardening";
  if (category.includes("headers") || title.includes("missing security header")) return "hardening";
  if (category.includes("attack surface") || category.includes("api") || category.includes("subdomain") || category.includes("robots")) return "attack_surface";
  if (["CRITICAL", "HIGH", "MEDIUM"].includes(severity)) return "possible";
  return "informational";
}

function buildFrontendSections(data) {
  let confirmed = normalizeFindingList(data.confirmed_vulnerabilities);
  let possible = normalizeFindingList(data.possible_issues);
  let hardening = normalizeFindingList(data.hardening_issues);
  let attackSurface = normalizeFindingList(data.attack_surface);
  let informational = normalizeFindingList(data.informational_findings);

  const hasBackendSections = confirmed.length || possible.length || hardening.length || attackSurface.length || informational.length;

  if (!hasBackendSections) {
    const combined = [
      ...(Array.isArray(data.findings) ? data.findings : []),
      ...(Array.isArray(data.vulnerability_checks) ? data.vulnerability_checks : [])
    ];

    for (const item of combined) {
      const bucket = classifyFindingFrontend(item);
      if (bucket === "confirmed") confirmed.push(item);
      else if (bucket === "possible") possible.push(item);
      else if (bucket === "hardening") hardening.push(item);
      else if (bucket === "attack_surface") attackSurface.push(item);
      else informational.push(item);
    }
  }

  return {confirmed, possible, hardening, attackSurface, informational};
}

function renderFindingCard(f, defaultStatus = "INFO") {
  const affectedUrl = getAffectedUrl(f);
  const title = f.title || f.name || f.type || "Finding";
  const status = f.status || defaultStatus;

  return `
    <div class="finding ${riskClass(f.severity)}">
      <div class="finding-head">
        <h4>${esc(title)}</h4>
        <span class="finding-status">${esc(status)}</span>
      </div>
      ${renderMetaBadges({...f, status})}
      <p><b>Category:</b> ${esc(f.category || "General")}</p>
      <p><b>Description:</b> ${esc(f.description || f.impact || "N/A")}</p>
      <p><b>Evidence:</b> ${esc(f.evidence || "N/A")}</p>
      ${renderUrlActions(affectedUrl)}
      ${f.fix_location ? `<p><b>Fix Location:</b> ${esc(f.fix_location)}</p>` : ""}
      ${f.exploitability ? `<p><b>Exploitability:</b> ${esc(f.exploitability)}</p>` : ""}
      <div class="fix-box"><b>Recommended Fix</b><p>${esc(f.fix || "Review manually")}</p></div>
    </div>
  `;
}

function renderEnterpriseSection(title, icon, items, emptyText, status, sectionClass) {
  return `
    <div class="result-card wide enterprise-section ${sectionClass}">
      <div class="section-title-row">
        <h3>${icon} ${title}</h3>
        <span class="section-count">${items.length}</span>
      </div>
      ${items.length ? items.map(item => renderFindingCard(item, status)).join("") : `<p class="muted">${esc(emptyText)}</p>`}
    </div>
  `;
}

function renderEnterpriseSummaryCards(sections) {
  return `
    <div class="result-grid">
      <div class="box confirmed-box"><span>Confirmed</span><h3>${sections.confirmed.length}</h3></div>
      <div class="box possible-box"><span>Possible</span><h3>${sections.possible.length}</h3></div>
      <div class="box hardening-box"><span>Hardening</span><h3>${sections.hardening.length}</h3></div>
      <div class="box attack-box"><span>Attack Surface</span><h3>${sections.attackSurface.length}</h3></div>
      <div class="box info-box"><span>Informational</span><h3>${sections.informational.length}</h3></div>
    </div>
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
// Live Scan Progress Helpers
// =========================
let currentScanJobId = null;
let currentScanPollTimer = null;

function progressStepsFromStatus(job) {
  const progress = Number(job?.progress || 0);
  const steps = [
    {label: "Queued", min: 0},
    {label: "Preparation", min: 10},
    {label: "DNS Analysis", min: 20},
    {label: "SSL / TLS", min: 35},
    {label: "Headers / WAF", min: 50},
    {label: "Exposure Engine", min: 65},
    {label: "Deep Analysis", min: 80},
    {label: "Saving Report", min: 95},
    {label: "Completed", min: 100},
  ];

  return `
    <div class="live-progress-card">
      <div class="progress-topline">
        <b>${esc(job?.phase || job?.step || "Preparing scan")}</b>
        <span>${progress}%</span>
      </div>
      <div class="progress-track-live">
        <div class="progress-fill-live" style="width:${Math.max(0, Math.min(100, progress))}%"></div>
      </div>
      <p class="muted">${esc(job?.step || "Scan queued")}</p>
      ${job?.queue_position ? `<p class="muted"><b>Queue position:</b> ${esc(job.queue_position)}</p>` : ""}
      <div class="progress-steps">
        ${steps.map(s => {
          const cls = progress >= s.min ? "done" : (progress + 15 >= s.min ? "active" : "");
          const icon = progress >= s.min ? "✓" : (progress + 15 >= s.min ? "⟳" : "•");
          return `<div class="step ${cls}">${icon} ${esc(s.label)}</div>`;
        }).join("")}
      </div>
      ${(job?.status === "running" || job?.status === "queued") ? `<button class="danger cancel-live-btn" onclick="cancelCurrentScan()">Cancel Scan</button>` : ""}
    </div>
  `;
}

function renderLiveScanStatus(job) {
  const out = $("out") || $("container");
  if (!out) return;

  out.innerHTML = `
    <div class="result-card scanning-card">
      <div class="scan-loader"></div>
      <h2>🔍 Live Scan Progress</h2>
      <p><b>Target:</b> ${esc(job?.target || "-")}</p>
      <p><b>Profile:</b> ${esc(job?.profile || "-")}</p>
      <p><b>Status:</b> ${esc(job?.status || "queued")}</p>
      ${progressStepsFromStatus(job)}
    </div>
  `;

  if (typeof setStatus === "function") {
    setStatus(`${esc(job?.status || "queued")} — ${esc(job?.step || "Scan queued")}`);
  }
}

async function pollScanStatus(jobId) {
  try {
    const res = await fetch(API + "/scan-status/" + encodeURIComponent(jobId), {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + getToken()
      }
    });

    const job = await res.json().catch(() => ({}));

    if (!res.ok) {
      clearInterval(currentScanPollTimer);
      currentScanPollTimer = null;
      showMessage(job.detail || "Could not read scan status", "error");
      return;
    }

    renderLiveScanStatus(job);

    if (job.status === "completed") {
      clearInterval(currentScanPollTimer);
      currentScanPollTimer = null;
      currentScanJobId = null;

      if (job.result) {
        lastReport = job.result;
        if (typeof setStatus === "function") setStatus("✅ Scan completed");
        renderScanResult(job.result);
        if (typeof loadData === "function") loadData(false);
      } else {
        showMessage("Scan completed, but no result returned", "success");
      }
      return;
    }

    if (job.status === "failed") {
      clearInterval(currentScanPollTimer);
      currentScanPollTimer = null;
      currentScanJobId = null;
      showMessage(job.error || "Scan failed", "error");
      return;
    }

    if (job.status === "cancelled") {
      clearInterval(currentScanPollTimer);
      currentScanPollTimer = null;
      currentScanJobId = null;
      showMessage("Scan cancelled", "info");
      return;
    }

  } catch (err) {
    console.error(err);
    clearInterval(currentScanPollTimer);
    currentScanPollTimer = null;
    showMessage("Live scan connection failed", "error");
  }
}

async function startAsyncScan(target, profile) {
  const res = await fetch(API + "/scan-async", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + getToken()
    },
    body: JSON.stringify({target, profile})
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(data.detail || "Could not start async scan");
  }

  return data;
}

async function cancelCurrentScan() {
  if (!currentScanJobId) {
    alert("No running scan");
    return;
  }

  try {
    const res = await fetch(API + "/cancel-scan/" + encodeURIComponent(currentScanJobId), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + getToken()
      }
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      alert(data.detail || "Cancel failed");
      return;
    }

    if (typeof setStatus === "function") setStatus("Scan cancel requested");
    await pollScanStatus(currentScanJobId);

  } catch (err) {
    console.error(err);
    alert("Cancel request failed");
  }
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

  if (typeof showSection === "function") showSection("scan");

  if (out) {
    out.innerHTML = `
      <div class="result-card scanning-card">
        <div class="scan-loader"></div>
        <h2>🔍 Starting Live Scan...</h2>
        <p><b>Target:</b> ${esc(target)}</p>
        <p><b>Profile:</b> ${esc(profile)}</p>
        <p class="muted">Creating scan job and connecting to live progress...</p>
        ${renderProgressSteps()}
      </div>
    `;
  }

  try {
    const job = await startAsyncScan(target, profile);

    currentScanJobId = job.job_id;

    renderLiveScanStatus({
      job_id: job.job_id,
      target,
      profile,
      status: job.status || "queued",
      progress: 0,
      step: job.message || "Scan queued",
      phase: "Queued",
      queue_position: job.queue_position,
      queue_size: job.queue_size
    });

    if (currentScanPollTimer) clearInterval(currentScanPollTimer);

    await pollScanStatus(currentScanJobId);

    currentScanPollTimer = setInterval(() => {
      if (currentScanJobId) pollScanStatus(currentScanJobId);
    }, 1500);

  } catch (err) {
    console.error(err);
    showMessage(err.message || "Cannot start live scan", "error");
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

  lastReport = data;

  const openPorts = Array.isArray(data.open_ports) ? data.open_ports : [];
  const nmapPorts = Array.isArray(data.nmap_scan?.ports) ? data.nmap_scan.ports : [];
  const allPorts = openPorts.length ? openPorts : nmapPorts;

  const cveGroups = Array.isArray(data.cve_results) ? data.cve_results : [];
  const technologies = Array.isArray(data.technologies) ? data.technologies : [];
  const subdomains = Array.isArray(data.subdomains) ? data.subdomains : [];
  const sections = buildFrontendSections(data);
  const allFindings = [...sections.confirmed, ...sections.possible, ...sections.hardening, ...sections.attackSurface, ...sections.informational];

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
        <div class="box"><span>Total Findings</span><h3>${allFindings.length}</h3></div>
      </div>

      ${renderEnterpriseSummaryCards(sections)}

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

        <div class="result-card"><h3>🚪 Open Ports</h3>${portHTML}</div>

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

        <div class="result-card wide"><h3>🧠 Technologies</h3><p>${safeList(technologies, "Unknown")}</p></div>
        <div class="result-card wide"><h3>🌍 Threat Intelligence / ASN</h3>${renderThreatIntel(data)}</div>
        <div class="result-card wide"><h3>🕸️ Attack Surface Map</h3>${renderAttackSurface(data)}</div>
        <div class="result-card wide"><h3>🧬 CVE Results</h3>${cveHTML}</div>
        <div class="result-card wide"><h3>🌐 Subdomains</h3>${subdomainHTML}</div>

        ${renderEnterpriseSection("Confirmed Vulnerabilities", "🔴", sections.confirmed, "No confirmed vulnerabilities found.", "CONFIRMED", "confirmed-section")}
        ${renderEnterpriseSection("Possible Issues / Manual Review", "🟡", sections.possible, "No possible issues returned.", "POSSIBLE", "possible-section")}
        ${renderEnterpriseSection("Hardening Issues", "🛡️", sections.hardening, "No hardening issues returned.", "HARDENING", "hardening-section")}
        ${renderEnterpriseSection("Attack Surface / Exposure", "🕸️", sections.attackSurface, "No attack surface findings returned.", "INFO", "attack-section")}
        ${renderEnterpriseSection("Informational Findings", "🔵", sections.informational, "No informational findings returned.", "INFO", "info-section")}

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



    .enterprise-section{position:relative}
    .section-title-row{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}
    .section-title-row h3{margin:0}
    .section-count{min-width:34px;height:34px;display:inline-grid;place-items:center;border-radius:999px;background:#0a0a0a;border:1px solid rgba(255,255,255,.14);font-weight:900}
    .confirmed-section,.confirmed-box{border-left:5px solid #ef4444 !important}
    .possible-section,.possible-box{border-left:5px solid #f59e0b !important}
    .hardening-section,.hardening-box{border-left:5px solid #22c55e !important}
    .attack-section,.attack-box{border-left:5px solid #60a5fa !important}
    .info-section,.info-box{border-left:5px solid #38bdf8 !important}



    .live-progress-card{max-width:520px;margin:18px auto 0;padding:16px;border-radius:18px;background:#070707;border:1px solid rgba(255,255,255,.12);text-align:left}
    .progress-topline{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}
    .progress-topline span{font-weight:900;color:#dbeafe}
    .progress-track-live{height:12px;border-radius:999px;overflow:hidden;background:#020202;border:1px solid rgba(255,255,255,.12);margin-bottom:10px}
    .progress-fill-live{height:100%;border-radius:999px;background:linear-gradient(90deg,#60a5fa,#22c55e);transition:width .35s ease}
    .cancel-live-btn{margin-top:14px;width:100%}


    @media(max-width:850px){
      .result-panels{grid-template-columns:1fr}
      .result-header{align-items:flex-start;flex-direction:column}
    }
  `;

  document.head.appendChild(style);
})();


// =========================
// Dashboard / History / Export Functions - no-conflict external app.js mode
// =========================
function setStatus(msg){ const el = $("statusBox"); if (el) el.innerHTML = msg; }
function showToast(msg){ let t = $("toast"); if (!t) { t = document.createElement("div"); t.id = "toast"; t.className = "toast"; document.body.appendChild(t); } t.innerHTML = esc(msg); t.style.display = "block"; setTimeout(() => t.style.display = "none", 2600); }
function showSection(name){ const scanSection=$("scanSection"), historySection=$("historySection"), tabScan=$("tabScan"), tabHistory=$("tabHistory"); if(scanSection) scanSection.classList.toggle("active", name==="scan"); if(historySection) historySection.classList.toggle("active", name==="history"); if(tabScan) tabScan.classList.toggle("active", name==="scan"); if(tabHistory) tabHistory.classList.toggle("active", name==="history"); }
function requireLogin(){ if(!getToken()){ const out=$("out")||$("container"); if(out) out.innerHTML = `<div class="result-card"><h2>❌ Not logged in</h2><p>Please login first.</p><button onclick="location.href='index.html'">Go to Login</button></div>`; return false; } return true; }
async function apiFetch(path, options={}){ const res = await fetch(API + path, { ...options, headers:{ "Content-Type":"application/json", "Authorization":"Bearer " + getToken(), ...(options.headers || {}) }}); const data = await res.json().catch(()=>({})); if(res.status===401){ localStorage.removeItem("token"); showToast("Session expired. Login again."); } return {res,data}; }
async function loadQueueStatus(){ if(!getToken()) return; const box=$("queueBox"); if(!box) return; try{ const {res,data}=await apiFetch("/queue-status"); if(!res.ok){ box.innerHTML=""; return; } box.innerHTML = `<div class="summary"><div class="card metric"><h3>📦 Queue Size</h3><p>${esc(data.queue_size ?? 0)}</p></div><div class="card metric medium"><h3>⚡ Running</h3><p>${esc(data.running ?? 0)}</p></div><div class="card metric"><h3>⏳ Queued</h3><p>${esc(data.queued ?? 0)}</p></div><div class="card metric low"><h3>✅ Completed</h3><p>${esc(data.completed ?? 0)}</p></div><div class="card metric high"><h3>❌ Failed</h3><p>${esc(data.failed ?? 0)}</p></div></div>`; }catch(e){ console.warn("Queue status failed", e); } }
async function loadData(manual=false){ if(!getToken()){ const container=$("container"); if(container) container.innerHTML = `<div class="card high"><h3>❌ Not Logged In</h3><p>Please login first.</p></div>`; return; } await loadQueueStatus(); const container=$("container"); if(!container) return; try{ const {res,data}=await apiFetch("/history"); if(!res.ok){ container.innerHTML = `<div class="card high"><h3>❌ Error</h3><p>${esc(data.detail || "Could not load history")}</p></div>`; return; } historyItems = Array.isArray(data.data) ? data.data : []; renderHistory(); if(manual) showToast("Dashboard refreshed"); }catch(e){ container.innerHTML = `<div class="card high"><h3>❌ Error</h3><p>Could not connect to backend</p></div>`; } }
function normalizeItem(item){ if(Array.isArray(item)) return {id:item[0], target:item[1], risk:item[2], score:item[3], created_at:item[4]}; return item || {}; }
function renderHistory(){ const container=$("container"), stats=$("historyStats"); if(!container) return; const q=$("searchBox") ? $("searchBox").value.toLowerCase().trim() : ""; const filter=$("riskFilter") ? $("riskFilter").value : "ALL"; const sort=$("sortBox") ? $("sortBox").value : "newest"; let items=historyItems.map(normalizeItem); const total=items.length; const high=items.filter(x=>["HIGH","CRITICAL"].includes(String(x.risk).toUpperCase())).length; const med=items.filter(x=>String(x.risk).toUpperCase()==="MEDIUM").length; const avg=total ? Math.round(items.reduce((s,x)=>s+Number(x.score||0),0)/total) : 0; if(stats) stats.innerHTML = `<div class="card metric"><h3>🧾 Total Scans</h3><p>${total}</p></div><div class="card metric high"><h3>🚨 High/Critical</h3><p>${high}</p></div><div class="card metric medium"><h3>⚠️ Medium</h3><p>${med}</p></div><div class="card metric"><h3>📈 Average Score</h3><p>${avg}/100</p></div>`; if(q) items=items.filter(x=>String(x.target||"").toLowerCase().includes(q)); if(filter!=="ALL") items=items.filter(x=>String(x.risk||"UNKNOWN").toUpperCase()===filter); items.sort((a,b)=>{ if(sort==="oldest") return new Date(a.created_at||0)-new Date(b.created_at||0); if(sort==="score_high") return Number(b.score||0)-Number(a.score||0); if(sort==="score_low") return Number(a.score||0)-Number(b.score||0); return new Date(b.created_at||0)-new Date(a.created_at||0); }); if(!items.length){ container.innerHTML = `<div class="card"><h3>📭 No Scan History</h3><p>No scans match your filters.</p></div>`; return; } container.innerHTML = items.map(item=>{ const r=String(item.risk||"UNKNOWN").toUpperCase(); return `<div class="card ${riskClass(r)}"><div class="scan-title"><h3>🌐 ${esc(item.target || "Unknown target")}</h3><span class="badge ${esc(r)}">${esc(r)}</span></div><p><b>Score:</b> ${esc(item.score ?? "N/A")}/100</p><p><b>Date:</b> <span class="muted">${esc(item.created_at || "Unknown")}</span></p><div class="row"><button onclick="viewReport(${Number(item.id)})">View Report</button><button onclick="downloadSingleReport(${Number(item.id)})">JSON</button><button class="danger" onclick="deleteHistory(${Number(item.id)})">Delete</button></div></div>`; }).join(""); }
function renderReportHTML(report){ return `<h1>🛡️ Scan Report</h1><div class="report-section ${riskClass(report.risk)}"><div class="mini-grid"><div class="mini"><b>Target</b>${esc(report.target || "-")}</div><div class="mini"><b>Risk</b>${esc(report.risk || "-")}</div><div class="mini"><b>Score</b>${esc(report.score ?? 0)}/100</div><div class="mini"><b>Host</b>${esc(report.host || "-")}</div></div></div><div class="report-section"><h2>📦 Full JSON</h2><pre>${esc(JSON.stringify(report, null, 2))}</pre></div>`; }
async function viewReport(id){ const {res,data:report}=await apiFetch("/history/"+id); if(!res.ok){ alert(report.detail || "Could not load report"); return; } const win=window.open("","_blank"); win.document.write(`<!DOCTYPE html><html><head><title>Scan Report</title><meta name="viewport" content="width=device-width, initial-scale=1.0"><style>${document.querySelector("style") ? document.querySelector("style").innerHTML : ""} body{padding:24px;background:#050505;color:#fff}</style></head><body><div class="wrap">${renderReportHTML(report)}<div class="row"><button onclick="window.print()">Download / Print PDF</button></div></div></body></html>`); win.document.close(); }
async function downloadSingleReport(id){ const {res,data}=await apiFetch("/history/"+id); if(!res.ok){ alert(data.detail || "Could not load report"); return; } downloadJSON(data, `scan-report-${data.host || data.target || id}.json`); }
function downloadLastJSON(){ if(!lastReport){ alert("No scan report yet"); return; } downloadJSON(lastReport, `scan-report-${lastReport.host || lastReport.target || "target"}.json`); }
function downloadLastPDF(){ if(!lastReport){ alert("No scan report yet"); return; } const win=window.open("","_blank"); win.document.write(`<!DOCTYPE html><html><head><title>PDF Report</title><style>${document.querySelector("style") ? document.querySelector("style").innerHTML : ""} body{padding:24px;background:#050505;color:#fff}</style></head><body>${renderReportHTML(lastReport)}<script>window.print();<\/script></body></html>`); win.document.close(); }
function exportHistory(){ downloadJSON(historyItems.map(normalizeItem), "scan-history.json"); }
function downloadJSON(data, filename){ const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const a=document.createElement("a"); a.href=url; a.download=filename.replace(/[^a-z0-9_.-]/gi,"-").toLowerCase(); a.click(); URL.revokeObjectURL(url); }
async function deleteHistory(id){ if(!confirm("Delete this scan from history?")) return; const {res,data}=await apiFetch("/history/"+id,{method:"DELETE"}); if(!res.ok){ alert(data.detail || "Could not delete scan"); return; } historyItems=historyItems.map(normalizeItem).filter(x=>Number(x.id)!==Number(id)); renderHistory(); showToast("Scan deleted"); }
document.addEventListener("DOMContentLoaded", ()=>{ if($("queueBox")){ if(!getToken()){ requireLogin(); return; } loadData(false); if(!autoRefreshTimer){ autoRefreshTimer=setInterval(()=>{ const historySection=$("historySection"); if(historySection && historySection.classList.contains("active")) loadData(false); else loadQueueStatus(); },15000); } } });
