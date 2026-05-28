const API = (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") ? "http://127.0.0.1:8000" : "https://threat-scanner-saas-2.onrender.com";
let historyItems = [];
let autoRefreshTimer = null;
let lastReport = null;
let currentScanJobId = null;
let currentScanPollTimer = null;
let currentBulkJobId = null;
let currentBulkPollTimer = null;

function $(id) { return document.getElementById(id); }
function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function getToken() { return localStorage.getItem("token"); }
function token(){ return getToken(); }
function riskClass(risk) {
  const r = String(risk || "UNKNOWN").toUpperCase();
  if (r === "CRITICAL") return "critical";
  if (r === "HIGH") return "high";
  if (r === "MEDIUM") return "medium";
  if (r === "LOW") return "low";
  return "unknown";
}
function setStatus(msg){ const el = $("statusBox"); if (el) el.innerHTML = msg; }
function showToast(msg){ let t = $("toast"); if (!t) { t = document.createElement("div"); t.id = "toast"; t.className = "toast"; document.body.appendChild(t); } t.innerHTML = esc(msg); t.style.display = "block"; setTimeout(() => t.style.display = "none", 2600); }
function safeList(items, empty = "None") { if (!items) return empty; if (Array.isArray(items)) return items.length ? items.map(esc).join(", ") : empty; return esc(items); }
function showMessage(msg, type = "info") {
  const out = $("out") || $("container");
  if (!out) { alert(msg); return; }
  const color = type === "error" ? "#ef4444" : type === "success" ? "#22c55e" : "#60a5fa";
  out.innerHTML = `<div class="result-card" style="border-left:5px solid ${color};"><h2>${type === "error" ? "❌" : type === "success" ? "✅" : "ℹ️"} ${esc(msg)}</h2></div>`;
}
async function apiFetch(path, options={}){
  const res = await fetch(API + path, { ...options, headers:{ "Content-Type":"application/json", "Authorization":"Bearer " + getToken(), ...(options.headers || {}) }});
  const data = await res.json().catch(()=>({}));
  if(res.status===401){ localStorage.removeItem("token"); showToast("Session expired. Login again."); }
  return {res,data};
}
function requireLogin(){
  if(!getToken()){
    const out=$("out")||$("container");
    if(out) out.innerHTML = `<div class="result-card"><h2>❌ Not logged in</h2><p>Please login first.</p><button onclick="location.href='index.html'">Go to Login</button></div>`;
    return false;
  }
  return true;
}

function showSection(name){
  const scanSection=$("scanSection"), historySection=$("historySection"), bulkSection=$("bulkSection");
  const tabScan=$("tabScan"), tabHistory=$("tabHistory"), tabBulk=$("tabBulk");
  if(scanSection) scanSection.classList.toggle("active", name==="scan");
  if(historySection) historySection.classList.toggle("active", name==="history");
  if(bulkSection) bulkSection.classList.toggle("active", name==="bulk");
  if(tabScan) tabScan.classList.toggle("active", name==="scan");
  if(tabHistory) tabHistory.classList.toggle("active", name==="history");
  if(tabBulk) tabBulk.classList.toggle("active", name==="bulk");
  if(name === "bulk") ensureBulkUI();
}

function ensureBulkUI(){
  if ($("bulkSection")) return;
  const tabs = document.querySelector(".tabs");
  if (tabs && !$("tabBulk")) {
    tabs.insertAdjacentHTML("beforeend", `<button class="tab" id="tabBulk" onclick="showSection('bulk')">Bulk Scan</button>`);
  }
  const parent = $("historySection")?.parentElement || $("scanSection")?.parentElement;
  if (!parent) return;
  parent.insertAdjacentHTML("beforeend", `
    <section id="bulkSection" class="section">
      <div class="panel out" id="bulkOut">
        <h2>🧩 Unlimited Bulk Scan</h2>
        <p class="muted">ضع الروابط، كل رابط بسطر. النظام يفحصها بالطابور حتى لا ينهار السيرفر.</p>
        <div class="field">
          <label>Targets list</label>
          <textarea id="bulkTargets" placeholder="https://site1.com\nhttps://site2.com\nscanme.nmap.org"></textarea>
        </div>
        <div class="field">
          <label>Bulk scan profile</label>
          <select id="bulkProfile">
            <option value="quick">⚡ Quick</option>
            <option value="full" selected>🛡️ Full</option>
            <option value="deep">🔥 Deep</option>
          </select>
        </div>
        <div class="scan-actions">
          <button class="green" onclick="startBulkScan()">Start Bulk Scan</button>
          <button class="danger" onclick="cancelBulkScan()">Cancel Bulk</button>
          <button onclick="downloadBulkJSON()">JSON</button>
        </div>
        <div id="bulkStatus" class="status">Ready for unlimited targets.</div>
        <div id="bulkResults"></div>
      </div>
    </section>
  `);
}

function injectBulkButtonIfNeeded(){
  const actions = document.querySelector(".actions");
  if(actions && !$("bulkNavBtn")){
    const btn = document.createElement("button");
    btn.id = "bulkNavBtn";
    btn.className = "ghost";
    btn.textContent = "🧩 Bulk Scan";
    btn.onclick = () => showSection("bulk");
    const historyBtn = Array.from(actions.children).find(x => String(x.textContent).includes("History"));
    actions.insertBefore(btn, historyBtn || actions.children[1] || null);
  }
  const tabs = document.querySelector(".tabs");
  if(tabs && !$("tabBulk")) tabs.insertAdjacentHTML("beforeend", `<button class="tab" id="tabBulk" onclick="showSection('bulk')">Bulk Scan</button>`);
}

function normalizeBulkTargets(raw){
  const seen = new Set();
  return String(raw || "")
    .split(/\r?\n|,/) 
    .map(x => x.trim())
    .filter(Boolean)
    .filter(x => {
      const key = x.toLowerCase();
      if(seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

async function startBulkScan(){
  if(!requireLogin()) return;
  ensureBulkUI();
  const targets = normalizeBulkTargets($("bulkTargets")?.value || "");
  const profile = $("bulkProfile")?.value || "full";
  if(!targets.length){ alert("أدخل روابط، كل رابط بسطر"); return; }
  const bulkResults = $("bulkResults");
  const bulkStatus = $("bulkStatus");
  if(bulkResults) bulkResults.innerHTML = `<div class="result-card scanning-card"><div class="scan-loader"></div><h2>🧩 Starting Bulk Scan...</h2><p>${targets.length} targets queued</p></div>`;
  if(bulkStatus) bulkStatus.innerHTML = `Starting bulk scan for ${targets.length} targets...`;
  try{
    const {res,data} = await apiFetch("/bulk-scan/start", {
      method:"POST",
      body: JSON.stringify({targets, profile})
    });
    if(!res.ok) throw new Error(data.detail || "Bulk scan start failed");
    currentBulkJobId = data.bulk_scan_id || data.job_id || data.id;
    if(!currentBulkJobId) throw new Error("Backend did not return bulk_scan_id");
    if(currentBulkPollTimer) clearInterval(currentBulkPollTimer);
    await pollBulkStatus(currentBulkJobId);
    currentBulkPollTimer = setInterval(()=>pollBulkStatus(currentBulkJobId), 2000);
  }catch(e){
    console.error(e);
    if(bulkResults) bulkResults.innerHTML = `<div class="result-card high"><h2>❌ Bulk Scan Error</h2><p>${esc(e.message || e)}</p></div>`;
    if(bulkStatus) bulkStatus.innerHTML = `Error: ${esc(e.message || e)}`;
  }
}

async function pollBulkStatus(id){
  try{
    const {res,data} = await apiFetch("/bulk-scan/status/" + encodeURIComponent(id));
    if(!res.ok) throw new Error(data.detail || "Could not read bulk status");
    renderBulkStatus(data);
    const status = String(data.status || "").toLowerCase();
    if(["completed","failed","cancelled"].includes(status)){
      if(currentBulkPollTimer) clearInterval(currentBulkPollTimer);
      currentBulkPollTimer = null;
      await loadBulkResults(id);
    }
  }catch(e){
    console.error(e);
    if(currentBulkPollTimer) clearInterval(currentBulkPollTimer);
    currentBulkPollTimer = null;
    const bulkStatus = $("bulkStatus");
    if(bulkStatus) bulkStatus.innerHTML = `Bulk status error: ${esc(e.message || e)}`;
  }
}

function renderBulkStatus(job){
  ensureBulkUI();
  const total = Number(job.total || job.total_targets || 0);
  const completed = Number(job.completed || job.scanned || 0);
  const failed = Number(job.failed || 0);
  const vulnerable = Number(job.vulnerable || job.vulnerable_targets || 0);
  const progress = total ? Math.round((completed + failed) / total * 100) : Number(job.progress || 0);
  const status = job.status || "running";
  const bulkStatus = $("bulkStatus");
  if(bulkStatus){
    bulkStatus.innerHTML = `
      <b>Status:</b> ${esc(status)}<br>
      <b>Progress:</b> ${progress}% · ${completed + failed}/${total || "?"}<br>
      <b>Vulnerable:</b> ${vulnerable} · <b>Failed:</b> ${failed}
      <div class="progress-track-live" style="margin-top:10px"><div class="progress-fill-live" style="width:${Math.max(0,Math.min(100,progress))}%"></div></div>
    `;
  }
  const bulkResults = $("bulkResults");
  if(bulkResults && !String(status).match(/completed|failed|cancelled/i)){
    bulkResults.innerHTML = `
      <div class="result-card scanning-card">
        <div class="scan-loader"></div>
        <h2>🧩 Bulk Scan Running</h2>
        <div class="result-grid">
          <div class="box"><span>Total</span><h3>${total}</h3></div>
          <div class="box"><span>Done</span><h3>${completed}</h3></div>
          <div class="box"><span>Failed</span><h3>${failed}</h3></div>
          <div class="box high"><span>Vulnerable</span><h3>${vulnerable}</h3></div>
        </div>
      </div>
    `;
  }
}

async function loadBulkResults(id){
  try{
    const {res,data} = await apiFetch("/bulk-scan/results/" + encodeURIComponent(id));
    if(!res.ok) throw new Error(data.detail || "Could not read bulk results");
    lastReport = data;
    renderBulkResults(data);
  }catch(e){
    const bulkResults = $("bulkResults");
    if(bulkResults) bulkResults.innerHTML = `<div class="result-card high"><h2>❌ Bulk Results Error</h2><p>${esc(e.message || e)}</p></div>`;
  }
}

function renderBulkResults(data){
  ensureBulkUI();
  const results = Array.isArray(data.results) ? data.results : [];
  const total = data.total_targets ?? results.length;
  const vulnerable = data.vulnerable_targets ?? results.filter(r => ["HIGH","CRITICAL","MEDIUM"].includes(String(r.risk || r.result?.risk).toUpperCase())).length;
  const failed = data.failed ?? results.filter(r => r.status === "failed" || r.error).length;
  const infectedUrls = [];
  const archiveUrls = [];
  results.forEach(r => {
    const rr = r.result || r;
    (rr.infected_urls || rr.vulnerable_urls || []).forEach(u => infectedUrls.push({target:r.target || rr.target, url:u}));
    (rr.archive_urls || rr.wayback_urls || rr.wayback_archive_urls || []).forEach(u => archiveUrls.push({target:r.target || rr.target, url: typeof u === "string" ? u : (u.url || u.archive_url)}));
  });
  const html = `
    <div class="result-card wide">
      <h2>🧩 Bulk Scan Results</h2>
      <div class="result-grid">
        <div class="box"><span>Total Targets</span><h3>${esc(total)}</h3></div>
        <div class="box high"><span>Vulnerable Targets</span><h3>${esc(vulnerable)}</h3></div>
        <div class="box"><span>Failed</span><h3>${esc(failed)}</h3></div>
        <div class="box"><span>Infected URLs</span><h3>${infectedUrls.length}</h3></div>
        <div class="box"><span>Archive URLs</span><h3>${archiveUrls.length}</h3></div>
      </div>
    </div>

    <div class="result-card wide">
      <h3>🚨 Vulnerable / Affected URLs</h3>
      ${infectedUrls.length ? infectedUrls.slice(0,120).map(x => `<div class="mini-result"><b>${esc(x.target || "target")}</b>${renderUrlActions(x.url)}</div>`).join("") : `<p class="muted">No affected URLs returned.</p>`}
    </div>

    <div class="result-card wide">
      <h3>🕰️ Wayback Archive URLs</h3>
      ${archiveUrls.length ? archiveUrls.slice(0,160).map(x => `<div class="mini-result"><b>${esc(x.target || "target")}</b>${renderUrlActions(x.url)}</div>`).join("") : `<p class="muted">No archive URLs returned.</p>`}
    </div>

    <div class="result-card wide">
      <h3>🌐 Targets Summary</h3>
      ${results.length ? results.map(r => {
        const rr = r.result || r;
        const risk = rr.risk || r.risk || "UNKNOWN";
        const target = r.target || rr.target || "Unknown";
        const confirmed = rr.confirmed_vulnerabilities?.length || 0;
        const possible = rr.possible_issues?.length || 0;
        return `<div class="finding ${riskClass(risk)}"><div class="finding-head"><h4>${esc(target)}</h4><span class="badge ${esc(String(risk).toUpperCase())}">${esc(risk)}</span></div><p><b>Score:</b> ${esc(rr.score ?? 0)}/100</p><p><b>Confirmed:</b> ${confirmed} · <b>Possible:</b> ${possible}</p>${rr.final_url ? renderUrlActions(rr.final_url) : ""}${r.error ? `<p><b>Error:</b> ${esc(r.error)}</p>` : ""}</div>`;
      }).join("") : `<p class="muted">No results returned.</p>`}
    </div>

    <div class="result-card wide"><h3>🧾 Raw Bulk JSON</h3><pre>${esc(JSON.stringify(data, null, 2))}</pre></div>
  `;
  const bulkResults = $("bulkResults");
  if(bulkResults) bulkResults.innerHTML = html;
}

async function cancelBulkScan(){
  if(!currentBulkJobId){ alert("No bulk scan running"); return; }
  try{
    const {res,data} = await apiFetch("/bulk-scan/cancel/" + encodeURIComponent(currentBulkJobId), {method:"POST"});
    if(!res.ok) throw new Error(data.detail || "Cancel bulk failed");
    showToast("Bulk scan cancel requested");
    await pollBulkStatus(currentBulkJobId);
  }catch(e){ alert(e.message || "Cancel failed"); }
}
function downloadBulkJSON(){
  if(!lastReport){ alert("No bulk report yet"); return; }
  downloadJSON(lastReport, "bulk-scan-report.json");
}

function extractFirstUrl(text) { const value = String(text || ""); const match = value.match(/https?:\/\/[^\s"'<>]+/i); return match ? match[0] : null; }
function getAffectedUrl(item) { return item?.affected_url || item?.url || extractFirstUrl(item?.evidence) || null; }
function cvssFromSeverity(severity) { const s = String(severity || "INFO").toUpperCase(); if (s === "CRITICAL") return "9.8"; if (s === "HIGH") return "8.1"; if (s === "MEDIUM") return "5.6"; if (s === "LOW") return "3.1"; return "0.0"; }
function confidencePercent(confidence) { const c = String(confidence || "MEDIUM").toUpperCase(); if (c === "HIGH") return "90%"; if (c === "LOW") return "45%"; return "70%"; }
async function copyText(text) { try { await navigator.clipboard.writeText(text); alert("Copied"); } catch (e) { const t = document.createElement("textarea"); t.value = text; document.body.appendChild(t); t.select(); document.execCommand("copy"); document.body.removeChild(t); alert("Copied"); } }
function openUrl(url) { if (!url) return; window.open(url, "_blank", "noopener,noreferrer"); }
function renderUrlActions(url) { if (!url) return ""; const safe = esc(url); return `<div class="affected-box"><div class="affected-label">🔗 Affected URL</div><a class="affected-link" href="${safe}" target="_blank" rel="noopener noreferrer">${safe}</a><div class="affected-actions"><button type="button" onclick="openUrl('${safe}')">Open</button><button type="button" onclick="copyText('${safe}')">Copy</button></div></div>`; }
function renderMetaBadges(item) { const severity = esc(item?.severity || "INFO"); const cvss = esc(item?.cvss || item?.score || cvssFromSeverity(item?.severity)); const confidence = esc(item?.confidence_percent || item?.confidence || confidencePercent(item?.confidence)); const status = esc(item?.status || "INFO"); return `<div class="meta-badges"><span class="meta-badge severity-${severity.toLowerCase()}">Severity: ${severity}</span><span class="meta-badge">CVSS: ${cvss}</span><span class="meta-badge">Confidence: ${confidence}</span><span class="meta-badge">Status: ${status}</span></div>`; }
function buildSeverityCounts(items) { const counts = {CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0,INFO:0}; (items || []).forEach(item => { const s = String(item?.severity || "INFO").toUpperCase(); if (counts[s] !== undefined) counts[s]++; else counts.INFO++; }); return counts; }
function renderSeverityBars(items) { const counts = buildSeverityCounts(items); const total = Math.max(Object.values(counts).reduce((a,b)=>a+b,0), 1); return `<div class="severity-bars">${Object.keys(counts).map(k => { const percent = Math.round((counts[k] / total) * 100); return `<div class="sev-row"><span>${k}</span><div class="sev-track"><div class="sev-fill ${k.toLowerCase()}" style="width:${percent}%"></div></div><b>${counts[k]}</b></div>`; }).join("")}</div>`; }
function renderProgressSteps() { return `<div class="progress-steps"><div class="step done">✓ Target normalization</div><div class="step done">✓ DNS analysis</div><div class="step done">✓ SSL/TLS analysis</div><div class="step active">⟳ Port scanning</div><div class="step">• WAF detection</div><div class="step">• CVE enumeration</div><div class="step">• Validation engine</div></div>`; }
function renderThreatIntel(data) { const ti = data.ip_intelligence || data.whois_asn || data.asn_info || data.geoip || {}; if (!ti || Object.keys(ti).length === 0) return `<p class="muted">No threat intelligence data returned.</p>`; return `<div class="intel-grid"><div class="mini-result"><b>ASN</b><span>${esc(ti.asn || "Unknown")}</span></div><div class="mini-result"><b>ISP</b><span>${esc(ti.isp || ti.provider || "Unknown")}</span></div><div class="mini-result"><b>Organization</b><span>${esc(ti.organization || ti.org || "Unknown")}</span></div><div class="mini-result"><b>Country</b><span>${esc(ti.country || "Unknown")}</span></div><div class="mini-result"><b>City</b><span>${esc(ti.city || "Unknown")}</span></div><div class="mini-result"><b>Reverse DNS</b><span>${esc(ti.reverse_dns || "Unknown")}</span></div></div>`; }
function renderAttackSurface(data) { const endpoints = data.api_endpoints || data.discovered_endpoints || []; const subdomains = Array.isArray(data.subdomains) ? data.subdomains : []; const ports = Array.isArray(data.open_ports) ? data.open_ports : []; const exposures = data.advanced_exposures || data.exposures || []; const jsEndpoints = data.js_endpoints || data.js_crawler?.endpoints || []; const parameters = data.parameter_miner || data.js_crawler?.parameters || []; return `<div class="attack-grid"><div class="mini-result"><b>API Endpoints</b><span>${endpoints.length || 0}</span></div><div class="mini-result"><b>Subdomains</b><span>${subdomains.length || 0}</span></div><div class="mini-result"><b>Open Ports</b><span>${ports.length || 0}</span></div><div class="mini-result"><b>Exposures</b><span>${exposures.length || 0}</span></div><div class="mini-result"><b>JS Endpoints</b><span>${jsEndpoints.length || 0}</span></div><div class="mini-result"><b>Parameters</b><span>${parameters.length || 0}</span></div></div>${endpoints.length ? `<h4>Discovered APIs</h4>${endpoints.slice(0,20).map(e => { const endpoint = e.endpoint || e.url || e; return `<div class="mini-result"><b>${esc(endpoint)}</b><span>${esc(e.severity || "INFO")}</span></div>`; }).join("")}` : `<p class="muted">No API endpoints returned.</p>`}`; }
function normalizeFindingList(list) { return Array.isArray(list) ? list : []; }
function classifyFindingFrontend(f) { const status = String(f?.status || "").toUpperCase(); const severity = String(f?.severity || "INFO").toUpperCase(); const category = String(f?.category || "").toLowerCase(); const title = String(f?.title || f?.name || f?.type || "").toLowerCase(); if (status === "CONFIRMED") return "confirmed"; if (status === "POSSIBLE") return "possible"; if (status === "HARDENING") return "hardening"; if (category.includes("headers") || title.includes("missing security header")) return "hardening"; if (category.includes("attack surface") || category.includes("api") || category.includes("subdomain") || category.includes("robots")) return "attack_surface"; if (["CRITICAL", "HIGH", "MEDIUM"].includes(severity)) return "possible"; return "informational"; }
function buildFrontendSections(data) { let confirmed = normalizeFindingList(data.confirmed_vulnerabilities); let possible = normalizeFindingList(data.possible_issues); let hardening = normalizeFindingList(data.hardening_issues); let attackSurface = normalizeFindingList(data.attack_surface); let informational = normalizeFindingList(data.informational_findings); const hasBackendSections = confirmed.length || possible.length || hardening.length || attackSurface.length || informational.length; if (!hasBackendSections) { const combined = [...(Array.isArray(data.findings) ? data.findings : []), ...(Array.isArray(data.vulnerability_checks) ? data.vulnerability_checks : [])]; for (const item of combined) { const bucket = classifyFindingFrontend(item); if (bucket === "confirmed") confirmed.push(item); else if (bucket === "possible") possible.push(item); else if (bucket === "hardening") hardening.push(item); else if (bucket === "attack_surface") attackSurface.push(item); else informational.push(item); } } return {confirmed, possible, hardening, attackSurface, informational}; }
function renderFindingCard(f, defaultStatus = "INFO") { const affectedUrl = getAffectedUrl(f); const title = f.title || f.name || f.type || "Finding"; const status = f.status || defaultStatus; return `<div class="finding ${riskClass(f.severity)}"><div class="finding-head"><h4>${esc(title)}</h4><span class="finding-status">${esc(status)}</span></div>${renderMetaBadges({...f, status})}<p><b>Category:</b> ${esc(f.category || "General")}</p><p><b>Description:</b> ${esc(f.description || f.impact || "N/A")}</p><p><b>Evidence:</b> ${esc(f.evidence || "N/A")}</p>${renderUrlActions(affectedUrl)}${f.fix_location ? `<p><b>Fix Location:</b> ${esc(f.fix_location)}</p>` : ""}${f.exploitability ? `<p><b>Exploitability:</b> ${esc(f.exploitability)}</p>` : ""}<div class="fix-box"><b>Recommended Fix</b><p>${esc(f.fix || "Review manually")}</p></div></div>`; }
function renderEnterpriseSection(title, icon, items, emptyText, status, sectionClass) { return `<div class="result-card wide enterprise-section ${sectionClass}"><div class="section-title-row"><h3>${icon} ${title}</h3><span class="section-count">${items.length}</span></div>${items.length ? items.map(item => renderFindingCard(item, status)).join("") : `<p class="muted">${esc(emptyText)}</p>`}</div>`; }
function renderEnterpriseSummaryCards(sections) { return `<div class="result-grid"><div class="box confirmed-box"><span>Confirmed</span><h3>${sections.confirmed.length}</h3></div><div class="box possible-box"><span>Possible</span><h3>${sections.possible.length}</h3></div><div class="box hardening-box"><span>Hardening</span><h3>${sections.hardening.length}</h3></div><div class="box attack-box"><span>Attack Surface</span><h3>${sections.attackSurface.length}</h3></div><div class="box info-box"><span>Informational</span><h3>${sections.informational.length}</h3></div></div>`; }
function renderJsCrawlerSection(data) { const crawler = data.smart_discovery || data.js_crawler || {}; const endpoints = data.js_endpoints || crawler.endpoints || []; const params = data.parameter_miner || crawler.parameters || []; const kxss = data.kxss_results || crawler.kxss || []; const runtime = crawler.runtime_requests || []; return `<div class="result-card wide"><h3>🧠 Smart Discovery</h3><div class="result-grid"><div class="box"><span>JS Files</span><h3>${(crawler.js_files || []).length}</h3></div><div class="box"><span>Endpoints</span><h3>${endpoints.length}</h3></div><div class="box"><span>Parameters</span><h3>${params.length}</h3></div><div class="box"><span>KXSS</span><h3>${kxss.length}</h3></div><div class="box"><span>Runtime APIs</span><h3>${runtime.length}</h3></div></div>${crawler.error ? `<p class="muted">Error: ${esc(crawler.error)}</p>` : ""}<h4>Discovered Endpoints</h4>${endpoints.length ? endpoints.slice(0,60).map(e => `<div class="mini-result"><b>${esc(e.endpoint || e.url || "-")}</b><span>Severity: ${esc(e.severity || "INFO")}</span>${renderUrlActions(e.endpoint || e.url)}</div>`).join("") : `<p class="muted">No JS endpoints discovered.</p>`}</div>`; }

async function login() { const username = $("u")?.value?.trim(); const password = $("p")?.value?.trim(); if (!username || !password) { alert("Enter username and password"); return; } try { const res = await fetch(API + "/login", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, password}) }); const data = await res.json().catch(() => ({})); if (!res.ok || !data.access_token) { alert(data.detail || "Login failed"); return; } localStorage.setItem("token", data.access_token); window.location.href = "dashboard.html"; } catch (err) { console.error(err); alert("Backend connection failed"); } }
async function register() { const username = $("ru")?.value?.trim() || $("r_user")?.value?.trim() || $("user")?.value?.trim(); const password = $("rp")?.value?.trim() || $("r_pass")?.value?.trim() || $("pass")?.value?.trim(); const confirm = $("rp2")?.value?.trim(); if (!username || !password) { alert("Enter username and password"); return; } if (confirm !== undefined && confirm && confirm !== password) { alert("Passwords do not match"); return; } try { const res = await fetch(API + "/register", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({username, password}) }); const data = await res.json().catch(() => ({})); if (!res.ok) { alert(data.detail || "Register failed"); return; } alert("Account created. Login now."); if ($("u")) $("u").value = username; if ($("p")) $("p").value = ""; if (typeof switchTab === "function") switchTab("login"); } catch (err) { console.error(err); alert("Backend connection failed"); } }
function logout() { localStorage.removeItem("token"); window.location.href = "index.html"; }

function progressStepsFromStatus(job) { const progress = Number(job?.progress || 0); const steps = [{label:"Queued",min:0},{label:"Preparation",min:10},{label:"DNS Analysis",min:20},{label:"SSL / TLS",min:35},{label:"Headers / WAF",min:50},{label:"Exposure Engine",min:65},{label:"Deep Analysis",min:80},{label:"Saving Report",min:95},{label:"Completed",min:100}]; return `<div class="live-progress-card"><div class="progress-topline"><b>${esc(job?.phase || job?.step || "Preparing scan")}</b><span>${progress}%</span></div><div class="progress-track-live"><div class="progress-fill-live" style="width:${Math.max(0, Math.min(100, progress))}%"></div></div><p class="muted">${esc(job?.step || "Scan queued")}</p>${job?.queue_position ? `<p class="muted"><b>Queue position:</b> ${esc(job.queue_position)}</p>` : ""}<div class="progress-steps">${steps.map(s => { const cls = progress >= s.min ? "done" : (progress + 15 >= s.min ? "active" : ""); const icon = progress >= s.min ? "✓" : (progress + 15 >= s.min ? "⟳" : "•"); return `<div class="step ${cls}">${icon} ${esc(s.label)}</div>`; }).join("")}</div>${(job?.status === "running" || job?.status === "queued") ? `<button class="danger cancel-live-btn" onclick="cancelCurrentScan()">Cancel Scan</button>` : ""}</div>`; }
function renderLiveScanStatus(job) { const out = $("out") || $("container"); if (!out) return; out.innerHTML = `<div class="result-card scanning-card"><div class="scan-loader"></div><h2>🔍 Live Scan Progress</h2><p><b>Target:</b> ${esc(job?.target || "-")}</p><p><b>Profile:</b> ${esc(job?.profile || "-")}</p><p><b>Status:</b> ${esc(job?.status || "queued")}</p>${progressStepsFromStatus(job)}</div>`; setStatus(`${esc(job?.status || "queued")} — ${esc(job?.step || "Scan queued")}`); }
async function pollScanStatus(jobId) { try { const {res,data:job} = await apiFetch("/scan-status/" + encodeURIComponent(jobId)); if (!res.ok) { clearInterval(currentScanPollTimer); currentScanPollTimer = null; showMessage(job.detail || "Could not read scan status", "error"); return; } renderLiveScanStatus(job); if (job.status === "completed") { clearInterval(currentScanPollTimer); currentScanPollTimer = null; currentScanJobId = null; if (job.result) { lastReport = job.result; setStatus("✅ Scan completed"); renderScanResult(job.result); loadData(false); } else showMessage("Scan completed, but no result returned", "success"); return; } if (job.status === "failed") { clearInterval(currentScanPollTimer); currentScanPollTimer = null; currentScanJobId = null; showMessage(job.error || "Scan failed", "error"); return; } if (job.status === "cancelled") { clearInterval(currentScanPollTimer); currentScanPollTimer = null; currentScanJobId = null; showMessage("Scan cancelled", "info"); return; } } catch (err) { console.error(err); clearInterval(currentScanPollTimer); currentScanPollTimer = null; showMessage("Live scan connection failed", "error"); } }
async function startAsyncScan(target, profile) { const {res,data} = await apiFetch("/scan-async", {method:"POST", body: JSON.stringify({target, profile})}); if (!res.ok) throw new Error(data.detail || "Could not start async scan"); return data; }
async function cancelCurrentScan() { if (!currentScanJobId) { alert("No running scan"); return; } try { const {res,data} = await apiFetch("/cancel-scan/" + encodeURIComponent(currentScanJobId), {method:"POST"}); if (!res.ok) { alert(data.detail || "Cancel failed"); return; } setStatus("Scan cancel requested"); await pollScanStatus(currentScanJobId); } catch (err) { console.error(err); alert("Cancel request failed"); } }
async function scan() { if (!requireLogin()) return; const targetInput = $("target") || $("t") || $("searchBox"); const profileInput = $("scan_profile") || $("profile"); if (!targetInput || !targetInput.value.trim()) { alert("Enter target"); return; } const target = targetInput.value.trim(); const profile = profileInput ? profileInput.value : "full"; const out = $("out") || $("container"); showSection("scan"); if (out) out.innerHTML = `<div class="result-card scanning-card"><div class="scan-loader"></div><h2>🔍 Starting Live Scan...</h2><p><b>Target:</b> ${esc(target)}</p><p><b>Profile:</b> ${esc(profile)}</p><p class="muted">Creating scan job and connecting to live progress...</p>${renderProgressSteps()}</div>`; try { const job = await startAsyncScan(target, profile); currentScanJobId = job.job_id; renderLiveScanStatus({job_id: job.job_id, target, profile, status: job.status || "queued", progress: 0, step: job.message || "Scan queued", phase: "Queued", queue_position: job.queue_position, queue_size: job.queue_size}); if (currentScanPollTimer) clearInterval(currentScanPollTimer); await pollScanStatus(currentScanJobId); currentScanPollTimer = setInterval(() => { if (currentScanJobId) pollScanStatus(currentScanJobId); }, 1500); } catch (err) { console.error(err); showMessage(err.message || "Cannot start live scan", "error"); } }

function renderScanResult(data) { const out = $("out") || $("container"); if (!out) { console.log(data); return; } lastReport = data; const openPorts = Array.isArray(data.open_ports) ? data.open_ports : []; const nmapPorts = Array.isArray(data.nmap_scan?.ports) ? data.nmap_scan.ports : []; const allPorts = openPorts.length ? openPorts : nmapPorts; const cveGroups = Array.isArray(data.cve_results) ? data.cve_results : []; const technologies = Array.isArray(data.technologies) ? data.technologies : []; const subdomains = Array.isArray(data.subdomains) ? data.subdomains : []; const sections = buildFrontendSections(data); const allFindings = [...sections.confirmed, ...sections.possible, ...sections.hardening, ...sections.attackSurface, ...sections.informational]; const cveCount = cveGroups.reduce((sum, group) => sum + ((group.cves || []).length), 0); const portHTML = allPorts.length ? allPorts.map(p => `<div class="mini-result"><b>Port ${esc(p.port)}</b><span>${esc(p.service || "Unknown")} · ${esc(p.protocol || "tcp")} · ${esc(p.state || "open")}</span>${p.banner ? `<small>Banner: ${esc(p.banner)}</small>` : ""}${p.product || p.version ? `<small>Product: ${esc(p.product || "")} ${esc(p.version || "")}</small>` : ""}${p.risk ? `<small>Risk: ${esc(p.risk)}</small>` : ""}</div>`).join("") : "<p class='muted'>No open ports returned</p>"; const cveHTML = cveGroups.length ? cveGroups.map(group => `<div class="finding"><h4>🧬 ${esc(group.technology || "Technology")}</h4>${group.cves && group.cves.length ? group.cves.map(c => `<div class="mini-result"><b>${esc(c.id || c.cve_id || "CVE")}</b><span>${esc(c.severity || "UNKNOWN")} · CVSS ${esc(c.score || c.cvss || "N/A")}</span><small>${esc(c.description || "")}</small>${c.url ? renderUrlActions(c.url) : ""}</div>`).join("") : "<p class='muted'>No CVEs found</p>"}</div>`).join("") : "<p class='muted'>No CVE results available</p>"; const subdomainHTML = subdomains.length ? subdomains.map(s => `<div class="mini-result"><b>${esc(s.subdomain)}</b><span>Status: ${esc(s.status_code || "N/A")} · HTTPS: ${s.https ? "Yes" : "No"}</span><small>${esc(s.final_url || "")}</small>${s.final_url ? renderUrlActions(s.final_url) : ""}</div>`).join("") : "<p class='muted'>No subdomains returned</p>"; out.innerHTML = `<section class="scan-result-shell"><div class="result-header ${riskClass(data.risk)}"><div><h2>🛡️ Scan Result</h2><p>${esc(data.target || data.host || "Unknown target")}</p></div><div class="risk-pill">${esc(data.risk || "UNKNOWN")}</div></div><div class="result-grid"><div class="box"><span>Risk</span><h3>${esc(data.risk || "UNKNOWN")}</h3></div><div class="box"><span>Score</span><h3>${esc(data.score ?? 0)}/100</h3></div><div class="box"><span>Target Type</span><h3>${esc(data.target_type || "domain")}</h3></div><div class="box"><span>Open Ports</span><h3>${allPorts.length}</h3></div><div class="box"><span>CVEs</span><h3>${cveCount}</h3></div><div class="box"><span>Total Findings</span><h3>${allFindings.length}</h3></div></div>${renderEnterpriseSummaryCards(sections)}<div class="result-card wide"><h3>📊 Severity Overview</h3>${renderSeverityBars(allFindings)}</div><div class="result-panels"><div class="result-card"><h3>🌐 Target Information</h3><p><b>Target:</b> ${esc(data.target || "-")}</p><p><b>Host:</b> ${esc(data.host || "-")}</p><p><b>IP:</b> ${esc(data.ip || "-")}</p><p><b>Final URL:</b> ${esc(data.final_url || "-")}</p><p><b>Status:</b> ${esc(data.status_code || "-")}</p>${data.final_url ? renderUrlActions(data.final_url) : ""}</div><div class="result-card"><h3>🛰️ Nmap Scan</h3><p><b>Enabled:</b> ${data.nmap_scan?.enabled ? "✅ Yes" : "❌ No"}</p><p><b>Host:</b> ${esc(data.nmap_scan?.host || data.host || "-")}</p><p><b>Error:</b> ${esc(data.nmap_scan?.error || "None")}</p></div><div class="result-card"><h3>🚪 Open Ports</h3>${portHTML}</div><div class="result-card"><h3>🔒 SSL / TLS</h3><p><b>Valid:</b> ${data.ssl?.valid ? "✅ Yes" : "❌ No"}</p><p><b>TLS:</b> ${esc(data.ssl?.tls_version || "-")}</p><p><b>Cipher:</b> ${esc(data.ssl?.cipher_name || "-")}</p><p><b>Expires:</b> ${esc(data.ssl?.info || data.ssl?.expires || "-")}</p></div><div class="result-card"><h3>🌍 DNS Security</h3><p><b>SPF:</b> ${data.dns_security?.spf ? "✅ Found" : "❌ Missing"}</p><p><b>DMARC:</b> ${data.dns_security?.dmarc ? "✅ Found" : "❌ Missing"}</p><p><b>A Records:</b> ${safeList(data.dns_security?.a_records)}</p><p><b>Issues:</b> ${safeList(data.dns_security?.issues)}</p></div><div class="result-card"><h3>🛡️ WAF Detection</h3><p><b>Name:</b> ${esc(data.waf?.name || data.waf || "Unknown")}</p><p><b>Confidence:</b> ${esc(data.waf?.confidence || "0%")}</p><p><b>Evidence:</b> ${safeList(data.waf?.evidence)}</p></div><div class="result-card wide"><h3>🧠 Technologies</h3><p>${safeList(technologies, "Unknown")}</p></div><div class="result-card wide"><h3>🌍 Threat Intelligence / ASN</h3>${renderThreatIntel(data)}</div><div class="result-card wide"><h3>🕸️ Attack Surface Map</h3>${renderAttackSurface(data)}</div>${renderJsCrawlerSection(data)}<div class="result-card wide"><h3>🧬 CVE Results</h3>${cveHTML}</div><div class="result-card wide"><h3>🌐 Subdomains</h3>${subdomainHTML}</div>${renderEnterpriseSection("Confirmed Vulnerabilities", "🔴", sections.confirmed, "No confirmed vulnerabilities found.", "CONFIRMED", "confirmed-section")}${renderEnterpriseSection("Possible Issues / Manual Review", "🟡", sections.possible, "No possible issues returned.", "POSSIBLE", "possible-section")}${renderEnterpriseSection("Hardening Issues", "🛡️", sections.hardening, "No hardening issues returned.", "HARDENING", "hardening-section")}${renderEnterpriseSection("Attack Surface / Exposure", "🕸️", sections.attackSurface, "No attack surface findings returned.", "INFO", "attack-section")}${renderEnterpriseSection("Informational Findings", "🔵", sections.informational, "No informational findings returned.", "INFO", "info-section")}<div class="result-card wide"><h3>🧾 Raw JSON</h3><pre>${esc(JSON.stringify(data, null, 2))}</pre></div></div></section>`; }

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

(function injectDashboardStyles() {
  if (document.getElementById("pro-dashboard-style")) return;
  const style = document.createElement("style");
  style.id = "pro-dashboard-style";
  style.textContent = `textarea{width:100%;min-height:210px;border:1px solid rgba(255,255,255,.16);border-radius:15px;padding:15px 14px;background:#080808;color:#fff;outline:none;font-size:15px;resize:vertical}.section{display:none}.section.active{display:block}.result-panels{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.result-card.wide{grid-column:1/-1}.progress-track-live{height:12px;border-radius:999px;overflow:hidden;background:#020202;border:1px solid rgba(255,255,255,.12);margin-bottom:10px}.progress-fill-live{height:100%;border-radius:999px;background:linear-gradient(90deg,#60a5fa,#22c55e);transition:width .35s ease}.live-progress-card{max-width:520px;margin:18px auto 0;padding:16px;border-radius:18px;background:#070707;border:1px solid rgba(255,255,255,.12);text-align:left}.progress-topline{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.cancel-live-btn{margin-top:14px;width:100%}.enterprise-section{position:relative}.section-title-row{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px}.section-count{min-width:34px;height:34px;display:inline-grid;place-items:center;border-radius:999px;background:#0a0a0a;border:1px solid rgba(255,255,255,.14);font-weight:900}.confirmed-section,.confirmed-box{border-left:5px solid #ef4444 !important}.possible-section,.possible-box{border-left:5px solid #f59e0b !important}.hardening-section,.hardening-box{border-left:5px solid #22c55e !important}.attack-section,.attack-box{border-left:5px solid #60a5fa !important}.info-section,.info-box{border-left:5px solid #38bdf8 !important}@media(max-width:850px){.result-panels{grid-template-columns:1fr}}`;
  document.head.appendChild(style);
})();

document.addEventListener("DOMContentLoaded", ()=>{
  injectBulkButtonIfNeeded();
  ensureBulkUI();
  if($("queueBox")){
    if(!getToken()){ requireLogin(); return; }
    loadData(false);
    if(!autoRefreshTimer){ autoRefreshTimer=setInterval(()=>{ const historySection=$("historySection"); if(historySection && historySection.classList.contains("active")) loadData(false); else loadQueueStatus(); },15000); }
  }
});
