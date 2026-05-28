
/* ============================================================
   CVE Intelligence UI Patch v2
   Add this file after app.js OR paste it at the end of app.js.
   It does not replace your existing scanner UI.
   ============================================================ */

(function CVE_INTELLIGENCE_UI_PATCH_V2(){
  if (window.__CVE_INTEL_PATCH_V2__) return;
  window.__CVE_INTEL_PATCH_V2__ = true;

  function cveEsc(value) {
    if (typeof esc === "function") return esc(value);
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function cveRiskClass(severity) {
    const s = String(severity || "UNKNOWN").toUpperCase();
    if (s === "CRITICAL") return "critical";
    if (s === "HIGH") return "high";
    if (s === "MEDIUM") return "medium";
    if (s === "LOW") return "low";
    return "unknown";
  }

  function boolBadge(value, labelTrue, labelFalse) {
    const yes = value === true || String(value).toLowerCase() === "yes" || String(value).toLowerCase() === "true";
    return `<span class="cve-intel-badge ${yes ? "danger-badge" : "safe-badge"}">${yes ? labelTrue : labelFalse}</span>`;
  }

  function extractCveIntelligence(data) {
    const groups = Array.isArray(data?.cve_results) ? data.cve_results : [];
    const flat = [];

    groups.forEach(group => {
      const technology = group.technology || group.product || "Technology";
      const cves = Array.isArray(group.cves) ? group.cves : [];
      cves.forEach(cve => {
        flat.push({
          technology,
          id: cve.id || cve.cve_id || cve.cve || "CVE",
          severity: cve.severity || cve.baseSeverity || "UNKNOWN",
          score: cve.score ?? cve.cvss ?? cve.cvss_score ?? "N/A",
          description: cve.description || cve.summary || "",
          url: cve.url || cve.nvd_url || (cve.id ? `https://nvd.nist.gov/vuln/detail/${cve.id}` : ""),
          exploit_available: cve.exploit_available ?? cve.public_exploit ?? cve.exploit ?? false,
          public_poc: cve.public_poc ?? cve.github_poc ?? cve.poc_available ?? false,
          exploitdb: cve.exploitdb ?? cve.exploit_db ?? cve.exploit_db_url ?? null,
          github_poc: cve.github_poc_url || cve.github_url || cve.poc_url || null,
          attack_type: cve.attack_type || cve.vulnerability_type || cve.category || inferAttackType(cve.description || ""),
          priority: cve.priority || inferPriority(cve),
          patch: cve.patch || cve.fix || cve.recommendation || "Review vendor advisory and upgrade to the latest patched version.",
          affected_version: cve.affected_version || cve.affected_versions || cve.version || "Unknown",
          patched_version: cve.patched_version || cve.fixed_version || "Check vendor advisory",
          confidence: cve.confidence || "MEDIUM"
        });
      });
    });

    return flat;
  }

  function inferAttackType(text) {
    const t = String(text || "").toLowerCase();
    if (t.includes("remote code") || t.includes("rce") || t.includes("code execution")) return "Remote Code Execution";
    if (t.includes("sql injection") || t.includes("sqli")) return "SQL Injection";
    if (t.includes("cross-site scripting") || t.includes("xss")) return "Cross-Site Scripting";
    if (t.includes("path traversal") || t.includes("directory traversal")) return "Path Traversal";
    if (t.includes("authentication") || t.includes("bypass")) return "Auth Bypass";
    if (t.includes("denial of service") || t.includes("dos")) return "Denial of Service";
    if (t.includes("information disclosure")) return "Information Disclosure";
    return "General Vulnerability";
  }

  function inferPriority(cve) {
    const sev = String(cve?.severity || "").toUpperCase();
    const score = Number(cve?.score || cve?.cvss || 0);
    const desc = String(cve?.description || "").toLowerCase();
    const exploit = cve?.exploit_available || cve?.public_poc || cve?.github_poc;

    if (exploit && (sev === "CRITICAL" || score >= 9)) return "P0 - Immediate";
    if (exploit && (sev === "HIGH" || score >= 7)) return "P1 - Urgent";
    if (sev === "CRITICAL" || score >= 9) return "P1 - Urgent";
    if (sev === "HIGH" || score >= 7) return "P2 - High";
    if (desc.includes("rce") || desc.includes("remote code")) return "P1 - Urgent";
    if (sev === "MEDIUM" || score >= 4) return "P3 - Medium";
    return "P4 - Monitor";
  }

  function cveScoreNumber(cve) {
    const n = Number(cve.score);
    return Number.isFinite(n) ? n : 0;
  }

  function renderCveCard(cve) {
    const sev = String(cve.severity || "UNKNOWN").toUpperCase();
    const score = cveScoreNumber(cve);
    const scoreWidth = Math.max(0, Math.min(100, score * 10));

    return `
      <div class="cve-intel-card ${cveRiskClass(sev)}">
        <div class="cve-intel-head">
          <div>
            <h4>${cveEsc(cve.id)}</h4>
            <p>${cveEsc(cve.technology)}</p>
          </div>
          <span class="cve-severity ${cveRiskClass(sev)}">${cveEsc(sev)}</span>
        </div>

        <div class="cve-intel-grid">
          <div class="mini-result"><b>CVSS</b><span>${cveEsc(cve.score)}</span></div>
          <div class="mini-result"><b>Priority</b><span>${cveEsc(cve.priority)}</span></div>
          <div class="mini-result"><b>Attack Type</b><span>${cveEsc(cve.attack_type)}</span></div>
          <div class="mini-result"><b>Confidence</b><span>${cveEsc(cve.confidence)}</span></div>
        </div>

        <div class="cve-score-track">
          <div class="cve-score-fill ${cveRiskClass(sev)}" style="width:${scoreWidth}%"></div>
        </div>

        <div class="cve-intel-badges">
          ${boolBadge(cve.exploit_available, "Exploit Available", "No Known Exploit")}
          ${boolBadge(cve.public_poc, "Public PoC", "No Public PoC")}
          ${cve.github_poc ? `<span class="cve-intel-badge warn-badge">GitHub PoC</span>` : ""}
          ${cve.exploitdb ? `<span class="cve-intel-badge warn-badge">Exploit-DB Match</span>` : ""}
        </div>

        <p><b>Description:</b> ${cveEsc(cve.description || "No description available.")}</p>
        <p><b>Affected Version:</b> ${cveEsc(cve.affected_version)}</p>
        <p><b>Patched Version:</b> ${cveEsc(cve.patched_version)}</p>

        <div class="fix-box">
          <b>Recommended Patch / Action</b>
          <p>${cveEsc(cve.patch)}</p>
        </div>

        <div class="affected-actions cve-links">
          ${cve.url ? `<button type="button" onclick="openUrl('${cveEsc(cve.url)}')">Open NVD</button>` : ""}
          ${cve.github_poc ? `<button type="button" onclick="openUrl('${cveEsc(cve.github_poc)}')">GitHub PoC</button>` : ""}
          ${cve.exploitdb ? `<button type="button" onclick="openUrl('${cveEsc(cve.exploitdb)}')">Exploit-DB</button>` : ""}
          <button type="button" onclick="copyText('${cveEsc(cve.id)}')">Copy CVE</button>
        </div>
      </div>
    `;
  }

  function renderCveIntelligenceSection(data) {
    const cves = extractCveIntelligence(data);
    if (!cves.length) return "";

    const critical = cves.filter(c => String(c.severity).toUpperCase() === "CRITICAL").length;
    const high = cves.filter(c => String(c.severity).toUpperCase() === "HIGH").length;
    const exploitable = cves.filter(c => c.exploit_available || c.public_poc || c.github_poc || c.exploitdb).length;
    const urgent = cves.filter(c => String(c.priority).includes("P0") || String(c.priority).includes("P1")).length;

    const sorted = [...cves].sort((a,b) => {
      const pa = String(a.priority).includes("P0") ? 100 : String(a.priority).includes("P1") ? 90 : 0;
      const pb = String(b.priority).includes("P0") ? 100 : String(b.priority).includes("P1") ? 90 : 0;
      return (pb + cveScoreNumber(b)) - (pa + cveScoreNumber(a));
    });

    return `
      <div class="result-card wide cve-intel-section" id="cveIntelligenceSection">
        <div class="section-title-row">
          <h3>🧬 CVE Intelligence Engine v2</h3>
          <span class="section-count">${cves.length}</span>
        </div>

        <div class="result-grid">
          <div class="box critical"><span>Critical CVEs</span><h3>${critical}</h3></div>
          <div class="box high"><span>High CVEs</span><h3>${high}</h3></div>
          <div class="box medium"><span>Exploitable / PoC</span><h3>${exploitable}</h3></div>
          <div class="box"><span>Urgent Priority</span><h3>${urgent}</h3></div>
        </div>

        <p class="muted">
          This section enriches detected CVEs with exploitability signals, public PoC indicators,
          patch guidance, affected versions, and remediation priority.
        </p>

        ${sorted.slice(0, 40).map(renderCveCard).join("")}
      </div>
    `;
  }

  function injectCveStyles() {
    if (document.getElementById("cve-intel-style-v2")) return;
    const style = document.createElement("style");
    style.id = "cve-intel-style-v2";
    style.textContent = `
      .cve-intel-section{border-left:5px solid #a855f7!important}
      .cve-intel-card{
        padding:14px;
        margin:12px 0;
        background:#070707;
        border:1px solid rgba(255,255,255,.10);
        border-left:5px solid #60a5fa;
        border-radius:14px;
      }
      .cve-intel-card.high,.cve-intel-card.critical{border-left-color:#ef4444}
      .cve-intel-card.medium{border-left-color:#f59e0b}
      .cve-intel-card.low{border-left-color:#22c55e}
      .cve-intel-head{
        display:flex;
        justify-content:space-between;
        align-items:flex-start;
        gap:12px;
        margin-bottom:12px;
      }
      .cve-intel-head h4{margin:0;font-size:18px}
      .cve-intel-head p{margin:5px 0 0;color:#a3a3a3}
      .cve-severity{
        padding:7px 10px;
        border-radius:999px;
        font-weight:900;
        font-size:12px;
        background:#111;
        border:1px solid rgba(255,255,255,.12);
      }
      .cve-severity.critical,.cve-severity.high{color:#fecaca;border-color:rgba(239,68,68,.45)}
      .cve-severity.medium{color:#fde68a;border-color:rgba(245,158,11,.45)}
      .cve-severity.low{color:#bbf7d0;border-color:rgba(34,197,94,.45)}
      .cve-intel-grid{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
        gap:10px;
      }
      .cve-score-track{
        height:10px;
        border-radius:999px;
        overflow:hidden;
        background:#020202;
        border:1px solid rgba(255,255,255,.12);
        margin:12px 0;
      }
      .cve-score-fill{height:100%;border-radius:999px;background:#60a5fa}
      .cve-score-fill.critical,.cve-score-fill.high{background:#ef4444}
      .cve-score-fill.medium{background:#f59e0b}
      .cve-score-fill.low{background:#22c55e}
      .cve-intel-badges{
        display:flex;
        flex-wrap:wrap;
        gap:8px;
        margin:10px 0;
      }
      .cve-intel-badge{
        display:inline-flex;
        padding:6px 9px;
        border-radius:999px;
        font-size:12px;
        font-weight:900;
        border:1px solid rgba(255,255,255,.12);
        background:#111;
      }
      .danger-badge{color:#fecaca;border-color:rgba(239,68,68,.45);background:rgba(239,68,68,.08)}
      .safe-badge{color:#bbf7d0;border-color:rgba(34,197,94,.35);background:rgba(34,197,94,.06)}
      .warn-badge{color:#fde68a;border-color:rgba(245,158,11,.45);background:rgba(245,158,11,.08)}
      .cve-links{margin-top:12px}
    `;
    document.head.appendChild(style);
  }

  function injectCveIntelAfterRender(data) {
    try {
      injectCveStyles();

      const old = document.getElementById("cveIntelligenceSection");
      if (old) old.remove();

      const html = renderCveIntelligenceSection(data);
      if (!html) return;

      const panels = document.querySelector(".result-panels");
      if (!panels) return;

      const rawJson = Array.from(panels.querySelectorAll(".result-card.wide h3"))
        .find(h => h.textContent.includes("Raw JSON"))?.closest(".result-card");

      if (rawJson) rawJson.insertAdjacentHTML("beforebegin", html);
      else panels.insertAdjacentHTML("beforeend", html);
    } catch (e) {
      console.warn("CVE Intelligence UI patch failed:", e);
    }
  }

  const waitForRender = setInterval(() => {
    if (typeof window.renderScanResult === "function") {
      clearInterval(waitForRender);
      const original = window.renderScanResult;
      window.renderScanResult = function patchedRenderScanResult(data) {
        original(data);
        injectCveIntelAfterRender(data);
      };
    }
  }, 250);

  window.renderCveIntelligenceSection = renderCveIntelligenceSection;
  window.injectCveIntelAfterRender = injectCveIntelAfterRender;
})();
