const API = "https://threat-scanner-saas-2.onrender.com";

// =========================
// LOGIN
// =========================
async function login() {
  const username = document.getElementById("u").value;
  const password = document.getElementById("p").value;

  if (!username || !password) {
    alert("Enter username and password");
    return;
  }

  try {
    const res = await fetch(API + "/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username,
        password
      })
    });

    const data = await res.json();

    if (data.access_token) {
      localStorage.setItem("token", data.access_token);

      // redirect
      window.location.href = "dashboard.html";
    } else {
      alert(data.detail || "Login failed");
    }

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
// =========================
async function scan() {

  const token = localStorage.getItem("token");

  if (!token) {
    alert("Login first");
    return;
  }

  const targetInput = document.getElementById("target");

  if (!targetInput || !targetInput.value) {
    alert("Enter target");
    return;
  }

  const target = targetInput.value.trim();

  // loading
  const out = document.getElementById("out");

  if (out) {
    out.innerHTML = `
      <div style="padding:20px;color:#38bdf8;font-size:18px;">
        🔍 Scanning target...
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
        profile: "full"
      })
    });

    const data = await res.json();

    console.log("SCAN RESULT:", data);

    // =========================
    // SHOW RESULT
    // =========================
    if (out) {

      out.innerHTML = `
      
      <div class="result-card">

        <h2>🛡️ Scan Result</h2>

        <div class="result-grid">

          <div class="box">
            <span>Risk</span>
            <h3>${data.risk || "Unknown"}</h3>
          </div>

          <div class="box">
            <span>Score</span>
            <h3>${data.score || 0}/100</h3>
          </div>

          <div class="box">
            <span>Target</span>
            <h3>${data.target_type || "domain"}</h3>
          </div>

        </div>

        <hr>

        <h3>🌐 Target Information</h3>

        <p><b>Target:</b> ${data.target || "-"}</p>
        <p><b>Host:</b> ${data.host || "-"}</p>
        <p><b>IP:</b> ${data.ip || "-"}</p>
        <p><b>Final URL:</b> ${data.final_url || "-"}</p>

        <hr>

        <h3>🛰️ Nmap Scan</h3>

        <p><b>Enabled:</b> ${data.nmap ? "✅ Yes" : "❌ No"}</p>

        <hr>

        <h3>🚪 Open Ports</h3>

        ${
          data.open_ports && data.open_ports.length > 0
          ? data.open_ports.map(p => `
            <div class="port-box">
              🔓 Port ${p.port}
              (${p.service || "unknown"})
            </div>
          `).join("")
          : "<p>No open ports returned</p>"
        }

        <hr>

        <h3>🔒 SSL / TLS</h3>

        <p><b>Valid:</b> ${data.ssl?.valid ? "✅ Yes" : "❌ No"}</p>
        <p><b>TLS:</b> ${data.ssl?.tls_version || "-"}</p>
        <p><b>Expires:</b> ${data.ssl?.info || "-"}</p>

        <hr>

        <h3>🧱 Security Headers</h3>

        <pre>${JSON.stringify(data.headers || {}, null, 2)}</pre>

        <hr>

        <h3>🌍 DNS Security</h3>

        <p><b>SPF:</b> ${data.dns_security?.spf ? "✅ Found" : "❌ Missing"}</p>
        <p><b>DMARC:</b> ${data.dns_security?.dmarc ? "✅ Found" : "❌ Missing"}</p>

        <hr>

        <h3>🚨 Findings</h3>

        ${
          data.findings && data.findings.length > 0
          ? data.findings.map(f => `
            <div class="finding">
              ⚠️ ${f}
            </div>
          `).join("")
          : "<p>No findings</p>"
        }

      </div>
      `;
    }

  } catch (err) {

    console.error(err);

    if (out) {
      out.innerHTML = `
        <div style="color:red;padding:20px;">
          ❌ Scan failed
        </div>
      `;
    }
  }
}