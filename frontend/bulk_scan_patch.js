```javascript
(function(){

function injectBulkUI(){

  const tabs = document.querySelector(".tabs");
  if(tabs && !document.getElementById("tabBulk")){
    tabs.insertAdjacentHTML(
      "beforeend",
      `<button class="tab" id="tabBulk" onclick="showBulkSection()">🧩 Bulk Scan</button>`
    );
  }

  const parent = document.querySelector("main section");
  if(!parent || document.getElementById("bulkSection")) return;

  parent.insertAdjacentHTML("beforeend", `
    <section id="bulkSection" class="section">
      <div class="panel out">
        <h2>🧩 Unlimited Bulk Scan</h2>

        <div class="field">
          <label>Targets (one per line)</label>
          <textarea id="bulkTargets"
          style="width:100%;min-height:220px;background:#080808;color:white;border:1px solid rgba(255,255,255,.15);border-radius:14px;padding:14px"
          placeholder="https://site1.com
https://site2.com
scanme.nmap.org"></textarea>
        </div>

        <div class="field">
          <label>Profile</label>
          <select id="bulkProfile">
            <option value="quick">Quick</option>
            <option value="full" selected>Full</option>
            <option value="deep">Deep</option>
          </select>
        </div>

        <div class="scan-actions">
          <button class="green" onclick="startBulkScan()">🚀 Start Bulk Scan</button>
        </div>

        <div id="bulkResults"></div>
      </div>
    </section>
  `);
}

window.showBulkSection = function(){

  document.querySelectorAll(".section").forEach(x=>{
    x.classList.remove("active");
  });

  document.querySelectorAll(".tab").forEach(x=>{
    x.classList.remove("active");
  });

  document.getElementById("bulkSection")?.classList.add("active");
  document.getElementById("tabBulk")?.classList.add("active");
};

window.startBulkScan = async function(){

  const raw = document.getElementById("bulkTargets").value;

  const targets = raw
    .split(/\n/)
    .map(x=>x.trim())
    .filter(Boolean);

  const profile = document.getElementById("bulkProfile").value;

  const box = document.getElementById("bulkResults");

  if(!targets.length){
    alert("Enter targets");
    return;
  }

  box.innerHTML = `
    <div class="result-card">
      <div class="scan-loader"></div>
      <h2>Running Bulk Scan...</h2>
    </div>
  `;

  try{

    const res = await fetch(API + "/bulk-scan/start",{
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "Authorization":"Bearer " + localStorage.getItem("token")
      },
      body:JSON.stringify({
        targets,
        profile
      })
    });

    const data = await res.json();

    if(!res.ok){
      throw new Error(data.detail || "Bulk scan failed");
    }

    box.innerHTML = `
      <div class="result-card">
        <h2>✅ Bulk Scan Started</h2>
        <pre>${JSON.stringify(data,null,2)}</pre>
      </div>
    `;

  }catch(err){

    box.innerHTML = `
      <div class="result-card high">
        <h2>❌ Error</h2>
        <p>${err.message}</p>
      </div>
    `;
  }
};

document.addEventListener("DOMContentLoaded",injectBulkUI);

})();
```
