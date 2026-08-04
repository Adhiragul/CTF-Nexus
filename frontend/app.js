// Frontend and backend run as separate services/ports (3000 vs 8000) whether
// you open index.html directly via file:// or via docker-compose - so always
// point at the backend's own port on whatever host we're loaded from.
const API_BASE = `${window.location.protocol === "file:" ? "http:" : window.location.protocol}//${window.location.hostname || "localhost"}:8000`;

// ---------------------------------------------------------------------------
// Global flag inventory - the signature feature. Every module funnels any
// flags_found into this single running list, with a toast + pulsing counter
// so a match is never missed regardless of which tab you're on.
// ---------------------------------------------------------------------------
const flagInventory = []; // { flag, source, timestamp }

function recordFlags(flags, source) {
  if (!flags || !flags.length) return;
  let added = false;
  for (const flag of flags) {
    if (flagInventory.some(f => f.flag === flag)) continue;
    flagInventory.push({ flag, source, timestamp: new Date() });
    added = true;
  }
  if (added) {
    renderFlagLog();
    updateFlagCounter();
    showToast(`FLAG DETECTED — ${flags[0]}`);
  }
}

function updateFlagCounter() {
  const counter = document.getElementById("flag-counter");
  const text = document.getElementById("flag-count-text");
  text.textContent = `${flagInventory.length} flag${flagInventory.length === 1 ? "" : "s"} found`;
  counter.classList.toggle("has-flags", flagInventory.length > 0);
}

function renderFlagLog() {
  const list = document.getElementById("flaglog-list");
  if (!flagInventory.length) {
    list.innerHTML = `<div class="empty-state">Nothing yet — flags found in any module will appear here automatically.</div>`;
    return;
  }
  list.innerHTML = flagInventory
    .slice()
    .reverse()
    .map(f => `<div class="flaglog-item"><span>${escapeHtml(f.flag)}</span><span class="src">${f.source} · ${f.timestamp.toLocaleTimeString()}</span></div>`)
    .join("");
}

let toastTimer = null;
function showToast(message) {
  const toast = document.getElementById("flag-toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 4000);
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

// ---------------------------------------------------------------------------
// Tab navigation
// ---------------------------------------------------------------------------
document.querySelectorAll(".nav-item").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ---------------------------------------------------------------------------
// Backend health check
// ---------------------------------------------------------------------------
async function checkHealth() {
  const dot = document.getElementById("api-status-dot");
  const text = document.getElementById("api-status-text");
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error();
    dot.className = "status-dot online";
    text.textContent = "backend online";
  } catch {
    dot.className = "status-dot offline";
    text.textContent = "backend unreachable — start uvicorn on :8000";
  }
}
checkHealth();

// ---------------------------------------------------------------------------
// Flag profile picker
// ---------------------------------------------------------------------------
async function loadProfiles() {
  const select = document.getElementById("profile-select");
  try {
    const res = await fetch(`${API_BASE}/api/flags/profiles`);
    const data = await res.json();
    select.innerHTML = "";
    for (const [name] of Object.entries(data.presets)) {
      const opt = document.createElement("option");
      opt.textContent = name;
      opt.value = name;
      select.appendChild(opt);
    }
    for (const p of data.profiles) {
      const opt = document.createElement("option");
      opt.textContent = p.name + " (custom)";
      opt.value = p.name;
      select.appendChild(opt);
    }
  } catch {
    select.innerHTML = `<option>backend offline</option>`;
  }
}
loadProfiles();

document.getElementById("new-profile-btn").addEventListener("click", async () => {
  const name = prompt("Event name (e.g. HackFest 2026):");
  if (!name) return;
  const prefix = prompt("Flag prefix (e.g. HF2026 → matches HF2026{...}), or leave blank to enter a custom regex instead:");
  let custom_regex = null;
  if (!prefix) {
    custom_regex = prompt("Custom regex for the flag format:");
    if (!custom_regex) return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/flags/profiles`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, prefix: prefix || null, custom_regex }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || "failed");
    await loadProfiles();
  } catch (e) {
    alert(`Could not create profile: ${e.message}`);
  }
});

// ---------------------------------------------------------------------------
// Shared rendering: AnalysisResult -> DOM
// ---------------------------------------------------------------------------
function confidenceMeter(conf) {
  const filled = Math.round(conf * 10);
  const bar = "█".repeat(filled) + "░".repeat(10 - filled);
  return `<span class="confidence-meter"><span class="meter-bar"><span class="meter-fill">${bar.slice(0, filled)}</span><span class="meter-empty">${bar.slice(filled)}</span></span> ${(conf * 100).toFixed(0)}%</span>`;
}

function renderResult(container, result, sourceLabel) {
  container.innerHTML = "";

  if (result.error) {
    container.innerHTML = `<div class="error-box">⚠ ${escapeHtml(result.error)}</div>`;
    return;
  }

  const findings = result.findings || [];
  if (!findings.length) {
    container.innerHTML = `<div class="empty-state">No findings — the input didn't match any known pattern.</div>`;
  }

  findings.forEach((f, i) => {
    if (f.flags_found && f.flags_found.length) recordFlags(f.flags_found, sourceLabel);

    const card = document.createElement("div");
    card.className = "finding-card" + (i === 0 ? " top-finding" : "") + (f.flags_found && f.flags_found.length ? " has-flag" : "");
    card.innerHTML = `
      <div class="finding-head">
        <span class="finding-label">${escapeHtml(f.label)}</span>
        ${confidenceMeter(f.confidence)}
      </div>
      <div class="finding-summary">${escapeHtml(f.summary)}</div>
      ${f.data ? `<div class="finding-data">${escapeHtml(f.data)}</div>` : ""}
      ${f.flags_found && f.flags_found.length ? `<div class="finding-flags">🚩 ${f.flags_found.map(escapeHtml).join(", ")}</div>` : ""}
    `;
    container.appendChild(card);
  });

  if (result.tool_log && result.tool_log.length) {
    const log = document.createElement("div");
    log.className = "tool-log";
    log.innerHTML = `<h4>tools executed</h4>` + result.tool_log.map(l => `<div class="tool-log-line">${escapeHtml(l)}</div>`).join("");
    container.appendChild(log);
  }

  if (result.next_steps && result.next_steps.length) {
    const steps = document.createElement("div");
    steps.className = "next-steps";
    steps.innerHTML = `<h4>recommended next steps</h4>` + result.next_steps.map(s => `<div class="next-step-line">${escapeHtml(s)}</div>`).join("");
    container.appendChild(steps);
  }
}

// ---------------------------------------------------------------------------
// Crypto tab
// ---------------------------------------------------------------------------
async function runCryptoAnalysis() {
  const text = document.getElementById("crypto-input").value.trim();
  const container = document.getElementById("crypto-results");
  if (!text) return;
  container.innerHTML = `<div class="empty-state">analyzing…</div>`;
  try {
    const res = await fetch(`${API_BASE}/api/crypto/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();
    renderResult(container, data, "crypto");
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
}
document.getElementById("crypto-analyze-btn").addEventListener("click", runCryptoAnalysis);
document.getElementById("crypto-input").addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runCryptoAnalysis();
});

// ---------------------------------------------------------------------------
// Stego tab
// ---------------------------------------------------------------------------
let selectedStegoFile = null;
const dropzone = document.getElementById("stego-dropzone");
const fileInput = document.getElementById("stego-file-input");

document.getElementById("stego-browse").addEventListener("click", () => fileInput.click());
dropzone.addEventListener("click", e => { if (e.target.id !== "stego-browse") fileInput.click(); });

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) setStegoFile(fileInput.files[0]);
});
dropzone.addEventListener("dragover", e => { e.preventDefault(); dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", e => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) setStegoFile(e.dataTransfer.files[0]);
});

function setStegoFile(file) {
  selectedStegoFile = file;
  document.getElementById("stego-filename").textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  document.getElementById("stego-analyze-btn").disabled = false;
}

document.getElementById("stego-analyze-btn").addEventListener("click", async () => {
  if (!selectedStegoFile) return;
  const container = document.getElementById("stego-results");
  container.innerHTML = `<div class="empty-state">running pipeline…</div>`;
  const formData = new FormData();
  formData.append("file", selectedStegoFile);
  try {
    const res = await fetch(`${API_BASE}/api/stego/analyze`, { method: "POST", body: formData });
    const data = await res.json();
    renderResult(container, data, "stego");
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
});

// ---------------------------------------------------------------------------
// Web tab
// ---------------------------------------------------------------------------
document.getElementById("web-analyze-btn").addEventListener("click", async () => {
  const url = document.getElementById("web-url-input").value.trim();
  const container = document.getElementById("web-results");
  if (!url) return;
  container.innerHTML = `<div class="empty-state">running recon…</div>`;
  try {
    const res = await fetch(`${API_BASE}/api/web/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    if (!res.ok) { container.innerHTML = `<div class="error-box">⚠ ${escapeHtml(data.detail || "request failed")}</div>`; return; }
    renderResult(container, data, "web");
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
});

// ---------------------------------------------------------------------------
// Misc tab
// ---------------------------------------------------------------------------
async function postJson(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

document.getElementById("bc-run").addEventListener("click", async () => {
  const value = document.getElementById("bc-value").value.trim();
  const from_base = parseInt(document.getElementById("bc-from").value, 10);
  const to_base = parseInt(document.getElementById("bc-to").value, 10);
  const out = await postJson("/api/misc/base-convert", { value, from_base, to_base });
  document.getElementById("bc-output").textContent = JSON.stringify(out, null, 2);
});

document.getElementById("jwt-run").addEventListener("click", async () => {
  const token = document.getElementById("jwt-input").value.trim();
  const out = await postJson("/api/misc/jwt-decode", { token });
  document.getElementById("jwt-output").textContent = JSON.stringify(out, null, 2);
  const flags = flagPatternScanLocal(JSON.stringify(out));
  if (flags.length) recordFlags(flags, "misc:jwt");
});

document.getElementById("ts-run").addEventListener("click", async () => {
  const value = document.getElementById("ts-value").value.trim();
  const out = await postJson("/api/misc/timestamp", { value });
  document.getElementById("ts-output").textContent = JSON.stringify(out, null, 2);
});

document.getElementById("uuid-run").addEventListener("click", async () => {
  const value = document.getElementById("uuid-value").value.trim();
  const out = await postJson("/api/misc/uuid", { value });
  document.getElementById("uuid-output").textContent = JSON.stringify(out, null, 2);
});

document.getElementById("uni-run").addEventListener("click", async () => {
  const text = document.getElementById("uni-value").value;
  const out = await postJson("/api/misc/unicode", { text });
  document.getElementById("uni-output").textContent = JSON.stringify(out, null, 2);
});

document.getElementById("rx-run").addEventListener("click", async () => {
  const pattern = document.getElementById("rx-pattern").value;
  const text = document.getElementById("rx-text").value;
  const out = await postJson("/api/misc/regex", { pattern, text });
  document.getElementById("rx-output").textContent = JSON.stringify(out, null, 2);
});

// lightweight client-side flag scan for misc-tool outputs, mirrors the
// backend's builtin presets so JWT payloads etc. still light up the counter
function flagPatternScanLocal(text) {
  const patterns = [/HTB\{[^}]{1,200}\}/g, /THM\{[^}]{1,200}\}/g, /picoCTF\{[^}]{1,200}\}/g, /flag\{[^}]{1,200}\}/gi, /CTF\{[^}]{1,200}\}/g];
  const hits = [];
  for (const p of patterns) {
    const matches = text.match(p);
    if (matches) for (const m of matches) if (!hits.includes(m)) hits.push(m);
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Forensics tab (PCAP)
// ---------------------------------------------------------------------------
let selectedPcapFile = null;
const pcapDropzone = document.getElementById("pcap-dropzone");
const pcapFileInput = document.getElementById("pcap-file-input");

document.getElementById("pcap-browse").addEventListener("click", () => pcapFileInput.click());
pcapDropzone.addEventListener("click", e => { if (e.target.id !== "pcap-browse") pcapFileInput.click(); });
pcapFileInput.addEventListener("change", () => { if (pcapFileInput.files.length) setPcapFile(pcapFileInput.files[0]); });
pcapDropzone.addEventListener("dragover", e => { e.preventDefault(); pcapDropzone.classList.add("dragover"); });
pcapDropzone.addEventListener("dragleave", () => pcapDropzone.classList.remove("dragover"));
pcapDropzone.addEventListener("drop", e => {
  e.preventDefault();
  pcapDropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) setPcapFile(e.dataTransfer.files[0]);
});

function setPcapFile(file) {
  selectedPcapFile = file;
  document.getElementById("pcap-filename").textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  document.getElementById("pcap-analyze-btn").disabled = false;
}

document.getElementById("pcap-analyze-btn").addEventListener("click", async () => {
  if (!selectedPcapFile) return;
  const container = document.getElementById("forensics-results");
  container.innerHTML = `<div class="empty-state">running tshark pipeline… (larger captures take longer)</div>`;
  const formData = new FormData();
  formData.append("file", selectedPcapFile);
  try {
    const res = await fetch(`${API_BASE}/api/forensics/pcap`, { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) { container.innerHTML = `<div class="error-box">⚠ ${escapeHtml(data.detail || "request failed")}</div>`; return; }
    renderResult(container, data, "forensics");
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
});

// ---------------------------------------------------------------------------
// Reverse tab — binary triage
// ---------------------------------------------------------------------------
let selectedBinaryFile = null;
const binaryDropzone = document.getElementById("binary-dropzone");
const binaryFileInput = document.getElementById("binary-file-input");

document.getElementById("binary-browse").addEventListener("click", () => binaryFileInput.click());
binaryDropzone.addEventListener("click", e => { if (e.target.id !== "binary-browse") binaryFileInput.click(); });
binaryFileInput.addEventListener("change", () => { if (binaryFileInput.files.length) setBinaryFile(binaryFileInput.files[0]); });
binaryDropzone.addEventListener("dragover", e => { e.preventDefault(); binaryDropzone.classList.add("dragover"); });
binaryDropzone.addEventListener("dragleave", () => binaryDropzone.classList.remove("dragover"));
binaryDropzone.addEventListener("drop", e => {
  e.preventDefault();
  binaryDropzone.classList.remove("dragover");
  if (e.dataTransfer.files.length) setBinaryFile(e.dataTransfer.files[0]);
});

function setBinaryFile(file) {
  selectedBinaryFile = file;
  document.getElementById("binary-filename").textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  document.getElementById("binary-analyze-btn").disabled = false;
}

document.getElementById("binary-analyze-btn").addEventListener("click", async () => {
  if (!selectedBinaryFile) return;
  const container = document.getElementById("reverse-binary-results");
  container.innerHTML = `<div class="empty-state">running static triage…</div>`;
  const formData = new FormData();
  formData.append("file", selectedBinaryFile);
  try {
    const res = await fetch(`${API_BASE}/api/reverse/binary`, { method: "POST", body: formData });
    const data = await res.json();
    if (!res.ok) { container.innerHTML = `<div class="error-box">⚠ ${escapeHtml(data.detail || "request failed")}</div>`; return; }
    renderResult(container, data, "reverse:binary");
    if (data.dynamic_plan) {
      const planHeader = document.createElement("div");
      planHeader.className = "section-label";
      planHeader.style.marginTop = "24px";
      planHeader.textContent = "auto-generated dynamic-analysis plan";
      container.appendChild(planHeader);
      const planDiv = document.createElement("div");
      container.appendChild(planDiv);
      renderResult(planDiv, data.dynamic_plan, "reverse:dynamic-plan");
    }
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
});

// ---------------------------------------------------------------------------
// Reverse tab — decompiled code
// ---------------------------------------------------------------------------
document.getElementById("decompiled-analyze-btn").addEventListener("click", async () => {
  const code = document.getElementById("decompiled-input").value.trim();
  const container = document.getElementById("reverse-decompiled-results");
  if (!code) return;
  container.innerHTML = `<div class="empty-state">analyzing…</div>`;
  try {
    const res = await fetch(`${API_BASE}/api/reverse/decompiled`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    const data = await res.json();
    renderResult(container, data, "reverse:decompiled");
  } catch (e) {
    container.innerHTML = `<div class="error-box">⚠ request failed: ${escapeHtml(e.message)}</div>`;
  }
});

renderFlagLog();
