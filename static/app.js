let lastBatchResults = [];

// History state
let historyFilter = "ALL";
let historyPage = 1;
const historyPageSize = 5;

document.addEventListener("DOMContentLoaded", () => {
  console.log("app.js loaded");
  checkAPI();
  renderHistory();
  loadModelInfo();
});

function showTab(tabId, btn) {
  document
    .querySelectorAll(".tab-section")
    .forEach((s) => s.classList.remove("active"));
  document
    .querySelectorAll(".nav-btn")
    .forEach((b) => b.classList.remove("active"));

  const tab = document.getElementById(tabId);
  if (tab) tab.classList.add("active");
  if (btn) btn.classList.add("active");
}

async function checkAPI() {
  const status = document.getElementById("apiStatus");
  if (!status) return;

  try {
    const res = await fetch("/health");
    const data = await res.json();
    status.textContent = data.status || "API Online";
    status.style.background = "#14532d";
  } catch (e) {
    console.error("Health check failed:", e);
    status.textContent = "API Offline";
    status.style.background = "#7f1d1d";
  }
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getPredictionBadge(prediction) {
  return `<span class="badge ${prediction === "PHISHING" ? "phishing" : "legit"}">${escapeHtml(prediction)}</span>`;
}

// ==========================
// SINGLE SCAN
// ==========================
async function scanSingleURL() {
  const url = document.getElementById("urlInput").value.trim();
  const container = document.getElementById("singleResult");

  if (!url) {
    container.innerHTML = "<p>Please enter a URL.</p>";
    return;
  }

  container.innerHTML = "<p>Scanning...</p>";

  try {
    const res = await fetch(`/predict?url=${encodeURIComponent(url)}`);
    const data = await res.json();

    if (data.error) {
      container.innerHTML = `<p>${escapeHtml(data.error)}</p>`;
      return;
    }

    container.innerHTML = `
      <div class="result-card">
        <div class="result-header">
          ${getPredictionBadge(data.prediction)}
          <span class="risk">${data.risk_score} (${data.risk_level})</span>
        </div>
        <p>${escapeHtml(data.url)}</p>
        <ul>
          ${data.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>
      </div>
    `;

    saveToHistory(data);
  } catch (e) {
    console.error("Single scan error:", e);
    container.innerHTML = "<p>Single scan failed.</p>";
  }
}

// ==========================
// BATCH SCAN
// ==========================
async function runBatchScan() {
  console.log("Run Batch Scan clicked");

  const input = document.getElementById("batchInput").value.trim();
  const container = document.getElementById("batchResult");

  if (!input) {
    container.innerHTML = "<p>Please enter at least one URL.</p>";
    return;
  }

  const urls = input
    .split("\n")
    .map((u) => u.trim())
    .filter((u) => u.length > 0);

  container.innerHTML = "<p>Running batch scan...</p>";

  try {
    const res = await fetch("/batch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ urls: urls }),
    });

    const text = await res.text();
    console.log("Raw /batch response:", text);

    let data;
    try {
      data = JSON.parse(text);
    } catch {
      container.innerHTML = `<p>Invalid server response: ${escapeHtml(text)}</p>`;
      return;
    }

    if (!res.ok) {
      container.innerHTML = `<p>Batch failed: ${escapeHtml(data.detail || data.error || "Unknown error")}</p>`;
      return;
    }

    if (data.error) {
      container.innerHTML = `<p>Batch failed: ${escapeHtml(data.error)}</p>`;
      return;
    }

    if (!data.results || data.results.length === 0) {
      container.innerHTML = "<p>No valid URLs were processed.</p>";
      return;
    }

    lastBatchResults = data.results;
    renderBatchResults(data.results);
    data.results.forEach(saveToHistory);
  } catch (e) {
    console.error("Batch scan error:", e);
    container.innerHTML = `<p>Batch scan failed: ${escapeHtml(e.message)}</p>`;
  }
}

function renderBatchResults(results) {
  const container = document.getElementById("batchResult");

  container.innerHTML = `
    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>Prediction</th>
            <th>Risk</th>
            <th>Level</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody>
          ${results
            .map(
              (r) => `
              <tr>
                <td>${escapeHtml(r.url)}</td>
                <td>${getPredictionBadge(r.prediction)}</td>
                <td>${r.risk_score}</td>
                <td>${escapeHtml(r.risk_level)}</td>
                <td>${escapeHtml(r.reasons.join(", "))}</td>
              </tr>
            `,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

function clearBatch() {
  document.getElementById("batchInput").value = "";
  document.getElementById("batchResult").innerHTML = "";
  lastBatchResults = [];
}

// ==========================
// CSV UPLOAD
// ==========================
async function uploadCSV() {
  const fileInput = document.getElementById("csvFile");
  const container = document.getElementById("uploadResult");

  if (!fileInput.files.length) {
    container.innerHTML = "<p>Please select a CSV file.</p>";
    return;
  }

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);

  container.innerHTML = "<p>Uploading...</p>";

  try {
    const res = await fetch("/upload", {
      method: "POST",
      body: formData,
    });

    const data = await res.json();

    if (data.error) {
      container.innerHTML = `<p>${escapeHtml(data.error)}</p>`;
      return;
    }

    renderUploadResults(data.results);
    data.results.forEach(saveToHistory);
  } catch (e) {
    console.error("Upload error:", e);
    container.innerHTML = "<p>Upload failed.</p>";
  }
}

function renderUploadResults(results) {
  const container = document.getElementById("uploadResult");

  container.innerHTML = `
    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>Prediction</th>
            <th>Risk</th>
            <th>Level</th>
          </tr>
        </thead>
        <tbody>
          ${results
            .map(
              (r) => `
              <tr>
                <td>${escapeHtml(r.url)}</td>
                <td>${getPredictionBadge(r.prediction)}</td>
                <td>${r.risk_score}</td>
                <td>${escapeHtml(r.risk_level)}</td>
              </tr>
            `,
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;
}

// ==========================
// HISTORY
// ==========================
function saveToHistory(item) {
  const history = JSON.parse(localStorage.getItem("phishlens_history") || "[]");
  history.unshift({
    ...item,
    time: new Date().toLocaleString(),
  });
  localStorage.setItem(
    "phishlens_history",
    JSON.stringify(history.slice(0, 100)),
  );
  renderHistory();
}

function getFilteredHistory() {
  const history = JSON.parse(localStorage.getItem("phishlens_history") || "[]");

  if (historyFilter === "ALL") return history;

  return history.filter((item) => item.prediction === historyFilter);
}

function renderHistory() {
  const container = document.getElementById("historyContainer");
  const pageInfo = document.getElementById("historyPageInfo");

  if (!container) return;

  const filteredHistory = getFilteredHistory();
  const totalPages = Math.max(
    1,
    Math.ceil(filteredHistory.length / historyPageSize),
  );

  if (historyPage > totalPages) historyPage = totalPages;
  if (historyPage < 1) historyPage = 1;

  const startIndex = (historyPage - 1) * historyPageSize;
  const endIndex = startIndex + historyPageSize;
  const paginatedHistory = filteredHistory.slice(startIndex, endIndex);

  if (filteredHistory.length === 0) {
    container.innerHTML = "<p>No history available.</p>";
    if (pageInfo) pageInfo.textContent = "Page 1 of 1";
    return;
  }

  container.innerHTML = paginatedHistory
    .map(
      (item) => `
      <div class="result-card">
        <div class="result-header">
          ${getPredictionBadge(item.prediction)}
          <span class="risk">${item.risk_score} (${item.risk_level})</span>
        </div>
        <p>${escapeHtml(item.url)}</p>
        <small>${escapeHtml(item.time)}</small>
        <ul>
          ${item.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}
        </ul>
      </div>
    `,
    )
    .join("");

  if (pageInfo) {
    pageInfo.textContent = `Page ${historyPage} of ${totalPages}`;
  }
}

function setHistoryFilter(filter, btn) {
  historyFilter = filter;
  historyPage = 1;

  document
    .querySelectorAll(".filter-btn")
    .forEach((b) => b.classList.remove("active"));

  if (btn) btn.classList.add("active");

  renderHistory();
}

function nextHistoryPage() {
  const filteredHistory = getFilteredHistory();
  const totalPages = Math.max(
    1,
    Math.ceil(filteredHistory.length / historyPageSize),
  );

  if (historyPage < totalPages) {
    historyPage++;
    renderHistory();
  }
}

function prevHistoryPage() {
  if (historyPage > 1) {
    historyPage--;
    renderHistory();
  }
}

function clearHistory() {
  localStorage.removeItem("phishlens_history");
  historyPage = 1;
  renderHistory();
}

// ==========================
// MODEL INFO
// ==========================
function loadModelInfo() {
  const container = document.getElementById("modelInfo");
  if (!container) return;

  container.innerHTML = `
    <div class="result-card">
      <p><strong>Mode:</strong> Web application + API-based phishing detection</p>
      <p><strong>Batch scan:</strong> Enabled</p>
      <p><strong>CSV upload:</strong> Enabled</p>
      <p><strong>History filters:</strong> All / Phishing / Legitimate</p>
      <p><strong>History pagination:</strong> Enabled</p>
    </div>
  `;
}
