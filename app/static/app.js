const API = "/api";

// --- Navigation between views ---
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});

function showView(view) {
  document.querySelectorAll(".view").forEach((el) => el.classList.add("hidden"));
  document.getElementById(`view-${view}`).classList.remove("hidden");
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });

  if (view === "dashboard") loadDashboard();
  if (view === "alerts") loadAlerts();
  if (view === "events") loadEvents();
  if (view === "timeline") loadTimeline();
}

function formatTimestamp(iso) {
  return new Date(iso).toLocaleString("de-DE");
}

// --- Dashboard ---
async function loadDashboard() {
  const res = await fetch(`${API}/stats`);
  const stats = await res.json();

  const cards = document.getElementById("stats-cards");
  cards.innerHTML = `
    <div class="card"><div>Events gesamt</div><div class="value">${stats.total_events}</div></div>
    <div class="card"><div>Offene Alerts</div><div class="value">${stats.open_alerts}</div></div>
    <div class="card"><div>Kritische Alerts</div><div class="value">${stats.critical_alerts}</div></div>
    <div class="card"><div>Quell-IPs</div><div class="value">${stats.unique_source_ips}</div></div>
    <div class="card"><div>Events (24h)</div><div class="value">${stats.events_last_24h}</div></div>
  `;

  const list = document.getElementById("top-alert-types");
  list.innerHTML = stats.top_alert_types
    .map((t) => `<li>${t.alert_type}: ${t.count}</li>`)
    .join("");
}

// --- Alerts ---
async function loadAlerts() {
  const params = new URLSearchParams();
  const severity = document.getElementById("alert-severity").value;
  const status = document.getElementById("alert-status").value;
  const ip = document.getElementById("alert-ip").value.trim();
  const q = document.getElementById("alert-search").value.trim();
  if (severity) params.set("severity", severity);
  if (status) params.set("status", status);
  if (ip) params.set("source_ip", ip);
  if (q) params.set("q", q);

  const res = await fetch(`${API}/alerts?${params.toString()}`);
  const alerts = await res.json();

  const tbody = document.querySelector("#alerts-table tbody");
  tbody.innerHTML = alerts
    .map(
      (a) => `
    <tr class="severity-row-${a.severity}">
      <td class="severity-${a.severity}">${a.severity}</td>
      <td>${a.alert_type}</td>
      <td>${a.title}</td>
      <td>${a.source_ip}</td>
      <td>${formatTimestamp(a.created_at)}</td>
      <td>${a.status}</td>
      <td>
        <button onclick="showAlertDetail(${a.id})">Details</button>
        <button onclick="updateAlertStatus(${a.id}, 'ACKNOWLEDGED')" ${a.status !== "OPEN" ? "disabled" : ""}>Ack</button>
        <button onclick="updateAlertStatus(${a.id}, 'RESOLVED')" ${a.status === "RESOLVED" ? "disabled" : ""}>Resolve</button>
      </td>
    </tr>`
    )
    .join("");
}

async function updateAlertStatus(alertId, status) {
  await fetch(`${API}/alerts/${alertId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
  loadAlerts();
}

async function showAlertDetail(alertId) {
  const res = await fetch(`${API}/alerts/${alertId}`);
  const a = await res.json();

  document.getElementById("modal-body").innerHTML = `
    <h3>${a.title}</h3>
    <p><strong>Typ:</strong> ${a.alert_type}</p>
    <p><strong>Severity:</strong> ${a.severity}</p>
    <p><strong>Quell-IP:</strong> ${a.source_ip}</p>
    <p><strong>Status:</strong> ${a.status}</p>
    <p><strong>Erstellt:</strong> ${formatTimestamp(a.created_at)}</p>
    <p>${a.description}</p>
    <p><strong>Betroffene Event-IDs:</strong> ${a.event_ids.join(", ")}</p>
    <p><strong>Zusatzinfo:</strong> ${a.extra_info ?? "-"}</p>
  `;
  document.getElementById("alert-detail-modal").classList.remove("hidden");
}

document.getElementById("modal-close").addEventListener("click", () => {
  document.getElementById("alert-detail-modal").classList.add("hidden");
});

document.getElementById("alert-filter-btn").addEventListener("click", loadAlerts);

// --- Events ---
async function loadEvents() {
  const params = new URLSearchParams();
  const ip = document.getElementById("event-ip").value.trim();
  const type = document.getElementById("event-type").value.trim();
  const user = document.getElementById("event-user").value.trim();
  const path = document.getElementById("event-path").value.trim();
  if (ip) params.set("source_ip", ip);
  if (type) params.set("event_type", type);
  if (user) params.set("username", user);
  if (path) params.set("path", path);

  const res = await fetch(`${API}/events?${params.toString()}`);
  const events = await res.json();

  const tbody = document.querySelector("#events-table tbody");
  tbody.innerHTML = events
    .map(
      (e) => `
    <tr class="severity-row-${e.severity}">
      <td>${formatTimestamp(e.timestamp)}</td>
      <td>${e.source_ip}</td>
      <td>${e.event_type}</td>
      <td>${e.username ?? "-"}</td>
      <td>${e.method ?? "-"}</td>
      <td>${e.path ?? "-"}</td>
      <td>${e.status_code ?? "-"}</td>
      <td class="severity-${e.severity}">${e.severity}</td>
    </tr>`
    )
    .join("");
}

document.getElementById("event-filter-btn").addEventListener("click", loadEvents);

// --- Timeline ---
async function loadTimeline() {
  const [eventsRes, alertsRes] = await Promise.all([
    fetch(`${API}/events?limit=100`),
    fetch(`${API}/alerts?limit=100`),
  ]);
  const events = await eventsRes.json();
  const alerts = await alertsRes.json();

  const items = [
    ...events.map((e) => ({
      time: e.timestamp,
      severity: e.severity,
      label: `[EVENT] ${e.event_type} von ${e.source_ip}`,
    })),
    ...alerts.map((a) => ({
      time: a.created_at,
      severity: a.severity,
      label: `[ALERT] ${a.alert_type}: ${a.title}`,
    })),
  ].sort((a, b) => new Date(b.time) - new Date(a.time));

  const list = document.getElementById("timeline-list");
  list.innerHTML = items
    .map(
      (item) => `
    <li class="severity-row-${item.severity}">
      <strong>${formatTimestamp(item.time)}</strong> – ${item.label}
      <span class="severity-${item.severity}"> (${item.severity})</span>
    </li>`
    )
    .join("");
}

// --- Log-Upload ---
document.getElementById("upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const fileInput = document.getElementById("upload-file");
  const logType = document.querySelector('input[name="log_type"]:checked').value;

  const formData = new FormData();
  formData.append("file", fileInput.files[0]);
  formData.append("log_type", logType);

  const res = await fetch(`${API}/logs/upload`, { method: "POST", body: formData });
  const result = await res.json();

  document.getElementById("upload-result").textContent = JSON.stringify(result, null, 2);
});

// --- Initial call when the page loads ---
loadDashboard();