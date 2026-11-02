"use strict";

const state = { paused: false, timer: null };

const byId = (id) => document.getElementById(id);

function normalizeText(value, max = 256) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, max);
}

function setText(element, value) {
  element.textContent = normalizeText(value);
}

function severityClass(severity) {
  const allowed = new Set(["critical", "high", "medium", "low", "informational"]);
  return allowed.has(severity) ? `badge ${severity}` : "badge";
}

function renderCounts(container, counts) {
  container.replaceChildren();
  Object.entries(counts || {}).forEach(([key, value]) => {
    const item = document.createElement("span");
    item.className = "count-item";
    const label = document.createElement("span");
    setText(label, key);
    const number = document.createElement("strong");
    setText(number, value);
    item.append(label, number);
    container.append(item);
  });
}

function renderSparkline(scores) {
  const svg = byId("ml-sparkline");
  svg.replaceChildren();
  if (!scores || scores.length === 0) return;
  const width = 320;
  const height = 80;
  const step = scores.length > 1 ? width / (scores.length - 1) : width;
  const points = scores.map((entry, index) => {
    const x = index * step;
    const y = height - Math.max(0, Math.min(1, Number(entry.score))) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  line.setAttribute("points", points);
  line.setAttribute("class", "sparkline");
  svg.append(line);
}

function renderAPs(aps) {
  const body = byId("aps-body");
  body.replaceChildren();
  (aps || []).forEach((ap) => {
    const row = document.createElement("tr");
    const values = [ap.ssid || "-", ap.bssid, ap.oui || "-", (ap.channels || []).join(","), ap.rssi, (ap.security || []).join(",")];
    values.forEach((value) => {
      const cell = document.createElement("td");
      setText(cell, value);
      row.append(cell);
    });
    const trustCell = document.createElement("td");
    const bar = document.createElement("div");
    bar.className = "trust-bar";
    const fill = document.createElement("div");
    fill.className = "trust-fill";
    fill.style.width = `${Math.max(0, Math.min(100, Number(ap.trust_score)))}%`;
    bar.append(fill);
    trustCell.append(bar);
    const trustNumber = document.createElement("span");
    setText(trustNumber, ap.trust_score);
    trustCell.append(trustNumber);
    row.append(trustCell);
    const flaggedCell = document.createElement("td");
    setText(flaggedCell, ap.flagged ? "Yes" : "No");
    row.append(flaggedCell);
    body.append(row);
  });
}

function detailList(title, items) {
  const wrapper = document.createElement("div");
  const heading = document.createElement("h4");
  setText(heading, title);
  wrapper.append(heading);
  const list = document.createElement("ul");
  (items || []).forEach((item) => {
    const li = document.createElement("li");
    setText(li, item.text || `${item.field}: ${item.observed} expected ${item.threshold}`);
    list.append(li);
  });
  wrapper.append(list);
  return wrapper;
}

function renderAlerts(alerts) {
  const list = byId("alerts-list");
  list.replaceChildren();
  const empty = byId("empty-state");
  empty.hidden = (alerts || []).length > 0;
  (alerts || []).forEach((alert) => {
    const item = document.createElement("li");
    item.className = "alert";
    const summary = document.createElement("button");
    summary.type = "button";
    summary.className = "alert-summary";
    summary.setAttribute("aria-expanded", "false");
    const badge = document.createElement("span");
    badge.className = severityClass(alert.severity);
    setText(badge, alert.severity);
    const risk = document.createElement("strong");
    setText(risk, `Risk ${alert.risk_score}`);
    const family = document.createElement("span");
    setText(family, alert.family);
    const technique = document.createElement("span");
    setText(technique, alert.mitre_attack && alert.mitre_attack.technique ? alert.mitre_attack.technique : "-");
    const time = document.createElement("span");
    setText(time, alert.timestamp);
    summary.append(badge, risk, family, technique, time);
    const detail = document.createElement("div");
    detail.className = "alert-detail";
    detail.hidden = true;
    const why = document.createElement("p");
    setText(why, alert.why);
    detail.append(why);
    detail.append(detailList("Evidence", alert.evidence || alert.rule_evidence));
    detail.append(detailList("Indicators found", alert.indicators_found));
    detail.append(detailList("Indicators not found", alert.indicators_not_found));
    summary.addEventListener("click", () => {
      detail.hidden = !detail.hidden;
      summary.setAttribute("aria-expanded", detail.hidden ? "false" : "true");
    });
    item.append(summary, detail);
    list.append(item);
  });
}

async function fetchJSON(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

async function refresh() {
  if (state.paused) return;
  const error = byId("error-state");
  try {
    const severity = byId("severity-filter").value;
    const suffix = severity ? `?severity=${encodeURIComponent(severity)}` : "";
    const [stats, aps, alerts] = await Promise.all([
      fetchJSON("/api/stats"),
      fetchJSON("/api/aps"),
      fetchJSON(`/api/alerts${suffix}`),
    ]);
    setText(byId("stat-frames"), stats.frames_processed);
    setText(byId("stat-windows"), stats.windows);
    renderCounts(byId("severity-counts"), stats.alerts_by_severity);
    renderCounts(byId("family-counts"), stats.alerts_by_family);
    renderSparkline(stats.latest_ml_scores);
    renderAPs(aps);
    renderAlerts(alerts);
    error.hidden = true;
    setText(byId("poll-status"), "Polling");
  } catch (err) {
    error.hidden = false;
    setText(error, `Unable to load data: ${err.message}`);
    setText(byId("poll-status"), "Error");
  }
}

byId("pause-button").addEventListener("click", () => {
  state.paused = !state.paused;
  setText(byId("pause-button"), state.paused ? "Resume" : "Pause");
  setText(byId("poll-status"), state.paused ? "Paused" : "Polling");
  if (!state.paused) refresh();
});

byId("severity-filter").addEventListener("change", refresh);
refresh();
state.timer = window.setInterval(refresh, 2000);
window.addEventListener("beforeunload", () => window.clearInterval(state.timer));