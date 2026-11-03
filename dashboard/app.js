"use strict";

const state = {
  paused: false,
  timer: null,
  expanded: new Set(),
  alertSignature: "",
};

const byId = (id) => document.getElementById(id);

function normalizeText(value, max = 256) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").slice(0, max);
}

function sentenceTruncate(value, max = 280) {
  const textValue = normalizeText(value, 4000);
  if (textValue.length <= max) return textValue;
  const boundary = textValue.lastIndexOf(".", max);
  if (boundary > 0) return textValue.slice(0, boundary + 1) + " ...";
  return textValue.slice(0, max).replace(/\s+\S*$/, "") + "...";
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

function renderSparkline(scores, alerts) {
  const svg = byId("ml-sparkline");
  svg.replaceChildren();
  if (!scores || scores.length < 2) {
    const empty = document.createElementNS("http://www.w3.org/2000/svg", "text");
    empty.setAttribute("x", "12");
    empty.setAttribute("y", "44");
    empty.setAttribute("class", "sparkline-empty");
    empty.textContent = "Not enough ML score data";
    svg.append(empty);
    return;
  }
  const width = 320;
  const height = 64;
  const top = 8;
  const values = scores.map((entry) => Number(entry.score));
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const step = width / (scores.length - 1);
  const yFor = (value) => top + (1 - Math.max(0, Math.min(1, value))) * height;
  const baseline = document.createElementNS("http://www.w3.org/2000/svg", "line");
  baseline.setAttribute("x1", "0");
  baseline.setAttribute("x2", String(width));
  baseline.setAttribute("y1", String(top + height));
  baseline.setAttribute("y2", String(top + height));
  baseline.setAttribute("class", "sparkline-baseline");
  svg.append(baseline);
  const points = scores.map((entry, index) => `${(index * step).toFixed(1)},${yFor(Number(entry.score)).toFixed(1)}`).join(" ");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  line.setAttribute("points", points);
  line.setAttribute("class", "sparkline");
  svg.append(line);
  const spans = (alerts || []).map((alert) => [Date.parse(alert.first_seen), Date.parse(alert.last_seen)]);
  scores.forEach((entry, index) => {
    const timestamp = Date.parse(entry.timestamp);
    if (spans.some(([start, end]) => timestamp >= start && timestamp <= end)) {
      const marker = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      marker.setAttribute("cx", (index * step).toFixed(1));
      marker.setAttribute("cy", yFor(Number(entry.score)).toFixed(1));
      marker.setAttribute("r", "2.5");
      marker.setAttribute("class", "sparkline-alert-point");
      svg.append(marker);
    }
  });
  const minLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
  minLabel.setAttribute("x", "2");
  minLabel.setAttribute("y", "77");
  minLabel.setAttribute("class", "sparkline-label");
  minLabel.textContent = `min ${minimum.toFixed(3)}`;
  svg.append(minLabel);
  const maxLabel = document.createElementNS("http://www.w3.org/2000/svg", "text");
  maxLabel.setAttribute("x", "250");
  maxLabel.setAttribute("y", "77");
  maxLabel.setAttribute("class", "sparkline-label");
  maxLabel.textContent = `max ${maximum.toFixed(3)}`;
  svg.append(maxLabel);
}

function alertSignature(alert) {
  return [alert.id, alert.hit_count, alert.last_seen, alert.risk_score].join("|");
}

function renderAPs(aps) {
  const body = byId("aps-body");
  body.replaceChildren();
  (aps || []).forEach((ap) => {
    const row = document.createElement("tr");
    const rssi = ap.rssi === null || ap.rssi === undefined ? "-" : `${Number(ap.rssi).toFixed(1)} dBm`;
    const values = [ap.ssid || "-", ap.bssid, ap.oui || "-", (ap.channels || []).join(","), rssi, ap.security || "unknown"];
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
    const statusCell = document.createElement("td");
    const status = ap.status || (ap.flagged ? "Flagged" : "Trusted");
    setText(statusCell, `${status}${ap.flag_reason ? `: ${ap.flag_reason}` : ""}`);
    row.append(statusCell);
    body.append(row);
  });
}

function evidenceText(item) {
  if (item.text) return item.text;
  const operator = item.operator || "?";
  const threshold = item.threshold === undefined ? "?" : item.threshold;
  return `${item.field}: observed ${item.observed}, expected ${operator} ${threshold}`;
}

function detailList(title, items) {
    const wrapper = document.createElement("div");
    const heading = document.createElement("h4");
    setText(heading, title);
    wrapper.append(heading);
    if (!items || items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "muted";
      setText(empty, "None evaluated");
      wrapper.append(empty);
      return wrapper;
    }
    const list = document.createElement("ul");
    items.forEach((item) => {
      const li = document.createElement("li");
      setText(li, evidenceText(item));
      list.append(li);
    });
    wrapper.append(list);
    return wrapper;
  }

function buildAlertItem(alert) {
  const item = document.createElement("li");
  item.className = "alert";
  item.dataset.alertId = alert.id;
  item.dataset.signature = alertSignature(alert);
  const summary = document.createElement("button");
  summary.type = "button";
  summary.className = "alert-summary";
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
  const why = document.createElement("p");
  setText(why, sentenceTruncate(alert.why));
  detail.append(why);
  detail.append(detailList("Evidence", alert.evidence || alert.rule_evidence));
  detail.append(detailList("Indicators found", alert.indicators_found));
  detail.append(detailList("Indicators not found", alert.indicators_not_found));
  summary.addEventListener("click", () => {
    if (state.expanded.has(alert.id)) state.expanded.delete(alert.id);
    else state.expanded.add(alert.id);
    detail.hidden = !state.expanded.has(alert.id);
    summary.setAttribute("aria-expanded", detail.hidden ? "false" : "true");
  });
  item.append(summary, detail);
  return item;
}

function applyExpandedState(item) {
  const expanded = state.expanded.has(item.dataset.alertId);
  const detail = item.querySelector(".alert-detail");
  const summary = item.querySelector(".alert-summary");
  if (detail) detail.hidden = !expanded;
  if (summary) summary.setAttribute("aria-expanded", expanded ? "true" : "false");
}

function renderAlerts(alerts) {
  const list = byId("alerts-list");
  const empty = byId("empty-state");
  empty.hidden = (alerts || []).length > 0;
  const signature = JSON.stringify((alerts || []).map(alertSignature));
  if (signature === state.alertSignature) {
    list.querySelectorAll(".alert").forEach(applyExpandedState);
    return;
  }
  const active = document.activeElement;
  const activeId = active && active.closest ? active.closest(".alert")?.dataset.alertId : null;
  const scrollY = window.scrollY;
  const existing = new Map(
    Array.from(list.querySelectorAll(".alert")).map((item) => [item.dataset.alertId, item]),
  );
  const next = document.createDocumentFragment();
  (alerts || []).forEach((alert) => {
    const signatureValue = alertSignature(alert);
    const current = existing.get(alert.id);
    if (current && current.dataset.signature === signatureValue) {
      next.append(current);
    } else {
      next.append(buildAlertItem(alert));
    }
  });
  list.replaceChildren(next);
  list.querySelectorAll(".alert").forEach((item) => {
    applyExpandedState(item);
  });
  if (activeId) {
    const restored = list.querySelector(`[data-alert-id="${CSS.escape(activeId)}"] .alert-summary`);
    if (restored) restored.focus({ preventScroll: true });
  }
  window.scrollTo(0, scrollY);
  state.alertSignature = signature;
}

async function fetchJSON(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

async function refresh() {
  if (state.paused) return;
  const failures = [];
  const load = async (name, url, render) => {
    try {
      const payload = await fetchJSON(url);
      render(payload);
    } catch (err) {
      failures.push(`${name}: ${err.message}`);
    }
  };
  const severity = byId("severity-filter").value;
  const suffix = severity ? `?severity=${encodeURIComponent(severity)}` : "";
  let alertsPayload = [];
  await Promise.all([
    load("stats", "/api/stats", (stats) => {
      setText(byId("stat-frames"), stats.frames_processed);
      setText(byId("stat-windows"), stats.windows);
      setText(byId("stat-fps"), Number(stats.frames_per_second || 0).toFixed(2));
      setText(byId("stat-parse-errors"), stats.parse_errors || 0);
      setText(byId("stat-dropped"), stats.dropped || 0);
      setText(byId("run-id"), stats.run_id === null ? "-" : stats.run_id);
      setText(byId("run-started"), stats.run_started_at || "-");
      renderCounts(byId("severity-counts"), stats.alerts_by_severity);
      renderCounts(byId("family-counts"), stats.alerts_by_family);
      state.stats = stats;
    }),
    load("APs", "/api/aps", renderAPs),
    load("alerts", `/api/alerts${suffix}`, (alerts) => {
      alertsPayload = alerts;
      state.alerts = alerts;
    }),
  ]);
  if (state.stats) renderSparkline(state.stats.latest_ml_scores, alertsPayload);
  if (state.alerts) renderAlerts(state.alerts);
  const error = byId("error-state");
  if (failures.length) {
    error.hidden = false;
    setText(error, `Unable to load ${failures.join("; ")}`);
    setText(byId("poll-status"), "Error");
  } else {
    error.hidden = true;
    setText(byId("poll-status"), "Polling");
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