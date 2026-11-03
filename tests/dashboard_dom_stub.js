"use strict";
const fs = require("fs");
const vm = require("vm");
const path = require("path");

class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.attributes = {};
    this.dataset = {};
    this.style = {};
    this.hidden = false;
    this.textContent = "";
    this.className = "";
    this.listeners = {};
    this.parentElement = null;
  }
  append(...nodes) { nodes.forEach((node) => { node.parentElement = this; this.children.push(node); }); }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) { return this.attributes[name]; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    const result = [];
    const match = (node) => {
      if (selector === ".alert-detail" && node.className === "alert-detail") result.push(node);
      if (selector === ".alert-summary" && node.className === "alert-summary") result.push(node);
      if (selector === ".alert" && node.className === "alert") result.push(node);
      node.children.forEach(match);
    };
    match(this);
    return result;
  }
  closest(selector) {
    let node = this;
    while (node) {
      if (selector === ".alert" && node.className === "alert") return node;
      node = node.parentElement;
    }
    return null;
  }
  focus() { global.document.activeElement = this; }
  click() { if (this.listeners.click) this.listeners.click(); }
}

const elements = {};
const ids = ["ml-sparkline", "aps-body", "alerts-list", "empty-state", "error-state", "stat-frames", "stat-windows", "severity-counts", "family-counts", "pause-button", "poll-status", "severity-filter", "run-id", "run-started"];
ids.forEach((id) => { elements[id] = new Element(id === "ml-sparkline" ? "svg" : "div"); });
elements["severity-filter"].value = "";
elements["severity-filter"].addEventListener = function (name, fn) { this.listeners[name] = fn; };

const document = {
  activeElement: null,
  getElementById: (id) => elements[id] || new Element("div"),
  createElement: (tag) => new Element(tag),
  createElementNS: (ns, tag) => new Element(tag),
  createDocumentFragment: () => new Element("fragment"),
};
let fetches = [];
const window = { scrollY: 0, scrollTo() {}, setInterval() { return 1; }, clearInterval() {}, addEventListener() {} };
const context = {
  console, document, window, CSS: { escape: (s) => s },
  fetch: async (url) => ({
    ok: true,
    json: async () => {
      if (url.startsWith("/api/stats")) return { frames_processed: 1, windows: 1, alerts_by_severity: {}, alerts_by_family: {}, latest_ml_scores: fetches.scores, run_id: 1, run_started_at: "now" };
      if (url.startsWith("/api/aps")) return [];
      return fetches.alerts;
    },
  }),
};
vm.createContext(context);
const source = fs.readFileSync(path.join(__dirname, "..", "dashboard", "app.js"), "utf8");
vm.runInContext(source, context);
fetches = { scores: [], alerts: [] };
context.renderSparkline([], []);
if (!elements["ml-sparkline"].children.length) throw new Error("empty sparkline should render a message");
context.renderSparkline([{ timestamp: "2025-01-01T00:00:00Z", score: 0.4 }], []);
if (!elements["ml-sparkline"].children.length) throw new Error("one point should render a message");
context.renderSparkline([
  { timestamp: "2025-01-01T00:00:00Z", score: 0.1 },
  { timestamp: "2025-01-01T00:00:05Z", score: 0.9 },
], []);
if (!elements["ml-sparkline"].children.length) throw new Error("many points should render a line");
const alerts = [{ id: "ALT-1", hit_count: 1, last_seen: "2025-01-01T00:00:10Z", risk_score: 60, severity: "high", family: "evil_twin_rogue_ap", timestamp: "2025-01-01T00:00:00Z", why: "Evidence.", evidence: [], indicators_found: [], indicators_not_found: [] }];
context.renderAlerts(alerts);
const item = elements["alerts-list"].children[0];
item.querySelector(".alert-summary").click();
if (item.querySelector(".alert-detail").hidden) throw new Error("alert should expand");
context.renderAlerts(alerts);
if (elements["alerts-list"].children[0].querySelector(".alert-detail").hidden) throw new Error("expanded state should survive re-render");
console.log("DOM_STUB_TESTS_PASS");