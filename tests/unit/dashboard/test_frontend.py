"""Small DOM-free checks for dashboard refresh behavior."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_refresh_does_not_overlap_and_log_scroll_is_user_controlled() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    script = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "sastsimi"
        / "dashboard"
        / "static"
        / "app.js"
    )
    harness = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const pending = [];
const nodes = new Map();
class Element {
  constructor() {
    this.classList = { add() {}, remove() {}, toggle() {} };
    this.children = [];
    this.style = {};
    this.value = "";
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 0;
  }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  addEventListener() {}
  setAttribute() {}
}
const context = {
  window: {
    location: { pathname: "/" },
    history: { replaceState() {} },
    setInterval() {},
  },
  document: {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, new Element());
      return nodes.get(id);
    },
    createElement() { return new Element(); },
    createDocumentFragment() { return new Element(); },
  },
  fetch(url) {
    return new Promise((resolve) => pending.push({ url, resolve }));
  },
  URLSearchParams, Intl, Date, Promise, encodeURIComponent, decodeURIComponent,
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), context);
assert.equal(pending.length, 1);
vm.runInContext("refresh()", context);
assert.equal(pending.length, 1, "a second refresh must not overlap");
pending.shift().resolve({ ok: true, json: async () => [] });
setImmediate(() => {
  assert.equal(vm.runInContext("refreshInFlight", context), false);
  const timeline = nodes.get("events");
  timeline.scrollHeight = 400;
  timeline.clientHeight = 100;
  timeline.scrollTop = 100;
  vm.runInContext(`state.events = [{
    stage: "STATIC_DONE", agent_role: "Static", summary_ko: "완료",
    status: "SUCCEEDED", elapsed_ms: 1
  }]; renderEvents()`, context);
  assert.equal(timeline.scrollTop, 100, "reading older logs keeps scroll position");
  timeline.scrollTop = 295;
  vm.runInContext("renderEvents()", context);
  assert.equal(timeline.scrollTop, 400, "tail followers see new logs");
});
"""
    result = subprocess.run(
        [node, "-e", harness, str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def test_coverage_page_repaints_for_internal_analysis_id_route() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not available")
    script = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "sastsimi"
        / "dashboard"
        / "static"
        / "app.js"
    )
    harness = r"""
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const pending = [];
const nodes = new Map();
class Element {
  constructor() {
    this.children = [];
    this.listeners = {};
    this.textContent = "";
    this.className = "";
    this.style = {};
    this.classList = { add() {}, remove() {}, toggle() {} };
  }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  addEventListener(name, handler) { this.listeners[name] = handler; }
}
const context = {
  window: { location: { pathname: "/analyses/analysis-1" }, setInterval() {} },
  document: {
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, new Element());
      return nodes.get(id);
    },
    createElement() { return new Element(); },
    createDocumentFragment() { return new Element(); },
  },
  fetch(url) { return new Promise((resolve) => pending.push({ url, resolve })); },
  URLSearchParams, Intl, Date, Promise, encodeURIComponent, decodeURIComponent,
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), context);
vm.runInContext(`state.detail = {
  analysis_id: "analysis-1", display_analysis_id: "A-001", status: "PARTIAL",
  progress_percent: 50, static_disposition: "PARTIAL",
  static_coverage_expected: 2, static_coverage_verified: 1,
  static_coverage_gap_count: 0, static_coverage_unsupported_count: 1,
  static_coverage_digest: "digest-1"
}`, context);
const sections = vm.runInContext("staticCoverageNodes(state.detail)", context);
const ledger = sections.find((item) => item.className === "coverage-ledger");
assert.ok(ledger);
const open = ledger.children.at(-1).children.at(-1);
const task = open.listeners.click();
const request = pending.at(-1);
assert.equal(
  request.url,
  "/api/analyses/A-001/static-coverage?kind=unsupported&offset=0&limit=100"
);
request.resolve({
  ok: true,
  json: async () => ({
    kind: "unsupported", total: 1, offset: 0,
    coverage_digest: "digest-1",
    items: [{ path: "tools/launcher", reason: "unsupported_extension" }],
  }),
});
task.then(() => {
  const overview = nodes.get("overview");
  const text = (item) => [item.textContent, ...item.children.map(text)].join(" ");
  assert.ok(
    overview && text(overview).includes("tools/launcher"),
    "loaded ledger must appear in the overview"
  );
}).catch((error) => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [node, "-e", harness, str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
