"""Candidate and file-scope disclosure in the dashboard."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def test_candidate_and_scope_status_are_visible_and_paginated() -> None:
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
const detail = {
  analysis_id: "analysis-1", display_analysis_id: "A-001",
  status: "PAUSED", progress_percent: 65, current_stage: "HYPOTHESIS_DONE",
  candidate_total_count: 4,
  candidate_decision_counts: {
    INCLUDE: 1, EXCLUDE: 1, UNDECIDED: 1, PENDING: 1, ERROR: 0,
  },
  deep_analysis_running_count: 1, deep_analysis_completed_count: 1,
  deep_analysis_pending_count: 1, deep_analysis_error_count: 0,
  hypothesis_count: 1, finding_count: 0,
  resume_action: "INCREASE_BUDGET_AND_RESUME",
  static_disposition: "PARTIAL", static_coverage_expected: 4,
  static_coverage_verified: 3, static_coverage_gap_count: 1,
  static_coverage_unsupported_count: 0, static_coverage_digest: "digest-1",
  static_unavailable_file_count: 2,
  static_unavailable_file_preview: [
    { path: "src/no_scan.py", reason: "OPENGREP_EXECUTION_FAILED" },
  ],
  static_unavailable_reason_counts: { OPENGREP_EXECUTION_FAILED: 2 },
  static_excluded_test_file_count: 2,
  static_excluded_test_file_preview: [
    { path: "tests/test_auth.py", reason: "test_directory" },
  ],
  static_excluded_test_reason_counts: { test_directory: 2 },
  static_out_of_scope_product_count: 1,
  static_out_of_scope_product_preview: [
    { path: "web/app.ts", reason: "non_python_product_source" },
  ],
  static_out_of_scope_reason_counts: { non_python_product_source: 1 },
};
vm.runInContext(
  "state.detail = globalThis.detail; renderOverview(state.detail)",
  Object.assign(context, { detail })
);
const text = (item) => [item.textContent, ...item.children.map(text)].join(" ");
let shown = text(nodes.get("overview"));
for (const expected of [
  "수집 후보", "4", "INCLUDE 1", "EXCLUDE 1", "UNDECIDED 1",
  "PENDING 1", "ERROR 0", "심층 분석", "가설", "Finding",
  "테스트 제외 2개", "tests/test_auth.py", "test_directory",
  "범위 밖 제품 코드 1개", "web/app.ts", "non_python_product_source",
  "검증되지 않은 제품 파일 2개", "src/no_scan.py", "OPENGREP_EXECUTION_FAILED",
  "예산 한도", "resume",
]) {
  assert.ok(shown.includes(expected), `missing ${expected}: ${shown}`);
}
const ledgers = [];
const collectLedgers = (item) => {
  if (item.className === "coverage-ledger") ledgers.push(item);
  for (const child of item.children) collectLedgers(child);
};
collectLedgers(nodes.get("overview"));
const testsLedger = ledgers.find((item) => text(item).includes("테스트 제외"));
assert.ok(testsLedger);
const unavailableLedger = ledgers.find(
  (item) => text(item).includes("검증되지 않은 제품 파일")
);
assert.ok(unavailableLedger);
const open = testsLedger.children.at(-1).children.at(-1);
const task = open.listeners.click();
const request = pending.at(-1);
assert.equal(
  request.url,
  "/api/analyses/A-001/static-coverage?kind=excluded_tests&offset=0&limit=100"
);
request.resolve({
  ok: true,
  json: async () => ({
    kind: "excluded_tests", total: 2, offset: 0,
    coverage_digest: "digest-1",
    items: [{ path: "tests/test_other.py", reason: "test_directory" }],
  }),
});
const unavailableOpen = unavailableLedger.children.at(-1).children.at(-1);
const unavailableTask = unavailableOpen.listeners.click();
const unavailableRequest = pending.at(-1);
assert.equal(
  unavailableRequest.url,
  "/api/analyses/A-001/static-coverage?kind=unavailable&offset=0&limit=100"
);
unavailableRequest.resolve({
  ok: true,
  json: async () => ({
    kind: "unavailable", total: 2, offset: 0,
    coverage_digest: "digest-1",
    items: [{ path: "src/other.py", reason: "OPENGREP_EXECUTION_FAILED" }],
  }),
});
Promise.all([task, unavailableTask]).then(() => {
  shown = text(nodes.get("overview"));
  assert.ok(
    shown.includes("tests/test_other.py"),
    "loaded exclusion ledger is visible"
  );
  detail.resume_action = "CHECK_USAGE_TELEMETRY";
  vm.runInContext("renderOverview(state.detail)", context);
  shown = text(nodes.get("overview"));
  assert.ok(shown.includes("사용량 정보가 없어"), shown);
  assert.ok(!shown.includes("예산 한도로"), shown);
  detail.resume_action = "RESUME_INTERRUPTED";
  detail.error_code = "INTERRUPTED_RESUME_REQUIRED";
  vm.runInContext("renderOverview(state.detail)", context);
  shown = text(nodes.get("overview"));
  assert.ok(shown.includes("INTERRUPTED_RESUME_REQUIRED"), shown);
  assert.ok(shown.includes("sastsimi resume A-001"), shown);
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
