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
    this.dataset = {};
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
const source = fs.readFileSync(process.argv[1], "utf8");
assert.match(source, /const refresh = singleFlight\(/);
const listenersStart = source.indexOf(
  'document.getElementById("log-search").addEventListener'
);
vm.runInContext(source.slice(0, listenersStart), context);
(async () => {
  const guarded = vm.runInContext(`singleFlight(async () => {
    state.testInvocations = (state.testInvocations || 0) + 1;
    await new Promise(resolve => { state.resolveTest = resolve; });
  })`, context);
  const first = guarded();
  const second = guarded();
  assert.equal(first, second, "a second refresh must not overlap");
  await Promise.resolve();
  assert.equal(vm.runInContext("state.testInvocations", context), 1);
  vm.runInContext("state.resolveTest()", context);
  await first;
  const timeline = context.document.getElementById("events");
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
  for (const name of [
    "renderOverview", "renderKpis", "renderStatusGrid", "renderExecutionHistory",
    "renderReadiness", "renderUsage", "renderStaticTools", "renderStaticToolFindings",
    "renderPipeline", "renderFailureGuidance", "renderHypotheses", "renderChains",
    "renderArtifacts", "renderInvocations", "renderArtifactRelations",
    "renderFindingTraces", "renderPinnedOutputs", "updateSelectionLink", "applyReplay"
  ]) vm.runInContext(`${name} = () => {}`, context);
  vm.runInContext("renderDetail({ analysis_id: 'test', artifacts: [] })", context);
  assert.equal(timeline.children.length, 1, "initial detail displays collected events");
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [node, "-e", harness, str(script)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
