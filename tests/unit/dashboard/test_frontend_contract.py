"""Smoke contracts for the local read-only dashboard's priority view."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_STATIC = (
    Path(__file__).resolve().parents[3] / "src" / "sastsimi" / "dashboard" / "static"
)


def test_dashboard_has_four_kpi_labels_grid_progress_and_history() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    for label in (
        "정적 검사 커버리지",
        "가설 검증 진행",
        "남은 가설",
        "확정 Finding",
    ):
        assert label in html
    for element_id in (
        "kpi-grid",
        "status-grid",
        "status-page-prev",
        "status-page-next",
        "discovery-progress",
        "verification-progress",
        "execution-history",
    ):
        assert f'id="{element_id}"' in html
    assert 'role="grid"' in html


def test_unknown_ratio_and_single_flight_polling_in_node() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    source = _STATIC / "app.js"
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[1], 'utf8');
const isolated = source.split(
  'document.getElementById("log-search").addEventListener'
)[0];
const context = { window: { location: { pathname: '/' } }, console };
vm.createContext(context);
vm.runInContext(isolated, context);
assert.equal(vm.runInContext('ratioPercent(null, null)', context), null);
assert.equal(vm.runInContext('ratioPercent(0, 0)', context), null);
assert.equal(vm.runInContext('ratioPercent(1, 4)', context), 25);
let calls = 0;
let release;
const gate = new Promise((resolve) => { release = resolve; });
const load = vm.runInContext('singleFlight', context)(async () => {
  calls += 1;
  await gate;
  return calls;
});
const first = load();
const second = load();
assert.equal(first, second);
Promise.resolve().then(async () => {
  assert.equal(calls, 1);
  release();
  await first;
  await load();
  assert.equal(calls, 2);
}).catch((error) => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run(
        [node, "-e", script, str(source)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_status_grid_is_paged_and_unknown_is_not_rendered_as_zero() -> None:
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert "status-cells?offset=" in source
    assert "limit=200" in source
    assert "slice(0, 200)" not in source
    assert '"—"' in source
    assert "const refresh = singleFlight(" in source
    assert "state.statusPageOffset !== requestedOffset" in source


def test_priority_view_has_narrow_layout_and_visible_keyboard_focus() -> None:
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    assert "@media (max-width: 1220px)" in css
    assert "@media (max-width: 620px)" in css
    assert ".status-cell:focus-visible" in css
    assert "prefers-reduced-motion" in css
