"""Smoke contracts for the local read-only dashboard's priority view."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_STATIC = (
    Path(__file__).resolve().parents[3] / "src" / "sastsimi" / "dashboard" / "static"
)


def test_dashboard_has_compact_kpis_grid_progress_and_history() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    for label in (
        "정적 검사 커버리지",
        "가설 검증 진행",
        "TRUE Finding",
        "검증된 PoC",
        "검증 완료 가설",
        "LLM 호출",
        "LLM 토큰",
        "확인된 LLM 비용",
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


def test_outputs_tab_receives_group_data_and_renders_verified_zip_link() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    source = _STATIC / "app.js"
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync(process.argv[1], 'utf8').split(
  'document.getElementById("log-search").addEventListener'
)[0];
const context = { window: { location: { pathname: '/' } }, console };
vm.createContext(context);
vm.runInContext(source, context);
vm.runInContext(`
  globalThis.rendered = null;
  el = (tag, label, className) => ({
    tag, label, className, children: [],
    append(...items) { this.children.push(...items); },
  });
  reportRow = (item) => ({ tag: 'raw', label: item.display_id });
  replace = (_id, rows) => { globalThis.rendered = rows; };
  renderArtifactSubset = () => {};
  renderOutputs({
    artifacts: [], poc_artifact_ids: [], evidence_artifact_ids: [],
    reports: [{display_id:'F-001'}, {display_id:'F-002'}],
    finding_groups: [{
      group_id:'aaa', representative_id:'F-001',
      status:'PROVEN_SAME_FLOW', member_ids:['F-001','F-002'],
      bundle_url:'/api/analyses/analysis/groups/aaa/bundle.zip'
    }]
  });
`, context);
assert.equal(context.rendered.length, 1);
const card = context.rendered[0];
assert.equal(card.className, 'report-group');
assert.ok(card.children.some((item) => item.tag === 'a' &&
  item.href === '/api/analyses/analysis/groups/aaa/bundle.zip'));
assert.ok(card.children.some((item) => String(item.label).includes('제보 허가')));
assert.equal(card.children.filter((item) => item.tag === 'raw').length, 2);
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


def test_dashboard_has_agreed_tabs_summary_and_llm_detail_views() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    for label in (
        "개요",
        "진행",
        "Finding∙검증",
        "Coverage",
        "아티팩트",
        "LLM",
        "PoC∙증거∙보고서",
        "로그",
    ):
        assert label in html
    for label in (
        "TRUE Finding",
        "검증된 PoC",
        "검증 완료 가설",
        "LLM 사용량",
        "응답 결과",
        "시스템 프롬프트",
        "사용자 프롬프트",
        "저장 원문 요청 JSON",
        "저장 원문 응답 JSON",
    ):
        assert label in html
    assert "Raw JSON" not in html


def test_dashboard_fetches_tabs_and_long_llm_content_on_demand() -> None:
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert "/tabs/${tab}?offset=${offset}&limit=${PAGE_SIZE}" in source
    assert "/llm/${encodeURIComponent(item.invocation_id)}" in source
    assert "/event-page?offset=${offset}&limit=${PAGE_SIZE}" in source
    assert "state.tabCache" in source
    assert "version !== state.requestVersion" in source


def test_tab_navigation_is_sticky_and_mobile_analysis_list_is_a_drawer() -> None:
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    assert ".dashboard-tabs" in css
    assert "position:sticky" in css.replace(" ", "")
    assert ".header-summary" in css
    assert ".header-kpi:hover::after" in css
    assert ".header-kpi:focus-visible::after" in css
    assert ".drawer-open #analysis-sidebar" in css
