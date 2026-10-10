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
    document = html + (_STATIC / "app.js").read_text(encoding="utf-8")
    for label in (
        "정적 검사 범위 확인률",
        "가설 검증 진행률",
        "TRUE Finding",
        "검증된 PoC",
        "검증 완료 가설",
        "LLM 호출",
        "LLM 토큰",
        "확인된 LLM 비용",
    ):
        assert label in document
    for element_id in (
        "kpi-grid",
        "status-grid",
        "status-page-prev",
        "status-page-next",
        "progress-summary",
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
assert.equal(vm.runInContext('ratioPercent(24, 24)', context), 100);
assert.equal(vm.runInContext('ratioPercent(2, 4)', context), 50);
assert.equal(vm.runInContext('ratioPercent(0, 4)', context), 0);
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
    assert "@media (max-width: 1120px)" in css
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
    assert "page: String(page), page_size: String(PAGE_SIZE)" in source
    assert "/tabs/${tab}?${parameters}" in source
    assert "/llm/${encodeURIComponent(item.invocation_id)}" in source
    assert "/logs?before=${encodeURIComponent(before)}&limit=${LOG_PAGE_SIZE}" in source
    assert "/logs?after=${encodeURIComponent(after)}&limit=100" in source
    assert "const PAGE_SIZE = 10" in source
    assert "const LOG_PAGE_SIZE = 10" in source
    assert "이전 로그 10개 불러오기" in source
    assert 'aria-current", "page"' in source
    assert "requestController" in source
    assert "state.tabCache" in source
    assert "version !== state.requestVersion" in source
    assert "const MAX_LOG_EVENTS = 500" in source
    assert "const seen = new Set()" in source
    assert "요청 시간이 초과되었습니다." in source
    assert "다시 시도" in source


def test_tab_navigation_is_sticky_and_mobile_analysis_list_is_a_drawer() -> None:
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    assert ".dashboard-tabs" in css
    assert "position:sticky" in css.replace(" ", "")
    assert ".header-summary" in css
    assert ".header-kpi:hover::after" in css
    assert ".header-kpi:focus-visible::after" in css
    assert ".drawer-open #analysis-sidebar" in css
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert "function syncDrawerAccessibility()" in source
    assert 'sidebar.setAttribute("inert", "")' in source


def test_dense_console_uses_tab_summaries_donut_and_master_detail() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    for element_id in (
        "progress-summary",
        "findings-summary",
        "coverage-kpi-summary",
        "artifacts-summary",
        "llm-summary",
        "logs-summary",
        "hypothesis-detail",
    ):
        assert f'id="{element_id}"' in html
    assert "function progressDonut(" in source
    assert 'aria-valuetext", "미확인"' in source
    assert "state.selectedHypothesis" in source
    assert "conic-gradient" in css
    assert ".finding-workspace" in css
    assert ".hypothesis-row.selected" in css
    assert "overflow-x: hidden" not in css


def test_progress_phases_use_accessible_donuts_without_horizontal_bars() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    assert 'class="tab-summary progress-command-summary"' in html
    assert "overall-progress-panel" not in html
    assert "<progress" not in html
    assert "function phaseProgressMetric(" in source
    assert 'phaseProgressMetric("정적 검사 범위 확인률"' in source
    assert 'phaseProgressMetric("가설 검증 진행률"' in source
    assert 'donut.setAttribute?.("aria-label", valueText)' in source
    assert "progress-warning:not(.progress-unknown)" in css
    assert "--color-coverage: #5b8def" in css
    assert "progress-coverage:not(.progress-unknown)" in css
    assert "primary.append(stage, overall)" in source
    assert "@media (max-width: 340px)" in css


def test_demo_preview_shows_three_repositories_with_two_runs_each() -> None:
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert "function demoAnalysisVariants(items)" in source
    assert 'repository: "https://example.invalid/sastsimi-api"' in source
    assert 'repository: "https://example.invalid/partner-portal"' in source
    assert 'repository: "https://example.invalid/legacy-auth-service"' in source
    assert source.count('display_analysis_id: "DEMO-') == 6
    assert "demo_source_id: demoSourceId" in source


def test_analysis_sidebar_groups_repository_runs_and_removes_comparison() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    for removed in (
        "compare-controls",
        "compare-analysis",
        "compare-button",
        "comparison-panel",
        "compare-close",
        "comparison-grid",
    ):
        assert removed not in html
    for removed in (
        "renderComparisonOptions",
        "compareSelectedAnalysis",
        'getElementById("compare-button")',
        'getElementById("compare-close")',
    ):
        assert removed not in source
    for removed in (".compare-controls", ".comparison-grid", ".comparison-card"):
        assert removed not in css
    assert "expandedRepositories: new Set()" in source
    assert "collapsedRepositories: new Set()" in source
    assert "initialHistoryExpansionHandled: false" in source
    assert "function groupAnalyses(items = [])" in source
    assert "function initializeSelectedHistoryExpansion(groups)" in source
    assert (
        "if (selectedHistory) state.expandedRepositories.add(group.key)" not in source
    )
    assert 'toggle.setAttribute("aria-expanded"' in source
    assert 'toggle.setAttribute("aria-controls", historyId)' in source
    assert 'el("button", "최신 실행 보기", "analysis-latest-action")' in source
    assert "analysis-history-row" in source
    assert "analysis-group-shell" in css
    assert ".analysis-current-history" in css


def test_repository_grouping_uses_full_identity_and_stable_latest_sort() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    source = _STATIC / "app.js"
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const context = {
  window: { location: { pathname: '/' } },
  document: {},
  Intl, Date, Number, URLSearchParams, console,
};
vm.createContext(context);
const source = fs.readFileSync(process.argv[1], 'utf8').split(
  'document.getElementById("log-search").addEventListener'
)[0];
vm.runInContext(source, context);
const groups = vm.runInContext(`groupAnalyses([
  {
    analysis_id: 'same-time-first',
    repository: 'https://one.example/shared',
    started_at: '2026-10-01T09:00:00Z',
  },
  {
    analysis_id: 'older-one',
    repository: 'https://one.example/shared',
    started_at: '2026-09-30T09:00:00Z',
  },
  {
    analysis_id: 'same-time-second',
    repository: 'https://two.example/shared',
    started_at: '2026-10-01T09:00:00Z',
  },
  {
    analysis_id: 'fallback-time',
    repository: 'https://two.example/shared',
    last_updated_at: '2026-09-29T09:00:00Z',
  },
  { analysis_id: 'missing-a', repository: null },
  { analysis_id: 'missing-b', repository: null }
]).map((group) => ({
  key: group.key,
  ids: group.items.map((entry) => entry.item.analysis_id),
}))`, context);
assert.deepEqual(JSON.parse(JSON.stringify(groups)), [
  { key: 'https://one.example/shared', ids: ['same-time-first', 'older-one'] },
  { key: 'https://two.example/shared', ids: ['same-time-second', 'fallback-time'] },
  { key: 'analysis:missing-a', ids: ['missing-a'] },
  { key: 'analysis:missing-b', ids: ['missing-b'] },
]);
const expansion = vm.runInContext(`(() => {
  state.selected = 'older-one';
  const grouped = groupAnalyses([
    {
      analysis_id: 'latest-one',
      repository: 'https://one.example/shared',
      started_at: '2026-10-01T09:00:00Z',
    },
    {
      analysis_id: 'older-one',
      repository: 'https://one.example/shared',
      started_at: '2026-09-30T09:00:00Z',
    }
  ]);
  initializeSelectedHistoryExpansion(grouped);
  const initiallyExpanded = state.expandedRepositories.has(
    'https://one.example/shared'
  );
  state.expandedRepositories.delete('https://one.example/shared');
  state.collapsedRepositories.add('https://one.example/shared');
  state.initialHistoryExpansionHandled = false;
  initializeSelectedHistoryExpansion(grouped);
  return {
    initiallyExpanded,
    remainsCollapsed: !state.expandedRepositories.has(
      'https://one.example/shared'
    ),
    manuallyCollapsed: state.collapsedRepositories.has(
      'https://one.example/shared'
    ),
    handled: state.initialHistoryExpansionHandled,
  };
})()`, context);
assert.deepEqual(JSON.parse(JSON.stringify(expansion)), {
  initiallyExpanded: true,
  remainsCollapsed: true,
  manuallyCollapsed: true,
  handled: true,
});
"""
    result = subprocess.run(
        [node, "-e", script, str(source)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_partial_and_paused_runtime_statuses_are_described_in_history() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    source = _STATIC / "app.js"
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const context = {
  window: { location: { pathname: '/' } },
  document: { createElement: (tag) => ({ tag, textContent: '', className: '' }) },
  Intl, Date, Number, console,
};
vm.createContext(context);
const source = fs.readFileSync(process.argv[1], 'utf8').split(
  'document.getElementById("log-search").addEventListener'
)[0];
vm.runInContext(source, context);
const partial = vm.runInContext("badge('PARTIAL')", context);
const paused = vm.runInContext("badge('PAUSED')", context);
assert.equal(partial.textContent, '부분 분석');
assert.equal(partial.className, 'badge status-partial');
assert.equal(paused.textContent, '일시 중단');
assert.equal(paused.className, 'badge status-paused');
assert.equal(vm.runInContext(`analysisKey({
  status: 'PARTIAL', confirmed_finding_count: 2
})`, context), '미검증 범위 남음');
assert.equal(vm.runInContext(`analysisKey({
  status: 'PAUSED', current_stage: 'STATIC_ANALYSIS'
})`, context), '재개 필요');
"""
    result = subprocess.run(
        [node, "-e", script, str(source)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    css = (_STATIC / "app.css").read_text(encoding="utf-8")
    assert ".status-partial" in css
    assert ".status-paused" in css


def test_phase_progress_renders_zero_and_unknown_truthfully() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")
    source = _STATIC / "app.js"
    script = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const nodes = new Map();
class Element {
  constructor(tag = 'div') {
    this.tag = tag; this.children = []; this.textContent = ''; this.attrs = {};
    this.style = {
      values: {},
      setProperty: (key, value) => { this.style.values[key] = value; },
    };
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attrs[key] = String(value); }
}
const document = {
  createElement(tag) { return new Element(tag); },
  getElementById(id) {
    if (!nodes.has(id)) nodes.set(id, new Element());
    return nodes.get(id);
  },
};
const context = {
  window: { location: { pathname: '/' } },
  document, Intl, Date, Number, console,
};
vm.createContext(context);
const source = fs.readFileSync(process.argv[1], 'utf8').split(
  'document.getElementById("log-search").addEventListener'
)[0];
vm.runInContext(source, context);
const text = (node) => [node.textContent, ...node.children.map(text)].join(' ');
const zero = vm.runInContext(`phaseProgressMetric(
  '정적 검사 범위 확인률', ratioPercent(0, 4), 0, 4, 'coverage'
)`, context);
const zeroDonut = zero.children[1];
assert.match(text(zero), /0%/); assert.match(text(zero), /0 \/ 4/);
assert.equal(zeroDonut.attrs['aria-valuenow'], '0');
assert.equal(zeroDonut.attrs['aria-label'], '정적 검사 범위 확인률 0%, 4개 중 0개');
const unknown = vm.runInContext(`phaseProgressMetric(
  '가설 검증 진행률', ratioPercent(null, null), null, null, 'warning'
)`, context);
const unknownDonut = unknown.children[1];
assert.match(text(unknown), /—/); assert.doesNotMatch(text(unknown), /0%/);
assert.equal(unknownDonut.attrs['aria-valuetext'], '미확인');
assert.equal(unknownDonut.style.values['--progress'], '0');
"""
    result = subprocess.run(
        [node, "-e", script, str(source)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_tab_hashes_do_not_collide_with_content_element_ids() -> None:
    html = (_STATIC / "index.html").read_text(encoding="utf-8")
    for tab in (
        "overview",
        "progress",
        "findings",
        "coverage",
        "artifacts",
        "llm",
        "outputs",
        "logs",
    ):
        assert f'id="{tab}"' not in html


def test_reserved_demo_repository_keeps_demo_banner_contract() -> None:
    source = (_STATIC / "app.js").read_text(encoding="utf-8")
    assert 'includes("example.invalid")' in source
