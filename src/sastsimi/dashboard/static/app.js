const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const TAB_NAMES = ["overview", "progress", "findings", "coverage", "artifacts", "llm", "outputs", "logs"];
const PAGE_SIZE = 50;
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null,
  analyses: [], shell: null, activeTab: "overview", tabCache: new Map(),
  tabOffsets: { findings: 0, artifacts: 0, llm: 0, logs: 0 },
  statusPage: null, statusPageOffset: 0, requestVersion: 0,
  artifactMap: new Map(), selectedArtifacts: new Set(), selectedReports: new Set(),
  pinnedFinding: null, llmDetail: null, llmView: "response", presentation: false,
  detail: null,
  coveragePages: { gaps: null, unavailable: null, unsupported: null, excluded_tests: null, out_of_scope: null },
  replay: { active: false, index: 0, timer: null },
};

function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function selectAll(selector) { return typeof document.querySelectorAll === "function" ? document.querySelectorAll(selector) : []; }
function selectOne(selector) { return typeof document.querySelector === "function" ? document.querySelector(selector) : null; }
function replace(id, nodes) { document.getElementById(id).replaceChildren(...nodes); }
function empty(message) { return [el("div", message, "empty")]; }
function knownCount(value) { return Number.isInteger(value) && value >= 0 ? value.toLocaleString("ko-KR") : "—"; }
function formatNumber(value) { return Number(value || 0).toLocaleString("ko-KR"); }
function formatTime(value) { if (!value) return "—"; return new Intl.DateTimeFormat("ko-KR", { dateStyle: "short", timeStyle: "medium" }).format(new Date(value)); }
function formatDuration(value) { if (value == null) return "—"; return value < 1000 ? `${value}ms` : `${(value / 1000).toFixed(1)}초`; }
function ratioPercent(done, total) { if (!Number.isInteger(done) || !Number.isInteger(total) || total <= 0) return null; return Math.max(0, Math.min(100, Math.round(done / total * 100))); }
function pageLabel(page, noun = "개") { if (!page) return ""; if (!page.total) return `0${noun}`; return `${page.offset + 1}–${page.offset + page.items.length} / ${page.total}`; }
function badge(status) { return el("span", statusLabel(status), `badge status-${String(status || "unknown").toLowerCase()}`); }
function singleFlight(task) { let active = null; return (...args) => { if (active) return active; active = Promise.resolve(task(...args)).finally(() => { active = null; }); return active; }; }
async function getJson(url) { const response = await fetch(url, { cache: "no-store" }); if (!response.ok) throw new Error(`요청 실패 (${response.status})`); return response.json(); }
function pinKey(id) { return `sastsimi.dashboard.pin.${id}`; }
function readPinnedFinding(id) { try { return localStorage.getItem(pinKey(id)); } catch (_) { return null; } }
function writePinnedFinding(id, value) { try { if (value) localStorage.setItem(pinKey(id), value); else localStorage.removeItem(pinKey(id)); } catch (_) { /* optional */ } }
function repositoryName(value) { if (!value) return null; const clean = value.replace(/[\\/]$/, "").replace(/\.git$/, ""); return clean.split(/[\\/]/).filter(Boolean).at(-1) || null; }

function statusLabel(status) {
  return ({ RUNNING: "분석 중", COMPLETE: "완료", SUCCEEDED: "완료", FAILED: "실패", BLOCKED: "차단", PENDING: "대기" })[status] || status || "상태 미확인";
}

function analysisButton(item) {
  const button = el("button", undefined, `analysis-card analysis-${String(item.status).toLowerCase()}`);
  const routeId = item.display_analysis_id || item.analysis_id;
  if ([item.analysis_id, routeId].includes(state.selected)) button.classList.add("selected");
  button.append(el("strong", repositoryName(item.repository) || routeId, "analysis-repository"));
  if (item.repository) button.append(el("div", item.repository, "meta truncate"));
  button.append(el("div", `분석 ${routeId}`, "mono meta"));
  const row = el("div", undefined, "status-row"); row.append(badge(item.status), el("span", formatTime(item.started_at || item.last_updated_at), "meta")); button.append(row);
  let key = "—";
  if (item.status === "RUNNING") key = `진행 ${item.progress_percent}%`;
  else if (["COMPLETE", "SUCCEEDED"].includes(item.status)) key = `확정 Finding ${knownCount(item.confirmed_finding_count)}`;
  else if (["FAILED", "BLOCKED"].includes(item.status)) key = `실패 단계 ${item.failed_stage || item.current_stage || "—"}`;
  button.append(el("div", key, "analysis-key"));
  if (item.percentage_kind === "known_checkpoint_fraction") button.append(el("div", "현재 알려진 checkpoint 비율", "meta"));
  button.addEventListener("click", () => selectAnalysis(routeId));
  return button;
}

function selectAnalysis(id) {
  if (state.selected === id) { closeDrawer(); return; }
  state.selected = id; state.shell = null; state.tabCache.clear(); state.statusPage = null; state.statusPageOffset = 0; state.requestVersion += 1;
  state.selectedArtifacts.clear(); state.selectedReports.clear(); state.pinnedFinding = null; state.llmDetail = null; state.artifactMap.clear(); stopReplay();
  window.history?.replaceState?.({}, "", `/analyses/${encodeURIComponent(id)}`); closeDrawer(); refresh();
}

function renderSummary(shell) {
  const kpis = shell?.kpis || {};
  document.getElementById("summary-status").textContent = shell ? `${statusLabel(shell.status)} · ${shell.current_stage}` : "—";
  document.getElementById("summary-true-findings").textContent = knownCount(kpis.confirmed_findings);
  document.getElementById("summary-validated-poc").textContent = knownCount(shell?.validated_poc_count);
  document.getElementById("summary-verified-hypotheses").textContent = kpis.verification_total == null ? "—" : `${knownCount(kpis.verification_done)} / ${knownCount(kpis.verification_total)}`;
  document.getElementById("summary-llm-calls").textContent = shell ? knownCount(shell.llm_attempt_count) : "—";
  document.getElementById("summary-llm-tokens").textContent = shell?.llm_token_usage_known ? formatNumber((shell.llm_input_tokens || 0) + (shell.llm_output_tokens || 0)) : "—";
  document.getElementById("summary-llm-cost").textContent = shell?.llm_cost_minor_units == null ? "—" : `${shell.llm_cost_minor_units}¢`;
  const usageNotes = [];
  if (shell?.llm_unrecorded_in_flight_codex_calls) usageNotes.push(`진행·종료 미확인 Codex 호출 ${shell.llm_unrecorded_in_flight_codex_calls}건`);
  if (shell?.llm_unknown_token_calls) usageNotes.push(`토큰 미확인 호출 ${shell.llm_unknown_token_calls}건`);
  if (shell?.on_demand_possible) usageNotes.push("추가 사용량 가능");
  else if (shell?.llm_unknown_cost_calls) usageNotes.push(`비용 미제공 ${shell.llm_unknown_cost_calls}건`);
  document.getElementById("summary-usage-note").textContent = usageNotes.join(" · ");
}

function renderOverview(shell) {
  if (!shell) { replace("overview", empty("분석을 선택하세요.")); return; }
  state.detail = shell;
  const box = el("div"); const heading = el("div", undefined, "panel-heading"), headingText = el("div", undefined); headingText.append(el("p", repositoryName(shell.repository) || "저장소 정보 없음", "eyebrow"), el("h2", shell.display_analysis_id || shell.analysis_id)); heading.append(headingText, badge(shell.status)); box.append(heading);
  box.append(el("div", shell.repository || "저장소 정보 없음", "repository mono"));
  const metrics = el("div", undefined, "metric-grid");
  [["현재 단계", shell.current_stage], ["진행률", `${shell.progress_percent}%`], ["Commit", shell.commit_id || "—"], ["실행 프로필", shell.profile_ref || "—"], ["Provider / 모델", [shell.provider, shell.model].filter(Boolean).join(" / ") || "—"], ["시작", formatTime(shell.started_at)], ["종료", shell.finished_at ? formatTime(shell.finished_at) : "진행 중"], ["마지막 갱신", formatTime(shell.last_updated_at)]].forEach(([label, value]) => { const metric = el("div", undefined, "metric"); metric.append(el("span", label, "meta"), el("strong", value)); metrics.append(metric); });
  box.append(metrics);
  if (shell.stale) box.append(el("div", "30초 넘게 갱신되지 않았습니다. 진행 탭과 로그를 확인하세요.", "warning"));
  if (shell.on_demand_possible) box.append(el("div", "Provider 추가 사용량 과금 가능성이 있습니다.", "warning"));
  const legacyMetrics = [];
  if (shell.candidate_total_count != null) {
    const decisions = shell.candidate_decision_counts || {};
    legacyMetrics.push(["수집 후보", String(shell.candidate_total_count)]);
    legacyMetrics.push(["선별", ["INCLUDE", "EXCLUDE", "UNDECIDED", "PENDING", "ERROR"].map((status) => `${status} ${decisions[status] || 0}`).join(" · ")]);
    legacyMetrics.push(["심층 분석", `진행 ${shell.deep_analysis_running_count || 0} · 완료 ${shell.deep_analysis_completed_count || 0} · 대기 ${shell.deep_analysis_pending_count || 0} · 오류 ${shell.deep_analysis_error_count || 0}`]);
  }
  legacyMetrics.push(["가설", String(shell.hypothesis_count ?? 0)], ["Finding", String(shell.finding_count ?? 0)]);
  if (shell.percentage_kind === "known_checkpoint_fraction") {
    const phases = shell.phase_counts || {};
    for (const [key, label] of [["static", "정적 단계"], ["triage", "후보 선별"], ["candidate_deep", "후보 심층 처리"], ["verification", "가설 검증"]]) {
      const phase = phases[key]; if (Number.isInteger(phase?.completed) && Number.isInteger(phase?.known)) legacyMetrics.push([label, `${phase.completed}/${phase.known}`]);
    }
    const poc = phases.poc; if (Number.isInteger(poc?.attempted) && Number.isInteger(poc?.completed)) legacyMetrics.push(["PoC 시도", `${poc.attempted}건 · 완료 ${poc.completed}건`]);
    const surface = phases.surface;
    if (Number.isInteger(surface?.total)) {
      if (["covered", "uncovered", "insufficient"].every((key) => Number.isInteger(surface[key]))) legacyMetrics.push(["보안 surface", `검토 근거 충족 ${surface.covered}/${surface.total} · 미검토 ${surface.uncovered} · 근거 부족 ${surface.insufficient}`]);
      else if (Number.isInteger(surface.recorded_contexts) && Number.isInteger(surface.recorded_surfaces)) legacyMetrics.push(["보안 surface", `context가 저장된 surface ${surface.recorded_surfaces}/${surface.total}개 · 저장된 context ${surface.recorded_contexts}건 (확장 포함) · coverage 확인 전`]);
      else if (Number.isInteger(surface.recorded_contexts)) legacyMetrics.push(["보안 surface", `저장된 context ${surface.recorded_contexts}건 · 인덱스 ${surface.total}개 · coverage 확인 전`]);
      else legacyMetrics.push(["보안 surface", "coverage 확인 불가"]);
    } else legacyMetrics.push(["보안 surface", "coverage 확인 불가"]);
    box.append(el("div", "현재 알려진 checkpoint 비율이며 비용·시간·저장소 전체 커버리지를 뜻하지 않습니다.", "meta"));
    if ((shell.phase_counts?.surface?.uncovered || 0) > 0 || (shell.phase_counts?.surface?.insufficient || 0) > 0) box.append(el("div", "부분 분석: 보안 surface 검토 범위가 남아 있습니다.", "warning"));
  }
  legacyMetrics.forEach(([label, value]) => { const metric = el("div", undefined, "metric"); metric.append(el("span", label, "meta"), el("strong", value)); metrics.append(metric); });
  staticCoverageNodes(shell).forEach((node) => box.append(node));
  if (shell.status === "PAUSED") {
    const advice = shell.resume_action === "REVALIDATE_POC" ? `이전 PoC 결과 재검증 필요 · sastsimi resume ${shell.display_analysis_id || shell.analysis_id}` : shell.resume_action === "RESUME_INTERRUPTED" ? `실행 중단 감지 (INTERRUPTED_RESUME_REQUIRED) · sastsimi resume ${shell.display_analysis_id || shell.analysis_id}` : shell.resume_action === "CHECK_USAGE_TELEMETRY" ? "사용량 정보가 없어 일시 중단됨 · 공급자 사용량과 한도 설정을 확인하세요." : "예산 한도로 일시 중단됨 · 한도를 늘린 뒤 resume 하세요.";
    box.append(el("div", advice, "warning"));
  }
  const codexCleanupReview = ["CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"].includes(shell.error_code);
  if (shell.status === "BLOCKED" || (shell.status === "FAILED" && codexCleanupReview)) box.append(el("div", codexCleanupReview ? "Codex 호출 또는 프로세스 정리 상태를 확인할 수 없습니다 · 운영자 수동 검토가 필요합니다. 현재 CLI에는 확인 명령이 없어 자동 재개할 수 없습니다." : "실행 오류로 중단됨 · 오류를 확인한 뒤 resume 하세요.", "warning"));
  if (shell.llm_unrecorded_in_flight_codex_calls > 0) box.append(el("div", `진행·종료 미확인 Codex 호출 ${shell.llm_unrecorded_in_flight_codex_calls}건 · 실제 사용량과 과금 여부는 미확인`, "warning"));
  const links = el("div", undefined, "actions"); [["진행 자세히", "progress"], ["Finding 확인", "findings"], ["Coverage 확인", "coverage"]].forEach(([label, tab]) => { const link = el("button", label, "small-button"); link.addEventListener("click", () => openTab(tab)); links.append(link); }); box.append(links);
  replace("overview", [box]); document.getElementById("overview").classList.remove("empty");
}

function renderKpis(kpis = {}) {
  [["discovery-progress", ratioPercent(kpis.discovery_done, kpis.discovery_total), kpis.discovery_done, kpis.discovery_total], ["verification-progress", ratioPercent(kpis.verification_done, kpis.verification_total), kpis.verification_done, kpis.verification_total]].forEach(([id, percent, done, total]) => { const progress = document.getElementById(id); const label = document.getElementById(`${id}-label`); if (percent == null) { progress.removeAttribute("value"); label.textContent = "—"; } else { progress.value = percent; label.textContent = `${percent}% · ${knownCount(done)}/${knownCount(total)}`; } });
}

function renderReadiness(items) {
  replace("readiness", items?.length ? items.map((item) => { const card = el("article", undefined, "readiness-card"); const row = el("div", undefined, "status-row"); row.append(el("strong", item.label_ko), badge(item.status)); card.append(row, el("p", item.detail_ko, "meta")); return card; }) : empty("저장된 준비 상태가 없습니다."));
}

function renderStatusGrid(page) {
  const grid = document.getElementById("status-grid"), label = document.getElementById("status-page-label");
  if (!page) { grid.replaceChildren(...empty("상태를 불러오는 중입니다.")); return; }
  document.getElementById("status-grid-count").textContent = `가설 ${knownCount(page.total)}개`;
  label.textContent = page.total ? `${page.offset + 1}–${page.offset + page.items.length} / ${page.total}` : "가설 0개";
  document.getElementById("status-page-prev").disabled = page.offset === 0; document.getElementById("status-page-next").disabled = page.offset + page.items.length >= page.total;
  grid.replaceChildren(...(page.items.length ? page.items.map((item, index) => { const button = el("button", String(page.offset + index + 1), `status-cell status-${item.status.toLowerCase()}`); button.title = `${item.label_ko} · ${item.status}`; button.addEventListener("click", async () => { await openTab("findings"); document.getElementById(`hypothesis-${item.id}`)?.scrollIntoView({ behavior: "smooth", block: "center" }); }); return button; }) : empty("생성된 가설이 없습니다.")));
}

function metricSummary(metrics = {}) { const labels = { expected: "대상", processed: "처리", verified: "검증", remaining: "남음", artifacts: "산출물", candidates: "후보", findings: "확정" }; return Object.entries(metrics).filter(([key, value]) => labels[key] && Number.isInteger(value)).map(([key, value]) => `${labels[key]} ${formatNumber(value)}`).join(" · "); }
function renderExecutionHistory(events = []) { const body = document.getElementById("execution-history"); body.replaceChildren(...(events.length ? [...events].reverse().map((item) => { const row = el("tr"); row.append(el("td", formatTime(item.started_at)), el("td", [item.stage, item.substage || item.tool_name].filter(Boolean).join(" / "), "mono"), el("td", item.summary_ko), el("td", metricSummary(item.metrics) || "—")); const status = el("td"); status.append(badge(item.status)); row.append(status); return row; }) : [(() => { const row = el("tr"); const cell = el("td", "기록된 실행 이벤트가 없습니다.", "empty"); cell.colSpan = 5; row.append(cell); return row; })()])); }
function renderPipeline(items = []) { replace("pipeline", items.length ? items.map((item) => { const card = el("article", undefined, `stage stage-${item.status.toLowerCase()}`); card.dataset.updatedAt = item.updated_at || ""; card.append(el("strong", item.label_ko), el("div", item.stage, "mono meta")); const row = el("div", undefined, "status-row"); row.append(badge(item.status), el("span", item.agent_role, "meta")); card.append(row); if (item.error_code) card.append(el("div", item.error_code, "error mono")); return card; }) : empty("파이프라인 상태가 없습니다.")); }
function renderFailureGuidance(items = []) { const failed = items.filter((item) => item.error_code || ["FAILED", "BLOCKED"].includes(item.status)); replace("failure-guidance", failed.length ? failed.map((item) => { const card = el("article", undefined, "card failure-card"); card.append(el("strong", item.label_ko), badge(item.status)); if (item.error_code) card.append(el("div", item.error_code, "error mono")); card.append(el("p", item.guidance_ko || "로그에서 실패 원인과 복구 기록을 확인하세요.", "meta")); return card; }) : empty("현재 저장된 실패·차단 단계가 없습니다.")); }

function renderHypotheses(page) {
  const items = page?.items || []; document.getElementById("hypothesis-page-label").textContent = pageLabel(page, "개");
  replace("hypotheses", items.length ? items.map((item) => { const card = el("article", undefined, "card"); card.id = `hypothesis-${item.hypothesis_id}`; const row = el("div", undefined, "status-row"); row.append(el("strong", item.title || item.hypothesis_id), badge(item.verdict || item.status)); card.append(row, el("div", `${item.hypothesis_id} · ${item.current_stage}`, "mono meta")); if (item.vulnerability_type) card.append(el("div", item.vulnerability_type, "hypothesis-type")); if (item.validated_poc) { const link = el("button", "검증된 PoC 보기", "text-button success"); link.addEventListener("click", () => openTab("outputs")); card.append(link); } card.append(el("div", `Technical Gate ${item.disposition || "미완료"} · Scope Gate ${item.scope_status || "UNCERTAIN"}`, "meta")); if (item.scope_source_url) { const link = el("a", `정책 출처 · ${item.scope_source_revision || "개정 미확인"}`); link.href = item.scope_source_url; link.target = "_blank"; link.rel = "noreferrer"; card.append(link); } Object.entries(item.scope_axes || {}).forEach(([axis, value]) => card.append(el("div", `${axis}: ${value.status} · ${value.reason}`, "meta"))); if (item.error_code) card.append(el("div", item.error_code, "error mono")); return card; }) : empty("생성된 가설이 없습니다."));
  document.getElementById("hypothesis-prev").disabled = !page || page.offset === 0; document.getElementById("hypothesis-next").disabled = !page || page.offset + items.length >= page.total;
}
function renderChains(items = []) { replace("chains", items.length ? items.map((item) => { const card = el("article", undefined, "chain-flow"); card.append(el("strong", item.title || item.hypothesis_id)); const flow = el("div", undefined, "flow-lane"); [["SOURCE", item.source || "미기록", "flow-source"], [item.vulnerability_type || "HYPOTHESIS", item.summary || item.title || item.hypothesis_id, "flow-finding"], ["SINK", item.sink || "미기록", "flow-sink"]].forEach(([label, value, klass], index) => { if (index) flow.append(el("span", "→", "flow-arrow")); const node = el("div", undefined, `flow-node ${klass}`); node.append(el("span", label, "flow-label"), el("strong", value)); flow.append(node); }); card.append(flow); return card; }) : empty("시각화할 가설이 없습니다.")); }
function renderFindingTraces(items = []) { document.getElementById("finding-pin-status").textContent = state.pinnedFinding ? `${state.pinnedFinding} 고정됨` : "Finding을 고정할 수 있습니다."; replace("finding-traces", items.length ? items.map((item) => { const card = el("article", undefined, `card finding-trace${state.pinnedFinding === item.display_id ? " pinned" : ""}`); const row = el("div", undefined, "status-row"); row.append(el("strong", `${item.display_id} · ${item.title || item.hypothesis_id || "연결 정보 없음"}`), badge(item.verdict || "RECORDED")); card.append(row); const pin = el("button", state.pinnedFinding === item.display_id ? "고정 해제" : "발표 Finding 고정", "small-button"); pin.addEventListener("click", () => { state.pinnedFinding = state.pinnedFinding === item.display_id ? null : item.display_id; writePinnedFinding(state.shell.analysis_id, state.pinnedFinding); renderFindingTraces(items); }); card.append(pin, el("div", `Source ${item.source || "—"} → Sink ${item.sink || "—"} · PoC ${item.validated_poc ? "검증됨" : "없음"}`, "meta")); const output = el("button", "최종 파일 보기", "text-button"); output.addEventListener("click", () => openTab("outputs")); card.append(output); return card; }) : empty("Finding 관계가 아직 저장되지 않았습니다.")); }

function staticCoverageNodes(detail) {
  if (detail.static_coverage_expected == null || detail.static_coverage_verified == null) return [el("div", "정적 검사 커버리지: — (검증된 기록 없음)", "empty")];
  const nodes = [el("div", `검증 ${detail.static_coverage_verified}/${detail.static_coverage_expected} · 미검증 ${detail.static_coverage_gap_count ?? "—"}`, "coverage-lead")];
  const engines = Object.entries(detail.static_coverage_engines || {}).map(([name, count]) => `${name} ${count}`).join(" · "); if (engines) nodes.push(el("div", `검증 엔진: ${engines}`, "meta"));
  if (detail.static_ast_parse_error_count != null) nodes.push(el("div", `Python AST 파싱 오류 ${detail.static_ast_parse_error_count} · 사실 수 제한 ${detail.static_ast_truncated ? "도달" : "미도달"}`, "meta"));
  if (detail.static_coverage_unsupported?.length) nodes.push(el("div", `규칙 범위 밖: ${detail.static_coverage_unsupported.map(([ext, count]) => `${ext} ${count}개`).join(" · ")}`, "meta"));
  if (detail.static_coverage_gap_preview?.length) { const details = el("details"); details.append(el("summary", `미검증 파일·규칙 보기 (${detail.static_coverage_gap_count}개)`)); detail.static_coverage_gap_preview.forEach((gap) => details.append(el("div", `${gap.path} · ${gap.rule_id} · ${gap.reason}`, "meta"))); nodes.push(details); }
  const scopeGroups = [["검증되지 않은 제품 파일", detail.static_unavailable_file_count, detail.static_unavailable_reason_counts, detail.static_unavailable_file_preview], ["테스트 제외", detail.static_excluded_test_file_count, detail.static_excluded_test_reason_counts, detail.static_excluded_test_file_preview], ["범위 밖 제품 코드", detail.static_out_of_scope_product_count, detail.static_out_of_scope_reason_counts, detail.static_out_of_scope_product_preview]];
  for (const [label, count, reasons, preview] of scopeGroups) { if (count == null) continue; nodes.push(el("div", `${label} ${count}개 (검사 완료 건수에 포함하지 않음)`, "meta")); const reasonText = Object.entries(reasons || {}).map(([reason, total]) => `${reason} ${total}개`).join(" · "); if (reasonText) nodes.push(el("div", `${label} 이유: ${reasonText}`, "meta")); if (preview?.length) { const details = el("details"); details.append(el("summary", `${label} 경로와 이유 보기 (${count}개 중 최대 100개)`)); preview.forEach((item) => details.append(el("div", `${item.path} · ${item.reason}`, "meta"))); nodes.push(details); } }
  const ledgers = [["gaps", detail.static_coverage_gap_count, "미검증 파일·규칙"], ["unavailable", detail.static_unavailable_file_count, "검증되지 않은 제품 파일"], ["unsupported", detail.static_coverage_unsupported_count, "지원되지 않는 파일"], ["excluded_tests", detail.static_excluded_test_file_count, "테스트 제외"], ["out_of_scope", detail.static_out_of_scope_product_count, "범위 밖 제품 코드"]];
  for (const [kind, count, label] of ledgers) {
    if (!count) continue;
    if (state.coveragePages[kind]?.coverage_digest !== detail.static_coverage_digest) state.coveragePages[kind] = null;
    const page = state.coveragePages[kind], section = el("section", undefined, "coverage-ledger"); section.append(el("strong", `${label} 전체 원장 (${count}개)`));
    if (page) { page.items.forEach((item) => section.append(el("div", `${item.path} · ${item.rule_id ? `${item.rule_id} · ` : ""}${item.reason}`, "meta"))); section.append(el("div", `${page.offset + 1}–${page.offset + page.items.length} / ${page.total}`, "meta")); }
    const offset = page?.offset || 0, controls = el("div", undefined, "coverage-controls");
    for (const [buttonLabel, nextOffset, enabled] of [["이전", Math.max(0, offset - 100), Boolean(page && offset > 0)], [page ? "다음" : "목록 열기", page ? offset + 100 : 0, !page || offset + 100 < count]]) { const button = el("button", buttonLabel); button.disabled = !enabled; button.addEventListener("click", async () => { try { const routeId = detail.display_analysis_id || detail.analysis_id; state.coveragePages[kind] = await getJson(`/api/analyses/${encodeURIComponent(routeId)}/static-coverage?kind=${kind}&offset=${nextOffset}&limit=100`); renderOverview(state.detail || detail); } catch (_) { section.append(el("div", "원장 조회 실패", "error")); } }); controls.append(button); }
    section.append(controls); nodes.push(section);
  }
  return nodes;
}
function renderStaticTools(items = []) { replace("static-tools", items.length ? items.map((item) => { const card = el("article", undefined, "tool-card"); card.append(el("strong", item.tool), badge(item.status), el("div", item.finding_count == null ? "결과 수 —" : `결과 ${item.finding_count}건`, "meta")); return card; }) : empty("정적분석 상태가 없습니다.")); }
function renderStaticToolFindings(items = []) { replace("static-tool-findings", items.length ? items.map((item) => { const row = el("div", undefined, `overlap-row${item.overlap ? " overlap" : ""}`); row.append(el("strong", item.location, "mono"), el("span", item.tools.join(" · "), "meta")); if (item.rule_ids.length) row.append(el("div", item.rule_ids.join(" · "), "meta")); return row; }) : empty("교차 비교할 위치가 없습니다.")); }

function artifactButton(item) { const button = el("button", undefined, "artifact-button"); button.append(el("strong", item.label_ko || item.kind), el("div", item.purpose_ko || "저장 아티팩트", "artifact-purpose"), el("div", `${item.media_type} · ${formatNumber(item.size_bytes)} bytes`, "meta"), el("div", `단계 ${item.stages?.join(", ") || "—"} · Agent ${item.agent_roles?.join(", ") || "—"}`, "meta"), el("div", `가설 ${item.hypothesis_ids?.join(", ") || "—"} · 생성 ${formatTime(item.created_at)}`, "mono meta")); button.addEventListener("click", () => showArtifact(item)); return button; }
function selectableArtifact(item) { const row = el("div", undefined, "selectable-row"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selectedArtifacts.has(item.artifact_id); check.addEventListener("change", () => { check.checked ? state.selectedArtifacts.add(item.artifact_id) : state.selectedArtifacts.delete(item.artifact_id); updateSelectionLink(); }); row.append(check, artifactButton(item)); return row; }
function renderArtifacts(page) { const search = document.getElementById("artifact-search").value.trim().toLowerCase(); const items = (page?.items || []).filter((item) => [item.label_ko, item.kind, item.purpose_ko, ...(item.stages || []), ...(item.agent_roles || []), ...(item.hypothesis_ids || [])].filter(Boolean).join(" ").toLowerCase().includes(search)); document.getElementById("artifact-count").textContent = `${pageLabel(page, "개")}${page?.omitted_count ? ` · 최소 ${page.omitted_count}개 미표시` : ""}`; state.artifactMap = new Map((page?.items || []).map((item) => [item.artifact_id, item])); replace("artifacts", items.length ? items.map(selectableArtifact) : empty("조건에 맞는 아티팩트가 없습니다.")); document.getElementById("artifact-prev").disabled = !page || page.offset === 0; document.getElementById("artifact-next").disabled = !page || page.offset + page.items.length >= page.total; }
async function showArtifact(item) { const viewer = document.getElementById("artifact-viewer"); viewer.replaceChildren(el("div", "불러오는 중…", "empty")); try { const payload = await getJson(item.view_url); const toolbar = el("div", undefined, "viewer-toolbar"); toolbar.append(el("strong", item.label_ko || payload.kind)); const actions = el("div", undefined, "actions"); const copy = el("button", "복사", "small-button"); const raw = typeof payload.content === "string" ? payload.content : JSON.stringify(payload.content); const pretty = typeof payload.content === "string" ? payload.content : JSON.stringify(payload.content, null, 2); copy.addEventListener("click", async () => { await navigator.clipboard.writeText(raw); copy.textContent = "복사됨"; }); const download = el("a", "다운로드", "download small-button"); download.href = item.download_url; actions.append(copy, download); toolbar.append(actions); let content = el("pre", pretty, "code-view"); if (payload.rendered_html && payload.media_type === "text/markdown") { content = el("div", undefined, "markdown-content"); content.innerHTML = payload.rendered_html; } viewer.replaceChildren(toolbar, ...(payload.truncated ? [el("p", "미리보기는 1 MiB까지만 표시합니다.", "meta")] : []), content); } catch (error) { viewer.replaceChildren(el("div", String(error), "error")); } }
function renderArtifactRelations(items = []) { replace("artifact-relations", items.length ? items.map((item) => el("div", `${item.source_kind} → ${item.relation} → ${item.target_kind}`, "relation-row mono")) : empty("저장된 아티팩트 관계가 없습니다.")); }

function renderInvocations(page) { const items = page?.items || []; document.getElementById("llm-page-label").textContent = pageLabel(page, "건"); replace("llm-invocations", items.length ? items.map((item) => { const button = el("button", undefined, `invocation-button${state.llmDetail?.invocation?.invocation_id === item.invocation_id ? " selected" : ""}`); const row = el("div", undefined, "status-row"); row.append(el("strong", `${item.agent_role} · ${item.model}`), badge(item.status)); button.append(row, el("div", `${formatTime(item.started_at)} · 시도 ${item.attempt_number || "—"} · 재시도 ${item.retry_count}`, "meta")); if (item.hypothesis_id) button.append(el("div", item.hypothesis_id, "mono meta")); button.addEventListener("click", () => loadInvocation(item)); return button; }) : empty("저장된 LLM 호출이 없습니다.")); document.getElementById("llm-prev").disabled = !page || page.offset === 0; document.getElementById("llm-next").disabled = !page || page.offset + items.length >= page.total; if (items.length && !state.llmDetail) loadInvocation(items.at(-1)); }
async function loadInvocation(item) { const version = state.requestVersion; const detailNode = document.getElementById("llm-detail"); detailNode.classList.remove("empty"); document.getElementById("llm-viewer").textContent = "호출 상세를 불러오는 중…"; try { const detail = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/llm/${encodeURIComponent(item.invocation_id)}`); if (version !== state.requestVersion) return; state.llmDetail = detail; state.llmView = "response"; renderLlmDetail(); renderInvocations(state.tabCache.get(tabCacheKey("llm"))); } catch (error) { document.getElementById("llm-viewer").textContent = String(error); } }
function renderLlmDetail() { const detail = state.llmDetail; if (!detail) return; const item = detail.invocation; const metadata = document.getElementById("llm-metadata"); metadata.replaceChildren(); [["Agent", item.agent_role], ["모델", item.model], ["호출 시각", formatTime(item.started_at)], ["상태", statusLabel(item.status)], ["시도·재시도", `${item.attempt_number || "—"} · ${item.retry_count}`], ["입력·출력 토큰", `${item.input_tokens ?? "—"} · ${item.output_tokens ?? "—"}`], ["연결 가설", item.hypothesis_id || "—"], ["연결 Finding", item.finding_ids?.join(", ") || "—"]].forEach(([label, value]) => { const box = el("div", undefined, "llm-meta-item"); box.append(el("span", label, "meta"), el("strong", value)); metadata.append(box); }); selectAll("[data-llm-view]").forEach((button) => button.setAttribute("aria-selected", String(button.dataset.llmView === state.llmView))); const values = { response: detail.response_result, system: detail.system_prompt, user: detail.user_prompt, "request-json": detail.stored_request_json, "response-json": detail.stored_response_json }; const value = values[state.llmView]; document.getElementById("llm-viewer").textContent = value == null ? "이 호출에는 해당 정보가 별도로 저장되지 않았습니다." : typeof value === "string" ? value : JSON.stringify(value, null, 2); }

function renderArtifactSubset(target, ids, map, message) { const items = (ids || []).map((id) => map.get(id)).filter(Boolean); replace(target, items.length ? items.map(artifactButton) : empty(message)); }
function renderOutputs(data) { const map = new Map((data.artifacts || []).map((item) => [item.artifact_id, item])); state.artifactMap = map; const trace = (data.finding_traces || []).find((item) => item.display_id === state.pinnedFinding); renderArtifactSubset("poc", trace ? trace.poc_artifact_ids : data.poc_artifact_ids, map, "검증된 PoC가 없습니다."); renderArtifactSubset("evidence", trace ? trace.evidence_artifact_ids : data.evidence_artifact_ids, map, "저장된 정적·동적 증거가 없습니다."); renderReports(trace ? data.reports.filter((item) => item.display_id === trace.display_id) : data.reports || [], data.finding_groups || []); }
function reportRow(item) { const row = el("div", undefined, "report-row"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selectedReports.has(item.display_id); check.setAttribute("aria-label", `${item.display_id} ZIP 선택`); check.addEventListener("change", () => { check.checked ? state.selectedReports.add(item.display_id) : state.selectedReports.delete(item.display_id); updateSelectionLink(); }); const ko = el("a", `${item.display_id} 한국어 보기`, "small-button"); ko.href = item.download_url; const koDownload = el("a", "한국어 MD", "download small-button"); koDownload.href = item.download_url; row.append(check, ko, koDownload); if (item.english_available) { const en = el("a", "English 보기", "small-button"); en.href = item.english_view_url; const enDownload = el("a", "English MD", "download small-button"); enDownload.href = item.english_download_url; row.append(en, enDownload); } else row.append(el("span", "영문 미생성", "badge status-waiting")); const labels = { "report_en.md": "영문 보고서", "report_kr.md": "국문 보고서", "poc.sh": "검증 PoC", "poc.py": "검증 PoC", "bundle.zip": "첨부파일 ZIP" }; Object.entries(item.attachment_urls || {}).forEach(([name, url]) => { const attachment = el("a", labels[name] || name, "report-attachment"); attachment.href = url; attachment.download = name.split("/").pop(); row.append(attachment); }); return row; }
function renderReports(items, groups) {
  if (!items.length) { replace("reports", empty("생성된 보고서가 없습니다.")); return; }
  const byId = new Map(items.map((item) => [item.display_id, item]));
  const provenByMember = new Map(), undeterminedByMember = new Map();
  for (const group of groups || []) {
    if (group.status === "GROUPING_UNDETERMINED") {
      for (const id of group.member_ids || []) undeterminedByMember.set(id, group);
      continue;
    }
    if (group.status !== "PROVEN_SAME_FLOW" || group.member_ids?.length < 2 || !group.member_ids.every((id) => byId.has(id))) continue;
    for (const id of group.member_ids) provenByMember.set(id, group);
  }
  const shown = new Set(), rows = [];
  for (const item of items) {
    if (shown.has(item.display_id)) continue;
    const group = provenByMember.get(item.display_id);
    if (!group) {
      const row = reportRow(item);
      if (undeterminedByMember.has(item.display_id)) row.append(el("span", "묶음 미확정 · 별도 원본 Finding", "meta"));
      rows.push(row);
      shown.add(item.display_id);
      continue;
    }
    const card = el("div", undefined, "report-group");
    card.append(
      el("strong", `${group.representative_id} · 동일 검증 경로 ${group.member_ids.length}건`),
      el("div", "원본 Finding·PoC·보고서는 각각 보존됩니다. 그룹화는 제보 허가를 뜻하지 않습니다.", "meta"),
    );
    if (group.bundle_url) {
      const download = el("a", "검증된 그룹 보고서 ZIP", "download small-button");
      download.href = group.bundle_url;
      download.download = `${group.group_id}-group-bundle.zip`;
      card.append(download);
    } else if (group.bundle_unavailable_reason) {
      card.append(el("span", `그룹 보고서 미제공: ${group.bundle_unavailable_reason}`, "meta"));
    }
    for (const id of group.member_ids) {
      card.append(reportRow(byId.get(id)));
      shown.add(id);
    }
    rows.push(card);
  }
  replace("reports", rows);
}
async function showReport(item) { const viewer = document.getElementById("report-viewer"); viewer.replaceChildren(el("div", "불러오는 중…", "empty")); try { const payload = await getJson(item.view_url); const toolbar = el("div", undefined, "viewer-toolbar"); toolbar.append(el("strong", payload.display_id)); const download = el("a", "MD 다운로드", "download small-button"); download.href = item.download_url; toolbar.append(download); const content = el("div", undefined, "markdown-content"); content.innerHTML = payload.rendered_html; viewer.replaceChildren(toolbar, content); } catch (error) { viewer.replaceChildren(el("div", String(error), "error")); } }

function renderEventsPage(page) { state.events = page?.items || []; document.getElementById("log-page-label").textContent = pageLabel(page, "건"); renderEvents(); document.getElementById("log-prev").disabled = !page || page.offset === 0; document.getElementById("log-next").disabled = !page || page.offset + page.items.length >= page.total; }
function renderEvents() { const timeline = document.getElementById("events"); const followTail = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 60; const search = document.getElementById("log-search").value.trim().toLowerCase(), status = document.getElementById("log-status").value; const items = (state.events || []).filter((item) => { const text = [item.stage, item.agent_role, item.summary_ko, item.hypothesis_id, item.error_code, item.tool_name].filter(Boolean).join(" ").toLowerCase(); return (!search || text.includes(search)) && (!status || item.status === status); }); replace("events", items.length ? items.map((item) => { const event = el("article", undefined, `event event-${item.status.toLowerCase()}`); const row = el("div", undefined, "status-row"); row.append(el("strong", item.summary_ko), badge(item.status)); event.append(row, el("div", `${formatTime(item.started_at)} · ${item.stage} · ${item.agent_role} · ${formatDuration(item.elapsed_ms)}`, "meta")); if (item.metrics && Object.keys(item.metrics).length) event.append(el("div", metricSummary(item.metrics), "meta")); if (item.error_code) event.append(el("div", item.error_code, "error mono")); return event; }) : empty("조건에 맞는 로그가 없습니다.")); if (followTail) timeline.scrollTop = timeline.scrollHeight; }

function renderComparisonOptions(items) { const select = document.getElementById("compare-analysis"); const options = items.filter((item) => ![item.analysis_id, item.display_analysis_id].includes(state.selected)).map((item) => { const option = document.createElement("option"); option.value = item.display_analysis_id || item.analysis_id; option.textContent = `${repositoryName(item.repository) || option.value} · ${statusLabel(item.status)}`; return option; }); select.replaceChildren(...options); document.getElementById("compare-button").disabled = !options.length; }
async function compareSelectedAnalysis() { const value = document.getElementById("compare-analysis").value; if (!value || !state.shell) return; const target = document.getElementById("comparison"); target.replaceChildren(el("div", "비교 데이터를 불러오는 중…", "empty")); document.getElementById("comparison-panel").classList.remove("hidden"); try { const other = await getJson(`/api/analyses/${encodeURIComponent(value)}/summary`); const current = state.shell; const fields = [["상태", statusLabel(current.status), statusLabel(other.status)], ["진행률", `${current.progress_percent}%`, `${other.progress_percent}%`], ["Commit", current.commit_id || "—", other.commit_id || "—"], ["TRUE Finding", knownCount(current.kpis.confirmed_findings), knownCount(other.kpis.confirmed_findings)], ["검증 가설", knownCount(current.kpis.verification_done), knownCount(other.kpis.verification_done)], ["LLM 호출", knownCount(current.llm_attempt_count), knownCount(other.llm_attempt_count)]]; replace("comparison", fields.map(([label, left, right]) => { const card = el("div", undefined, `comparison-card${left !== right ? " changed" : ""}`); card.append(el("span", label, "meta"), el("strong", left), el("span", "→"), el("strong", right)); return card; })); } catch (error) { target.replaceChildren(el("div", String(error), "error")); } }

function tabCacheKey(tab) { return `${state.selected}:${tab}:${state.tabOffsets[tab] || 0}`; }
async function loadActiveTab(force = false) { if (!state.selected) return; const tab = state.activeTab, key = tabCacheKey(tab), version = state.requestVersion; let data = !force ? state.tabCache.get(key) : null; try { if (!data) { selectOne(`[data-panel="${tab}"]`)?.classList.add("loading"); const offset = state.tabOffsets[tab] || 0; data = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/tabs/${tab}?offset=${offset}&limit=${PAGE_SIZE}`); if (version !== state.requestVersion) return; state.tabCache.set(key, data); } renderTab(tab, data); } catch (error) { document.getElementById("notice").textContent = `${tab} 데이터를 불러오지 못했습니다: ${error}`; } finally { selectOne(`[data-panel="${tab}"]`)?.classList.remove("loading"); } }
function renderTab(tab, data) { if (tab === "overview") renderReadiness(data.readiness || []); else if (tab === "progress") { renderPipeline(data.pipeline || []); renderFailureGuidance(data.pipeline || []); renderExecutionHistory(data.history || []); renderKpis(state.shell?.kpis); changeStatusPage(state.statusPageOffset); state.events = data.history || []; applyReplay(Math.max(0, state.events.length - 1)); } else if (tab === "findings") { renderHypotheses(data); renderChains(data.items || []); renderFindingTraces(data.finding_traces || []); } else if (tab === "coverage") { replace("coverage-summary", staticCoverageNodes(data)); renderStaticTools(data.static_tools || []); renderStaticToolFindings(data.static_tool_findings || []); } else if (tab === "artifacts") { renderArtifacts(data); renderArtifactRelations(data.relations || []); } else if (tab === "llm") renderInvocations(data); else if (tab === "outputs") renderOutputs(data); else if (tab === "logs") loadLogPage(); }
async function openTab(tab) { if (!TAB_NAMES.includes(tab)) return; state.activeTab = tab; selectAll("[data-tab]").forEach((button) => button.setAttribute("aria-selected", String(button.dataset.tab === tab))); selectAll("[data-panel]").forEach((panel) => { const active = panel.dataset.panel === tab; panel.hidden = !active; panel.classList.toggle("active", active); }); if (window.location.hash !== `#${tab}`) window.history?.replaceState?.({}, "", `${window.location.pathname}#${tab}`); await loadActiveTab(); }
async function changeStatusPage(offset) { if (!state.selected) return; const requestedOffset = Math.max(0, offset); state.statusPageOffset = requestedOffset; try { const page = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/status-cells?offset=${requestedOffset}&limit=200`); if (state.statusPageOffset !== requestedOffset) return; state.statusPage = page; renderStatusGrid(page); } catch (error) { document.getElementById("status-grid-count").textContent = String(error); } }
async function loadLogPage() { const offset = state.tabOffsets.logs || 0; try { const page = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/event-page?offset=${offset}&limit=${PAGE_SIZE}`); renderEventsPage(page); document.getElementById("log-stream-status").textContent = "저장 이벤트 기준"; } catch (error) { replace("events", empty(String(error))); } }
function pageTab(tab, delta) { state.tabOffsets[tab] = Math.max(0, (state.tabOffsets[tab] || 0) + delta); state.tabCache.delete(tabCacheKey(tab)); if (tab === "llm") state.llmDetail = null; loadActiveTab(true); }

function updateSelectionLink() { const link = document.getElementById("selection-download"); if (!state.shell?.bundle_url) { link.classList.add("hidden"); return; } const parameters = new URLSearchParams({ selected: "1" }); state.selectedArtifacts.forEach((id) => parameters.append("artifact", id)); state.selectedReports.forEach((id) => parameters.append("report", id)); if (document.getElementById("include-logs").checked) parameters.set("logs", "1"); link.href = `${state.shell.bundle_url}?${parameters}`; link.textContent = `선택 결과 ZIP 다운로드 (${state.selectedArtifacts.size + state.selectedReports.size}개)`; link.classList.remove("hidden"); document.getElementById("logs-selection").classList.remove("hidden"); }
function updateDownloadLinks(shell) { [["bundle-download", shell?.bundle_url], ["presentation-download", shell?.presentation_bundle_url]].forEach(([id, url]) => { const node = document.getElementById(id); node.href = url || "#"; node.classList.toggle("hidden", !url); }); document.getElementById("logs-download").href = shell?.logs_url || "#"; updateSelectionLink(); }

function replayFrames() { return state.events || []; }
function applyReplay(index) { const frames = replayFrames(), bounded = Math.max(0, Math.min(index, Math.max(0, frames.length - 1))); state.replay.index = bounded; const slider = document.getElementById("replay-slider"); slider.max = String(Math.max(0, frames.length - 1)); slider.value = String(bounded); document.getElementById("replay-status").textContent = frames.length ? `${bounded + 1}/${frames.length} · ${frames[bounded].summary_ko}` : "재생할 저장 이벤트가 없습니다."; }
function stopReplay() { if (state.replay.timer) clearInterval(state.replay.timer); state.replay.timer = null; const button = document.getElementById("replay-toggle"); if (button) button.textContent = "재생"; }
function toggleReplay() { const frames = replayFrames(); if (!frames.length) return; if (state.replay.timer) { stopReplay(); return; } if (state.replay.index >= frames.length - 1) state.replay.index = 0; document.getElementById("replay-toggle").textContent = "일시정지"; state.replay.timer = setInterval(() => { if (state.replay.index >= frames.length - 1) { stopReplay(); return; } applyReplay(state.replay.index + 1); }, 1200); }
function resetReplay() { stopReplay(); applyReplay(Math.max(0, replayFrames().length - 1)); }

function renderDetail(detail) { state.shell = detail; renderSummary(detail); renderOverview(detail); renderKpis(detail.kpis || {}); }
function clearDetail(message) { state.shell = null; state.detail = null; renderSummary(null); replace("overview", empty(message)); replace("events", []); }
function setPresentationMode(enabled) { state.presentation = enabled; document.body.classList.toggle("presentation", enabled); const toggle = document.getElementById("presentation-toggle"); toggle.setAttribute("aria-pressed", String(enabled)); toggle.textContent = enabled ? "발표 모드 종료" : "발표 모드"; }
function openDrawer() { document.body.classList.add("drawer-open"); document.getElementById("analysis-drawer-toggle").setAttribute("aria-expanded", "true"); document.getElementById("drawer-backdrop").hidden = false; }
function closeDrawer() { document.body.classList.remove("drawer-open"); document.getElementById("analysis-drawer-toggle").setAttribute("aria-expanded", "false"); document.getElementById("drawer-backdrop").hidden = true; }

let refreshInFlight = false;
const refreshTask = async () => {
  const version = state.requestVersion; const connection = document.getElementById("connection"), notice = document.getElementById("notice");
  try {
    const analyses = await getJson("/api/analyses"); if (version !== state.requestVersion) return; state.analyses = analyses; if (!state.selected && analyses.length) state.selected = analyses[0].display_analysis_id || analyses[0].analysis_id;
    replace("analyses", analyses.length ? analyses.map(analysisButton) : empty("저장된 분석이 없습니다.")); renderComparisonOptions(analyses);
    if (!state.selected) { clearDetail("분석을 실행하면 현황이 표시됩니다."); notice.textContent = "저장된 분석이 없습니다."; return; }
    const selected = state.selected; const shell = await getJson(`/api/analyses/${encodeURIComponent(selected)}/summary`); if (selected !== state.selected) return;
    const changed = !state.shell || shell.updated_at !== state.shell.updated_at; state.shell = shell; state.pinnedFinding ??= readPinnedFinding(shell.analysis_id); renderDetail(shell); updateDownloadLinks(shell);
    if (changed) { state.tabCache.clear(); await loadActiveTab(true); }
    notice.textContent = shell.stale ? "실행이 멈췄을 수 있습니다." : "저장된 최신 상태를 표시합니다."; notice.classList.toggle("warning", shell.stale);
    connection.textContent = "로컬 서버 연결됨"; connection.classList.remove("error"); document.getElementById("last-updated").textContent = `화면 갱신 ${formatTime(new Date().toISOString())}`;
  } catch (error) { connection.textContent = "연결 실패"; connection.classList.add("error"); notice.textContent = `데이터를 불러오지 못했습니다: ${error}`; notice.classList.add("warning"); }
};
const refresh = singleFlight(async () => { refreshInFlight = true; try { return await refreshTask(); } finally { refreshInFlight = false; } });

document.getElementById("log-search").addEventListener("input", renderEvents);
selectAll("[data-tab]").forEach((button) => button.addEventListener("click", () => openTab(button.dataset.tab)));
selectAll("[data-open-tab]").forEach((link) => link.addEventListener("click", (event) => { event.preventDefault(); openTab(link.dataset.openTab); }));
selectAll("[data-llm-view]").forEach((button) => button.addEventListener("click", () => { state.llmView = button.dataset.llmView; renderLlmDetail(); }));
document.getElementById("analysis-drawer-toggle").addEventListener("click", openDrawer); document.getElementById("analysis-drawer-close").addEventListener("click", closeDrawer); document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
document.getElementById("compare-button").addEventListener("click", compareSelectedAnalysis); document.getElementById("compare-close").addEventListener("click", () => document.getElementById("comparison-panel").classList.add("hidden"));
document.getElementById("artifact-search").addEventListener("input", () => renderArtifacts(state.tabCache.get(tabCacheKey("artifacts")))); document.getElementById("log-status").addEventListener("change", renderEvents); document.getElementById("include-logs").addEventListener("change", updateSelectionLink);
document.getElementById("status-page-prev").addEventListener("click", () => changeStatusPage(Math.max(0, state.statusPageOffset - 200))); document.getElementById("status-page-next").addEventListener("click", () => changeStatusPage(state.statusPageOffset + 200));
document.getElementById("hypothesis-prev").addEventListener("click", () => pageTab("findings", -PAGE_SIZE)); document.getElementById("hypothesis-next").addEventListener("click", () => pageTab("findings", PAGE_SIZE)); document.getElementById("artifact-prev").addEventListener("click", () => pageTab("artifacts", -PAGE_SIZE)); document.getElementById("artifact-next").addEventListener("click", () => pageTab("artifacts", PAGE_SIZE)); document.getElementById("llm-prev").addEventListener("click", () => pageTab("llm", -PAGE_SIZE)); document.getElementById("llm-next").addEventListener("click", () => pageTab("llm", PAGE_SIZE)); document.getElementById("log-prev").addEventListener("click", () => { state.tabOffsets.logs = Math.max(0, state.tabOffsets.logs - PAGE_SIZE); loadLogPage(); }); document.getElementById("log-next").addEventListener("click", () => { state.tabOffsets.logs += PAGE_SIZE; loadLogPage(); });
document.getElementById("replay-toggle").addEventListener("click", toggleReplay); document.getElementById("replay-reset").addEventListener("click", resetReplay); document.getElementById("replay-slider").addEventListener("input", (event) => { stopReplay(); applyReplay(Number(event.target.value)); }); document.getElementById("presentation-toggle").addEventListener("click", () => setPresentationMode(!state.presentation));
document.addEventListener?.("keydown", (event) => { if (event.key === "Escape") { if (state.presentation) setPresentationMode(false); else closeDrawer(); } if (event.key.toLowerCase() === "p" && !["INPUT", "SELECT", "TEXTAREA"].includes(event.target.tagName)) setPresentationMode(!state.presentation); });
const initialTab = (window.location.hash || "").slice(1); if (TAB_NAMES.includes(initialTab)) state.activeTab = initialTab; openTab(state.activeTab); refresh(); window.setInterval(refresh, 2000);
