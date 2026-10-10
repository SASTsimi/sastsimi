const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const TAB_NAMES = ["overview", "progress", "findings", "coverage", "artifacts", "llm", "outputs", "logs"];
const PAGE_SIZE = 10;
const LOG_PAGE_SIZE = 10;
const MAX_LOG_EVENTS = 500;
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null,
  analyses: [], shell: null, activeTab: "overview", tabCache: new Map(),
  tabOffsets: { findings: 0, coverage: 0, artifacts: 0, llm: 0, outputs: 0, logs: 0 },
  requestControllers: new Map(), filterTimers: new Map(),
  statusPage: null, statusPageOffset: 0, requestVersion: 0,
  artifactMap: new Map(), selectedArtifacts: new Set(), selectedReports: new Set(),
  pinnedFinding: null, llmDetail: null, llmView: "response", presentation: false,
  selectedHypothesis: null,
  detail: null,
  demoAliases: new Map(),
  expandedRepositories: new Set(),
  repositoryHistoryPages: new Map(),
  collapsedRepositories: new Set(),
  initialHistoryExpansionHandled: false,
  coveragePages: { gaps: null, unavailable: null, unsupported: null, excluded_tests: null, out_of_scope: null },
  replay: { active: false, index: 0, timer: null },
  log: { items: [], oldestCursor: null, latestCursor: null, hasMore: false, initialized: false },
};

function el(tag, text, className) { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node; }
function selectAll(selector) { return typeof document.querySelectorAll === "function" ? document.querySelectorAll(selector) : []; }
function selectOne(selector) { return typeof document.querySelector === "function" ? document.querySelector(selector) : null; }
function targetById(id) {
  if (id === "overview-content") {
    const legacyOverview = document.getElementById("overview");
    if (legacyOverview) return legacyOverview;
  }
  return document.getElementById(id);
}
function replace(id, nodes) { targetById(id).replaceChildren(...nodes); }
function empty(message) { return [el("div", message, "empty")]; }
function knownCount(value) { return Number.isInteger(value) && value >= 0 ? value.toLocaleString("ko-KR") : "—"; }
function formatNumber(value) { return Number(value || 0).toLocaleString("ko-KR"); }
function formatTime(value) { if (!value) return "—"; return new Intl.DateTimeFormat("ko-KR", { dateStyle: "short", timeStyle: "medium" }).format(new Date(value)); }
function formatDuration(value) { if (value == null) return "—"; return value < 1000 ? `${value}ms` : `${(value / 1000).toFixed(1)}초`; }
function ratioPercent(done, total) { if (!Number.isInteger(done) || !Number.isInteger(total) || total <= 0) return null; return Math.max(0, Math.min(100, Math.round(done / total * 100))); }
function pageLabel(page, noun = "개") { if (!page) return ""; const total = page.total_items ?? page.total ?? 0; if (!total) return `0${noun}`; const offset = page.offset ?? ((page.page - 1) * page.page_size); return `${offset + 1}–${offset + page.items.length} / ${total}`; }
function pageNumber(page) { return Math.max(1, Number(page?.page) || Math.floor((page?.offset || 0) / (page?.page_size || page?.limit || PAGE_SIZE)) + 1); }
function totalPages(page) { const total = page?.total_items ?? page?.total ?? 0; const size = page?.page_size || page?.limit || PAGE_SIZE; return Number(page?.total_pages) || (total ? Math.ceil(total / size) : 0); }
function visiblePages(current, total) {
  const limit = window.matchMedia?.("(max-width: 640px)")?.matches ? 3 : 5;
  if (total <= limit) return Array.from({ length: total }, (_, index) => index + 1);
  const radius = Math.floor(limit / 2), start = Math.max(1, Math.min(current - radius, total - limit + 1));
  return Array.from({ length: limit }, (_, index) => start + index);
}
function renderPagination(prefix, page, tab) {
  if (typeof document === "undefined") return;
  const container = document.getElementById(`${prefix}-pagination`), previous = document.getElementById(`${prefix}-prev`), next = document.getElementById(`${prefix}-next`), numbers = document.getElementById(`${prefix}-pages`);
  if (!container || !previous || !next || !numbers) return;
  const current = pageNumber(page), total = totalPages(page); container.hidden = total <= 1;
  previous.disabled = !page?.has_previous && current <= 1; next.disabled = !page?.has_next && current >= total;
  numbers.replaceChildren(...visiblePages(current, total).map((number) => { const button = el("button", String(number), "page-number"); button.type = "button"; button.setAttribute("aria-label", `${number}페이지`); if (number === current) { button.classList.add("current"); button.setAttribute("aria-current", "page"); } button.addEventListener("click", () => pageTabTo(tab, number)); return button; }));
}
const LIST_TARGETS = { findings: "hypotheses", coverage: "static-tool-findings", artifacts: "artifact-list", llm: "llm-invocations", outputs: "poc" };
function renderListMessage(tab, message, className = "empty", retry = false) {
  const targetId = LIST_TARGETS[tab], target = targetId ? document.getElementById(targetId) : null; if (!target) return;
  const box = el("div", message, className); if (retry) { const button = el("button", "다시 시도", "small-button"); button.type = "button"; button.addEventListener("click", () => loadActiveTab(true)); box.append(button); } target.replaceChildren(box);
}
function badge(status) { return el("span", statusLabel(status), `badge status-${String(status || "unknown").toLowerCase()}`); }
function singleFlight(task) { let active = null; return (...args) => { if (active) return active; active = Promise.resolve(task(...args)).finally(() => { active = null; }); return active; }; }
function requestController() { return typeof AbortController === "function" ? new AbortController() : { signal: undefined, abort() {} }; }
function demoRequest(url) {
  const match = url.match(/^\/api\/analyses\/([^/]+)(\/|$)/); if (!match) return { url, variant: null };
  const variant = state.demoAliases.get(decodeURIComponent(match[1])); if (!variant) return { url, variant: null };
  return { url: url.replace(`/api/analyses/${match[1]}`, `/api/analyses/${encodeURIComponent(variant.demo_source_id)}`), variant };
}
async function getJson(url, options = {}) {
  const request = demoRequest(url); const response = await fetch(request.url, { cache: "no-store", signal: options.signal }); if (!response.ok) { let error = null; try { error = await response.json(); } catch (_) { /* non-JSON failure */ } if (error?.error === "index_not_ready") throw new Error("목록 인덱스 준비가 필요합니다. dashboard-index rebuild를 실행하세요."); throw new Error(`요청 실패 (${response.status})`); }
  const data = await response.json();
  if (!request.variant || !/\/summary(?:\?|$)/.test(url) || Array.isArray(data)) return data;
  const merged = { ...data, ...request.variant };
  if (data.kpis) merged.kpis = { ...data.kpis, confirmed_findings: request.variant.confirmed_finding_count ?? data.kpis.confirmed_findings };
  return merged;
}
function pinKey(id) { return `sastsimi.dashboard.pin.${id}`; }
function readPinnedFinding(id) { try { return localStorage.getItem(pinKey(id)); } catch (_) { return null; } }
function writePinnedFinding(id, value) { try { if (value) localStorage.setItem(pinKey(id), value); else localStorage.removeItem(pinKey(id)); } catch (_) { /* optional */ } }
function repositoryName(value) { if (!value) return null; const clean = value.replace(/[\\/]$/, "").replace(/\.git$/, ""); return clean.split(/[\\/]/).filter(Boolean).at(-1) || null; }
function isDemoAnalysis(shell) { return Boolean(shell && (shell.analysis_id === "demo-analysis" || String(shell.display_analysis_id || "").startsWith("DEMO-") || shell.commit_id === "synthetic-demo-data" || String(shell.repository || "").includes("example.invalid"))); }

const DEMO_ANALYSIS_VARIANTS = [
  { display_analysis_id: "DEMO-API-002", repository: "https://example.invalid/sastsimi-api", commit_id: "demo-api-v2", status: "RUNNING", current_stage: "VERIFICATION_INITIAL", progress_percent: 75, started_at: "2026-10-06T08:35:00+09:00", last_updated_at: "2026-10-06T08:55:00+09:00", confirmed_finding_count: null, failed_stage: null },
  { display_analysis_id: "DEMO-API-001", repository: "https://example.invalid/sastsimi-api", commit_id: "demo-api-v1", status: "COMPLETE", current_stage: "COMPLETE", progress_percent: 100, started_at: "2026-10-05T14:10:00+09:00", last_updated_at: "2026-10-05T14:42:00+09:00", finished_at: "2026-10-05T14:42:00+09:00", confirmed_finding_count: 2, validated_poc_count: 2, failed_stage: null },
  { display_analysis_id: "DEMO-WEB-002", repository: "https://example.invalid/partner-portal", commit_id: "demo-web-v2", status: "BLOCKED", current_stage: "POC_VALIDATION", progress_percent: 82, started_at: "2026-10-06T07:50:00+09:00", last_updated_at: "2026-10-06T08:21:00+09:00", confirmed_finding_count: null, failed_stage: "POC_VALIDATION" },
  { display_analysis_id: "DEMO-WEB-001", repository: "https://example.invalid/partner-portal", commit_id: "demo-web-v1", status: "COMPLETE", current_stage: "COMPLETE", progress_percent: 100, started_at: "2026-10-04T16:05:00+09:00", last_updated_at: "2026-10-04T16:39:00+09:00", finished_at: "2026-10-04T16:39:00+09:00", confirmed_finding_count: 1, validated_poc_count: 1, failed_stage: null },
  { display_analysis_id: "DEMO-AUTH-002", repository: "https://example.invalid/legacy-auth-service", commit_id: "demo-auth-v2", status: "FAILED", current_stage: "STATIC_ANALYSIS", progress_percent: 28, started_at: "2026-10-06T06:40:00+09:00", last_updated_at: "2026-10-06T06:48:00+09:00", confirmed_finding_count: null, failed_stage: "STATIC_ANALYSIS" },
  { display_analysis_id: "DEMO-AUTH-001", repository: "https://example.invalid/legacy-auth-service", commit_id: "demo-auth-v1", status: "COMPLETE", current_stage: "COMPLETE", progress_percent: 100, started_at: "2026-10-03T11:20:00+09:00", last_updated_at: "2026-10-03T11:58:00+09:00", finished_at: "2026-10-03T11:58:00+09:00", confirmed_finding_count: 3, validated_poc_count: 2, failed_stage: null },
];

function demoAnalysisVariants(items) {
  if (!Array.isArray(items) || items.length !== 1 || !isDemoAnalysis(items[0])) return items;
  const source = items[0], demoSourceId = source.display_analysis_id || source.analysis_id;
  return DEMO_ANALYSIS_VARIANTS.map((variant, index) => ({ ...source, ...variant, analysis_id: `demo-analysis-${index + 1}`, demo_source_id: demoSourceId }));
}

function statusLabel(status) {
  return ({ RUNNING: "분석 중", COMPLETE: "완료", SUCCEEDED: "완료", PARTIAL: "부분 분석", PAUSED: "일시 중단", FAILED: "실패", BLOCKED: "차단", PENDING: "대기" })[status] || status || "상태 미확인";
}

function stageLabel(stage) {
  return ({
    SETUP: "분석 준비", REPOSITORY_FETCH: "저장소 확보", STATIC_ANALYSIS: "정적 분석",
    TRIAGE: "후보 선별", HYPOTHESIS_GENERATION: "가설 생성", VERIFICATION_INITIAL: "초기 검증",
    VERIFICATION: "가설 검증", POC_GENERATION: "PoC 생성", POC_VALIDATION: "PoC 검증",
    POC_CANDIDATE_DONE: "PoC 후보 생성 완료", POC_EXECUTION_DONE: "PoC 실행 완료",
    POC_NOT_FOUND: "PoC 미확정", REPORTING: "보고서 생성", COMPLETE: "분석 완료",
  })[stage] || stage || "단계 미확인";
}

function progressDonut(value, label = "전체 분석 진행률") {
  const known = Number.isFinite(value);
  const bounded = known ? Math.max(0, Math.min(100, Math.round(value))) : 0;
  const donut = el("div", undefined, `progress-donut${known ? "" : " progress-unknown"}`);
  donut.style?.setProperty?.("--progress", String(bounded));
  donut.setAttribute?.("role", "progressbar"); donut.setAttribute?.("aria-label", label);
  donut.setAttribute?.("aria-valuemin", "0"); donut.setAttribute?.("aria-valuemax", "100");
  if (known) donut.setAttribute?.("aria-valuenow", String(bounded)); else donut.setAttribute?.("aria-valuetext", "미확인");
  const center = el("div", undefined, "donut-center"); center.append(el("strong", known ? `${bounded}%` : "—"), el("span", "전체 진행", "meta")); donut.append(center);
  return donut;
}

function renderTabSummary(targetId, label, primaries = [], facts = []) {
  if (typeof document === "undefined") return;
  const target = document.getElementById(targetId); if (!target) return;
  const focus = el("div", undefined, "summary-focus"); focus.append(el("p", label, "section-label"));
  const primaryRow = el("div", undefined, "summary-primary-row");
  primaries.forEach(({ label: itemLabel, value, node, tone = "" }) => { const item = el("div", undefined, `summary-primary ${tone}`.trim()); item.append(el("span", itemLabel, "summary-label")); if (node) item.append(node); else item.append(el("strong", value == null ? "—" : String(value))); primaryRow.append(item); });
  focus.append(primaryRow);
  const factList = el("dl", undefined, "summary-facts");
  facts.forEach(([factLabel, value, code]) => { const row = el("div", undefined, "summary-fact"); row.append(el("dt", factLabel), el("dd", value == null ? "—" : String(value), code ? "mono" : undefined)); factList.append(row); });
  target.replaceChildren(focus, factList);
}

function renderAttention(targetId, items = []) {
  const target = document.getElementById(targetId); if (!target) return;
  const visible = items.filter((item) => item?.text);
  target.hidden = !visible.length; target.replaceChildren(); if (!visible.length) return;
  const heading = el("div", undefined, "attention-heading"); heading.append(el("strong", `주의가 필요한 항목 ${visible.length}개`), el("span", "실패 · 차단 · 미확인", "meta")); target.append(heading);
  const list = el("ul"); visible.slice(0, 4).forEach((item) => { const row = el("li"); row.append(el("span", item.kind || "주의", `attention-kind attention-${item.tone || "warning"}`), el("span", item.text)); list.append(row); }); target.append(list);
  if (visible.length > 4) { const details = el("details"); details.append(el("summary", `나머지 ${visible.length - 4}개 보기`)); const more = el("ul"); visible.slice(4).forEach((item) => { const row = el("li"); row.append(el("span", item.kind || "주의", `attention-kind attention-${item.tone || "warning"}`), el("span", item.text)); more.append(row); }); details.append(more); target.append(details); }
}

function completePage(page) { return Boolean(page && page.offset === 0 && page.items?.length === page.total); }

function analysisRouteId(item) { return item.display_analysis_id || item.analysis_id; }
function analysisSelected(item) { return [item.analysis_id, analysisRouteId(item)].includes(state.selected); }
function analysisTime(item) { return item.started_at || item.last_updated_at || null; }
function analysisTimestamp(item) { const value = analysisTime(item); if (!value) return null; const parsed = Date.parse(value); return Number.isFinite(parsed) ? parsed : null; }
function analysisKey(item) {
  if (item.status === "RUNNING") return Number.isFinite(item.progress_percent) ? `진행 ${item.progress_percent}%` : "진행 —";
  if (["COMPLETE", "SUCCEEDED"].includes(item.status)) return `확정 Finding ${knownCount(item.confirmed_finding_count)}`;
  if (["FAILED", "BLOCKED"].includes(item.status)) return `${item.status === "BLOCKED" ? "차단" : "실패"} 단계 ${item.failed_stage || item.current_stage || "—"}`;
  if (item.status === "PARTIAL") return "미검증 범위 남음";
  if (item.status === "PAUSED") return "재개 필요";
  return "—";
}
function sortAnalysisOrder(left, right) {
  if (left.timestamp != null && right.timestamp != null && left.timestamp !== right.timestamp) return right.timestamp - left.timestamp;
  if (left.timestamp != null && right.timestamp == null) return -1;
  if (left.timestamp == null && right.timestamp != null) return 1;
  return left.index - right.index;
}
function groupAnalyses(items = []) {
  const grouped = new Map();
  items.forEach((item, index) => {
    const routeId = analysisRouteId(item), key = item.repository || `analysis:${item.analysis_id || routeId || index}`;
    if (!grouped.has(key)) grouped.set(key, { key, firstIndex: index, items: [] });
    grouped.get(key).items.push({ item, index, timestamp: analysisTimestamp(item) });
  });
  return [...grouped.values()].map((group) => {
    group.items.sort(sortAnalysisOrder); group.latestTimestamp = group.items[0]?.timestamp ?? null; return group;
  }).sort((left, right) => sortAnalysisOrder({ timestamp: left.latestTimestamp, index: left.firstIndex }, { timestamp: right.latestTimestamp, index: right.firstIndex }));
}
function analysisEmptyState() {
  const target = el("div", undefined, "analysis-empty"); target.append(el("strong", "저장된 분석이 없습니다."), el("span", "분석을 실행하면 저장소별 최신 결과가 여기에 표시됩니다.", "meta")); return target;
}
function analysisHistoryButton(item) {
  const routeId = analysisRouteId(item), button = el("button", undefined, `analysis-history-row analysis-${String(item.status || "unknown").toLowerCase()}`);
  button.type = "button"; if (analysisSelected(item)) button.classList.add("selected");
  const heading = el("div", undefined, "analysis-history-heading"), id = el("strong", routeId || "분석 ID 없음", "mono technical-id"); id.title = routeId || ""; heading.append(id, badge(item.status));
  button.append(heading, el("div", analysisKey(item), "analysis-history-key"), el("time", formatTime(analysisTime(item)), "meta"));
  if (item.percentage_kind === "known_checkpoint_fraction") button.append(el("div", "현재 알려진 checkpoint 비율", "meta"));
  button.addEventListener("click", () => selectAnalysis(routeId)); return button;
}
function analysisButton(item) { return analysisHistoryButton(item); }
function initializeSelectedHistoryExpansion(groups) {
  if (state.initialHistoryExpansionHandled) return;
  const selectedGroup = groups.find((group) => group.items.slice(1).some((entry) => analysisSelected(entry.item)));
  if (!selectedGroup) return;
  if (!state.collapsedRepositories.has(selectedGroup.key)) state.expandedRepositories.add(selectedGroup.key);
  state.initialHistoryExpansionHandled = true;
}
async function loadRepositoryHistory(group, page = 1, selectedId = null, focusList = false) {
  const latest = group.items[0]?.item; if (!latest) return;
  const requestKey = `history:${group.key}`; state.requestControllers.get(requestKey)?.abort(); const controller = requestController(); state.requestControllers.set(requestKey, controller);
  const parameters = new URLSearchParams({ analysis_id: analysisRouteId(latest), page: String(Math.max(1, page)), page_size: String(PAGE_SIZE) }); if (selectedId) parameters.set("selected_id", selectedId);
  let timedOut = false; const timeout = typeof window.setTimeout === "function" ? window.setTimeout(() => { timedOut = true; controller.abort(); }, 15000) : null;
  try {
    const result = await getJson(`/api/repository-history?${parameters}`, { signal: controller.signal }); if (state.requestControllers.get(requestKey) !== controller) return;
    state.repositoryHistoryPages.set(group.key, result); if (selectedId) state.expandedRepositories.add(group.key); renderAnalysisList(state.analyses);
    if (focusList) { const index = groupAnalyses(state.analyses).findIndex((item) => item.key === group.key), history = document.getElementById(`analysis-history-${index}`); if (history) { history.tabIndex = -1; history.focus?.({ preventScroll: true }); history.scrollIntoView?.({ block: "start", behavior: "smooth" }); } }
  } catch (error) {
    if (error?.name === "AbortError" && !timedOut) return;
    state.repositoryHistoryPages.set(group.key, { items: [], page: 1, page_size: PAGE_SIZE, total_items: latest.history_count || 0, total_pages: Math.ceil((latest.history_count || 0) / PAGE_SIZE), load_error: timedOut ? "timeout" : "failed" }); renderAnalysisList(state.analyses);
  } finally {
    if (timeout != null && typeof window.clearTimeout === "function") window.clearTimeout(timeout); if (state.requestControllers.get(requestKey) === controller) state.requestControllers.delete(requestKey);
  }
}
function repositoryHistoryPager(group, page) {
  const controls = el("div", undefined, "page-controls analysis-history-pagination"), current = pageNumber(page), total = totalPages(page); if (total <= 1) { controls.hidden = true; return controls; }
  const previous = el("button", "이전", "small-button"); previous.type = "button"; previous.disabled = current <= 1; previous.addEventListener("click", (event) => { event.stopPropagation(); loadRepositoryHistory(group, current - 1, null, true); });
  const numbers = el("span", undefined, "page-numbers"); visiblePages(current, total).forEach((number) => { const button = el("button", String(number), "page-number"); button.type = "button"; button.setAttribute("aria-label", `${number}페이지`); if (number === current) { button.classList.add("current"); button.setAttribute("aria-current", "page"); } button.addEventListener("click", (event) => { event.stopPropagation(); loadRepositoryHistory(group, number, null, true); }); numbers.append(button); });
  const next = el("button", "다음", "small-button"); next.type = "button"; next.disabled = current >= total; next.addEventListener("click", (event) => { event.stopPropagation(); loadRepositoryHistory(group, current + 1, null, true); }); controls.append(previous, numbers, next); return controls;
}
async function ensureSelectedRepositoryHistory(shell) {
  if (state.initialHistoryExpansionHandled || !shell) return;
  const group = groupAnalyses(state.analyses).find((item) => item.items[0]?.item.repository === shell.repository); if (!group) return;
  const latest = group.items[0].item; if (analysisSelected(latest)) { state.initialHistoryExpansionHandled = true; return; }
  state.expandedRepositories.add(group.key); state.initialHistoryExpansionHandled = true; await loadRepositoryHistory(group, 1, state.selected);
}
function analysisRepositoryGroup(group, index) {
  const latest = group.items[0].item, historyPage = state.repositoryHistoryPages.get(group.key), clientHistory = group.items.slice(1).map((entry) => entry.item), historyItems = historyPage?.items || clientHistory, historyTotal = Math.max(latest.history_count ?? 0, historyPage?.total_items ?? 0, clientHistory.length), repositoryLabel = repositoryName(latest.repository) || "저장소 정보 없음";
  const historyId = `analysis-history-${index}`, hasHistory = historyTotal > 0, selectedHistoryItem = historyItems.find(analysisSelected), latestSelected = analysisSelected(latest), selectedHistory = Boolean(selectedHistoryItem) || (!latestSelected && state.shell?.repository === latest.repository);
  const expanded = hasHistory && state.expandedRepositories.has(group.key), container = el("section", undefined, `analysis-group${selectedHistory ? " contains-selected" : ""}`);
  if (selectedHistory) container.setAttribute("aria-label", `${repositoryLabel}, 과거 실행 ${analysisRouteId(selectedHistoryItem) || state.selected} 보는 중`);
  const shell = el("div", undefined, `analysis-group-shell analysis-${String(latest.status || "unknown").toLowerCase()}${latestSelected ? " latest-selected" : ""}${hasHistory ? "" : " single-run"}`);
  if (hasHistory) {
    const toggle = el("button", expanded ? "▼" : "▶", "analysis-expand-toggle"); toggle.type = "button"; toggle.id = `${historyId}-toggle`; toggle.setAttribute("aria-expanded", String(expanded)); toggle.setAttribute("aria-controls", historyId); toggle.setAttribute("aria-label", `${repositoryLabel}의 이전 분석 실행 ${expanded ? "접기" : "펼치기"}`);
    toggle.addEventListener("click", (event) => { event.stopPropagation(); if (expanded) { state.expandedRepositories.delete(group.key); state.collapsedRepositories.add(group.key); renderAnalysisList(state.analyses, group.key); } else { state.expandedRepositories.add(group.key); state.collapsedRepositories.delete(group.key); renderAnalysisList(state.analyses, group.key); if (!historyPage && latest.history_count != null) loadRepositoryHistory(group, 1); } }); shell.append(toggle);
  }
  const latestColumn = el("div", undefined, "analysis-latest-column"), latestButton = el("button", undefined, "analysis-latest-button"); latestButton.type = "button"; if (latestSelected) latestButton.classList.add("selected"); latestButton.title = latest.repository || `${repositoryLabel} · ${analysisRouteId(latest)}`;
  const repository = el("strong", repositoryLabel, "analysis-repository line-clamp-2"), status = el("div", undefined, "analysis-latest-status"); status.append(el("span", "최신 실행", "meta"), badge(latest.status));
  const footer = el("div", undefined, "analysis-latest-footer"); footer.append(el("time", formatTime(analysisTime(latest)), "meta")); if (hasHistory) footer.append(el("span", `이전 실행 ${historyTotal}개`, "analysis-history-count"));
  latestButton.append(repository, status, el("div", analysisKey(latest), "analysis-key")); if (latest.percentage_kind === "known_checkpoint_fraction") latestButton.append(el("div", "현재 알려진 checkpoint 비율", "meta")); latestButton.append(footer); latestButton.addEventListener("click", () => selectAnalysis(analysisRouteId(latest))); latestColumn.append(latestButton);
  if (selectedHistory) { const currentId = analysisRouteId(selectedHistoryItem) || state.selected, current = el("div", undefined, `analysis-current-history${expanded ? " is-expanded" : ""}`), currentCopy = el("div", undefined, "analysis-current-history-copy"); currentCopy.id = `${historyId}-current-copy`; currentCopy.append(el("span", "과거 실행 보는 중", "analysis-current-history-label"), el("strong", currentId || "분석 ID 없음", "mono technical-id")); const latestAction = el("button", "최신 실행 보기", "analysis-latest-action"); latestAction.type = "button"; latestAction.setAttribute("aria-label", `${repositoryLabel}의 최신 실행 ${analysisRouteId(latest)} 보기`); latestAction.addEventListener("click", (event) => { event.stopPropagation(); selectAnalysis(analysisRouteId(latest)); }); current.append(currentCopy, latestAction); latestColumn.append(current); latestButton.setAttribute("aria-describedby", currentCopy.id); }
  shell.append(latestColumn); container.append(shell);
  if (hasHistory) { const history = el("div", undefined, "analysis-history"); history.id = historyId; history.hidden = !expanded; history.setAttribute("aria-label", `${repositoryLabel}의 이전 분석 실행`); if (expanded && !historyPage && latest.history_count != null) history.append(el("div", "과거 실행을 불러오는 중…", "empty")); else if (historyPage?.load_error) { const error = el("div", historyPage.load_error === "timeout" ? "요청 시간이 초과되었습니다." : "과거 실행을 불러오지 못했습니다.", "error"), retry = el("button", "다시 시도", "small-button"); retry.addEventListener("click", () => loadRepositoryHistory(group, 1)); error.append(retry); history.append(error); } else historyItems.forEach((item) => history.append(analysisHistoryButton(item))); if (historyPage) history.append(repositoryHistoryPager(group, historyPage)); container.append(history); }
  return container;
}
function renderAnalysisList(items, focusGroupKey = null) {
  const target = document.getElementById("analyses"), groups = groupAnalyses(items); let focusId = null;
  if (!groups.length) { target.replaceChildren(analysisEmptyState()); return; }
  initializeSelectedHistoryExpansion(groups);
  const nodes = groups.map((group, index) => { if (group.key === focusGroupKey) focusId = `analysis-history-${index}-toggle`; return analysisRepositoryGroup(group, index); });
  target.replaceChildren(...nodes); if (focusId) document.getElementById(focusId)?.focus?.();
}

function selectAnalysis(id) {
  if (state.selected === id) { closeDrawer(); return; }
  state.selected = id; state.shell = null; state.tabCache.clear(); Object.keys(state.tabOffsets).forEach((tab) => { state.tabOffsets[tab] = 0; }); state.requestControllers.forEach((controller) => controller.abort()); state.requestControllers.clear(); resetLogState(); state.statusPage = null; state.statusPageOffset = 0; state.requestVersion += 1;
  state.selectedArtifacts.clear(); state.selectedReports.clear(); state.pinnedFinding = null; state.llmDetail = null; state.selectedHypothesis = null; state.artifactMap.clear(); stopReplay();
  window.history?.replaceState?.({}, "", `/analyses/${encodeURIComponent(id)}${window.location.hash || ""}`); closeDrawer(); refresh();
}

function renderSummary(shell) {
  const kpis = shell?.kpis || {};
  const statusText = shell ? `${statusLabel(shell.status)} · ${stageLabel(shell.current_stage)}` : "—";
  document.getElementById("summary-status").textContent = statusText;
  const repository = shell ? repositoryName(shell.repository) || shell.display_analysis_id || shell.analysis_id : "분석을 선택하세요";
  const headerRepository = document.getElementById("header-repository"); if (headerRepository) headerRepository.textContent = repository;
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
  const compactStatus = document.getElementById("compact-status"); if (compactStatus) compactStatus.textContent = shell ? statusLabel(shell.status) : "—";
  const compactTrue = document.getElementById("compact-true"); if (compactTrue) compactTrue.textContent = knownCount(kpis.confirmed_findings);
  const compactPoc = document.getElementById("compact-poc"); if (compactPoc) compactPoc.textContent = knownCount(shell?.validated_poc_count);
}

function renderOverview(shell) {
  if (!shell) { replace("overview-content", empty("분석을 선택하세요.")); return; }
  state.detail = shell;
  const box = el("div"); const heading = el("div", undefined, "panel-heading overview-heading"), headingText = el("div", undefined); const repositoryTitle = el("h2", repositoryName(shell.repository) || "저장소 정보 없음", "repository-title line-clamp-2"); repositoryTitle.title = shell.repository || repositoryTitle.textContent; headingText.append(repositoryTitle, el("div", `분석 ${shell.display_analysis_id || shell.analysis_id}`, "analysis-identity mono meta technical-id")); heading.append(headingText, badge(shell.status)); box.append(heading);
  const repository = el("div", shell.repository || "저장소 정보 없음", "repository mono"); repository.title = shell.repository || ""; box.append(repository);
  const overviewCore = el("div", undefined, "overview-core"); const stage = el("div", undefined, "overview-stage"); stage.append(el("span", "현재 단계", "section-label"), el("strong", stageLabel(shell.current_stage), "overview-stage-value"), el("code", shell.current_stage || "—", "metric-code mono")); overviewCore.append(stage, progressDonut(Number.isFinite(shell.progress_percent) ? shell.progress_percent : null)); box.append(overviewCore);
  const metrics = el("div", undefined, "metric-grid overview-facts");
  [["Commit", shell.commit_id || "—"], ["실행 프로필", shell.profile_ref || "—"], ["Provider / 모델", [shell.provider, shell.model].filter(Boolean).join(" / ") || "—"], ["시작", formatTime(shell.started_at)], ["종료", shell.finished_at ? formatTime(shell.finished_at) : "진행 중"], ["마지막 갱신", formatTime(shell.last_updated_at)]].forEach(([label, value]) => { const metric = el("div", undefined, "metric"); metric.append(el("span", label, "meta"), el("strong", value)); metrics.append(metric); });
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
    if (shell.status === "PARTIAL") {
      const countsKnown = Number.isInteger(surface?.total) && ["covered", "uncovered", "insufficient"].every((key) => Number.isInteger(surface[key])) && surface.covered + surface.uncovered + surface.insufficient === surface.total;
      const scope = countsKnown ? ` · 보안 표면 근거 충족 ${surface.covered}/${surface.total} · 근거 부족 ${surface.insufficient}${surface.uncovered ? ` · 미검토 ${surface.uncovered}` : ""}` : " · 보안 표면 근거 미확인";
      box.append(el("div", `실행 종료${scope} · 전체 분석은 PARTIAL`, "warning"));
    }
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
  replace("overview-content", [box]); targetById("overview-content").classList.remove("empty");
}

function phaseProgressMetric(label, percent, done, total, tone) {
  const target = el("article", undefined, "detail-progress-metric");
  const known = Number.isFinite(percent); const bounded = known ? Math.max(0, Math.min(100, Math.round(percent))) : 0;
  const donut = el("div", undefined, `progress-donut detail-progress-donut progress-${tone}${known ? "" : " progress-unknown"}`);
  donut.style?.setProperty?.("--progress", String(bounded)); donut.setAttribute?.("role", "progressbar"); donut.setAttribute?.("aria-valuemin", "0"); donut.setAttribute?.("aria-valuemax", "100");
  const valueText = known ? `${label} ${bounded}%, ${total}개 중 ${done}개` : `${label} 미확인`;
  donut.setAttribute?.("aria-label", valueText); if (known) donut.setAttribute?.("aria-valuenow", String(bounded)); else donut.setAttribute?.("aria-valuetext", "미확인");
  const center = el("div", undefined, "donut-center detail-donut-center"); center.append(el("strong", known ? `${bounded}%` : "—")); donut.append(center);
  target.replaceChildren(el("span", label, "section-label"), donut, el("strong", known ? `${knownCount(done)} / ${knownCount(total)}` : "—", "phase-progress-count"));
  return target;
}

function countStatus(items, status, field = "status") { return items.filter((item) => item?.[field] === status).length; }
function compactCounts(values = []) { const counts = new Map(); values.filter(Boolean).forEach((value) => counts.set(value, (counts.get(value) || 0) + 1)); return [...counts].map(([value, count]) => `${value} ${count}`).join(" · ") || "—"; }

function renderProgressSummary(pipeline = []) {
  const shell = state.shell || {}, kpis = shell.kpis || {}; const failed = countStatus(pipeline, "FAILED"), blocked = countStatus(pipeline, "BLOCKED");
  const retriesKnown = pipeline.every((item) => Number.isInteger(item.attempt_number)); const retries = retriesKnown ? pipeline.reduce((sum, item) => sum + Math.max(0, item.attempt_number), 0) : null;
  const target = document.getElementById("progress-summary"), layout = el("div", undefined, "progress-command-grid");
  const stage = el("div", undefined, "progress-stage"); stage.append(el("span", "현재 단계", "section-label"), el("strong", stageLabel(shell.current_stage), "progress-stage-value"), el("code", shell.current_stage || "—", "mono technical-code"));
  const overall = el("div", undefined, "progress-overall"); const overallDonut = progressDonut(Number.isFinite(shell.progress_percent) ? shell.progress_percent : null, "전체 분석 진행률"); overallDonut.classList?.add?.("progress-primary-donut"); overall.append(el("span", "전체 진행률", "section-label"), overallDonut);
  const primary = el("div", undefined, "progress-primary-group"); primary.append(stage, overall);
  const detail = el("div", undefined, "progress-detail"); const detailMetrics = el("div", undefined, "detail-progress-grid"); detailMetrics.append(phaseProgressMetric("정적 검사 범위 확인률", ratioPercent(kpis.discovery_done, kpis.discovery_total), kpis.discovery_done, kpis.discovery_total, "coverage"), phaseProgressMetric("가설 검증 진행률", ratioPercent(kpis.verification_done, kpis.verification_total), kpis.verification_done, kpis.verification_total, "warning")); detail.append(el("span", "세부 진행", "section-label"), detailMetrics);
  const execution = el("div", undefined, "progress-execution"); const statusGrid = el("dl", undefined, "progress-status-grid"); [["실패", knownCount(failed), failed > 0 ? "danger" : "quiet"], ["차단", knownCount(blocked), blocked > 0 ? "warning" : "quiet"], ["재시도", retries == null ? "—" : knownCount(retries), retries > 0 ? "warning" : "quiet"], ["마지막 갱신", formatTime(shell.last_updated_at), "neutral"]].forEach(([label, value, tone]) => { const row = el("div", undefined, `progress-status-item status-${tone}`); row.append(el("dt", label), el("dd", value)); statusGrid.append(row); }); execution.append(el("span", "실행 상태", "section-label"), statusGrid);
  layout.append(primary, detail, execution); target.replaceChildren(el("p", "진행 핵심", "section-label progress-command-title"), layout);
  const problems = pipeline.filter((item) => ["FAILED", "BLOCKED"].includes(item.status) || item.error_code).map((item) => ({ kind: statusLabel(item.status), tone: "danger", text: `${item.label_ko || stageLabel(item.stage)}${item.error_code ? ` · ${item.error_code}` : ""}` }));
  if (shell.stale) problems.unshift({ kind: "갱신 지연", tone: "warning", text: "30초 넘게 새 상태가 저장되지 않았습니다." });
  renderAttention("progress-alerts", problems);
}

function renderFindingsSummary(page) {
  const counts = page?.summary?.verdict_counts || {}, shell = state.shell || {};
  const verdictCount = (verdict) => Number.isInteger(counts[verdict]) ? knownCount(counts[verdict]) : "—";
  renderTabSummary("findings-summary", "Finding · 검증 핵심", [{ label: "확정 TRUE Finding", value: knownCount(shell.kpis?.confirmed_findings) }, { label: "검증된 PoC", value: knownCount(shell.validated_poc_count) }], [["TRUE", verdictCount("TRUE")], ["FALSE", verdictCount("FALSE")], ["HOLD", verdictCount("HOLD")], ["BLOCKED", verdictCount("BLOCKED")]]);
  const problems = (page?.items || []).filter((item) => ["FAILED", "BLOCKED"].includes(item.status) || item.error_code).map((item) => ({ kind: item.status === "BLOCKED" ? "차단" : "실패", tone: "danger", text: `${item.title || item.hypothesis_id}${item.error_code ? ` · ${item.error_code}` : ""}` })); renderAttention("findings-alerts", problems);
}
function renderCoverageKpis(data = {}) {
  const tools = data.static_tools || []; const executed = tools.length ? tools.filter((item) => ["SUCCEEDED", "COMPLETE"].includes(item.status)).length : null;
  const scope = data.static_coverage_expected == null || data.static_coverage_verified == null ? "—" : `${knownCount(data.static_coverage_verified)} / ${knownCount(data.static_coverage_expected)}`;
  renderTabSummary("coverage-kpi-summary", "Coverage 핵심", [{ label: "실행 완료 도구", value: executed == null ? "—" : knownCount(executed) }, { label: "검사된 범위", value: scope }], [["미검사 영역", knownCount(data.static_coverage_gap_count)], ["결과 수", knownCount(data.summary?.result_count)], ["부분 기록", data.static_coverage_truncated == null ? "—" : data.static_coverage_truncated ? "있음" : "없음"], ["미실행 도구", tools.length ? knownCount(tools.filter((item) => ["PENDING", "NOT_RUN"].includes(item.status)).length) : "—"]]);
  const problems = []; if ((data.static_coverage_gap_count || 0) > 0) problems.push({ kind: "미검사", text: `검증되지 않은 파일·규칙 ${data.static_coverage_gap_count}개`, tone: "warning" }); tools.filter((item) => ["FAILED", "BLOCKED"].includes(item.status)).forEach((item) => problems.push({ kind: statusLabel(item.status), text: `${item.tool} 실행 기록`, tone: "danger" })); renderAttention("coverage-alerts", problems);
}
function renderArtifactKpis(page) {
  const summary = page?.summary || {};
  renderTabSummary("artifacts-summary", "아티팩트 핵심", [{ label: "전체 아티팩트", value: page ? knownCount(page.total_items ?? page.total) : "—" }, { label: "검증 결과물", value: "—" }], [["단계별", Object.keys(summary.stage_counts || {}).length ? Object.entries(summary.stage_counts).map(([key, value]) => `${key} ${value}`).join(" · ") : "—"], ["종류별", Object.keys(summary.kind_counts || {}).length ? Object.entries(summary.kind_counts).map(([key, value]) => `${key} ${value}`).join(" · ") : "—"]]);
  const problems = []; if (page?.omitted_count) problems.push({ kind: "미표시", text: `목록에서 생략된 아티팩트가 최소 ${page.omitted_count}개 있습니다.`, tone: "warning" }); renderAttention("artifacts-alerts", problems);
}
function renderLlmKpis(page) {
  const summary = page?.summary || {}, counts = summary.status_counts || {}, shell = state.shell || {};
  renderTabSummary("llm-summary", "LLM 핵심", [{ label: "성공 호출", value: Number.isInteger(counts.SUCCEEDED) ? knownCount(counts.SUCCEEDED + (counts.COMPLETE || 0)) : "—", tone: "violet" }, { label: "실패 호출", value: Number.isInteger(counts.FAILED) ? knownCount(counts.FAILED) : "—", tone: "violet" }], [["입력 토큰", Number.isInteger(summary.input_tokens) ? formatNumber(summary.input_tokens) : "—"], ["출력 토큰", Number.isInteger(summary.output_tokens) ? formatNumber(summary.output_tokens) : "—"], ["재시도", knownCount(summary.retry_count)], ["미확인 사용량", knownCount(shell.llm_unknown_token_calls)]]);
  const problems = (page?.items || []).filter((item) => item.status === "FAILED").map((item) => ({ kind: "실패", text: `${item.agent_role || "Agent"} · ${item.model || "모델 미확인"}`, tone: "danger" })); if ((shell.llm_unknown_token_calls || 0) > 0) problems.push({ kind: "미확인", text: `토큰 정보 미확인 호출 ${shell.llm_unknown_token_calls}건`, tone: "warning" }); renderAttention("llm-alerts", problems);
}
function renderLogKpis(page) {
  const items = page?.items || [], complete = completePage(page); const value = (status) => complete ? knownCount(countStatus(items, status)) : "—"; const failureTotal = complete ? items.filter((item) => ["FAILED", "BLOCKED"].includes(item.status)).length : null;
  renderTabSummary("logs-summary", "로그 핵심", [{ label: "실패 · 차단 이벤트", value: failureTotal == null ? "—" : knownCount(failureTotal) }], [["오류", value("FAILED")], ["경고", value("WARNING")], ["차단", value("BLOCKED")], ["마지막 이벤트", items.length ? formatTime(items[0].started_at || items[0].created_at) : "—"]]);
  const problems = items.filter((item) => ["FAILED", "BLOCKED"].includes(item.status)).map((item) => ({ kind: statusLabel(item.status), text: item.summary_ko || item.error_code || stageLabel(item.stage), tone: "danger" })); renderAttention("logs-alerts", problems);
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
function renderPipeline(items = []) { replace("pipeline", items.length ? items.map((item) => { const card = el("article", undefined, `stage stage-${item.status.toLowerCase()}`); card.dataset.updatedAt = item.updated_at || ""; const identity = el("div", undefined, "row-identity"); identity.append(el("strong", item.label_ko), el("div", item.stage, "mono meta technical-code")); const row = el("div", undefined, "status-row"); row.append(badge(item.status), el("span", item.agent_role, "meta")); card.append(identity, row); if (item.error_code) card.append(el("div", item.error_code, "error mono")); return card; }) : empty("파이프라인 상태가 없습니다.")); }
function renderFailureGuidance(items = []) { const failed = items.filter((item) => item.error_code || ["FAILED", "BLOCKED"].includes(item.status)), panel = selectOne(".failure-panel"); if (panel) panel.hidden = !failed.length; replace("failure-guidance", failed.map((item) => { const card = el("article", undefined, "failure-row"); card.append(el("strong", item.label_ko), badge(item.status)); if (item.error_code) card.append(el("div", item.error_code, "error mono")); card.append(el("p", item.guidance_ko || "로그에서 실패 원인과 복구 기록을 확인하세요.", "meta")); return card; })); }

function renderHypotheses(page) {
  const items = page?.items || []; document.getElementById("hypothesis-page-label").textContent = pageLabel(page, "개");
  if (!items.some((item) => item.hypothesis_id === state.selectedHypothesis)) state.selectedHypothesis = items[0]?.hypothesis_id || null;
  const choose = (id) => { state.selectedHypothesis = id; renderHypotheses(page); };
  replace("hypotheses", items.length ? items.map((item, index) => { const selected = item.hypothesis_id === state.selectedHypothesis; const button = el("button", undefined, `hypothesis-row${selected ? " selected" : ""}`); button.id = `hypothesis-${item.hypothesis_id}`; button.setAttribute("role", "option"); button.setAttribute("aria-selected", String(selected)); const top = el("div", undefined, "hypothesis-row-top"); top.append(badge(item.verdict || item.status), el("strong", item.title || item.hypothesis_id, "line-clamp-2")); button.append(top); const meta = el("div", undefined, "hypothesis-row-meta"); const identifier = el("span", item.hypothesis_id, "mono technical-id"); identifier.title = item.hypothesis_id; meta.append(identifier, el("span", item.vulnerability_type || "유형 미기록"), el("span", stageLabel(item.current_stage))); button.append(meta); button.addEventListener("click", () => choose(item.hypothesis_id)); button.addEventListener("keydown", (event) => { if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return; event.preventDefault(); const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length; choose(items[next].hypothesis_id); document.getElementById(`hypothesis-${items[next].hypothesis_id}`)?.focus(); }); return button; }) : empty("생성된 가설이 없습니다."));
  renderHypothesisDetail(items.find((item) => item.hypothesis_id === state.selectedHypothesis));
  renderPagination("hypothesis", page, "findings");
}
function renderHypothesisDetail(item) {
  const detail = document.getElementById("hypothesis-detail"); detail.replaceChildren(); detail.classList.toggle("empty", !item); if (!item) { detail.textContent = "가설을 선택하세요."; return; }
  const heading = el("div", undefined, "detail-heading"); const title = el("div", undefined); title.append(el("span", "선택 항목 상세", "section-label"), el("h3", item.title || item.hypothesis_id)); heading.append(title, badge(item.verdict || item.status)); detail.append(heading);
  const identity = el("div", item.hypothesis_id, "mono meta technical-id"); identity.title = item.hypothesis_id; detail.append(identity);
  const gates = el("dl", undefined, "detail-definition"); [["판정", statusLabel(item.verdict || item.status)], ["Technical Gate", item.disposition || "—"], ["Scope Gate", item.scope_status || "—"], ["취약점 유형", item.vulnerability_type || "—"], ["현재 단계", stageLabel(item.current_stage)]].forEach(([label, value]) => { const row = el("div"); row.append(el("dt", label), el("dd", value)); gates.append(row); }); detail.append(gates);
  if (item.summary) { detail.append(el("h4", "검증 요약"), el("p", item.summary, "detail-copy")); }
  const flow = el("div", undefined, "detail-flow"); [["SOURCE", item.source || "—"], ["SINK", item.sink || "—"]].forEach(([label, value], index) => { if (index) flow.append(el("span", "→", "flow-arrow")); const node = el("div", undefined, "detail-flow-node"); node.append(el("span", label, "flow-label"), el("strong", value)); flow.append(node); }); detail.append(el("h4", "Source → Sink"), flow);
  const axes = Object.entries(item.scope_axes || {}); if (axes.length) { detail.append(el("h4", "검증 근거")); const list = el("div", undefined, "evidence-list"); axes.forEach(([axis, value]) => list.append(el("div", `${axis} · ${value.status} · ${value.reason}`, "meta"))); detail.append(list); }
  const actions = el("div", undefined, "actions"); if (item.validated_poc) { const poc = el("button", "검증된 PoC 보기", "small-button success"); poc.addEventListener("click", () => openTab("outputs")); actions.append(poc); } if (item.scope_source_url) { const policy = el("a", `정책 출처 · ${item.scope_source_revision || "개정 미확인"}`, "text-link"); policy.href = item.scope_source_url; policy.target = "_blank"; policy.rel = "noreferrer"; actions.append(policy); } if (actions.childElementCount) detail.append(actions); if (item.error_code) detail.append(el("div", item.error_code, "error mono"));
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
function renderStaticTools(items = []) { replace("static-tools", items.length ? items.map((item) => { const row = el("article", undefined, "tool-row"); const identity = el("div", undefined, "row-identity"); identity.append(el("strong", item.tool), el("span", item.finding_count == null ? "결과 수 —" : `결과 ${item.finding_count}건`, "meta")); row.append(identity, badge(item.status)); return row; }) : empty("정적분석 상태가 없습니다.")); }
function renderStaticToolFindings(items = [], page = null) { replace("static-tool-findings", items.length ? items.map((item) => { const row = el("div", undefined, `overlap-row${item.overlap ? " overlap" : ""}`); row.append(el("strong", item.location, "mono"), el("span", item.tools.join(" · "), "meta")); if (item.rule_ids.length) row.append(el("div", item.rule_ids.join(" · "), "meta")); return row; }) : empty("검사 결과가 없습니다.")); document.getElementById("coverage-page-label").textContent = pageLabel(page, "건"); renderPagination("coverage", page, "coverage"); }
function artifactButton(item) { const button = el("button", undefined, "artifact-button"); const top = el("div", undefined, "artifact-row-top"); const title = el("strong", item.label_ko || item.kind, "line-clamp-2"); title.title = item.label_ko || item.kind; top.append(title); if (item.validation_status) top.append(badge(item.validation_status)); button.append(top, el("div", item.purpose_ko || "저장 아티팩트", "artifact-purpose")); const relations = el("div", undefined, "artifact-row-meta"); relations.append(el("span", `종류 ${item.kind || "—"}`), el("span", `단계 ${item.stages?.join(", ") || "—"}`), el("span", `Agent ${item.agent_roles?.join(", ") || "—"}`), el("span", `가설·Finding ${[...(item.hypothesis_ids || []), ...(item.finding_ids || [])].join(", ") || "—"}`)); button.append(relations, el("div", `${item.media_type || "형식 미확인"} · ${Number.isFinite(item.size_bytes) ? `${formatNumber(item.size_bytes)} bytes` : "크기 —"} · ${formatTime(item.created_at)}`, "mono meta")); button.addEventListener("click", () => showArtifact(item)); return button; }
async function showArtifact(item) { const viewer = document.getElementById("artifact-viewer"); viewer.replaceChildren(el("div", "불러오는 중…", "empty")); try { const payload = await getJson(item.view_url); const toolbar = el("div", undefined, "viewer-toolbar"); toolbar.append(el("strong", item.label_ko || payload.kind)); const raw = typeof payload.content === "string" ? payload.content : JSON.stringify(payload.content); const pretty = typeof payload.content === "string" ? payload.content : JSON.stringify(payload.content, null, 2); let content = el("pre", pretty, "code-view"); if (payload.rendered_html && payload.media_type === "text/markdown") { content = el("div", undefined, "markdown-content"); content.innerHTML = payload.rendered_html; } const purpose = el("div", undefined, "artifact-detail-purpose"); purpose.append(el("span", "용도", "section-label"), el("strong", item.purpose_ko || "저장 아티팩트")); if (item.validation_status) purpose.append(badge(item.validation_status)); const relations = el("dl", undefined, "artifact-detail-relations"); [["생성 단계", item.stages?.join(", ") || "—"], ["생성 Agent", item.agent_roles?.join(", ") || "—"], ["연결 가설", item.hypothesis_ids?.join(", ") || "—"], ["연결 Finding", item.finding_ids?.join(", ") || "—"]].forEach(([label, value]) => { const row = el("div"); row.append(el("dt", label), el("dd", value)); relations.append(row); }); const actions = el("div", undefined, "actions artifact-detail-actions"); const copy = el("button", "원문 복사", "small-button"); copy.addEventListener("click", async () => { await navigator.clipboard.writeText(raw); copy.textContent = "복사됨"; }); const download = el("a", "파일 다운로드", "download small-button"); download.href = item.download_url; actions.append(download, copy); const stored = el("details", undefined, "stored-source"); stored.append(el("summary", "저장 원문 보기"), el("pre", pretty, "code-view")); viewer.replaceChildren(toolbar, purpose, el("h4", "미리보기"), ...(payload.truncated ? [el("p", "미리보기는 1 MiB까지만 표시합니다.", "meta")] : []), content, el("h4", "연결 관계"), relations, el("h4", "다운로드"), actions, stored); } catch (error) { viewer.replaceChildren(el("div", String(error), "error")); } }
function selectableArtifact(item) { const row = el("div", undefined, "selectable-row"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selectedArtifacts.has(item.artifact_id); check.addEventListener("change", () => { check.checked ? state.selectedArtifacts.add(item.artifact_id) : state.selectedArtifacts.delete(item.artifact_id); updateSelectionLink(); }); row.append(check, artifactButton(item)); return row; }
function renderArtifacts(page) { const items = page?.items || []; document.getElementById("artifact-count").textContent = `${pageLabel(page, "개")}${page?.omitted_count ? ` · 최소 ${page.omitted_count}개 미표시` : ""}`; state.artifactMap = new Map(items.map((item) => [item.artifact_id, item])); replace("artifact-list", items.length ? items.map(selectableArtifact) : empty(document.getElementById("artifact-search").value.trim() ? "검색 결과가 없습니다." : "저장된 아티팩트가 없습니다.")); renderPagination("artifact", page, "artifacts"); renderArtifactKpis(page); }
function renderArtifactRelations(items = []) { replace("artifact-relations", items.length ? items.map((item) => el("div", `${item.source_kind} → ${item.relation} → ${item.target_kind}`, "relation-row mono")) : empty("저장된 아티팩트 관계가 없습니다.")); }

function renderInvocations(page) { const items = page?.items || []; document.getElementById("llm-page-label").textContent = pageLabel(page, "건"); replace("llm-invocations", items.length ? items.map((item) => { const button = el("button", undefined, `invocation-button${state.llmDetail?.invocation?.invocation_id === item.invocation_id ? " selected" : ""}`); const row = el("div", undefined, "status-row"); const name = el("strong", `${item.agent_role} · ${item.model}`, "line-clamp-2"); name.title = `${item.agent_role} · ${item.model}`; row.append(name, badge(item.status)); button.append(row, el("div", `${formatTime(item.started_at)} · 시도 ${item.attempt_number ?? "—"} · 재시도 ${item.retry_count ?? "—"}`, "meta")); if (item.hypothesis_id) { const id = el("div", item.hypothesis_id, "mono meta technical-id"); id.title = item.hypothesis_id; button.append(id); } button.addEventListener("click", () => loadInvocation(item)); return button; }) : empty("저장된 LLM 호출이 없습니다.")); renderPagination("llm", page, "llm"); renderLlmKpis(page); }
async function loadInvocation(item) { const version = state.requestVersion; const detailNode = document.getElementById("llm-detail"); detailNode.classList.remove("empty"); document.getElementById("llm-viewer").textContent = "호출 상세를 불러오는 중…"; try { const detail = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/llm/${encodeURIComponent(item.invocation_id)}`); if (version !== state.requestVersion) return; state.llmDetail = detail; state.llmView = "response"; renderLlmDetail(); renderInvocations(state.tabCache.get(tabCacheKey("llm"))); } catch (error) { document.getElementById("llm-viewer").textContent = String(error); } }
function renderLlmDetail() { const detail = state.llmDetail; if (!detail) return; const item = detail.invocation; const metadata = document.getElementById("llm-metadata"); metadata.replaceChildren(); [["Agent", item.agent_role], ["모델", item.model], ["호출 시각", formatTime(item.started_at)], ["상태", statusLabel(item.status)], ["시도·재시도", `${item.attempt_number || "—"} · ${item.retry_count}`], ["입력·출력 토큰", `${item.input_tokens ?? "—"} · ${item.output_tokens ?? "—"}`], ["연결 가설", item.hypothesis_id || "—"], ["연결 Finding", item.finding_ids?.join(", ") || "—"]].forEach(([label, value]) => { const box = el("div", undefined, "llm-meta-item"); box.append(el("span", label, "meta"), el("strong", value)); metadata.append(box); }); const viewer = document.getElementById("llm-viewer"); selectAll("[data-llm-view]").forEach((button) => { const active = button.dataset.llmView === state.llmView; button.setAttribute("aria-selected", String(active)); button.setAttribute("tabindex", active ? "0" : "-1"); if (active) viewer?.setAttribute("aria-labelledby", button.id); }); const values = { response: detail.response_result, system: detail.system_prompt, user: detail.user_prompt, "request-json": detail.stored_request_json, "response-json": detail.stored_response_json }; const value = values[state.llmView]; viewer.textContent = value == null ? "이 호출에는 해당 정보가 별도로 저장되지 않았습니다." : typeof value === "string" ? value : JSON.stringify(value, null, 2); }

function renderArtifactSubset(target, ids, map, message) { const items = (ids || []).map((id) => map.get(id)).filter(Boolean); replace(target, items.length ? items.map(artifactButton) : empty(message)); }
function renderOutputs(data) { const map = new Map((data.artifacts || []).map((item) => [item.artifact_id, item])); state.artifactMap = map; const trace = (data.finding_traces || []).find((item) => item.display_id === state.pinnedFinding); renderArtifactSubset("poc", trace ? trace.poc_artifact_ids : data.poc_artifact_ids, map, "이 페이지에는 검증된 PoC가 없습니다."); renderArtifactSubset("evidence", trace ? trace.evidence_artifact_ids : data.evidence_artifact_ids, map, "이 페이지에는 정적·동적 증거가 없습니다."); renderReports(trace ? (data.reports || []).filter((item) => item.display_id === trace.display_id) : data.reports || [], data.finding_groups || []); const summary = data.summary || {}; renderTabSummary("outputs-summary", "결과물 핵심", [{ label: "검증된 PoC", value: knownCount(summary.poc_count) }, { label: "보고서", value: knownCount(summary.report_count) }], [["증거", knownCount(summary.evidence_count)], ["전체 결과물", knownCount(data.total_items ?? data.total)]]); renderPagination("outputs", data, "outputs"); }
function reportRow(item) { const row = el("div", undefined, "report-row"); const check = document.createElement("input"); check.type = "checkbox"; check.checked = state.selectedReports.has(item.display_id); check.setAttribute("aria-label", `${item.display_id} ZIP 선택`); check.addEventListener("change", () => { check.checked ? state.selectedReports.add(item.display_id) : state.selectedReports.delete(item.display_id); updateSelectionLink(); }); const ko = el("a", `${item.display_id} 한국어 보기`, "small-button"); ko.href = item.download_url; const koDownload = el("a", "한국어 MD", "download small-button"); koDownload.href = item.download_url; row.append(check, ko, koDownload); if (item.english_available) { if (item.english_view_url) { const en = el("a", "English 보기", "small-button"); en.href = item.english_view_url; row.append(en); } if (item.english_download_url) { const enDownload = el("a", "English MD", "download small-button"); enDownload.href = item.english_download_url; row.append(enDownload); } } else row.append(el("span", "영문 미생성", "badge status-waiting")); const labels = { "report_en.md": "영문 보고서", "report_kr.md": "국문 보고서", "poc.sh": "검증 PoC", "poc.py": "검증 PoC", "bundle.zip": "첨부파일 ZIP" }; Object.entries(item.attachment_urls || {}).forEach(([name, url]) => { const attachment = el("a", labels[name] || name, "report-attachment"); attachment.href = url; attachment.download = name.split("/").pop(); row.append(attachment); }); return row; }
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

function resetLogState() { state.requestControllers.get("logs-cursor")?.abort(); state.requestControllers.get("logs-newer")?.abort(); state.requestControllers.delete("logs-cursor"); state.requestControllers.delete("logs-newer"); state.log = { items: [], oldestCursor: null, latestCursor: null, hasMore: false, initialized: false }; }
function renderEventsPage() { const page = { items: state.log.items, total_items: null }; document.getElementById("log-loaded-label").textContent = state.log.items.length ? `불러온 로그 ${state.log.items.length}개` : "최신 로그 10개"; const older = document.getElementById("log-load-older"); older.hidden = state.log.initialized && !state.log.hasMore; older.disabled = !state.log.initialized || !state.log.hasMore; older.textContent = "이전 로그 10개 불러오기"; renderEvents(); renderLogKpis(page); }
function renderEvents() { const timeline = document.getElementById("events"); const followTail = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 60; const search = document.getElementById("log-search").value.trim().toLowerCase(), status = document.getElementById("log-status").value; const items = (state.log.items || []).filter((item) => { const text = [item.stage, item.agent_role, item.summary_ko, item.hypothesis_id, item.error_code, item.tool_name].filter(Boolean).join(" ").toLowerCase(); return (!search || text.includes(search)) && (!status || item.status === status); }); replace("events", items.length ? items.map((item) => { const event = el("article", undefined, `event event-${item.status.toLowerCase()}`); const row = el("div", undefined, "status-row"); row.append(el("strong", item.summary_ko), badge(item.status)); event.append(row, el("div", `${formatTime(item.started_at)} · ${item.stage} · ${item.agent_role} · ${formatDuration(item.elapsed_ms)}`, "meta")); if (item.metrics && Object.keys(item.metrics).length) event.append(el("div", metricSummary(item.metrics), "meta")); if (item.error_code) event.append(el("div", item.error_code, "error mono")); return event; }) : empty("조건에 맞는 로그가 없습니다.")); if (followTail) timeline.scrollTop = timeline.scrollHeight; }

function tabCacheKey(tab) { const query = tab === "artifacts" ? document.getElementById("artifact-search")?.value.trim() || "" : ""; return `${state.selected}:${tab}:${state.tabOffsets[tab] || 0}:${query}`; }
async function loadActiveTab(force = false) {
  if (!state.selected) return;
  const tab = state.activeTab, key = tabCacheKey(tab), version = state.requestVersion; let data = !force ? state.tabCache.get(key) : null;
  if (data) { renderTab(tab, data); return; }
  state.requestControllers.get(tab)?.abort(); const controller = requestController(); state.requestControllers.set(tab, controller); let timedOut = false;
  const timeout = typeof window.setTimeout === "function" ? window.setTimeout(() => { timedOut = true; controller.abort(); }, 15000) : null;
  try {
    selectOne(`[data-panel="${tab}"]`)?.classList.add("loading");
    const offset = state.tabOffsets[tab] || 0, page = Math.floor(offset / PAGE_SIZE) + 1, parameters = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
    if (tab === "artifacts") { const query = document.getElementById("artifact-search")?.value.trim(); if (query) parameters.set("query", query); }
    renderListMessage(tab, offset ? "페이지 변경 중…" : tab === "artifacts" && parameters.has("query") ? "검색 중…" : "목록을 불러오는 중…");
    data = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/tabs/${tab}?${parameters}`, { signal: controller.signal });
    if (version !== state.requestVersion || state.requestControllers.get(tab) !== controller) return;
    state.tabCache.set(key, data); renderTab(tab, data);
  } catch (error) {
    if (error?.name === "AbortError" && !timedOut) return;
    const message = timedOut ? "요청 시간이 초과되었습니다." : "데이터를 불러오지 못했습니다.";
    renderListMessage(tab, message, "error", true); document.getElementById("notice").textContent = `${tab} ${message}`;
  } finally {
    if (timeout != null && typeof window.clearTimeout === "function") window.clearTimeout(timeout); if (state.requestControllers.get(tab) === controller) state.requestControllers.delete(tab); selectOne(`[data-panel="${tab}"]`)?.classList.remove("loading");
  }
}
function renderTab(tab, data) { if (tab === "overview") renderReadiness(data.readiness || []); else if (tab === "progress") { renderProgressSummary(data.pipeline || []); renderPipeline(data.pipeline || []); renderFailureGuidance(data.pipeline || []); renderExecutionHistory(data.history || []); changeStatusPage(state.statusPageOffset); state.events = data.history || []; applyReplay(Math.max(0, state.events.length - 1)); } else if (tab === "findings") { renderFindingsSummary(data); renderHypotheses(data); renderChains(data.items || []); renderFindingTraces(data.finding_traces || []); } else if (tab === "coverage") { renderCoverageKpis(data); replace("coverage-summary", staticCoverageNodes(data)); renderStaticTools(data.static_tools || []); renderStaticToolFindings(data.items || data.static_tool_findings || [], data); } else if (tab === "artifacts") { renderArtifacts(data); renderArtifactRelations(data.relations || []); } else if (tab === "llm") renderInvocations(data); else if (tab === "outputs") renderOutputs(data); else if (tab === "logs") { if (state.log.initialized) renderEventsPage(); else loadLogPage(); } }
function revealTabButton(button) { const tabs = button?.closest?.(".dashboard-tabs"); if (!tabs) return; const left = button.offsetLeft, right = left + button.offsetWidth, visibleLeft = tabs.scrollLeft, visibleRight = visibleLeft + tabs.clientWidth; if (left < visibleLeft) tabs.scrollLeft = left; else if (right > visibleRight) tabs.scrollLeft = Math.max(0, right - tabs.clientWidth); }
async function openTab(tab) { if (!TAB_NAMES.includes(tab)) return; state.activeTab = tab; let selectedButton = null; selectAll("[data-tab]").forEach((button) => { const active = button.dataset.tab === tab; button.setAttribute("aria-selected", String(active)); button.setAttribute("tabindex", active ? "0" : "-1"); if (active) selectedButton = button; }); selectAll("[data-panel]").forEach((panel) => { const active = panel.dataset.panel === tab; panel.hidden = !active; panel.classList.toggle("active", active); }); revealTabButton(selectedButton); updateTabOverflow(); if (window.location.hash !== `#${tab}`) window.history?.replaceState?.({}, "", `${window.location.pathname}#${tab}`); await loadActiveTab(); }
async function changeStatusPage(offset) { if (!state.selected) return; const requestedOffset = Math.max(0, offset); state.statusPageOffset = requestedOffset; try { const page = await getJson(`/api/analyses/${encodeURIComponent(state.selected)}/status-cells?offset=${requestedOffset}&limit=200`); if (state.statusPageOffset !== requestedOffset) return; state.statusPage = page; renderStatusGrid(page); } catch (error) { document.getElementById("status-grid-count").textContent = String(error); } }
function mergeLogItems(existing, incoming, { prepend = false } = {}) { const incomingOrdered = prepend ? [...incoming].reverse() : incoming; const combined = prepend ? [...incomingOrdered, ...existing] : [...existing, ...incomingOrdered]; const seen = new Set(); return combined.filter((item) => { if (!item?.event_id || seen.has(item.event_id)) return false; seen.add(item.event_id); return true; }).slice(0, MAX_LOG_EVENTS); }
async function loadLogPage() { if (!state.selected) return; resetLogState(); const version = state.requestVersion, selected = state.selected, controller = requestController(); state.requestControllers.set("logs-cursor", controller); document.getElementById("log-stream-status").textContent = "최신 로그 불러오는 중…"; try { const page = await getJson(`/api/analyses/${encodeURIComponent(selected)}/logs?limit=${LOG_PAGE_SIZE}`, { signal: controller.signal }); if (version !== state.requestVersion || selected !== state.selected || state.requestControllers.get("logs-cursor") !== controller) return; state.log = { items: page.items || [], oldestCursor: page.next_cursor, latestCursor: page.latest_cursor, hasMore: Boolean(page.has_more), initialized: true }; renderEventsPage(); document.getElementById("log-stream-status").textContent = "2초 자동 갱신 · 최신 우선"; } catch (error) { if (error?.name === "AbortError") return; state.log.initialized = false; replace("events", empty("로그를 불러오지 못했습니다.")); const button = document.getElementById("log-load-older"); button.hidden = false; button.disabled = false; button.textContent = "다시 시도"; document.getElementById("log-stream-status").textContent = "요청 실패"; } finally { if (state.requestControllers.get("logs-cursor") === controller) state.requestControllers.delete("logs-cursor"); } }
async function loadOlderLogs() { if (!state.log.initialized) { await loadLogPage(); return; } if (!state.log.hasMore || !state.log.oldestCursor) return; const version = state.requestVersion, selected = state.selected, before = state.log.oldestCursor, controller = requestController(), button = document.getElementById("log-load-older"); state.requestControllers.get("logs-cursor")?.abort(); state.requestControllers.set("logs-cursor", controller); button.disabled = true; button.textContent = "이전 로그 불러오는 중…"; try { const page = await getJson(`/api/analyses/${encodeURIComponent(selected)}/logs?before=${encodeURIComponent(before)}&limit=${LOG_PAGE_SIZE}`, { signal: controller.signal }); if (version !== state.requestVersion || selected !== state.selected || before !== state.log.oldestCursor || state.requestControllers.get("logs-cursor") !== controller) return; state.log.items = mergeLogItems(state.log.items, page.items || []); state.log.oldestCursor = page.next_cursor; state.log.hasMore = Boolean(page.has_more); renderEventsPage(); } catch (error) { if (error?.name !== "AbortError") { button.disabled = false; button.textContent = "다시 시도"; document.getElementById("log-stream-status").textContent = "이전 로그 요청 실패 · 표시된 로그 유지"; } } finally { if (state.requestControllers.get("logs-cursor") === controller) state.requestControllers.delete("logs-cursor"); } }
async function pollNewLogs() { if (!state.selected || state.activeTab !== "logs" || !state.log.initialized || !state.log.latestCursor || state.requestControllers.has("logs-newer")) return; const version = state.requestVersion, selected = state.selected, after = state.log.latestCursor, controller = requestController(); state.requestControllers.set("logs-newer", controller); try { const page = await getJson(`/api/analyses/${encodeURIComponent(selected)}/logs?after=${encodeURIComponent(after)}&limit=100`, { signal: controller.signal }); if (version !== state.requestVersion || selected !== state.selected || after !== state.log.latestCursor || state.requestControllers.get("logs-newer") !== controller) return; if (page.items?.length) { state.log.items = mergeLogItems(state.log.items, page.items, { prepend: true }); state.log.latestCursor = page.latest_cursor || state.log.latestCursor; renderEventsPage(); } } catch (error) { if (error?.name !== "AbortError") document.getElementById("log-stream-status").textContent = "새 로그 갱신 실패 · 기존 로그 유지"; } finally { if (state.requestControllers.get("logs-newer") === controller) state.requestControllers.delete("logs-newer"); } }
async function pageTab(tab, delta) { return pageTabTo(tab, Math.floor((state.tabOffsets[tab] || 0) / PAGE_SIZE) + 1 + Math.sign(delta)); }
function pageTabTo(tab, page) { state.tabOffsets[tab] = Math.max(0, (Math.max(1, page) - 1) * PAGE_SIZE); for (const key of [...state.tabCache.keys()]) if (key.startsWith(`${state.selected}:${tab}:`)) state.tabCache.delete(key); if (tab === "llm") { state.llmDetail = null; document.getElementById("llm-detail")?.classList.add("empty"); } if (tab === "findings") state.selectedHypothesis = null; if (tab === "artifacts") document.getElementById("artifact-viewer").replaceChildren(el("div", "아티팩트를 선택하세요.", "empty")); loadActiveTab(true).then(() => { const target = document.getElementById(LIST_TARGETS[tab]); if (target) { target.tabIndex = -1; target.focus({ preventScroll: true }); target.scrollIntoView({ block: "start", behavior: "smooth" }); } }); }
function updateSelectionLink() { const link = document.getElementById("selection-download"); if (!state.shell?.bundle_url) { link.classList.add("hidden"); return; } const parameters = new URLSearchParams({ selected: "1" }); state.selectedArtifacts.forEach((id) => parameters.append("artifact", id)); state.selectedReports.forEach((id) => parameters.append("report", id)); if (document.getElementById("include-logs").checked) parameters.set("logs", "1"); link.href = `${state.shell.bundle_url}?${parameters}`; link.textContent = `선택 결과 ZIP 다운로드 (${state.selectedArtifacts.size + state.selectedReports.size}개)`; link.classList.remove("hidden"); document.getElementById("logs-selection").classList.remove("hidden"); }
function updateDownloadLinks(shell) { [["bundle-download", shell?.bundle_url], ["presentation-download", shell?.presentation_bundle_url]].forEach(([id, url]) => { const node = document.getElementById(id); node.href = url || "#"; node.classList.toggle("hidden", !url); }); document.getElementById("logs-download").href = shell?.logs_url || "#"; updateSelectionLink(); }

function replayFrames() { return state.events || []; }
function applyReplay(index) { const frames = replayFrames(), bounded = Math.max(0, Math.min(index, Math.max(0, frames.length - 1))); state.replay.index = bounded; const slider = document.getElementById("replay-slider"); slider.max = String(Math.max(0, frames.length - 1)); slider.value = String(bounded); document.getElementById("replay-status").textContent = frames.length ? `${bounded + 1}/${frames.length} · ${frames[bounded].summary_ko}` : "재생할 저장 이벤트가 없습니다."; }
function stopReplay() { if (state.replay.timer) clearInterval(state.replay.timer); state.replay.timer = null; const button = document.getElementById("replay-toggle"); if (button) button.textContent = "재생"; }
function toggleReplay() { const frames = replayFrames(); if (!frames.length) return; if (state.replay.timer) { stopReplay(); return; } if (state.replay.index >= frames.length - 1) state.replay.index = 0; document.getElementById("replay-toggle").textContent = "일시정지"; state.replay.timer = setInterval(() => { if (state.replay.index >= frames.length - 1) { stopReplay(); return; } applyReplay(state.replay.index + 1); }, 1200); }
function resetReplay() { stopReplay(); applyReplay(Math.max(0, replayFrames().length - 1)); }

function renderDetail(detail) { state.shell = detail; document.getElementById("demo-banner").hidden = !isDemoAnalysis(detail); renderSummary(detail); renderOverview(detail); }
function clearDetail(message) { state.shell = null; state.detail = null; document.getElementById("demo-banner").hidden = true; renderSummary(null); replace("overview-content", empty(message)); replace("events", []); }
function setPresentationMode(enabled) { state.presentation = enabled; document.body.classList.toggle("presentation", enabled); const toggle = document.getElementById("presentation-toggle"); toggle.setAttribute("aria-pressed", String(enabled)); toggle.textContent = enabled ? "발표 모드 종료" : "발표 모드"; }
let drawerReturnFocus = null;
function drawerFocusables() { const sidebar = document.getElementById("analysis-sidebar"); return sidebar && typeof sidebar.querySelectorAll === "function" ? [...sidebar.querySelectorAll('button:not([disabled]), a[href], select:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])')].filter((node) => !node.hidden) : []; }
function syncDrawerAccessibility() { const sidebar = document.getElementById("analysis-sidebar"), mobile = window.matchMedia?.("(max-width: 1120px)")?.matches; if (mobile && !document.body.classList.contains("drawer-open")) sidebar.setAttribute("inert", ""); else sidebar.removeAttribute?.("inert"); }
function openDrawer() { const sidebar = document.getElementById("analysis-sidebar"); drawerReturnFocus = document.activeElement; document.body.classList.add("drawer-open"); sidebar.removeAttribute?.("inert"); document.getElementById("analysis-drawer-toggle").setAttribute("aria-expanded", "true"); document.getElementById("drawer-backdrop").hidden = false; sidebar.setAttribute("role", "dialog"); sidebar.setAttribute("aria-modal", "true"); sidebar.setAttribute("tabindex", "-1"); selectOne(".content")?.setAttribute?.("inert", ""); document.querySelector?.(".app-header")?.setAttribute("aria-hidden", "true"); document.getElementById("analysis-drawer-close")?.focus?.(); }
function closeDrawer(restoreFocus = true) { const wasOpen = document.body.classList.contains("drawer-open"), sidebar = document.getElementById("analysis-sidebar"); document.body.classList.remove("drawer-open"); document.getElementById("analysis-drawer-toggle").setAttribute("aria-expanded", "false"); document.getElementById("drawer-backdrop").hidden = true; sidebar.removeAttribute?.("role"); sidebar.removeAttribute?.("aria-modal"); sidebar.removeAttribute?.("tabindex"); selectOne(".content")?.removeAttribute?.("inert"); document.querySelector?.(".app-header")?.removeAttribute?.("aria-hidden"); syncDrawerAccessibility(); if (wasOpen && restoreFocus) drawerReturnFocus?.focus?.(); drawerReturnFocus = null; }

function updateTabOverflow() { const tabs = document.getElementById("dashboard-tabs"), dock = document.getElementById("tab-dock"); if (!tabs || !dock) return; const overflow = tabs.scrollWidth - tabs.clientWidth > 1; dock.classList.toggle("tab-overflow-left", overflow && tabs.scrollLeft > 1); dock.classList.toggle("tab-overflow-right", overflow && tabs.scrollLeft + tabs.clientWidth < tabs.scrollWidth - 1); }
function activateLlmView(button, focus = false) { state.llmView = button.dataset.llmView; renderLlmDetail(); if (focus) button.focus?.(); }
function handleTablistKeydown(event, buttons, activate) { const current = buttons.indexOf(event.currentTarget); if (current < 0) return; let next = null; if (["ArrowRight", "ArrowDown"].includes(event.key)) next = (current + 1) % buttons.length; else if (["ArrowLeft", "ArrowUp"].includes(event.key)) next = (current - 1 + buttons.length) % buttons.length; else if (event.key === "Home") next = 0; else if (event.key === "End") next = buttons.length - 1; if (next == null) return; event.preventDefault(); buttons[next].focus?.(); activate(buttons[next]); }
function trapDrawerFocus(event) { if (!document.body.classList.contains("drawer-open") || event.key !== "Tab") return; const focusable = drawerFocusables(); if (!focusable.length) { event.preventDefault(); document.getElementById("analysis-sidebar")?.focus?.(); return; } const first = focusable[0], last = focusable.at(-1); if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus?.(); } else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus?.(); } }

let refreshInFlight = false;
const refreshTask = async () => {
  const version = state.requestVersion; const connection = document.getElementById("connection"), notice = document.getElementById("notice");
  try {
    const received = await getJson("/api/repositories"), analyses = demoAnalysisVariants(received); if (version !== state.requestVersion) return;
    state.demoAliases = new Map(); analyses.filter((item) => item.demo_source_id).forEach((item) => { state.demoAliases.set(item.display_analysis_id, item); state.demoAliases.set(item.analysis_id, item); });
    const selectionExists = analyses.some((item) => [item.analysis_id, item.display_analysis_id].includes(state.selected));
    state.analyses = analyses; if ((!state.selected || !selectionExists) && analyses.length) { const previous = state.selected; state.selected = analysisRouteId(groupAnalyses(analyses)[0].items[0].item); if (previous) window.history?.replaceState?.({}, "", `/analyses/${encodeURIComponent(state.selected)}${window.location.hash || ""}`); }
    renderAnalysisList(analyses);
    if (!state.selected) { clearDetail("분석을 실행하면 현황이 표시됩니다."); notice.textContent = "저장된 분석이 없습니다."; return; }
    const selected = state.selected; const shell = await getJson(`/api/analyses/${encodeURIComponent(selected)}/summary`); if (selected !== state.selected) return;
    const changed = !state.shell || shell.updated_at !== state.shell.updated_at; state.shell = shell; state.pinnedFinding ??= readPinnedFinding(shell.analysis_id); renderDetail(shell); updateDownloadLinks(shell); if (!selectionExists) await ensureSelectedRepositoryHistory(shell);
    if (changed) { state.tabCache.clear(); await loadActiveTab(true); }
    if (state.activeTab === "logs") await pollNewLogs();
    notice.textContent = shell.stale ? "실행이 멈췄을 수 있습니다." : "저장된 최신 상태를 표시합니다."; notice.classList.toggle("warning", shell.stale);
    connection.textContent = "로컬 서버 연결됨"; connection.classList.remove("error"); document.getElementById("last-updated").textContent = `화면 갱신 ${formatTime(new Date().toISOString())}`;
  } catch (error) { connection.textContent = "연결 실패"; connection.classList.add("error"); notice.textContent = `데이터를 불러오지 못했습니다: ${error}`; notice.classList.add("warning"); }
};
const refresh = singleFlight(async () => { refreshInFlight = true; try { return await refreshTask(); } finally { refreshInFlight = false; } });

document.getElementById("log-search").addEventListener("input", renderEvents);
const dashboardTabButtons = [...selectAll("[data-tab]")];
dashboardTabButtons.forEach((button) => { button.addEventListener("click", () => openTab(button.dataset.tab)); button.addEventListener("keydown", (event) => handleTablistKeydown(event, dashboardTabButtons, (next) => openTab(next.dataset.tab))); });
selectAll("[data-open-tab]").forEach((link) => link.addEventListener("click", (event) => { event.preventDefault(); openTab(link.dataset.openTab); }));
const llmViewButtons = [...selectAll("[data-llm-view]")];
llmViewButtons.forEach((button) => { button.addEventListener("click", () => activateLlmView(button)); button.addEventListener("keydown", (event) => handleTablistKeydown(event, llmViewButtons, (next) => activateLlmView(next, true))); });
document.getElementById("analysis-drawer-toggle").addEventListener("click", openDrawer); document.getElementById("analysis-drawer-close").addEventListener("click", closeDrawer); document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
document.getElementById("artifact-search").addEventListener("input", () => { window.clearTimeout(state.filterTimers.get("artifacts")); state.filterTimers.set("artifacts", window.setTimeout(() => { state.tabOffsets.artifacts = 0; for (const key of [...state.tabCache.keys()]) if (key.startsWith(`${state.selected}:artifacts:`)) state.tabCache.delete(key); if (state.activeTab === "artifacts") loadActiveTab(true); }, 250)); }); document.getElementById("log-status").addEventListener("change", renderEvents); document.getElementById("include-logs").addEventListener("change", updateSelectionLink);
document.getElementById("status-page-prev").addEventListener("click", () => changeStatusPage(Math.max(0, state.statusPageOffset - 200))); document.getElementById("status-page-next").addEventListener("click", () => changeStatusPage(state.statusPageOffset + 200));
document.getElementById("hypothesis-prev").addEventListener("click", () => pageTab("findings", -PAGE_SIZE)); document.getElementById("hypothesis-next").addEventListener("click", () => pageTab("findings", PAGE_SIZE)); document.getElementById("coverage-prev").addEventListener("click", () => pageTab("coverage", -PAGE_SIZE)); document.getElementById("coverage-next").addEventListener("click", () => pageTab("coverage", PAGE_SIZE)); document.getElementById("artifact-prev").addEventListener("click", () => pageTab("artifacts", -PAGE_SIZE)); document.getElementById("artifact-next").addEventListener("click", () => pageTab("artifacts", PAGE_SIZE)); document.getElementById("llm-prev").addEventListener("click", () => pageTab("llm", -PAGE_SIZE)); document.getElementById("llm-next").addEventListener("click", () => pageTab("llm", PAGE_SIZE)); document.getElementById("outputs-prev").addEventListener("click", () => pageTab("outputs", -PAGE_SIZE)); document.getElementById("outputs-next").addEventListener("click", () => pageTab("outputs", PAGE_SIZE)); document.getElementById("log-load-older").addEventListener("click", loadOlderLogs);
document.getElementById("replay-toggle").addEventListener("click", toggleReplay); document.getElementById("replay-reset").addEventListener("click", resetReplay); document.getElementById("replay-slider").addEventListener("input", (event) => { stopReplay(); applyReplay(Number(event.target.value)); }); document.getElementById("presentation-toggle").addEventListener("click", () => setPresentationMode(!state.presentation));
document.getElementById("dashboard-tabs")?.addEventListener?.("scroll", updateTabOverflow, { passive: true });
window.addEventListener?.("resize", () => { updateTabOverflow(); if (window.matchMedia?.("(min-width: 1121px)").matches) closeDrawer(false); else syncDrawerAccessibility(); });
document.addEventListener?.("keydown", (event) => { trapDrawerFocus(event); if (event.key === "Escape") { if (state.presentation) setPresentationMode(false); else closeDrawer(); } if (event.key.toLowerCase() === "p" && !event.altKey && !event.ctrlKey && !event.metaKey && !["INPUT", "SELECT", "TEXTAREA"].includes(event.target.tagName)) setPresentationMode(!state.presentation); });
if (typeof IntersectionObserver === "function") { const summary = document.getElementById("summary-strip"); const summaryObserver = new IntersectionObserver(([entry]) => document.body.classList.toggle("summary-condensed", !entry.isIntersecting), { rootMargin: "-8px 0px 0px" }); if (summary) summaryObserver.observe(summary); }
const initialTab = (window.location.hash || "").slice(1); if (TAB_NAMES.includes(initialTab)) state.activeTab = initialTab; openTab(state.activeTab); syncDrawerAccessibility(); refresh(); window.setInterval(refresh, 2000);
