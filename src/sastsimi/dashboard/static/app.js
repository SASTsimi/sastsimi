const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null,
  analyses: [],
  detail: null,
  events: [],
  eventCursor: null,
  artifactMap: new Map(),
  pinnedFinding: null,
  selectedArtifacts: new Set(),
  selectedReports: new Set(),
  presentation: false,
  replay: { active: false, index: 0, timer: null },
};

function pinKey(analysisId) {
  return `sastsimi.dashboard.pin.${analysisId}`;
}

function readPinnedFinding(analysisId) {
  try { return window.localStorage.getItem(pinKey(analysisId)); } catch (_error) { return null; }
}

function writePinnedFinding(analysisId, displayId) {
  try {
    if (displayId) window.localStorage.setItem(pinKey(analysisId), displayId);
    else window.localStorage.removeItem(pinKey(analysisId));
  } catch (_error) { /* Local storage is optional. */ }
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function replace(id, nodes) {
  document.getElementById(id).replaceChildren(...nodes);
}

function formatTime(value) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("ko-KR", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

function formatDuration(milliseconds) {
  if (milliseconds === null || milliseconds === undefined) return "-";
  if (milliseconds < 1000) return `${milliseconds}ms`;
  return `${(milliseconds / 1000).toFixed(1)}초`;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("ko-KR");
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`요청 실패 (${response.status})`);
  return response.json();
}

function badge(status) {
  return el("span", status || "UNKNOWN", `badge status-${String(status || "unknown").toLowerCase()}`);
}

function empty(message) {
  return [el("div", message, "empty")];
}

function analysisButton(item) {
  const button = el("button");
  const routeId = item.display_analysis_id || item.analysis_id;
  if (state.selected === routeId || state.selected === item.analysis_id) button.classList.add("selected");
  button.append(el("strong", routeId));
  button.append(el("div", item.repository || "저장소 정보 없음", "meta truncate"));
  const row = el("div", undefined, "status-row");
  row.append(badge(item.status), el("span", `${item.progress_percent}%`));
  button.append(row);
  button.addEventListener("click", () => {
    if (state.selected !== routeId) {
      state.selectedArtifacts.clear();
      state.selectedReports.clear();
      state.events = [];
      state.eventCursor = null;
      state.pinnedFinding = readPinnedFinding(item.analysis_id);
      stopReplay();
    }
    state.selected = routeId;
    window.history.replaceState({}, "", `/analyses/${encodeURIComponent(routeId)}`);
    refresh();
  });
  return button;
}

function renderOverview(detail) {
  const box = el("div");
  const title = el("div", undefined, "panel-heading");
  title.append(el("h2", detail.display_analysis_id || detail.analysis_id), badge(detail.status));
  box.append(title);
  box.append(el("div", detail.repository || "저장소 정보 없음", "repository mono"));
  const metrics = el("div", undefined, "metric-grid");
  const values = [
    ["진행률", `${detail.progress_percent}%`],
    ["현재 단계", detail.current_stage],
    ["Commit", detail.commit_id || "-"],
    ["실행 프로필", detail.profile_ref || "미기록"],
    ["Provider / 모델", [detail.provider, detail.model].filter(Boolean).join(" / ") || "미기록"],
    ["시작", formatTime(detail.started_at)],
    ["종료", detail.finished_at ? formatTime(detail.finished_at) : "진행 중"],
    ["가설", String(detail.hypothesis_count)],
    ["Finding", String(detail.finding_count)],
    ["경과 시간", formatDuration(detail.elapsed_ms)],
    ["마지막 갱신", formatTime(detail.last_updated_at)],
  ];
  values.forEach(([label, value]) => {
    const metric = el("div", undefined, "metric");
    metric.append(el("span", label, "meta"), el("strong", value));
    metrics.append(metric);
  });
  box.append(metrics);
  const progress = el("div", undefined, "progress-wrap");
  const bar = el("div", undefined, "progress-bar");
  bar.style.width = `${detail.progress_percent}%`;
  progress.append(bar);
  box.append(progress);
  if (detail.stale) box.append(el("div", "30초 넘게 갱신되지 않았습니다. 실행 상태와 터미널을 확인하세요.", "warning"));
  replace("overview", [box]);
  document.getElementById("overview").classList.remove("empty");
}

function renderStaticTools(items) {
  replace("static-tools", items.length ? items.map((item) => {
    const card = el("div", undefined, "tool-card");
    card.append(el("strong", item.tool), badge(item.status));
    card.append(el("div", item.finding_count === null || item.finding_count === undefined ? "결과 수 미제공" : `결과 ${item.finding_count}건`, "meta"));
    return card;
  }) : empty("정적분석 상태가 아직 없습니다."));
}

function renderStaticToolFindings(items) {
  replace("static-tool-findings", items.length ? items.map((item) => {
    const row = el("div", undefined, `overlap-row${item.overlap ? " overlap" : ""}`);
    row.append(el("strong", item.location, "mono"));
    const tools = el("div", undefined, "actions");
    item.tools.forEach((tool) => tools.append(el("span", tool, "tool-chip")));
    row.append(tools);
    if (item.rule_ids.length) row.append(el("div", item.rule_ids.join(" · "), "meta"));
    return row;
  }) : empty("교차 비교할 정적분석 위치가 없습니다."));
}

function renderFailureGuidance(items) {
  const failed = items.filter((item) => item.error_code || ["FAILED", "BLOCKED"].includes(item.status));
  replace("failure-guidance", failed.length ? failed.map((item) => {
    const card = el("div", undefined, "card failure-card");
    const row = el("div", undefined, "status-row");
    row.append(el("strong", item.label_ko), badge(item.status));
    card.append(row);
    if (item.error_code) card.append(el("div", item.error_code, "error mono"));
    card.append(el("div", item.guidance_ko || "오류 코드를 기록하고 안전한 복구 절차를 확인하세요.", "guidance"));
    return card;
  }) : empty("현재 저장된 실패·차단 단계가 없습니다."));
}

function renderReadiness(items) {
  const required = items.filter((item) => item.required);
  const ready = required.filter((item) => item.status === "READY").length;
  replace("readiness", items.length ? items.map((item) => {
    const card = el("div", undefined, "readiness-card");
    const row = el("div", undefined, "status-row");
    row.append(el("strong", item.label_ko), badge(item.status));
    card.append(row, el("div", item.detail_ko, "meta"));
    if (!item.required) card.append(el("span", "선택 항목", "optional-label"));
    return card;
  }) : empty("저장된 준비 상태가 없습니다."));
  const title = document.querySelector("#readiness")?.closest(".panel")?.querySelector(".panel-heading .meta");
  if (title) title.textContent = `필수 ${ready}/${required.length} · 저장 기록 기준`;
}

function renderUsage(usage) {
  const values = [
    ["LLM 호출", formatNumber(usage.invocation_count)],
    ["성공 / 실패", `${formatNumber(usage.succeeded_count)} / ${formatNumber(usage.failed_count)}`],
    ["재시도", formatNumber(usage.retry_count)],
    ["입력 token", formatNumber(usage.input_tokens)],
    ["출력 token", formatNumber(usage.output_tokens)],
    ["총 token", formatNumber(usage.total_tokens)],
    ["LLM 누적 시간", formatDuration(usage.elapsed_ms)],
  ];
  replace("usage", values.map(([label, value]) => {
    const metric = el("div", undefined, "usage-metric");
    metric.append(el("span", label, "meta"), el("strong", value));
    return metric;
  }));
  document.getElementById("usage-coverage").textContent = usage.unknown_usage_count
    ? `token 미제공 ${formatNumber(usage.unknown_usage_count)}건`
    : `token 기록 ${formatNumber(usage.known_usage_count)}건`;
}

function renderPipeline(items) {
  replace("pipeline", items.length ? items.map((item) => {
    const card = el("div", undefined, `stage stage-${item.status.toLowerCase()}`);
    card.dataset.updatedAt = item.updated_at || "";
    card.append(el("div", item.label_ko, "stage-title"));
    card.append(el("div", item.stage, "mono meta"));
    const row = el("div", undefined, "status-row");
    row.append(badge(item.status), el("span", item.agent_role, "meta"));
    card.append(row);
    if (item.hypothesis_id) card.append(el("div", item.hypothesis_id, "mono meta truncate"));
    if (item.error_code) card.append(el("div", item.error_code, "error mono"));
    if (item.guidance_ko) card.append(el("div", item.guidance_ko, "guidance meta"));
    return card;
  }) : empty("파이프라인 상태가 아직 없습니다."));
}

function renderHypotheses(items) {
  replace("hypotheses", items.length ? items.map((item) => {
    const card = el("div", undefined, "card");
    const row = el("div", undefined, "status-row");
    row.append(el("strong", item.title || item.hypothesis_id), badge(item.status));
    card.append(row);
    if (item.title) card.append(el("div", item.hypothesis_id, "mono meta truncate"));
    if (item.vulnerability_type) card.append(el("div", item.vulnerability_type, "hypothesis-type"));
    card.append(el("div", `${item.current_stage} · ${item.completed_count}/${item.stage_count}`, "meta"));
    if (item.verdict) card.append(el("div", `판정: ${item.verdict}`));
    if (item.validated_poc) card.append(el("div", "검증된 PoC 있음", "success"));
    if (item.error_code) card.append(el("div", item.error_code, "error mono"));
    return card;
  }) : empty("생성된 가설이 없습니다."));
}

function renderChains(items) {
  replace("chains", items.length ? items.map((item) => {
    const card = el("article", undefined, "chain-flow");
    const heading = el("div", undefined, "status-row");
    const identity = el("div");
    identity.append(el("strong", item.title || item.hypothesis_id));
    identity.append(el("div", `${item.hypothesis_id} · 깊이 ${item.chain_depth}`, "mono meta"));
    heading.append(identity, badge(item.verdict || item.status));
    card.append(heading);

    if (item.parent_hypothesis_ids.length) {
      const parents = el("div", undefined, "chain-parents");
      parents.append(el("span", "부모", "meta"));
      item.parent_hypothesis_ids.forEach((parent) => parents.append(el("span", parent, "parent-chip mono")));
      card.append(parents);
    }

    const flow = el("div", undefined, "flow-lane");
    const source = el("div", undefined, "flow-node flow-source");
    source.append(el("span", "SOURCE", "flow-label"), el("strong", item.source || "source 미기록"));
    const finding = el("div", undefined, "flow-node flow-finding");
    finding.append(el("span", item.vulnerability_type || "HYPOTHESIS", "flow-label"), el("strong", item.summary || item.title || item.hypothesis_id));
    const sink = el("div", undefined, "flow-node flow-sink");
    sink.append(el("span", "SINK", "flow-label"), el("strong", item.sink || "sink 미기록"));
    flow.append(source, el("span", "→", "flow-arrow"), finding, el("span", "→", "flow-arrow"), sink);
    card.append(flow);
    if (item.code_locations.length) card.append(el("div", item.code_locations.join(" · "), "mono meta locations"));
    return card;
  }) : empty("시각화할 가설이 없습니다."));
}

function renderArtifactRelations(items) {
  replace("artifact-relations", items.length ? items.map((item) => {
    const row = el("div", undefined, "relation-row");
    const source = el("button", item.source_kind, "relation-node mono");
    const target = el("button", item.target_kind, "relation-node mono");
    if (state.artifactMap.has(item.source_artifact_id)) source.addEventListener("click", () => showArtifact(state.artifactMap.get(item.source_artifact_id)));
    if (state.artifactMap.has(item.target_artifact_id)) target.addEventListener("click", () => showArtifact(state.artifactMap.get(item.target_artifact_id)));
    row.append(source, el("span", "→", "relation-arrow"), target);
    return row;
  }) : empty("연결된 아티팩트 관계가 없습니다."));
}

function renderFindingTraces(items) {
  const validIds = new Set(items.map((item) => item.display_id));
  if (state.pinnedFinding && !validIds.has(state.pinnedFinding)) state.pinnedFinding = null;
  document.getElementById("finding-pin-status").textContent = state.pinnedFinding ? `${state.pinnedFinding} 고정됨` : "Finding을 고정할 수 있습니다.";
  replace("finding-traces", items.length ? items.map((item) => {
    const card = el("article", undefined, `card finding-trace${state.pinnedFinding === item.display_id ? " pinned" : ""}`);
    const heading = el("div", undefined, "status-row");
    heading.append(el("strong", `${item.display_id} · ${item.title || item.hypothesis_id || "연결 정보 없음"}`), badge(item.verdict || "RECORDED"));
    const pin = el("button", state.pinnedFinding === item.display_id ? "고정 해제" : "발표 Finding 고정", "small-button");
    pin.addEventListener("click", () => {
      state.pinnedFinding = state.pinnedFinding === item.display_id ? null : item.display_id;
      writePinnedFinding(state.detail.analysis_id, state.pinnedFinding);
      renderFindingTraces(items);
      renderPinnedOutputs();
    });
    card.append(heading, pin);
    const steps = el("div", undefined, "trace-steps");
    [
      ["정적 근거", `${item.evidence_artifact_ids.length}개`],
      ["가설", item.vulnerability_type || item.hypothesis_id || "미연결"],
      ["Source", item.source || "미기록"],
      ["Sink", item.sink || "미기록"],
      ["PoC", item.validated_poc ? "검증됨" : "없음"],
      ["보고서", item.english_available ? "한국어·영어" : "한국어"],
    ].forEach(([label, value], index) => {
      const step = el("div", undefined, "trace-step");
      step.append(el("span", label, "meta"), el("strong", value));
      steps.append(step);
      if (index < 5) steps.append(el("span", "→", "trace-arrow"));
    });
    card.append(steps);
    return card;
  }) : empty("Finding과 exact artifact 관계가 아직 저장되지 않았습니다."));
}

function renderPinnedOutputs() {
  if (!state.detail) return;
  const trace = (state.detail.finding_traces || []).find((item) => item.display_id === state.pinnedFinding);
  const pocIds = trace ? trace.poc_artifact_ids : state.detail.poc_artifact_ids || [];
  const evidenceIds = trace ? trace.evidence_artifact_ids : state.detail.evidence_artifact_ids || [];
  const reports = trace ? state.detail.reports.filter((item) => item.display_id === trace.display_id) : state.detail.reports || [];
  renderArtifactSubset("poc", pocIds, state.artifactMap, "검증된 PoC가 없습니다.");
  renderArtifactSubset("evidence", evidenceIds, state.artifactMap, "저장된 정적·동적 증거가 없습니다.");
  renderReports(reports);
}

function renderEvents() {
  const search = document.getElementById("log-search").value.trim().toLowerCase();
  const status = document.getElementById("log-status").value;
  const items = state.events.filter((item) => {
    const haystack = [item.stage, item.agent_role, item.summary_ko, item.hypothesis_id, item.error_code, item.tool_name].filter(Boolean).join(" ").toLowerCase();
    return (!search || haystack.includes(search)) && (!status || item.status === status);
  });
  replace("events", items.length ? items.map((item, index) => {
    const event = el("div", undefined, `event event-${item.status.toLowerCase()}`);
    event.dataset.replayIndex = String(index);
    event.dataset.startedAt = item.started_at || "";
    const row = el("div", undefined, "status-row");
    row.append(el("strong", item.summary_ko), badge(item.status));
    event.append(row);
    event.append(el("div", `${item.stage} · ${item.agent_role} · ${formatDuration(item.elapsed_ms)}`, "meta"));
    if (item.hypothesis_id) event.append(el("div", item.hypothesis_id, "mono meta"));
    if (item.tool_name) event.append(el("div", `도구: ${item.tool_name}`, "meta"));
    if (item.provider) event.append(el("div", `LLM: ${item.provider} / ${item.model || "미확인"}`, "meta"));
    if (item.error_code) event.append(el("div", item.error_code, "error mono"));
    return event;
  }) : empty("조건에 맞는 로그가 없습니다."));
  const timeline = document.getElementById("events");
  timeline.scrollTop = timeline.scrollHeight;
}

async function showArtifact(item) {
  const viewer = document.getElementById("artifact-viewer");
  viewer.classList.remove("empty");
  viewer.replaceChildren(el("div", "불러오는 중…", "empty"));
  try {
    const payload = await getJson(item.view_url);
    const toolbar = el("div", undefined, "viewer-toolbar");
    toolbar.append(el("strong", payload.kind));
    const actions = el("div", undefined, "actions");
    const copy = el("button", "복사", "small-button");
    const isJson = typeof payload.content !== "string";
    const raw = isJson ? JSON.stringify(payload.content) : payload.content;
    const pretty = isJson ? JSON.stringify(payload.content, null, 2) : payload.content;
    let rawMode = false;
    const content = el("pre", pretty, "code-view");
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(raw);
      copy.textContent = "복사됨";
    });
    if (isJson) {
      const toggle = el("button", "원문 보기", "small-button");
      toggle.addEventListener("click", () => {
        rawMode = !rawMode;
        content.textContent = rawMode ? raw : pretty;
        toggle.textContent = rawMode ? "트리 보기" : "원문 보기";
      });
      actions.append(toggle);
    }
    const download = el("a", "다운로드", "download small-button");
    download.href = item.download_url;
    actions.append(copy, download);
    toolbar.append(actions);
    viewer.replaceChildren(toolbar, content);
  } catch (error) {
    viewer.replaceChildren(el("div", String(error), "error"));
  }
}

function artifactButton(item) {
  const button = el("button", undefined, "artifact-button");
  button.append(el("strong", item.kind));
  button.append(el("div", `${item.media_type} · ${item.size_bytes.toLocaleString()} bytes`, "meta"));
  button.append(el("div", item.stages.join(", ") || "단계 미상", "mono meta truncate"));
  button.addEventListener("click", () => showArtifact(item));
  return button;
}

function selectableArtifact(item) {
  const row = el("div", undefined, "selectable-row");
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = state.selectedArtifacts.has(item.artifact_id);
  checkbox.setAttribute("aria-label", `${item.kind} ZIP 선택`);
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) state.selectedArtifacts.add(item.artifact_id);
    else state.selectedArtifacts.delete(item.artifact_id);
    updateSelectionLink();
  });
  row.append(checkbox, artifactButton(item));
  return row;
}

function renderArtifacts() {
  const search = document.getElementById("artifact-search").value.trim().toLowerCase();
  const artifacts = (state.detail?.artifacts || []).filter((item) => [item.kind, item.data_kind, ...item.stages, ...item.hypothesis_ids].join(" ").toLowerCase().includes(search));
  document.getElementById("artifact-count").textContent = `${artifacts.length}/${state.detail?.artifacts.length || 0}개`;
  replace("artifacts", artifacts.length ? artifacts.map(selectableArtifact) : empty("조건에 맞는 아티팩트가 없습니다."));
}

function renderInvocations(items, artifactMap) {
  replace("llm-invocations", items.length ? items.map((item) => {
    const card = el("div", undefined, "card");
    const row = el("div", undefined, "status-row");
    row.append(el("strong", `${item.provider} / ${item.model}`), badge(item.status));
    card.append(row);
    card.append(el("div", `${item.stage} · ${item.agent_role} · ${formatDuration(item.elapsed_ms)}`, "meta"));
    if (item.hypothesis_id) card.append(el("div", item.hypothesis_id, "mono meta"));
    card.append(el("div", `template ${item.template_revision || "미기록"} · 시도 ${item.attempt_number || "-"} · 재시도 ${item.retry_count}`, "meta"));
    const usage = [item.input_tokens !== null ? `입력 ${item.input_tokens}` : null, item.output_tokens !== null ? `출력 ${item.output_tokens}` : null].filter(Boolean).join(" · ");
    if (usage) card.append(el("div", usage, "meta"));
    const actions = el("div", undefined, "actions");
    [["요청 보기", item.request_artifact_id], ["응답 보기", item.response_artifact_id]].forEach(([label, id]) => {
      if (!id || !artifactMap.has(id)) return;
      const button = el("button", label, "small-button");
      button.addEventListener("click", () => showArtifact(artifactMap.get(id)));
      actions.append(button);
    });
    if (actions.children.length) card.append(actions);
    return card;
  }) : empty("저장된 LLM 요청·응답이 없습니다. 새 분석부터 안전하게 저장됩니다."));
}

function renderArtifactSubset(target, ids, artifactMap, message) {
  const items = ids.map((id) => artifactMap.get(id)).filter(Boolean);
  replace(target, items.length ? items.map(artifactButton) : empty(message));
}

function renderMarkdown(markdown) {
  const fragment = document.createDocumentFragment();
  let list = null;
  markdown.split(/\r?\n/).forEach((line) => {
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    const bullet = line.match(/^[-*]\s+(.+)$/);
    if (heading) {
      list = null;
      fragment.append(el(`h${heading[1].length}`, heading[2]));
    } else if (bullet) {
      if (!list) {
        list = el("ul");
        fragment.append(list);
      }
      list.append(el("li", bullet[1]));
    } else if (!line.trim()) {
      list = null;
      fragment.append(document.createElement("br"));
    } else {
      list = null;
      fragment.append(el("p", line));
    }
  });
  return fragment;
}

async function showReport(item) {
  const viewer = document.getElementById("report-viewer");
  viewer.classList.remove("empty");
  viewer.replaceChildren(el("div", "불러오는 중…", "empty"));
  try {
    const payload = await getJson(item.view_url);
    const toolbar = el("div", undefined, "viewer-toolbar");
    toolbar.append(el("strong", `${payload.display_id} · ${payload.language === "en" ? "English" : "한국어"}`));
    const actions = el("div", undefined, "actions");
    const toggle = el("button", "원문 보기", "small-button");
    let raw = false;
    const content = el("div", undefined, "markdown-content");
    const paint = () => {
      content.replaceChildren(raw ? el("pre", payload.markdown, "code-view") : renderMarkdown(payload.markdown));
      toggle.textContent = raw ? "렌더링 보기" : "원문 보기";
    };
    toggle.addEventListener("click", () => { raw = !raw; paint(); });
    const download = el("a", "MD 다운로드", "download small-button");
    download.href = item.download_url;
    actions.append(toggle, download);
    toolbar.append(actions);
    paint();
    viewer.replaceChildren(toolbar, content);
  } catch (error) {
    viewer.replaceChildren(el("div", String(error), "error"));
  }
}

function renderReports(items) {
  replace("reports", items.length ? items.map((item) => {
    const row = el("div", undefined, "report-row");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selectedReports.has(item.display_id);
    checkbox.setAttribute("aria-label", `${item.display_id} ZIP 선택`);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selectedReports.add(item.display_id);
      else state.selectedReports.delete(item.display_id);
      updateSelectionLink();
    });
    const view = el("button", `${item.display_id} 한국어 보기`, "small-button");
    view.addEventListener("click", () => showReport(item));
    const download = el("a", "한국어 MD", "download small-button");
    download.href = item.download_url;
    row.append(checkbox, view, download);
    if (item.english_available) {
      const englishView = el("button", "English 보기", "small-button");
      englishView.addEventListener("click", () => showReport({ ...item, view_url: item.english_view_url }));
      const englishDownload = el("a", "English MD", "download small-button");
      englishDownload.href = item.english_download_url;
      row.append(englishView, englishDownload);
    } else {
      row.append(el("span", "영문 미생성", "badge status-waiting"));
    }
    return row;
  }) : empty("생성된 보고서가 없습니다."));
}

function updateSelectionLink() {
  const link = document.getElementById("selection-download");
  if (!state.detail?.bundle_url) {
    link.classList.add("hidden");
    return;
  }
  const parameters = new URLSearchParams({ selected: "1" });
  state.selectedArtifacts.forEach((id) => parameters.append("artifact", id));
  state.selectedReports.forEach((id) => parameters.append("report", id));
  if (document.getElementById("include-logs").checked) parameters.set("logs", "1");
  link.href = `${state.detail.bundle_url}?${parameters}`;
  const count = state.selectedArtifacts.size + state.selectedReports.size;
  link.textContent = `선택 결과 ZIP 다운로드 (${count}개)`;
  link.classList.remove("hidden");
  document.getElementById("logs-selection").classList.remove("hidden");
}

function renderComparisonOptions(items) {
  const select = document.getElementById("compare-analysis");
  const previous = select.value;
  const options = items.filter((item) => ![item.analysis_id, item.display_analysis_id].includes(state.selected)).map((item) => {
    const option = document.createElement("option");
    option.value = item.display_analysis_id || item.analysis_id;
    option.textContent = `${option.value} · ${item.status}`;
    return option;
  });
  select.replaceChildren(...options);
  if (options.some((item) => item.value === previous)) select.value = previous;
  document.getElementById("compare-button").disabled = options.length === 0;
}

function renderComparison(other) {
  const current = state.detail;
  const fields = [
    ["상태", current.status, other.status],
    ["진행률", `${current.progress_percent}%`, `${other.progress_percent}%`],
    ["Commit", current.commit_id || "-", other.commit_id || "-"],
    ["Finding", String(current.finding_count), String(other.finding_count)],
    ["가설", String(current.hypothesis_count), String(other.hypothesis_count)],
    ["LLM 호출", String(current.usage.invocation_count), String(other.usage.invocation_count)],
    ["총 token", formatNumber(current.usage.total_tokens), formatNumber(other.usage.total_tokens)],
  ];
  replace("comparison", fields.map(([label, left, right]) => {
    const card = el("div", undefined, `comparison-card${left !== right ? " changed" : ""}`);
    card.append(el("span", label, "meta"), el("strong", left), el("span", "→", "comparison-arrow"), el("strong", right));
    return card;
  }));
  document.getElementById("comparison-panel").classList.remove("hidden");
}

async function compareSelectedAnalysis() {
  const value = document.getElementById("compare-analysis").value;
  if (!value || !state.detail) return;
  const target = document.getElementById("comparison");
  target.replaceChildren(el("div", "비교 데이터를 불러오는 중…", "empty"));
  document.getElementById("comparison-panel").classList.remove("hidden");
  try { renderComparison(await getJson(`/api/analyses/${encodeURIComponent(value)}`)); }
  catch (error) { target.replaceChildren(el("div", String(error), "error")); }
}

function replayFrames() {
  return state.events.map((item) => ({ time: item.started_at, label: item.summary_ko }));
}

function applyReplay(index) {
  const frames = replayFrames();
  const bounded = Math.max(0, Math.min(index, Math.max(0, frames.length - 1)));
  state.replay.index = bounded;
  const slider = document.getElementById("replay-slider");
  slider.max = String(Math.max(0, frames.length - 1));
  slider.value = String(bounded);
  if (!frames.length) {
    document.getElementById("replay-status").textContent = "재생할 저장 이벤트가 없습니다.";
    return;
  }
  const cutoff = new Date(frames[bounded].time).getTime();
  document.querySelectorAll("#events .event").forEach((node) => {
    const timestamp = node.dataset.startedAt ? new Date(node.dataset.startedAt).getTime() : Number.POSITIVE_INFINITY;
    node.classList.toggle("replay-future", state.replay.active && timestamp > cutoff);
  });
  document.querySelectorAll("#pipeline .stage").forEach((node) => {
    const timestamp = node.dataset.updatedAt ? new Date(node.dataset.updatedAt).getTime() : Number.POSITIVE_INFINITY;
    node.classList.toggle("replay-future", state.replay.active && timestamp > cutoff);
  });
  document.getElementById("replay-status").textContent = state.replay.active ? `${bounded + 1}/${frames.length} · ${frames[bounded].label}` : `저장 이벤트 ${frames.length}개 · 실시간 화면`;
}

function stopReplay() {
  if (state.replay.timer) window.clearInterval(state.replay.timer);
  state.replay.timer = null;
  document.getElementById("replay-toggle")?.replaceChildren(document.createTextNode("재생"));
}

function resetReplay() {
  stopReplay();
  state.replay.active = false;
  applyReplay(Math.max(0, replayFrames().length - 1));
}

function toggleReplay() {
  const frames = replayFrames();
  if (!frames.length) return;
  if (state.replay.timer) {
    stopReplay();
    return;
  }
  state.replay.active = true;
  if (state.replay.index >= frames.length - 1) state.replay.index = 0;
  document.getElementById("replay-toggle").textContent = "일시정지";
  applyReplay(state.replay.index);
  state.replay.timer = window.setInterval(() => {
    if (state.replay.index >= replayFrames().length - 1) {
      stopReplay();
      return;
    }
    applyReplay(state.replay.index + 1);
  }, 1200);
}

async function fetchEvents(encoded) {
  const incremental = Boolean(state.eventCursor);
  const url = `/api/analyses/${encoded}/events${incremental ? `?after=${encodeURIComponent(state.eventCursor)}` : ""}`;
  try {
    const incoming = await getJson(url);
    state.events = incremental ? [...state.events, ...incoming] : incoming;
  } catch (error) {
    if (!incremental) throw error;
    state.events = await getJson(`/api/analyses/${encoded}/events`);
  }
  state.eventCursor = state.events.at(-1)?.event_id || null;
  document.getElementById("log-stream-status").textContent = state.eventCursor ? "증분 로그 연결됨" : "이벤트 대기 중";
  return state.events;
}

function renderDetail(detail) {
  state.detail = detail;
  if (state.pinnedFinding === null) state.pinnedFinding = readPinnedFinding(detail.analysis_id);
  renderOverview(detail);
  renderReadiness(detail.readiness || []);
  renderUsage(detail.usage || {});
  renderStaticTools(detail.static_tools || []);
  renderStaticToolFindings(detail.static_tool_findings || []);
  renderPipeline(detail.pipeline || []);
  renderFailureGuidance(detail.pipeline || []);
  renderHypotheses(detail.hypotheses || []);
  renderChains(detail.hypotheses || []);
  renderEvents();
  renderArtifacts();
  const artifactMap = new Map((detail.artifacts || []).map((item) => [item.artifact_id, item]));
  state.artifactMap = artifactMap;
  renderInvocations(detail.llm_invocations || [], artifactMap);
  renderArtifactRelations(detail.artifact_relations || []);
  renderFindingTraces(detail.finding_traces || []);
  renderPinnedOutputs();
  const bundle = document.getElementById("bundle-download");
  bundle.href = detail.bundle_url || "#";
  bundle.classList.toggle("hidden", !detail.bundle_url);
  const presentation = document.getElementById("presentation-download");
  presentation.href = detail.presentation_bundle_url || "#";
  presentation.classList.toggle("hidden", !detail.presentation_bundle_url);
  const logs = document.getElementById("logs-download");
  logs.href = detail.logs_url || "#";
  updateSelectionLink();
  applyReplay(state.replay.active ? state.replay.index : Math.max(0, state.events.length - 1));
}

function clearDetail(message) {
  state.detail = null;
  state.events = [];
  replace("overview", empty(message));
  ["readiness", "usage", "static-tools", "static-tool-findings", "pipeline", "failure-guidance", "hypotheses", "events", "chains", "finding-traces", "artifacts", "llm-invocations", "artifact-relations", "poc", "evidence", "reports"].forEach((id) => replace(id, []));
  document.getElementById("usage-coverage").textContent = "";
  document.getElementById("bundle-download").classList.add("hidden");
  document.getElementById("presentation-download").classList.add("hidden");
  document.getElementById("selection-download").classList.add("hidden");
  document.getElementById("logs-selection").classList.add("hidden");
}

function setPresentationMode(enabled) {
  state.presentation = enabled;
  document.body.classList.toggle("presentation", enabled);
  const toggle = document.getElementById("presentation-toggle");
  toggle.setAttribute("aria-pressed", String(enabled));
  toggle.textContent = enabled ? "발표 모드 종료" : "발표 모드";
  if (enabled) window.scrollTo({ top: 0, behavior: "smooth" });
}

async function refresh() {
  const connection = document.getElementById("connection");
  const notice = document.getElementById("notice");
  try {
    const analyses = await getJson("/api/analyses");
    state.analyses = analyses;
    replace("analyses", analyses.length ? analyses.map(analysisButton) : empty("저장된 분석이 없습니다."));
    if (!state.selected && analyses.length) state.selected = analyses[0].display_analysis_id || analyses[0].analysis_id;
    renderComparisonOptions(analyses);
    if (!state.selected) {
      clearDetail("분석을 실행하면 단계별 현황이 표시됩니다.");
      notice.textContent = "저장된 분석이 없습니다.";
    } else {
      const encoded = encodeURIComponent(state.selected);
      const [detail] = await Promise.all([
        getJson(`/api/analyses/${encoded}`),
        fetchEvents(encoded),
      ]);
      renderDetail(detail);
      notice.textContent = detail.stale ? "실행이 멈췄을 수 있습니다." : "저장된 최신 상태를 표시합니다.";
      notice.classList.toggle("warning", detail.stale);
    }
    connection.textContent = "로컬 서버 연결됨";
    connection.classList.remove("error");
    document.getElementById("last-updated").textContent = `화면 갱신 ${formatTime(new Date().toISOString())}`;
  } catch (error) {
    connection.textContent = "연결 실패";
    connection.classList.add("error");
    notice.textContent = `데이터를 불러오지 못했습니다: ${error}`;
    notice.classList.add("warning");
  }
}

document.getElementById("log-search").addEventListener("input", renderEvents);
document.getElementById("log-status").addEventListener("change", renderEvents);
document.getElementById("artifact-search").addEventListener("input", renderArtifacts);
document.getElementById("include-logs").addEventListener("change", updateSelectionLink);
document.getElementById("compare-button").addEventListener("click", compareSelectedAnalysis);
document.getElementById("compare-close").addEventListener("click", () => document.getElementById("comparison-panel").classList.add("hidden"));
document.getElementById("replay-toggle").addEventListener("click", toggleReplay);
document.getElementById("replay-reset").addEventListener("click", resetReplay);
document.getElementById("replay-slider").addEventListener("input", (event) => {
  stopReplay();
  state.replay.active = true;
  applyReplay(Number(event.target.value));
});
document.getElementById("presentation-toggle").addEventListener("click", () => setPresentationMode(!state.presentation));
document.addEventListener("keydown", (event) => {
  if (event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement || event.target instanceof HTMLTextAreaElement) return;
  if (event.key.toLowerCase() === "p") setPresentationMode(!state.presentation);
  if (event.key === "Escape" && state.presentation) setPresentationMode(false);
});
refresh();
window.setInterval(refresh, 2000);
