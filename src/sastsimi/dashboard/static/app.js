const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null,
  detail: null,
  events: [],
  selectedArtifacts: new Set(),
  selectedReports: new Set(),
};

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
  if (item.on_demand_possible) button.append(el("div", "추가 사용량 과금 가능", "meta"));
  button.addEventListener("click", () => {
    if (state.selected !== routeId) {
      state.selectedArtifacts.clear();
      state.selectedReports.clear();
    }
    state.selected = routeId;
    window.history.replaceState({}, "", `/analyses/${encodeURIComponent(routeId)}`);
    refresh();
  });
  return button;
}

function recoveryAttempt(item) {
  if (item.disposition || item.status === "COMPLETE") return null;
  if (item.attempt_number > 1 || item.error_code === "RECOVERY_EXHAUSTED") {
    return el("div", `복구 시도 ${item.attempt_number}/${item.attempt_limit}`, "meta");
  }
  return null;
}

function staticCoverageNodes(detail) {
  if (detail.static_coverage_expected == null || detail.static_coverage_verified == null) {
    return [el("div", "정적 검사 커버리지: 확인 불가 (검증된 기록 없음)", "meta")];
  }
  const nodes = [el("div", `정적 검사 파일·규칙: 검증 ${detail.static_coverage_verified}/${detail.static_coverage_expected} · 미검증 ${detail.static_coverage_gap_count}`, "meta")];
  const engines = Object.entries(detail.static_coverage_engines || {}).map(([name, count]) => `${name} ${count}`).join(" · ");
  if (engines) nodes.push(el("div", `검증 엔진: ${engines}`, "meta"));
  if (detail.static_codeql_configured === true) {
    nodes.push(el("div", `CodeQL: ${detail.static_codeql_scope === "python_only" ? "Python만" : "범위 확인 불가"} · ${detail.static_codeql_executed ? "실행 완료" : "실행 미완료"}`, "meta"));
  } else if (detail.static_codeql_configured === false) {
    nodes.push(el("div", "CodeQL: 미설정", "meta"));
  }
  if (detail.static_ast_parse_error_count || detail.static_ast_truncated) nodes.push(el("div", `Python AST 파싱 오류 ${detail.static_ast_parse_error_count || 0} · 사실 수 제한 ${detail.static_ast_truncated ? "도달" : "미도달"}`, "meta"));
  if (detail.static_coverage_unsupported?.length) {
    const unsupported = detail.static_coverage_unsupported.map(([extension, count]) => `${extension} ${count}개`).join(" · ");
    nodes.push(el("div", `알려진 소스 확장자 중 현재 규칙 범위 밖: ${unsupported}`, "meta"));
  }
  if (detail.static_coverage_gap_preview?.length) {
    const details = el("details");
    details.append(el("summary", `미검증 파일·규칙 보기 (${detail.static_coverage_gap_count}개 중 최대 100개)`));
    detail.static_coverage_gap_preview.forEach((gap) => details.append(el("div", `${gap.path} · ${gap.rule_id} · ${gap.reason}`, "meta")));
    nodes.push(details);
  }
  return nodes;
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
    ["미확정 / 근거 부족", `${detail.inconclusive_hypothesis_count} / ${detail.rejected_hypothesis_count}`],
    ["LLM 호출", String(detail.llm_attempt_count || 0)],
    ["LLM 토큰", `입력 ${detail.llm_input_tokens || 0} / 출력 ${detail.llm_output_tokens || 0}`],
    ["확인된 비용", detail.llm_cost_minor_units == null ? "미제공" : `${detail.llm_cost_minor_units}¢`],
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
  staticCoverageNodes(detail).forEach((node) => box.append(node));
  if (detail.on_demand_possible) box.append(el("div", "추가 사용량 과금 가능", "warning"));
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

function renderPipeline(items) {
  replace("pipeline", items.length ? items.map((item) => {
    const card = el("div", undefined, `stage stage-${item.status.toLowerCase()}`);
    card.append(el("div", item.label_ko, "stage-title"));
    card.append(el("div", item.stage, "mono meta"));
    const row = el("div", undefined, "status-row");
    row.append(badge(item.status), el("span", item.agent_role, "meta"));
    card.append(row);
    if (item.hypothesis_id) card.append(el("div", item.hypothesis_id, "mono meta truncate"));
    if (item.error_code) card.append(el("div", item.error_code, "error mono"));
    return card;
  }) : empty("파이프라인 상태가 아직 없습니다."));
}

function renderHypotheses(items) {
  replace("hypotheses", items.length ? items.map((item) => {
    const card = el("div", undefined, "card");
    const row = el("div", undefined, "status-row");
    row.append(el("strong", item.hypothesis_id, "mono"), badge(item.status));
    card.append(row);
    card.append(el("div", `${item.current_stage} · ${item.completed_count}/${item.stage_count}`, "meta"));
    if (item.verdict) card.append(el("div", `판정: ${item.verdict}`));
    if (item.disposition === "INCONCLUSIVE") card.append(el("div", "Gate 미확정 · 제보 불가", "warning"));
    if (item.disposition === "REJECT") card.append(el("div", "Gate 거절 · 제보 불가", "warning"));
    if (item.validated_poc) card.append(el("div", "검증된 PoC 있음", "success"));
    const scope = item.scope_status || "UNCERTAIN";
    const reporting = item.private_reporting_policy_passed ? "비공개 제보 정책 예비 판정 통과·사람 검토 필수" : scope === "DENY" ? "정책상 제보 제외" : "비공개 제보 허가 미확인";
    card.append(el("div", `Scope Gate ${scope} · 정책 ${item.scope_collection_status || "UNVERIFIED"} · ${reporting} · 외부 공개 허용 미확인`, "meta"));
    if (item.scope_source_url) {
      const source = el("a", `정책 출처 · ${item.scope_source_revision || "개정 미확인"}`);
      source.href = item.scope_source_url;
      source.target = "_blank";
      source.rel = "noreferrer";
      card.append(source);
    }
    Object.entries(item.scope_axes || {}).forEach(([axis, evidence]) => {
      const quote = evidence.quote ? ` · ${evidence.line}행 “${evidence.quote}”` : "";
      card.append(el("div", `${axis}: ${evidence.status}${quote} · ${evidence.reason}`, "meta"));
    });
    if (item.scope_reasons?.length) card.append(el("div", `정책 판정 이유: ${item.scope_reasons.join(", ")}`, "meta"));
    const attempt = recoveryAttempt(item);
    if (attempt) card.append(attempt);
    if (item.error_code) card.append(el("div", item.error_code, "error mono"));
    return card;
  }) : empty("생성된 가설이 없습니다."));
}

function renderChains(items) {
  const chained = items.filter((item) => item.chain_depth || item.parent_hypothesis_ids.length);
  replace("chains", chained.length ? chained.map((item) => {
    const card = el("div", undefined, "card chain-card");
    card.append(el("strong", `${item.hypothesis_id} (깊이 ${item.chain_depth})`, "mono"));
    card.append(el("div", `부모: ${item.parent_hypothesis_ids.join(", ") || "없음"}`, "meta"));
    return card;
  }) : empty("연계된 가설이 없습니다."));
}

function renderEvents() {
  const search = document.getElementById("log-search").value.trim().toLowerCase();
  const status = document.getElementById("log-status").value;
  const items = state.events.filter((item) => {
    const haystack = [item.stage, item.agent_role, item.summary_ko, item.hypothesis_id, item.error_code, item.tool_name].filter(Boolean).join(" ").toLowerCase();
    return (!search || haystack.includes(search)) && (!status || item.status === status);
  });
  replace("events", items.length ? items.map((item) => {
    const event = el("div", undefined, `event event-${item.status.toLowerCase()}`);
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
    toolbar.append(el("strong", payload.display_id));
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
    const view = el("button", `${item.display_id} 보기`, "small-button");
    view.addEventListener("click", () => showReport(item));
    const download = el("a", "다운로드", "download small-button");
    download.href = item.download_url;
    row.append(checkbox, view, download);
    const labels = {
      "report_en.md": "영문 보고서",
      "report_kr.md": "국문 보고서",
      "poc.sh": "검증 PoC",
      "poc.py": "검증 PoC",
      "bundle.zip": "첨부파일 ZIP",
    };
    Object.entries(item.attachment_urls || {}).forEach(([name, url]) => {
      const attachment = el("a", labels[name] || name, "report-attachment");
      attachment.href = url;
      attachment.download = name.split("/").pop();
      row.append(attachment);
    });
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

function renderDetail(detail, events) {
  state.detail = detail;
  state.events = events;
  renderOverview(detail);
  renderStaticTools(detail.static_tools || []);
  renderPipeline(detail.pipeline || []);
  renderHypotheses(detail.hypotheses || []);
  renderChains(detail.hypotheses || []);
  renderEvents();
  renderArtifacts();
  const artifactMap = new Map((detail.artifacts || []).map((item) => [item.artifact_id, item]));
  renderInvocations(detail.llm_invocations || [], artifactMap);
  renderArtifactSubset("poc", detail.poc_artifact_ids || [], artifactMap, "검증된 PoC가 없습니다.");
  renderArtifactSubset("evidence", detail.evidence_artifact_ids || [], artifactMap, "저장된 정적·동적 증거가 없습니다.");
  renderReports(detail.reports || []);
  const bundle = document.getElementById("bundle-download");
  bundle.href = detail.bundle_url || "#";
  bundle.classList.toggle("hidden", !detail.bundle_url);
  const logs = document.getElementById("logs-download");
  logs.href = detail.logs_url || "#";
  updateSelectionLink();
}

function clearDetail(message) {
  state.detail = null;
  state.events = [];
  replace("overview", empty(message));
  ["static-tools", "pipeline", "hypotheses", "events", "chains", "artifacts", "llm-invocations", "poc", "evidence", "reports"].forEach((id) => replace(id, []));
  document.getElementById("bundle-download").classList.add("hidden");
  document.getElementById("selection-download").classList.add("hidden");
  document.getElementById("logs-selection").classList.add("hidden");
}

async function refresh() {
  const connection = document.getElementById("connection");
  const notice = document.getElementById("notice");
  try {
    const analyses = await getJson("/api/analyses");
    replace("analyses", analyses.length ? analyses.map(analysisButton) : empty("저장된 분석이 없습니다."));
    if (!state.selected && analyses.length) state.selected = analyses[0].display_analysis_id || analyses[0].analysis_id;
    if (!state.selected) {
      clearDetail("분석을 실행하면 단계별 현황이 표시됩니다.");
      notice.textContent = "저장된 분석이 없습니다.";
    } else {
      const encoded = encodeURIComponent(state.selected);
      const [detail, events] = await Promise.all([
        getJson(`/api/analyses/${encoded}`),
        getJson(`/api/analyses/${encoded}/events`),
      ]);
      renderDetail(detail, events);
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
refresh();
window.setInterval(refresh, 2000);
