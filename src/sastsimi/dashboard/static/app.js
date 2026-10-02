const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null,
  coveragePages: { gaps: null, unavailable: null, unsupported: null, excluded_tests: null, out_of_scope: null },
  detail: null,
  events: [],
  selectedArtifacts: new Set(),
  selectedReports: new Set(),
  eventAnalysis: null,
  detailUpdatedAt: null,
  detailRefreshedAt: 0,
};
let refreshInFlight = false;

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
  const percentLabel = item.percentage_kind === "known_checkpoint_fraction" ? "현재 알려진 checkpoint 비율 " : "";
  row.append(badge(item.status), el("span", `${percentLabel}${item.progress_percent}%`));
  button.append(row);
  button.append(el("div", `현재 단계: ${item.current_stage}`, "meta"));
  if (item.static_disposition === "PARTIAL") button.append(el("div", "정적 분석 일부만 검증됨", "warning"));
  if (item.on_demand_possible) button.append(el("div", "추가 사용량 과금 가능", "meta"));
  button.addEventListener("click", () => {
    if (state.selected !== routeId) {
      state.selectedArtifacts.clear();
      state.selectedReports.clear();
      state.events = [];
      state.eventAnalysis = null;
      state.detail = null;
    }
    state.selected = routeId;
    state.coveragePages = { gaps: null, unavailable: null, unsupported: null, excluded_tests: null, out_of_scope: null };
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

function staticScopeNodes(detail) {
  const nodes = [];
  const groups = [
    ["검증되지 않은 제품 파일", detail.static_unavailable_file_count, detail.static_unavailable_reason_counts, detail.static_unavailable_file_preview],
    ["테스트 제외", detail.static_excluded_test_file_count, detail.static_excluded_test_reason_counts, detail.static_excluded_test_file_preview],
    ["범위 밖 제품 코드", detail.static_out_of_scope_product_count, detail.static_out_of_scope_reason_counts, detail.static_out_of_scope_product_preview],
  ];
  for (const [label, count, reasonCounts, preview] of groups) {
    if (count == null) continue;
    nodes.push(el("div", `${label} ${count}개 (검사 완료 건수에 포함하지 않음)`, "meta"));
    const reasons = Object.entries(reasonCounts || {}).map(([reason, total]) => `${reason} ${total}개`).join(" · ");
    if (reasons) nodes.push(el("div", `${label} 이유: ${reasons}`, "meta"));
    if (preview?.length) {
      const details = el("details");
      details.append(el("summary", `${label} 경로와 이유 보기 (${count}개 중 최대 100개)`));
      preview.forEach((item) => details.append(el("div", `${item.path} · ${item.reason}`, "meta")));
      nodes.push(details);
    }
  }
  return nodes;
}

function staticCoverageNodes(detail) {
  if (detail.static_coverage_expected == null || detail.static_coverage_verified == null) {
    return [
      ...(detail.static_disposition === "PARTIAL" ? [el("div", "부분 분석: 커버리지 증거를 확인할 수 없습니다.", "warning")] : []),
      el("div", "정적 검사 커버리지: 확인 불가 (검증된 기록 없음)", "meta"),
      ...staticScopeNodes(detail),
    ];
  }
  const nodes = [el("div", `정적 검사 파일·규칙: 검증 ${detail.static_coverage_verified}/${detail.static_coverage_expected} · 미검증 ${detail.static_coverage_gap_count}`, "meta")];
  if (detail.static_disposition === "PARTIAL" || detail.static_coverage_gap_count > 0 || detail.static_unavailable_file_count > 0 || detail.static_coverage_unsupported_count > 0 || detail.static_out_of_scope_product_count > 0) {
    nodes.unshift(el("div", "부분 분석: 정적 검사가 불완전합니다. 확인된 Finding은 전체 검사 완료를 뜻하지 않습니다.", "warning"));
  }
  nodes.push(el("div", `지원되지 않는 제품 파일 ${detail.static_coverage_unsupported_count ?? "확인 불가"}개 · 커버리지 SHA-256 ${detail.static_coverage_digest || "확인 불가"}`, "meta"));
  const reasons = Object.entries(detail.static_coverage_reason_counts || {}).map(([reason, count]) => `${reason} ${count}개`).join(" · ");
  if (reasons) nodes.push(el("div", `제한 이유: ${reasons}`, "meta"));
  const engines = Object.entries(detail.static_coverage_engines || {}).map(([name, count]) => `${name} ${count}`).join(" · ");
  if (engines) nodes.push(el("div", `검증 엔진: ${engines}`, "meta"));
  if (detail.static_codeql_configured === true) {
    nodes.push(el("div", `CodeQL: ${detail.static_codeql_scope === "python_only" ? "Python만" : "범위 확인 불가"} · ${detail.static_codeql_executed ? "실행 완료" : "실행 미완료"}`, "meta"));
  } else if (detail.static_codeql_configured === false) {
    nodes.push(el("div", "CodeQL: 미설정", "meta"));
  }
  if (detail.static_ast_parse_error_count || detail.static_ast_truncated) nodes.push(el("div", `Python AST 파싱 오류 ${detail.static_ast_parse_error_count || 0} · 사실 수 제한 ${detail.static_ast_truncated ? "도달" : "미도달"}`, "meta"));
  if (detail.static_coverage_unsupported?.length) {
    const unsupported = detail.static_coverage_unsupported.map(([extension, count]) => `${extension || "확장자 없음"} ${count}개`).join(" · ");
    nodes.push(el("div", `알려진 소스 확장자 중 현재 규칙 범위 밖: ${unsupported}`, "meta"));
  }
  if (detail.static_coverage_gap_preview?.length) {
    const details = el("details");
    details.append(el("summary", `미검증 파일·규칙 보기 (${detail.static_coverage_gap_count}개 중 최대 100개)`));
    detail.static_coverage_gap_preview.forEach((gap) => details.append(el("div", `${gap.path} · ${gap.rule_id} · ${gap.reason}`, "meta")));
    nodes.push(details);
  }
  nodes.push(...staticScopeNodes(detail));
  const ledgers = [
    ["gaps", detail.static_coverage_gap_count, "미검증 파일·규칙"],
    ["unavailable", detail.static_unavailable_file_count, "검증되지 않은 제품 파일"],
    ["unsupported", detail.static_coverage_unsupported_count, "지원되지 않는 파일"],
    ["excluded_tests", detail.static_excluded_test_file_count, "테스트 제외"],
    ["out_of_scope", detail.static_out_of_scope_product_count, "범위 밖 제품 코드"],
  ];
  for (const [kind, count, label] of ledgers) {
    if (!count) continue;
    if (state.coveragePages[kind]?.coverage_digest !== detail.static_coverage_digest) state.coveragePages[kind] = null;
    const page = state.coveragePages[kind];
    const section = el("section", undefined, "coverage-ledger");
    section.append(el("strong", `${label} 전체 원장 (${count}개)`));
    if (page) {
      for (const item of page.items) section.append(el("div", `${item.path} · ${item.rule_id ? `${item.rule_id} · ` : ""}${item.reason}`, "meta"));
      section.append(el("div", `${page.offset + 1}–${page.offset + page.items.length} / ${page.total}`, "meta"));
    }
    const offset = page?.offset || 0;
    const controls = el("div", undefined, "coverage-controls");
    for (const [label, nextOffset, enabled] of [
      ["이전", Math.max(0, offset - 100), Boolean(page && offset > 0)],
      [page ? "다음" : "목록 열기", page ? offset + 100 : 0, !page || offset + 100 < count]
    ]) {
      const button = el("button", label);
      button.disabled = !enabled;
      button.addEventListener("click", async () => {
        try {
          const routeId = detail.display_analysis_id || detail.analysis_id;
          state.coveragePages[kind] = await getJson(`/api/analyses/${encodeURIComponent(routeId)}/static-coverage?kind=${kind}&offset=${nextOffset}&limit=100`);
          if ((state.selected === routeId || state.selected === detail.analysis_id) && state.detail?.analysis_id === detail.analysis_id) {
            renderOverview(state.detail);
          }
        } catch (_) {
          section.append(el("div", "원장 조회 실패", "error"));
        }
      });
      controls.append(button);
    }
    section.append(controls);
    nodes.push(section);
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
  const v2 = detail.percentage_kind === "known_checkpoint_fraction";
  const values = [
    [v2 ? "현재 알려진 checkpoint 비율" : "진행률", `${detail.progress_percent}%`],
    ["현재 단계", detail.current_stage],
    ["Commit", detail.commit_id || "-"],
    ["실행 프로필", detail.profile_ref || "미기록"],
    ["Provider / 모델", [detail.provider, detail.model].filter(Boolean).join(" / ") || "미기록"],
    ["시작", formatTime(detail.started_at)],
    ["종료", detail.finished_at ? formatTime(detail.finished_at) : "진행 중"],
    ["가설", String(detail.hypothesis_count)],
    ["Finding", String(detail.finding_count)],
    ["미확정 / 근거 부족", `${detail.inconclusive_hypothesis_count} / ${detail.rejected_hypothesis_count}`],
    ["완료 작업", `${detail.completed_units}/${detail.known_units}`],
    ["Primitive 허용 / 제외", `${detail.admitted_primitive_count} / ${detail.excluded_primitive_count}`],
    ["체이닝 자식", String(detail.child_hypothesis_count)],
    ["LLM 호출", String(detail.llm_attempt_count || 0)],
    ["LLM 토큰", `입력 ${detail.llm_input_tokens || 0} / 출력 ${detail.llm_output_tokens || 0}`],
    ["토큰 미확인 호출", String(detail.llm_unknown_token_calls || 0)],
    ["확인된 비용", detail.llm_cost_minor_units == null ? "미제공" : `${detail.llm_cost_minor_units}¢`],
    ["비용 미확인 호출", String(detail.llm_unknown_cost_calls || 0)],
    ["경과 시간", formatDuration(detail.elapsed_ms)],
    ["마지막 갱신", formatTime(detail.last_updated_at)],
  ];
  if (detail.candidate_total_count != null) {
    const decisions = detail.candidate_decision_counts || {};
    values.splice(7, 0,
      ["수집 후보", String(detail.candidate_total_count)],
      ["선별", ["INCLUDE", "EXCLUDE", "UNDECIDED", "PENDING", "ERROR"].map((status) => `${status} ${decisions[status] || 0}`).join(" · ")],
      ["심층 분석", `진행 ${detail.deep_analysis_running_count || 0} · 완료 ${detail.deep_analysis_completed_count || 0} · 대기 ${detail.deep_analysis_pending_count || 0} · 오류 ${detail.deep_analysis_error_count || 0}`]
    );
  }
  if (v2) {
    const phases = detail.phase_counts || {};
    for (const [key, label] of [
      ["static", "정적 단계"], ["triage", "후보 선별"],
      ["candidate_deep", "후보 심층 처리"], ["verification", "가설 검증"],
    ]) {
      const phase = phases[key];
      if (Number.isInteger(phase?.completed) && Number.isInteger(phase?.known)) {
        values.push([label, `${phase.completed}/${phase.known}`]);
      }
    }
    const poc = phases.poc;
    if (Number.isInteger(poc?.attempted) && Number.isInteger(poc?.completed)) {
      values.push(["PoC 시도", `${poc.attempted}건 · 완료 ${poc.completed}건`]);
    }
    const surface = phases.surface;
    if (Number.isInteger(surface?.total)) {
      if (["covered", "uncovered", "insufficient"].every((key) => Number.isInteger(surface[key]))) {
        values.push(["보안 surface", `검토 근거 충족 ${surface.covered}/${surface.total} · 미검토 ${surface.uncovered} · 근거 부족 ${surface.insufficient}`]);
      } else if (Number.isInteger(surface.recorded_contexts)) {
        values.push(["보안 surface", `저장된 context ${surface.recorded_contexts}건 · 인덱스 ${surface.total}개 · coverage 확인 전`]);
      } else {
        values.push(["보안 surface", "coverage 확인 불가"]);
      }
    } else {
      values.push(["보안 surface", "coverage 확인 불가"]);
    }
  }
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
  if (v2) {
    box.append(el("div", "진행률은 현재 알려진 checkpoint 비율이며 비용·시간·저장소 전체 커버리지를 뜻하지 않습니다.", "meta"));
    if ((detail.phase_counts?.surface?.uncovered || 0) > 0 || (detail.phase_counts?.surface?.insufficient || 0) > 0) {
      box.append(el("div", "부분 분석: 보안 surface 검토 범위가 남아 있습니다.", "warning"));
    }
  }
  staticCoverageNodes(detail).forEach((node) => box.append(node));
  if (detail.status === "PAUSED") {
    const advice = detail.resume_action === "REVALIDATE_POC"
      ? `이전 PoC 결과 재검증 필요 · sastsimi resume ${detail.display_analysis_id || detail.analysis_id}`
      : detail.resume_action === "RESUME_INTERRUPTED"
        ? `실행 중단 감지 (INTERRUPTED_RESUME_REQUIRED) · sastsimi resume ${detail.display_analysis_id || detail.analysis_id}`
        : detail.resume_action === "CHECK_USAGE_TELEMETRY"
          ? "사용량 정보가 없어 일시 중단됨 · 공급자 사용량과 한도 설정을 확인하세요."
          : "예산 한도로 일시 중단됨 · 한도를 늘린 뒤 resume 하세요.";
    box.append(el("div", advice, "warning"));
  }
  const codexCleanupReview = ["CODEX_CALL_IN_FLIGHT_UNRESOLVED", "CODEX_PROCESS_CLEANUP_UNCONFIRMED"].includes(detail.error_code);
  if (detail.status === "BLOCKED" || (detail.status === "FAILED" && codexCleanupReview)) {
    const advice = codexCleanupReview
      ? "Codex 호출 또는 프로세스 정리 상태를 확인할 수 없습니다 · 운영자 수동 검토가 필요합니다. 현재 CLI에는 확인 명령이 없어 자동 재개할 수 없습니다."
      : "실행 오류로 중단됨 · 오류를 확인한 뒤 resume 하세요.";
    box.append(el("div", advice, "warning"));
  }
  if (detail.on_demand_possible) box.append(el("div", "추가 사용량 과금 가능", "warning"));
  if (detail.llm_unrecorded_in_flight_codex_calls > 0) {
    box.append(el("div", `진행·종료 미확인 Codex 호출 ${detail.llm_unrecorded_in_flight_codex_calls}건 · 실제 사용량과 과금 여부는 미확인`, "warning"));
  }
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
  const timeline = document.getElementById("events");
  const followTail = timeline.scrollHeight - timeline.scrollTop - timeline.clientHeight < 60;
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
  if (followTail) timeline.scrollTop = timeline.scrollHeight;
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
  const omitted = state.detail?.artifact_omitted_count || 0;
  document.getElementById("artifact-count").textContent = `${artifacts.length}/${state.detail?.artifacts.length || 0}개${omitted ? ` · 최소 ${omitted}개 미표시 (전체 ZIP 불가)` : ""}`;
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

function renderDetail(detail) {
  state.detail = detail;
  renderOverview(detail);
  renderStaticTools(detail.static_tools || []);
  renderPipeline(detail.pipeline || []);
  renderHypotheses(detail.hypotheses || []);
  renderChains(detail.hypotheses || []);
  renderArtifacts();
  const artifactMap = new Map((detail.artifacts || []).map((item) => [item.artifact_id, item]));
  renderInvocations(detail.llm_invocations || [], artifactMap);
  renderArtifactSubset("poc", detail.poc_artifact_ids || [], artifactMap, "검증된 PoC가 없습니다.");
  renderArtifactSubset("evidence", detail.evidence_artifact_ids || [], artifactMap, "저장된 정적·동적 증거가 없습니다.");
  renderReports(detail.reports || []);
  const bundle = document.getElementById("bundle-download");
  bundle.href = detail.bundle_url || "#";
  bundle.classList.toggle("hidden", !detail.bundle_url || !detail.artifact_projection_complete);
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
  if (refreshInFlight) return;
  refreshInFlight = true;
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
      const selected = state.selected;
      const encoded = encodeURIComponent(selected);
      if (state.eventAnalysis !== selected) {
        state.events = [];
        state.eventAnalysis = selected;
        renderEvents();
      }
      const summary = analyses.find((item) => item.analysis_id === selected || item.display_analysis_id === selected);
      const cursor = state.events.at(-1)?.event_id;
      const eventUrl = `/api/analyses/${encoded}/events`;
      const eventRequest = getJson(cursor ? `${eventUrl}?after=${encodeURIComponent(cursor)}` : eventUrl)
        .then((items) => ({ items, reset: false }))
        .catch(async (error) => {
          if (!cursor || !String(error).includes("(404)")) throw error;
          return { items: await getJson(eventUrl), reset: true };
        });
      const needsDetail = !state.detail || state.detailUpdatedAt !== summary?.updated_at || Date.now() - state.detailRefreshedAt > 30000;
      const [initialDetail, eventDelta] = await Promise.all([
        needsDetail ? getJson(`/api/analyses/${encoded}`) : Promise.resolve(null),
        eventRequest,
      ]);
      if (selected !== state.selected) return;
      const detail = initialDetail || (eventDelta.items.length ? await getJson(`/api/analyses/${encoded}`) : state.detail);
      if (selected !== state.selected) return;
      if (detail !== state.detail) {
        renderDetail(detail);
        state.detailUpdatedAt = summary?.updated_at;
        state.detailRefreshedAt = Date.now();
      }
      if (eventDelta.reset) state.events = eventDelta.items;
      else state.events.push(...eventDelta.items);
      if (eventDelta.reset || eventDelta.items.length) renderEvents();
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
  } finally {
    refreshInFlight = false;
  }
}

document.getElementById("log-search").addEventListener("input", renderEvents);
document.getElementById("log-status").addEventListener("change", renderEvents);
document.getElementById("artifact-search").addEventListener("input", renderArtifacts);
document.getElementById("include-logs").addEventListener("change", updateSelectionLink);
refresh();
window.setInterval(refresh, 2000);
