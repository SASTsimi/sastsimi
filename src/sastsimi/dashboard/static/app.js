const routeMatch = window.location.pathname.match(/^\/analyses\/([^/]+)$/);
const state = {
  selected: routeMatch ? decodeURIComponent(routeMatch[1]) : null
};

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function replace(id, nodes) {
  const target = document.getElementById(id);
  target.replaceChildren(...nodes);
}

async function getJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error("request failed");
  return response.json();
}

function analysisButton(item) {
  const button = el("button");
  const routeId = item.display_analysis_id || item.analysis_id;
  if (state.selected === routeId) button.classList.add("selected");
  button.append(el("strong", item.display_analysis_id || item.analysis_id));
  button.append(el("div", `${item.current_stage} · ${item.status}`, "status"));
  if (item.on_demand_possible) button.append(el("div", "추가 사용량 과금 가능", "meta"));
  button.append(el("div", `진행 ${item.progress_percent}% · ${item.completed_units}/${item.known_units}`, "meta"));
  button.addEventListener("click", () => {
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

function renderDetail(detail, events) {
  const overview = document.getElementById("overview");
  overview.className = "panel";
  overview.replaceChildren(
    el("h2", detail.display_analysis_id || detail.analysis_id),
    el("div", `현재 단계: ${detail.current_stage}`, "status"),
    ...(detail.on_demand_possible ? [el("div", "추가 사용량 과금 가능", "meta")] : []),
    ...(detail.llm_attempt_count ? [el("div", `LLM 시도 ${detail.llm_attempt_count} · 토큰 입력 ${detail.llm_input_tokens} · 출력 ${detail.llm_output_tokens} · 확인된 비용 ${detail.llm_cost_minor_units ?? "미제공"}¢ · 비용 미제공 ${detail.llm_unknown_cost_calls}건`, "meta")] : []),
    (() => {
      const wrap = el("div", undefined, "progress-wrap");
      const bar = el("div", undefined, "progress-bar");
      bar.style.width = `${detail.progress_percent}%`;
      wrap.append(bar);
      return wrap;
    })(),
    el("div", `진행 ${detail.progress_percent}% · 완료 ${detail.completed_units}/${detail.known_units} · 가설 ${detail.hypothesis_count} · Finding ${detail.finding_count} · 미확정 ${detail.inconclusive_hypothesis_count} · 근거 부족 ${detail.rejected_hypothesis_count}`, "meta"),
    el("div", `Primitive 허용 ${detail.admitted_primitive_count} · 제외 ${detail.excluded_primitive_count} · 체이닝 자식 ${detail.child_hypothesis_count}`, "meta"),
    el("div", `commit: ${detail.commit_id || "미확인"}`, "meta")
  );
  replace("hypotheses", detail.hypotheses.map(item => {
    const card = el("article", undefined, "card");
    card.append(el("strong", item.hypothesis_id));
    card.append(el("div", `${item.current_stage} · ${item.status}`, "status"));
    const gateOutcome = item.disposition === "INCONCLUSIVE" ? "Gate 미확정·제보 불가" : item.disposition === "REJECT" ? "Gate 거절·제보 불가" : null;
    card.append(el("div", `완료 ${item.completed_count}/${item.stage_count} · ${gateOutcome || `판정 ${item.verdict || "미확정"}`} · PoC ${item.validated_poc ? "검증됨" : "미검증"}`, "meta"));
    const attempt = recoveryAttempt(item);
    if (attempt) card.append(attempt);
    if (item.error_code) card.append(el("div", `오류: ${item.error_code}`, "error"));
    return card;
  }));
  replace("chains", detail.hypotheses.filter(item => item.parent_hypothesis_ids.length).map(item => {
    const card = el("article", undefined, "card chain-card");
    card.append(el("strong", `${item.parent_hypothesis_ids.join(" + ")} → ${item.hypothesis_id}`));
    card.append(el("div", `깊이 ${item.chain_depth} · ${item.current_stage} · ${item.status}`, "meta"));
    return card;
  }));
  replace("events", events.map(item => {
    const event = el("article", undefined, "event");
    event.append(el("strong", `${item.agent_role} · ${item.kind}`));
    event.append(el("div", item.summary_ko));
    event.append(el("div", `${item.stage} · ${item.status}`, "meta"));
    return event;
  }));
  replace("reports", detail.reports.map(item => {
    const link = el("a", `${item.display_id} 보고서 열기`);
    link.href = item.url;
    link.target = "_blank";
    link.rel = "noreferrer";
    return link;
  }));
}

async function refresh() {
  const connection = document.getElementById("connection");
  try {
    const analyses = await getJson("/api/analyses");
    if (!state.selected && analyses.length) state.selected = analyses[0].display_analysis_id || analyses[0].analysis_id;
    replace("analyses", analyses.map(analysisButton));
    if (state.selected) {
      const [detail, events] = await Promise.all([
        getJson(`/api/analyses/${encodeURIComponent(state.selected)}`),
        getJson(`/api/analyses/${encodeURIComponent(state.selected)}/events`)
      ]);
      renderDetail(detail, events);
    }
    connection.textContent = "실시간 조회 중";
    connection.className = "connection";
  } catch (_) {
    connection.textContent = "조회 실패 · 분석은 계속됩니다";
    connection.className = "connection error";
  }
}

refresh();
setInterval(refresh, 2000);
