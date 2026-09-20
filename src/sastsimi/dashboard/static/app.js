const state = { selected: null };

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
  if (state.selected === item.analysis_id) button.classList.add("selected");
  button.append(el("strong", item.analysis_id));
  button.append(el("div", `${item.current_stage} · ${item.status}`, "status"));
  button.append(el("div", `완료 ${item.completed_count} / 저장 ${item.stage_count}`, "meta"));
  button.addEventListener("click", () => { state.selected = item.analysis_id; refresh(); });
  return button;
}

function renderDetail(detail, events) {
  const overview = document.getElementById("overview");
  overview.className = "panel";
  overview.replaceChildren(
    el("h2", detail.analysis_id),
    el("div", `현재 단계: ${detail.current_stage}`, "status"),
    el("div", `상태: ${detail.status} · 완료 ${detail.completed_count} · 가설 ${detail.hypothesis_count} · Finding ${detail.finding_count}`, "meta"),
    el("div", `commit: ${detail.commit_id || "미확인"}`, "meta")
  );
  replace("hypotheses", detail.hypotheses.map(item => {
    const card = el("article", undefined, "card");
    card.append(el("strong", item.hypothesis_id));
    card.append(el("div", `${item.current_stage} · ${item.status}`, "status"));
    card.append(el("div", `완료 ${item.completed_count}/${item.stage_count} · 판정 ${item.verdict || "미확정"} · PoC ${item.validated_poc ? "검증됨" : "미검증"}`, "meta"));
    if (item.error_code) card.append(el("div", `오류: ${item.error_code}`, "error"));
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
    if (!state.selected && analyses.length) state.selected = analyses[0].analysis_id;
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
