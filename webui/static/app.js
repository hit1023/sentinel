const feedEl = document.getElementById("feed");
const connDot = document.getElementById("connDot");
const connLabel = document.getElementById("connLabel");
const clockEl = document.getElementById("clock");

const MAX_FEED_LINES = 300;

function tick() {
  clockEl.textContent = new Date().toLocaleTimeString("ja-JP", { hour12: false });
}
setInterval(tick, 1000);
tick();

function severityClass(sev) {
  const s = (sev || "").toLowerCase();
  if (["critical", "error"].includes(s)) return s === "critical" ? "critical" : "error";
  if (s === "warning") return "warning";
  return "info";
}

const SEV_ICON = { critical: "▲", error: "✕", warning: "◆", info: "●" };

// --- カードクリックによるフィード絞り込み ---
const MAX_STORED_ALERTS = 500;
let allAlerts = []; // 表示順（新しい順）で保持する生データ
let activeFilter = null; // { type: "severity"|"category", value } | null

function matchesFilter(a) {
  if (!activeFilter) return true;
  if (activeFilter.type === "severity") return severityClass(a.severity) === activeFilter.value;
  if (activeFilter.type === "category") return a.category === activeFilter.value;
  return true;
}

function buildAlertElement(a) {
  const div = document.createElement("div");
  const sevClass = severityClass(a.severity);
  div.className = "feed-line " + sevClass;
  const ts = a.timestamp || "";
  const aiLine = a.ai_summary
    ? `<div class="ai-note"><span class="ai-badge">AI</span>${escapeHtml(a.ai_summary)}</div>`
    : "";
  const dismissedBadge = a.ai_dismissed
    ? `<span class="ai-dismissed-badge" title="元の重大度: ${(a.original_severity || "").toUpperCase()}">AI SILENCED</span>`
    : "";
  const suppressedBadge = a.suppressed
    ? `<span class="ai-dismissed-badge" title="ルール: ${escapeHtml(a.suppression_pattern || "")}">USER SILENCED</span>`
    : "";
  const hostBadge = a.host
    ? `<span class="host-badge">${escapeHtml(a.host)}</span>`
    : "";
  // 元々critical/warningだったもの（AIやユーザーの判断で既に格下げ済みのものは除く）だけ
  // 「これは脅威じゃない」ボタンを出す
  const canSuppress =
    !a.suppressed && !a.ai_dismissed && ["critical", "warning"].includes((a.severity || "").toLowerCase());
  const suppressBtn = canSuppress
    ? `<span class="suppress-btn" title="今後、同じパターンのアラートを自動的にINFO扱いにする">✕ 誤検知</span>`
    : "";
  div.innerHTML =
    `<div class="feed-line-main">` +
    `<span class="sev-icon">${SEV_ICON[sevClass] || "●"}</span>` +
    `<span class="ts">${ts}</span>` +
    hostBadge +
    `<span class="cat">${a.category || ""}</span>` +
    dismissedBadge +
    suppressedBadge +
    `<span class="msg">${escapeHtml(a.message || "")}</span>` +
    `<div class="spacer"></div>` +
    suppressBtn +
    `</div>` +
    aiLine;
  if (a.ai_dismissed || a.suppressed) {
    div.classList.add("dismissed");
  }
  if (canSuppress) {
    div.querySelector(".suppress-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      openSuppressPrompt(a);
    });
  }
  return div;
}

async function openSuppressPrompt(a) {
  const defaultPattern = (a.message || "").slice(0, 60);
  const pattern = window.prompt(
    `今後「${a.category}」カテゴリでこの文字列を含むアラートを自動的にINFO扱いにします。\n` +
      `（AIの判定に関わらず抑制されます）\n\n一致させる文字列:`,
    defaultPattern
  );
  if (pattern === null || !pattern.trim()) return;
  const hostOnly = window.confirm(
    `ホスト「${a.host}」だけに適用しますか？\nOK = このホストのみ / キャンセル = 全ホスト共通`
  );
  try {
    await fetch("/api/suppressions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        category: a.category,
        pattern: pattern.trim(),
        host: hostOnly ? a.host : null,
      }),
    });
    loadSuppressions();
  } catch (e) {
    console.error("抑制ルールの登録に失敗", e);
    alert("登録に失敗しました");
  }
}

function renderAlert(a, prepend, highlight) {
  // フィルタの有無に関わらず生データは常に保持しておく（フィルタ解除時に復元するため）
  if (prepend) {
    allAlerts.unshift(a);
  } else {
    allAlerts.push(a);
  }
  if (allAlerts.length > MAX_STORED_ALERTS) {
    allAlerts.length = MAX_STORED_ALERTS;
  }

  const sevClass = severityClass(a.severity);
  if (!matchesFilter(a)) {
    return; // フィルタに合わないものはDOMに出さない（データはallAlertsに残っている）
  }

  const div = buildAlertElement(a);
  if (prepend) {
    feedEl.prepend(div);
  } else {
    feedEl.appendChild(div);
  }
  while (feedEl.children.length > MAX_FEED_LINES) {
    feedEl.removeChild(feedEl.lastChild);
  }

  if (highlight) {
    div.classList.add("is-new");
    setTimeout(() => div.classList.remove("is-new"), 1600);
  }
  if (highlight && sevClass === "critical") {
    triggerCriticalFlash();
  }
}

function reRenderFeed() {
  feedEl.innerHTML = "";
  const visible = allAlerts.filter(matchesFilter).slice(0, MAX_FEED_LINES);
  for (const a of visible) {
    feedEl.appendChild(buildAlertElement(a));
  }
}

const FILTER_LABELS = {
  severity: { critical: "CRITICAL", warning: "WARNING", info: "INFO", error: "ERROR" },
  category: {},
};

function setFilter(filter) {
  // 同じフィルタを再クリックしたら解除する（トグル動作）
  if (
    activeFilter &&
    filter &&
    activeFilter.type === filter.type &&
    activeFilter.value === filter.value
  ) {
    filter = null;
  }
  activeFilter = filter;

  document.querySelectorAll(".stat-card[data-filter-type]").forEach((card) => {
    const isActive =
      activeFilter &&
      card.dataset.filterType === activeFilter.type &&
      card.dataset.filterValue === activeFilter.value;
    card.classList.toggle("filter-active", !!isActive);
  });

  const chip = document.getElementById("feedFilterChip");
  const label = document.getElementById("feedFilterLabel");
  if (activeFilter) {
    const text =
      FILTER_LABELS[activeFilter.type]?.[activeFilter.value] || activeFilter.value;
    label.textContent = text;
    chip.style.display = "inline-flex";
  } else {
    chip.style.display = "none";
  }

  reRenderFeed();
}

function initStatCardFilters() {
  document.querySelectorAll(".stat-card[data-filter-type]").forEach((card) => {
    card.addEventListener("click", () => {
      const type = card.dataset.filterType;
      if (type === "clear") {
        setFilter(null);
        return;
      }
      setFilter({ type, value: card.dataset.filterValue });
    });
  });
  document.getElementById("feedFilterClear").addEventListener("click", (e) => {
    e.stopPropagation();
    setFilter(null);
  });
}

function triggerCriticalFlash() {
  const overlay = document.getElementById("flashOverlay");
  overlay.classList.remove("active");
  // リフローを挟んでアニメーションを再トリガー
  void overlay.offsetWidth;
  overlay.classList.add("active");
  document.body.classList.remove("alert-critical");
  void document.body.offsetWidth;
  document.body.classList.add("alert-critical");

  const criticalCard = document.querySelector(".stat-card.sev-critical");
  if (criticalCard) {
    criticalCard.classList.remove("card-flash");
    void criticalCard.offsetWidth;
    criticalCard.classList.add("card-flash");
    setTimeout(() => criticalCard.classList.remove("card-flash"), 1200);
  }
}

function updateAiBanner(a, animate) {
  // AIが「脅威ではない」と判定して静音化したものは、わざわざ目立つ
  // TOPバナーには出さない（フィード内には引き続き薄く残る）
  if (!a || !a.ai_summary || a.ai_dismissed || a.suppressed) return;
  const banner = document.getElementById("aiBanner");
  const sevEl = document.getElementById("aiBannerSev");
  sevEl.textContent = (a.severity || "").toUpperCase();
  sevEl.className = "ai-banner-sev " + severityClass(a.severity);
  const host = a.host || "unknown";
  const category = a.category || "";
  document.getElementById("aiBannerMeta").textContent = category ? `[${host}] ${category}` : `[${host}]`;
  document.getElementById("aiBannerText").textContent = a.ai_summary;
  document.getElementById("aiBannerTime").textContent = a.timestamp || "";
  banner.style.display = "flex";
  if (animate) {
    banner.style.animation = "none";
    void banner.offsetWidth;
    banner.style.animation = "";
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function loadInitialAlerts() {
  try {
    const res = await fetch("/api/alerts?limit=100");
    const data = await res.json();
    feedEl.innerHTML = "";
    // 新しい順で来るので、上から新しい→古いになるようappendで積む
    data.alerts.forEach((a) => renderAlert(a, false));
    const latestAi = data.alerts.find((a) => a.ai_summary && !a.ai_dismissed && !a.suppressed);
    if (latestAi) updateAiBanner(latestAi, false);
  } catch (e) {
    console.error("初期アラート取得に失敗", e);
  }
}

function setConnected(ok) {
  connDot.className = "dot " + (ok ? "dot-on" : "dot-off");
  connLabel.textContent = ok ? "LIVE" : "RECONNECTING…";
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/alerts`);

  ws.onopen = () => setConnected(true);
  ws.onclose = () => {
    setConnected(false);
    setTimeout(connectWs, 2000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => {
    try {
      const record = JSON.parse(evt.data);
      renderAlert(record, true, true);
      updateAiBanner(record, true);
    } catch (e) {
      console.error("WSメッセージのパースに失敗", e);
    }
  };
}

const SEV_COLORS = { critical: "critical", warning: "warning", info: "info", error: "error" };

// --- リアルタイムスパークライン ---
const SPARK_MAX_POINTS = 40;
const sparkHistory = {};
const sparkCanvases = {};
document.querySelectorAll(".spark").forEach((el) => {
  const key = el.dataset.key;
  sparkCanvases[key] = el;
  sparkHistory[key] = [];
});

const SPARK_COLORS = {
  critical: ["#ff3860", "rgba(255,56,96,0.08)"],
  warning: ["#ffb347", "rgba(255,179,71,0.08)"],
  info: ["#24f0ff", "rgba(36,240,255,0.08)"],
  total: ["#39ff8a", "rgba(57,255,138,0.08)"],
  proc: ["#24f0ff", "rgba(36,240,255,0.08)"],
  ports: ["#24f0ff", "rgba(36,240,255,0.08)"],
  mem: ["#ff5fd8", "rgba(255,95,216,0.08)"],
};

function pushSparkValue(key, value) {
  const hist = sparkHistory[key];
  if (!hist) return;
  hist.push(value);
  while (hist.length > SPARK_MAX_POINTS) hist.shift();
  drawSparkline(key);
}

function drawSparkline(key) {
  const canvas = sparkCanvases[key];
  if (!canvas) return;
  const values = sparkHistory[key];
  if (!values.length) return;

  const dpr = window.devicePixelRatio || 1;
  const cssW = canvas.clientWidth || 140;
  const cssH = canvas.clientHeight || 34;
  if (canvas.width !== cssW * dpr || canvas.height !== cssH * dpr) {
    canvas.width = cssW * dpr;
    canvas.height = cssH * dpr;
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  let colorKey = key;
  if (key.startsWith("hostmem_")) colorKey = "mem";
  else if (key.startsWith("host_")) colorKey = "info";
  const [lineColor, fillColor] = SPARK_COLORS[colorKey] || SPARK_COLORS.info;
  const max = Math.max(1, ...values);
  const barGap = 2;
  const barWidth = Math.max(2, cssW / SPARK_MAX_POINTS - barGap);
  const startX = cssW - values.length * (barWidth + barGap);

  values.forEach((v, i) => {
    const h = Math.max(1.5, (v / max) * (cssH - 4));
    const x = startX + i * (barWidth + barGap);
    const y = cssH - h;
    const isLast = i === values.length - 1;
    ctx.fillStyle = isLast ? lineColor : fillColor.replace(/[\d.]+\)$/, isLast ? "0.9)" : "0.35)");
    ctx.beginPath();
    if (ctx.roundRect) {
      ctx.roundRect(x, y, barWidth, h, 1.5);
    } else {
      ctx.rect(x, y, barWidth, h);
    }
    ctx.fill();
    if (isLast) {
      ctx.shadowColor = lineColor;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  });
}

async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    const critical = data.by_severity.critical || 0;
    const warning = data.by_severity.warning || 0;
    const info = data.by_severity.info || 0;
    const total = data.total_alerts_24h || 0;

    document.getElementById("statCritical").textContent = critical;
    document.getElementById("statWarning").textContent = warning;
    document.getElementById("statInfo").textContent = info;
    document.getElementById("statTotal").textContent = total;
    pushSparkValue("critical", critical);
    pushSparkValue("warning", warning);
    pushSparkValue("info", info);
    pushSparkValue("total", total);

    const st = data.status || {};
    document.getElementById("statProc").textContent = st.process_count ?? "--";
    document.getElementById("statPorts").textContent = st.listen_port_count ?? "--";
    pushSparkValue("proc", st.process_count ?? 0);
    pushSparkValue("ports", st.listen_port_count ?? 0);

    if (st.updated_at) {
      const d = new Date(st.updated_at * 1000);
      document.getElementById("lastUpdate").textContent = d.toLocaleString("ja-JP");
    }

    const hostCountBadge = document.getElementById("hostCountBadge");
    hostCountBadge.textContent = `${st.online_host_count ?? 0}/${st.host_count ?? 0} HOSTS`;

    renderHostsList(data.hosts || []);
    renderCategoryBars(data.by_category || {});
  } catch (e) {
    console.error("stats取得に失敗", e);
  }
}

function renderHostsList(hosts) {
  const container = document.getElementById("hostsList");
  if (!hosts.length) {
    container.innerHTML = '<div class="mono-dim">ホストからの報告待ち…</div>';
    return;
  }
  container.innerHTML = "";
  for (const h of hosts) {
    const row = document.createElement("div");
    row.className = "host-row" + (h.online ? "" : " offline");
    const cpu = h.cpu_percent != null ? h.cpu_percent.toFixed(0) + "%" : "--";
    const mem = h.mem_percent != null ? h.mem_percent.toFixed(0) + "%" : "--";
    row.innerHTML = `
      <span class="host-dot ${h.online ? "dot-on" : "dot-off"}"></span>
      <span class="host-name">${escapeHtml(h.host || "unknown")}</span>
      <span class="host-metric">CPU ${cpu}</span>
      <canvas class="host-spark" width="70" height="22" title="CPU推移"></canvas>
      <span class="host-metric">MEM ${mem}</span>
      <canvas class="host-spark" width="70" height="22" title="MEM推移"></canvas>
    `;
    container.appendChild(row);

    // ホスト別のCPU/MEM推移をミニスパークラインで表示（履歴自体はsparkHistoryに
    // キーごとに保持し続け、行を再描画するたびに新しいcanvas要素へ紐付け直して復元する）
    const sparkCanvasEls = row.querySelectorAll(".host-spark");
    const cpuKey = "host_" + (h.host || "unknown");
    const memKey = "hostmem_" + (h.host || "unknown");
    sparkCanvases[cpuKey] = sparkCanvasEls[0];
    sparkCanvases[memKey] = sparkCanvasEls[1];
    if (!sparkHistory[cpuKey]) sparkHistory[cpuKey] = [];
    if (!sparkHistory[memKey]) sparkHistory[memKey] = [];
    if (h.cpu_percent != null) {
      pushSparkValue(cpuKey, h.cpu_percent);
    } else {
      drawSparkline(cpuKey);
    }
    if (h.mem_percent != null) {
      pushSparkValue(memKey, h.mem_percent);
    } else {
      drawSparkline(memKey);
    }
  }
}

function renderCategoryBars(byCategory) {
  const container = document.getElementById("categoryBars");
  const entries = Object.entries(byCategory).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  container.innerHTML = "";
  if (entries.length === 0) {
    container.innerHTML = '<div class="mono-dim">直近24時間のアラートはありません</div>';
    return;
  }
  for (const [cat, count] of entries) {
    const row = document.createElement("div");
    row.className = "bar-row";
    row.innerHTML = `
      <div class="bar-label"><span>${cat}</span><span>${count}</span></div>
      <div class="bar-track"><div class="bar-fill" style="width:${(count / max) * 100}%"></div></div>
    `;
    container.appendChild(row);
  }
}

async function loadSuppressions() {
  const container = document.getElementById("suppressionList");
  if (!container) return;
  try {
    const res = await fetch("/api/suppressions");
    const data = await res.json();
    const rules = data.suppressions || [];
    if (!rules.length) {
      container.innerHTML = '<div class="mono-dim">登録された除外ルールはありません</div>';
      return;
    }
    container.innerHTML = "";
    for (const rule of rules) {
      const row = document.createElement("div");
      row.className = "suppression-row";
      row.innerHTML = `
        <span class="cat">${escapeHtml(rule.category)}</span>
        <span class="suppression-scope">${rule.host ? escapeHtml(rule.host) : "全ホスト"}</span>
        <span class="suppression-pattern">${escapeHtml(rule.pattern)}</span>
        <span class="suppression-del" title="このルールを削除">✕</span>
      `;
      row.querySelector(".suppression-del").addEventListener("click", async () => {
        await fetch(`/api/suppressions/${rule.id}`, { method: "DELETE" });
        loadSuppressions();
      });
      container.appendChild(row);
    }
  } catch (e) {
    console.error("抑制ルール取得に失敗", e);
  }
}

document.getElementById("reapplySuppressionsBtn")?.addEventListener("click", async (e) => {
  const btn = e.target;
  const original = btn.textContent;
  btn.textContent = "適用中…";
  try {
    const res = await fetch("/api/suppressions/reapply", { method: "POST" });
    const data = await res.json();
    btn.textContent = `${data.updated ?? 0}件更新`;
    loadInitialAlerts();
    loadStats();
  } catch (err) {
    console.error("既存アラートへの再適用に失敗", err);
    btn.textContent = "失敗";
  } finally {
    setTimeout(() => { btn.textContent = original; }, 2000);
  }
});

initStatCardFilters();
loadInitialAlerts();
connectWs();
loadStats();
loadSuppressions();
setInterval(loadStats, 3000);
