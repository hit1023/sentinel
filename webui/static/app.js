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

function renderAlert(a, prepend, highlight) {
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
  const hostBadge = a.host
    ? `<span class="host-badge">${escapeHtml(a.host)}</span>`
    : "";
  div.innerHTML =
    `<div class="feed-line-main">` +
    `<span class="sev-icon">${SEV_ICON[sevClass] || "●"}</span>` +
    `<span class="ts">${ts}</span>` +
    hostBadge +
    `<span class="cat">${a.category || ""}</span>` +
    dismissedBadge +
    `<span class="msg">${escapeHtml(a.message || "")}</span>` +
    `</div>` +
    aiLine;
  if (a.ai_dismissed) {
    div.classList.add("dismissed");
  }
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
  if (!a || !a.ai_summary) return;
  const banner = document.getElementById("aiBanner");
  const sevEl = document.getElementById("aiBannerSev");
  sevEl.textContent = (a.severity || "").toUpperCase();
  sevEl.className = "ai-banner-sev " + severityClass(a.severity);
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
    const latestAi = data.alerts.find((a) => a.ai_summary);
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

  const [lineColor, fillColor] = SPARK_COLORS[key] || SPARK_COLORS.info;
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

// --- HOST CPU 波形チャート ---
const CPU_WAVE_MAX_POINTS = 60;
const cpuHistory = [];
const cpuWaveCanvas = document.getElementById("cpuWave");

function pushCpuValue(value) {
  cpuHistory.push(value);
  while (cpuHistory.length > CPU_WAVE_MAX_POINTS) cpuHistory.shift();
  drawCpuWave();
}

function drawCpuWave() {
  if (!cpuWaveCanvas || cpuHistory.length < 2) return;
  const dpr = window.devicePixelRatio || 1;
  const cssW = cpuWaveCanvas.clientWidth || 600;
  const cssH = cpuWaveCanvas.clientHeight || 140;
  if (cpuWaveCanvas.width !== cssW * dpr || cpuWaveCanvas.height !== cssH * dpr) {
    cpuWaveCanvas.width = cssW * dpr;
    cpuWaveCanvas.height = cssH * dpr;
  }
  const ctx = cpuWaveCanvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, cssH);

  const padTop = 10;
  const padBottom = 10;
  const usableH = cssH - padTop - padBottom;
  const max = 100; // CPU%は0-100固定スケールで波形の暴れを安定させる
  const stepX = cssW / (CPU_WAVE_MAX_POINTS - 1);
  const offsetIdx = CPU_WAVE_MAX_POINTS - cpuHistory.length;

  // 横方向のグリッド線（25/50/75%）
  ctx.strokeStyle = "rgba(36,240,255,0.08)";
  ctx.lineWidth = 1;
  [0.25, 0.5, 0.75].forEach((f) => {
    const y = padTop + usableH * (1 - f);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(cssW, y);
    ctx.stroke();
  });

  const points = cpuHistory.map((v, i) => {
    const x = (offsetIdx + i) * stepX;
    const y = padTop + usableH * (1 - Math.min(v, max) / max);
    return [x, y];
  });

  // 塗りつぶし（グラデーション、波の下側）
  ctx.beginPath();
  ctx.moveTo(points[0][0], cssH - padBottom);
  points.forEach(([x, y], i) => {
    if (i === 0) { ctx.lineTo(x, y); return; }
    const [px, py] = points[i - 1];
    const midX = (px + x) / 2;
    ctx.bezierCurveTo(midX, py, midX, y, x, y);
  });
  ctx.lineTo(points[points.length - 1][0], cssH - padBottom);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, padTop, 0, cssH - padBottom);
  grad.addColorStop(0, "rgba(57,255,138,0.35)");
  grad.addColorStop(1, "rgba(57,255,138,0.02)");
  ctx.fillStyle = grad;
  ctx.fill();

  // 波形の線
  ctx.beginPath();
  points.forEach(([x, y], i) => {
    if (i === 0) { ctx.moveTo(x, y); return; }
    const [px, py] = points[i - 1];
    const midX = (px + x) / 2;
    ctx.bezierCurveTo(midX, py, midX, y, x, y);
  });
  ctx.strokeStyle = "#39ff8a";
  ctx.lineWidth = 2;
  ctx.shadowColor = "#39ff8a";
  ctx.shadowBlur = 8;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // 現在値の光点
  const [lastX, lastY] = points[points.length - 1];
  ctx.beginPath();
  ctx.arc(lastX, lastY, 3.5, 0, Math.PI * 2);
  ctx.fillStyle = "#eafffb";
  ctx.shadowColor = "#39ff8a";
  ctx.shadowBlur = 10;
  ctx.fill();
  ctx.shadowBlur = 0;
}

window.addEventListener("resize", () => drawCpuWave());

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
    const cpu = st.cpu_percent;
    pushCpuValue(cpu ?? 0);
    document.getElementById("statCpuBig").textContent = cpu != null ? cpu.toFixed(0) + "%" : "--%";

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
      <span class="host-metric">MEM ${mem}</span>
    `;
    container.appendChild(row);
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

loadInitialAlerts();
connectWs();
loadStats();
setInterval(loadStats, 3000);
