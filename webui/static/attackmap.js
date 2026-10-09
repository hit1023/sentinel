// ATTACK MAP: 世界地図（ドットマトリクス）上に、攻撃元から自宅へ「びよーん」と伸びる光の線を描く。
// データは /api/attack-map（直近24時間の攻撃系アラート、攻撃元IPの緯度経度つき）。
//  - ライブ: 5秒ごとに新着イベントを取得し、明るい線で描く（まとめて届いたら少しずつずらして「ぶわっ」と出す）
//  - リプレイ: 新着が無い間は直近24時間のイベントを薄くランダム再生し、地図を常に動かしておく
//  - 打ち返し: ログイン失敗・Webスキャン＝「失敗に終わった攻撃」は、着弾地点で火花を散らし、
//    緑の光弾が同じ弧をたどって攻撃元へ跳ね返る（実際に反撃しているわけではなく、防げたことの表現）。
//    「不審なログイン成功」は防げていないので跳ね返さない
(function () {
  const wrap = document.getElementById("attackMapWrap");
  if (!wrap) return;
  // スマホ幅では上位国・ティッカーを地図の下に回すため、地図の描画領域は別要素で測る
  const area = document.getElementById("attackCanvasArea");
  const baseCanvas = document.getElementById("attackBase");
  const fxCanvas = document.getElementById("attackFx");
  const baseCtx = baseCanvas.getContext("2d");
  const fxCtx = fxCanvas.getContext("2d");

  const KIND_COLORS = { ssh: [255, 56, 96], web: [255, 179, 71], login: [199, 125, 255] };
  const KIND_LABELS = { ssh: "SSH攻撃", web: "Web攻撃", login: "不審ログイン成功" };
  const MAX_ARCS = 70;
  const LIVE_POLL_MS = 5000;
  const FULL_RELOAD_MS = 60000;

  let land = null;
  let projection = null;
  let width = 0;
  let height = 0;
  let dpr = 1;
  let data = null;          // 直近24時間の集計（/api/attack-map）
  let lastEpoch = 0;        // ライブ取得の起点
  const arcs = [];          // 描画中の線
  const impacts = [];       // 着弾・発射の波紋
  const returns = [];       // 打ち返しの光弾
  const sparks = [];        // 着弾時の火花パーティクル
  const REPEL_COLOR = [57, 255, 138];
  const pending = [];       // これから発射するライブイベント（時刻つき）
  let nextReplayAt = 0;

  // ---- 地図の土台（陸地をドットで描く。リサイズ時のみ再描画） ----
  function setupProjection() {
    // 自宅（既定: 東京）を中央やや右に置き、太平洋を挟んで米国・欧州が両側に来る向きにする
    const homeLon = data ? data.home.lon : 139.69;
    const center = homeLon - 20;
    // 南極と北極圏は攻撃元にならないので、南緯56度〜北緯78度だけをパネルいっぱいに収める
    const frame = [];
    for (let i = -179; i <= 179; i += 4) {
      frame.push([center + i, -56], [center + i, 78]);
    }
    projection = d3.geoNaturalEarth1()
      .rotate([-center, 0])
      .fitExtent([[8, 8], [width - 8, height - 8]], { type: "MultiPoint", coordinates: frame });
  }

  function drawBase() {
    baseCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    baseCtx.clearRect(0, 0, width, height);
    if (!land) return;
    // 陸地を見えないキャンバスに塗り、そのピクセルを格子状にサンプリングしてドットにする
    const off = document.createElement("canvas");
    off.width = Math.ceil(width);
    off.height = Math.ceil(height);
    const offCtx = off.getContext("2d");
    const path = d3.geoPath(projection, offCtx);
    offCtx.fillStyle = "#fff";
    offCtx.beginPath();
    path(land);
    offCtx.fill();
    const pixels = offCtx.getImageData(0, 0, off.width, off.height).data;
    const step = Math.max(4, Math.round(width / 190));
    baseCtx.fillStyle = "rgba(36, 240, 255, 0.28)";
    for (let y = step / 2; y < off.height; y += step) {
      for (let x = step / 2; x < off.width; x += step) {
        if (pixels[(Math.floor(y) * off.width + Math.floor(x)) * 4 + 3] > 0) {
          baseCtx.beginPath();
          baseCtx.arc(x, y, step * 0.22, 0, Math.PI * 2);
          baseCtx.fill();
        }
      }
    }
    // 地球の輪郭をうっすら
    const outline = d3.geoPath(projection, baseCtx);
    baseCtx.strokeStyle = "rgba(36, 240, 255, 0.12)";
    baseCtx.lineWidth = 1;
    baseCtx.beginPath();
    outline({ type: "Sphere" });
    baseCtx.stroke();
  }

  function resize() {
    const rect = area.getBoundingClientRect();
    width = rect.width;
    height = rect.height;
    dpr = window.devicePixelRatio || 1;
    for (const c of [baseCanvas, fxCanvas]) {
      c.width = Math.round(width * dpr);
      c.height = Math.round(height * dpr);
      c.style.width = `${width}px`;
      c.style.height = `${height}px`;
    }
    if (typeof d3 === "undefined") return;
    setupProjection();
    drawBase();
  }

  // ---- 線（アーク） ----
  function launch(ev, live) {
    if (!projection || !data) return;
    const from = projection([ev.lon, ev.lat]);
    const to = projection([data.home.lon, data.home.lat]);
    if (!from || !to) return;
    const dist = Math.hypot(to[0] - from[0], to[1] - from[1]);
    if (dist < 4) return;
    while (arcs.length >= MAX_ARCS) arcs.shift();
    // 制御点を中点から上へ持ち上げて弧にする（遠いほど高く跳ねる）
    const mx = (from[0] + to[0]) / 2;
    const my = (from[1] + to[1]) / 2 - Math.min(dist * 0.45, height * 0.42);
    arcs.push({
      from, to, ctrl: [mx, my],
      color: KIND_COLORS[ev.kind] || KIND_COLORS.ssh,
      alpha: live ? 1 : 0.5,
      width: live ? 2 : 1.3,
      start: performance.now(),
      duration: 900 + dist * 2.2,
      ev, live,
    });
    impacts.push({ x: from[0], y: from[1], start: performance.now(), color: KIND_COLORS[ev.kind] || KIND_COLORS.ssh, alpha: live ? 0.9 : 0.4, size: 14 });
    if (live) pushTicker(ev);
  }

  function bezier(a, t) {
    const u = 1 - t;
    return [
      u * u * a.from[0] + 2 * u * t * a.ctrl[0] + t * t * a.to[0],
      u * u * a.from[1] + 2 * u * t * a.ctrl[1] + t * t * a.to[1],
    ];
  }

  // 先端はゴムが伸びるように少し行き過ぎてから戻る（「びよーん」感）
  function easeOutBack(t) {
    const c1 = 1.25;
    const c3 = c1 + 1;
    return 1 + c3 * Math.pow(t - 1, 3) + c1 * Math.pow(t - 1, 2);
  }

  function drawArc(a, now) {
    const raw = (now - a.start) / a.duration;
    const head = Math.min(1, raw < 1 ? easeOutBack(raw) : 1);
    // 着弾後は尾が先端へ追いつくように縮みながら消える
    const tailStart = raw < 1 ? Math.max(0, head - 0.55) : Math.min(1, (raw - 1) * 1.6 + 0.45);
    if (tailStart >= 1) return false;
    const [r, g, b] = a.color;
    const segments = 28;
    for (let i = 0; i < segments; i++) {
      const t0 = tailStart + ((head - tailStart) * i) / segments;
      const t1 = tailStart + ((head - tailStart) * (i + 1)) / segments;
      const p0 = bezier(a, Math.min(t0, 1));
      const p1 = bezier(a, Math.min(t1, 1));
      const k = (i + 1) / segments; // 先端ほど明るく太い
      fxCtx.strokeStyle = `rgba(${r},${g},${b},${a.alpha * k})`;
      fxCtx.lineWidth = a.width * (0.4 + k);
      fxCtx.beginPath();
      fxCtx.moveTo(p0[0], p0[1]);
      fxCtx.lineTo(p1[0], p1[1]);
      fxCtx.stroke();
    }
    if (raw < 1) {
      const p = bezier(a, Math.min(head, 1));
      const glow = fxCtx.createRadialGradient(p[0], p[1], 0, p[0], p[1], 9 * a.width);
      glow.addColorStop(0, `rgba(255,255,255,${a.alpha})`);
      glow.addColorStop(0.3, `rgba(${r},${g},${b},${a.alpha * 0.8})`);
      glow.addColorStop(1, `rgba(${r},${g},${b},0)`);
      fxCtx.fillStyle = glow;
      fxCtx.beginPath();
      fxCtx.arc(p[0], p[1], 9 * a.width, 0, Math.PI * 2);
      fxCtx.fill();
    } else if (!a.landed) {
      a.landed = true;
      impacts.push({ x: a.to[0], y: a.to[1], start: now, color: a.color, alpha: a.alpha, size: a.live ? 30 : 16 });
      if (a.ev.kind !== "login") repel(a, now);
    }
    return true;
  }

  // 防げた攻撃: 着弾点で火花を散らし、緑の光弾を攻撃元へ打ち返す
  function repel(a, now) {
    const n = a.live ? 14 : 6;
    for (let i = 0; i < n; i++) {
      const ang = Math.random() * Math.PI * 2;
      const speed = (a.live ? 1.6 : 1) * (0.6 + Math.random() * 1.8);
      sparks.push({
        x: a.to[0], y: a.to[1], vx: Math.cos(ang) * speed, vy: Math.sin(ang) * speed - 0.6,
        start: now, life: 500 + Math.random() * 500,
        color: Math.random() < 0.6 ? REPEL_COLOR : a.color, alpha: a.alpha,
      });
    }
    returns.push({ arc: a, start: now + 120, duration: a.duration * 0.55, alpha: a.alpha, live: a.live });
  }

  function drawReturn(rt, now) {
    const raw = (now - rt.start) / rt.duration;
    if (raw < 0) return true;
    if (raw >= 1) {
      // 攻撃元に命中: 緑の小さな波紋
      impacts.push({ x: rt.arc.from[0], y: rt.arc.from[1], start: now, color: REPEL_COLOR, alpha: rt.alpha, size: rt.live ? 18 : 10 });
      return false;
    }
    const at = 1 - easeOutQuad(raw); // 着弾点(t=1)から攻撃元(t=0)へ、減速しながら戻る
    const [r, g, b] = REPEL_COLOR;
    const segments = 10;
    for (let i = 0; i < segments; i++) {
      const t0 = Math.min(1, at + (i / segments) * 0.12);
      const t1 = Math.min(1, at + ((i + 1) / segments) * 0.12);
      const p0 = bezier(rt.arc, t0);
      const p1 = bezier(rt.arc, t1);
      const k = 1 - i / segments;
      fxCtx.strokeStyle = `rgba(${r},${g},${b},${rt.alpha * k * 0.9})`;
      fxCtx.lineWidth = (rt.live ? 2.2 : 1.4) * k + 0.3;
      fxCtx.beginPath();
      fxCtx.moveTo(p0[0], p0[1]);
      fxCtx.lineTo(p1[0], p1[1]);
      fxCtx.stroke();
    }
    const p = bezier(rt.arc, at);
    const rad = rt.live ? 7 : 4.5;
    const glow = fxCtx.createRadialGradient(p[0], p[1], 0, p[0], p[1], rad);
    glow.addColorStop(0, `rgba(255,255,255,${rt.alpha})`);
    glow.addColorStop(0.4, `rgba(${r},${g},${b},${rt.alpha * 0.8})`);
    glow.addColorStop(1, `rgba(${r},${g},${b},0)`);
    fxCtx.fillStyle = glow;
    fxCtx.beginPath();
    fxCtx.arc(p[0], p[1], rad, 0, Math.PI * 2);
    fxCtx.fill();
    return true;
  }

  function easeOutQuad(t) {
    return 1 - (1 - t) * (1 - t);
  }

  function drawSpark(sp, now) {
    const t = (now - sp.start) / sp.life;
    if (t >= 1) return false;
    sp.x += sp.vx;
    sp.y += sp.vy;
    sp.vy += 0.05; // わずかに重力
    sp.vx *= 0.97;
    const [r, g, b] = sp.color;
    fxCtx.fillStyle = `rgba(${r},${g},${b},${sp.alpha * (1 - t)})`;
    fxCtx.beginPath();
    fxCtx.arc(sp.x, sp.y, 1.6 * (1 - t) + 0.4, 0, Math.PI * 2);
    fxCtx.fill();
    return true;
  }

  function drawImpact(im, now) {
    const t = (now - im.start) / 900;
    if (t >= 1) return false;
    const [r, g, b] = im.color;
    fxCtx.strokeStyle = `rgba(${r},${g},${b},${im.alpha * (1 - t)})`;
    fxCtx.lineWidth = 1.5;
    fxCtx.beginPath();
    fxCtx.arc(im.x, im.y, 2 + im.size * t, 0, Math.PI * 2);
    fxCtx.stroke();
    return true;
  }

  function drawSources(now) {
    if (!data) return;
    const max = Math.max(1, ...data.sources.map((s) => s.count));
    for (const s of data.sources) {
      const p = projection([s.lon, s.lat]);
      if (!p) continue;
      const kind = Object.entries(s.kinds).sort((x, y) => y[1] - x[1])[0][0];
      const [r, g, b] = KIND_COLORS[kind] || KIND_COLORS.ssh;
      const radius = 1.5 + 4 * Math.sqrt(s.count / max);
      const pulse = 0.55 + 0.45 * Math.sin(now / 600 + s.lat);
      fxCtx.fillStyle = `rgba(${r},${g},${b},${0.35 + 0.4 * pulse})`;
      fxCtx.beginPath();
      fxCtx.arc(p[0], p[1], radius, 0, Math.PI * 2);
      fxCtx.fill();
    }
    // 自宅（攻撃先）
    const h = projection([data.home.lon, data.home.lat]);
    if (h) {
      const pulse = (now % 2000) / 2000;
      fxCtx.strokeStyle = `rgba(57,255,138,${0.8 * (1 - pulse)})`;
      fxCtx.lineWidth = 1.5;
      fxCtx.beginPath();
      fxCtx.arc(h[0], h[1], 4 + 14 * pulse, 0, Math.PI * 2);
      fxCtx.stroke();
      fxCtx.fillStyle = "#39ff8a";
      fxCtx.beginPath();
      fxCtx.arc(h[0], h[1], 3.5, 0, Math.PI * 2);
      fxCtx.fill();
      fxCtx.font = "10px 'JetBrains Mono', monospace";
      fxCtx.fillText(data.home.label, h[0] + 8, h[1] + 14);
    }
  }

  function frame(now) {
    fxCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    fxCtx.clearRect(0, 0, width, height);
    if (projection && data) {
      // ライブイベントを予定時刻に発射
      while (pending.length && pending[0].at <= now) launch(pending.shift().ev, true);
      // 新着が無ければ、直近24時間の攻撃を薄くリプレイして地図を動かし続ける
      if (!pending.length && now >= nextReplayAt && data.events.length) {
        const recent = data.events;
        // 新しいイベントほど選ばれやすくする
        const idx = Math.floor(recent.length * Math.sqrt(Math.random()));
        launch(recent[Math.min(idx, recent.length - 1)], false);
        nextReplayAt = now + 180 + Math.random() * 520;
      }
      drawSources(now);
      fxCtx.globalCompositeOperation = "lighter";
      for (let i = arcs.length - 1; i >= 0; i--) if (!drawArc(arcs[i], now)) arcs.splice(i, 1);
      for (let i = returns.length - 1; i >= 0; i--) if (!drawReturn(returns[i], now)) returns.splice(i, 1);
      for (let i = sparks.length - 1; i >= 0; i--) if (!drawSpark(sparks[i], now)) sparks.splice(i, 1);
      for (let i = impacts.length - 1; i >= 0; i--) if (!drawImpact(impacts[i], now)) impacts.splice(i, 1);
      fxCtx.globalCompositeOperation = "source-over";
    }
    requestAnimationFrame(frame);
  }

  // ---- 文字情報（上位国・ティッカー・統計） ----
  function flag(cc) {
    if (!cc || cc.length !== 2) return "🏴";
    return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
  }

  function renderInfo() {
    const top = document.getElementById("attackTop");
    const stats = document.getElementById("attackStats");
    stats.textContent = `${data.total_events.toLocaleString()}件 / ${data.unique_ips.toLocaleString()} IP`
      + (data.located_events < data.total_events ? `（位置特定 ${data.located_events.toLocaleString()}件）` : "");
    const max = Math.max(1, ...data.top_countries.map((c) => c.count));
    top.innerHTML = '<div class="attack-top-title">TOP SOURCES / 24H</div>' + (data.top_countries.length
      ? data.top_countries.map((c) => `
        <div class="attack-top-row" title="${escapeHtml(`${c.country}: ${c.count}件 / ${c.ips} IP`)}">
          <span class="attack-flag">${flag(c.cc)}</span>
          <span class="attack-cc">${escapeHtml(c.cc || "??")}</span>
          <span class="attack-bar"><span style="width:${(c.count / max) * 100}%"></span></span>
          <span class="attack-count">${c.count.toLocaleString()}</span>
        </div>`).join("")
      : '<div class="mono-dim">外部からの攻撃はありません</div>');
  }

  function pushTicker(ev) {
    const ticker = document.getElementById("attackTicker");
    const [r, g, b] = KIND_COLORS[ev.kind] || KIND_COLORS.ssh;
    const time = new Date(ev.epoch * 1000).toLocaleTimeString("ja-JP", { hour12: false });
    const line = document.createElement("div");
    line.className = "attack-tick";
    line.innerHTML = `<span class="mono-dim">${time}</span> `
      + `<span style="color:rgb(${r},${g},${b})">${escapeHtml(KIND_LABELS[ev.kind] || ev.kind)}</span> `
      + `${flag(ev.cc)} ${escapeHtml([ev.country, ev.city].filter(Boolean).join(" / "))} `
      + `<span class="mono-dim">${escapeHtml(ev.ip)} → ${escapeHtml(ev.host || "")}</span>`;
    ticker.prepend(line);
    while (ticker.children.length > 5) ticker.lastChild.remove();
  }

  // ---- データ取得 ----
  async function loadFull() {
    try {
      const res = await fetch("/api/attack-map?hours=24");
      const fresh = await res.json();
      const first = !data;
      data = fresh;
      const newest = data.events.length ? data.events[data.events.length - 1].epoch : Date.now() / 1000 - 60;
      lastEpoch = Math.max(lastEpoch, newest);
      if (first) {
        setupProjection();
        drawBase();
        // 初回は直近の数件をライブ扱いでティッカーに出す
        data.events.slice(-5).forEach(pushTicker);
      }
      renderInfo();
    } catch (err) {
      console.error("ATTACK MAPの取得に失敗", err);
    }
  }

  async function pollLive() {
    if (!data) return;
    try {
      const res = await fetch(`/api/attack-map?since=${lastEpoch}`);
      const fresh = await res.json();
      const events = fresh.events.filter((e) => e.epoch > lastEpoch);
      if (!events.length) return;
      lastEpoch = events[events.length - 1].epoch;
      // まとめて届いた分は次のポーリングまでの間に散らして発射する（一斉に出ると見えないため）
      const now = performance.now();
      events.forEach((ev, i) => {
        pending.push({ at: now + (i * (LIVE_POLL_MS * 0.9)) / events.length + Math.random() * 120, ev });
      });
      data.events = data.events.concat(events).slice(-400);
    } catch (err) {
      console.error("ATTACK MAPのライブ取得に失敗", err);
    }
  }

  async function init() {
    if (typeof d3 === "undefined" || typeof topojson === "undefined") {
      wrap.insertAdjacentHTML("beforeend", '<div class="attack-error mono-dim">地図ライブラリを読み込めませんでした（オフライン？）</div>');
      return;
    }
    resize();
    new ResizeObserver(() => resize()).observe(area);
    try {
      const res = await fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json");
      const topo = await res.json();
      land = topojson.feature(topo, topo.objects.land);
    } catch (err) {
      console.error("世界地図データの取得に失敗", err);
    }
    await loadFull();
    drawBase();
    requestAnimationFrame(frame);
    setInterval(pollLive, LIVE_POLL_MS);
    setInterval(loadFull, FULL_RELOAD_MS);
  }

  init();
})();
