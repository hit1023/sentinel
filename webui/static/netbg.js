// 背景の「動く線」演出（コンステレーション風パーティクルネットワーク）
(() => {
  const canvas = document.getElementById("netCanvas");
  const ctx = canvas.getContext("2d");
  let particles = [];
  let width, height;

  const DENSITY = 12000; // 値が大きいほどパーティクルが少なくなる
  const LINK_DIST = 130;
  const SPEED = 0.25;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const count = Math.min(140, Math.floor((width * height) / DENSITY));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * SPEED,
      vy: (Math.random() - 0.5) * SPEED,
    }));
  }

  function step() {
    ctx.clearRect(0, 0, width, height);

    for (const p of particles) {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;
    }

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i];
        const b = particles[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < LINK_DIST) {
          const alpha = 1 - dist / LINK_DIST;
          ctx.strokeStyle = `rgba(36, 240, 255, ${alpha * 0.35})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    for (const p of particles) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.6, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(57, 255, 138, 0.7)";
      ctx.fill();
    }

    requestAnimationFrame(step);
  }

  window.addEventListener("resize", resize);
  resize();
  requestAnimationFrame(step);
})();
