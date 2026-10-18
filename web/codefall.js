/* Light "code rain" background: sparse 0/1/hex columns drifting down, drawn on a
   fixed canvas behind the page. Colour + strength follow --ok / --scan-k so it
   tracks the theme; honours prefers-reduced-motion (one static frame). */
(() => {
  const CELL = 18, TRAIL = 14, FPS = 12, GLYPHS = "01010101abcdef";
  const reduce = matchMedia("(prefers-reduced-motion: reduce)");
  const cv = document.createElement("canvas");
  cv.className = "codefall";
  cv.setAttribute("aria-hidden", "true");
  document.body.prepend(cv);
  const ctx = cv.getContext("2d");
  let cols = [], w = 0, h = 0, last = 0, raf = 0;

  const glyph = () => GLYPHS[(Math.random() * GLYPHS.length) | 0];
  const newCol = (stagger) => ({
    y: stagger ? Math.random() * (h / CELL + TRAIL) : -Math.random() * 30,
    speed: 0.25 + Math.random() * 0.55,
    live: Math.random() < 0.42,
    chars: Array.from({ length: TRAIL }, glyph),
  });

  function resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    w = innerWidth; h = innerHeight;
    cv.width = w * dpr; cv.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = "12px ui-monospace, Consolas, monospace";
    ctx.textBaseline = "top";
    const n = Math.ceil(w / CELL);
    cols = Array.from({ length: n }, () => newCol(true));
    draw();
  }

  function draw() {
    const cs = getComputedStyle(document.documentElement);
    const k = parseFloat(cs.getPropertyValue("--scan-k")) || 1;
    ctx.fillStyle = cs.getPropertyValue("--ok").trim() || "#39d98a";
    ctx.clearRect(0, 0, w, h);
    cols.forEach((c, i) => {
      if (!c.live) return;
      for (let t = 0; t < TRAIL; t++) {
        const y = (c.y - t) * CELL;
        if (y < -CELL || y > h) continue;
        ctx.globalAlpha = (t === 0 ? 0.9 : 0.5 * (1 - t / TRAIL)) * k;
        ctx.fillText(c.chars[t], i * CELL + 3, y);
      }
    });
    ctx.globalAlpha = 1;
  }

  function step(now) {
    raf = requestAnimationFrame(step);
    if (now - last < 1000 / FPS) return;
    last = now;
    cols.forEach((c, i) => {
      if (!c.live) { if (Math.random() < 0.004) cols[i] = { ...newCol(false), live: true }; return; }
      c.y += c.speed;
      if (Math.random() < 0.15) c.chars[(Math.random() * TRAIL) | 0] = glyph();
      if ((c.y - TRAIL) * CELL > h) cols[i] = newCol(false);
    });
    draw();
  }

  function sync() {
    cancelAnimationFrame(raf);
    if (!reduce.matches && !document.hidden) raf = requestAnimationFrame(step);
  }

  addEventListener("resize", resize);
  document.addEventListener("visibilitychange", sync);
  reduce.addEventListener("change", sync);
  new MutationObserver(draw).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  resize();
  sync();
})();
