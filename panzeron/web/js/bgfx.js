// A living background for each theme, drawn on one canvas behind the glass. Nothing here reads data or touches the network.
//   royal -> Constellation   midnight -> Starfield   ocean -> Bubbles   emerald -> Matrix code   crimson -> Embers   graphite -> Circuit   solid -> still
// It stops by itself when: "Interface animations" is off, the theme is Solid, the system asks for reduced motion, or the tab is hidden.
// Performance mode ("lite", chosen automatically on slow graphics) halves the density and drops to 20 frames a second.
const reduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false, addEventListener() {} };
let canvas = null, ctx = null, raf = 0, eff = null, last = 0, W = 0, H = 0, key = '';
let cfg = { bg: 'royal', anim: true, lite: false, rgb: [65, 105, 225] };
const rand = (a, b) => a + Math.random() * (b - a);
const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
const tint = (c, amount = 0.72) => c.map((v) => Math.round(v + (255 - v) * amount));

function ensureCanvas() {
  if (canvas) return true;
  const host = document.querySelector('.bg'); if (!host) return false;
  canvas = document.createElement('canvas'); canvas.id = 'bgfx'; canvas.setAttribute('aria-hidden', 'true');
  host.appendChild(canvas); ctx = canvas.getContext('2d'); return !!ctx;
}
function size() {
  const dpr = Math.min(window.devicePixelRatio || 1, cfg.lite ? 1 : 1.5);
  W = Math.max(1, window.innerWidth); H = Math.max(1, window.innerHeight);
  canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  if (eff) eff.init();
}

// ---- Matrix code (Emerald): falling katakana and digits, a bright accent-coloured head that fades ----------------------------
function matrix() {
  const FS = cfg.lite ? 18 : 16, GL = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789';
  const glyph = () => GL[(Math.random() * GL.length) | 0];
  let cols = [];
  const reset = (c, first) => { c.row = first ? rand(-H / FS, 0) : rand(-22, -2); c.speed = rand(7, 18); c.on = Math.random() < (cfg.lite ? 0.4 : 0.7); c.wait = rand(0, 5); };
  return {
    init() {
      cols = Array.from({ length: Math.ceil(W / FS) }, () => { const c = {}; reset(c, true); return c; });
      ctx.font = `${FS}px "MS Gothic","Yu Gothic UI","Cascadia Mono",ui-monospace,monospace`; ctx.textBaseline = 'top';
    },
    frame(t, dt) {
      ctx.globalCompositeOperation = 'destination-out'; ctx.fillStyle = 'rgba(0,0,0,.085)'; ctx.fillRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'source-over';
      for (let i = 0; i < cols.length; i++) {
        const c = cols[i], x = i * FS;
        if (!c.on) { c.wait -= dt; if (c.wait <= 0) { c.on = true; c.row = rand(-12, 0); c.speed = rand(7, 18); } continue; }
        const prev = Math.floor(c.row); c.row += c.speed * dt; const next = Math.floor(c.row);
        for (let r = prev + 1; r <= next; r++) {
          if (r < 0) continue;
          if (r > 0) { ctx.clearRect(x, (r - 1) * FS, FS, FS); ctx.fillStyle = rgba(cfg.rgb, .95); ctx.fillText(glyph(), x, (r - 1) * FS); }
          ctx.clearRect(x, r * FS, FS, FS); ctx.fillStyle = rgba(tint(cfg.rgb), 1); ctx.fillText(glyph(), x, r * FS);
        }
        if (c.row * FS > H + FS * 4) reset(c, false);
      }
    },
  };
}

// ---- Constellation (Royal): slowly drifting points joined by faint lines, a few in champagne gold ------------------------------
function constellation() {
  let P = []; const LINK = 140;
  return {
    init() { const n = Math.min(cfg.lite ? 34 : 80, Math.round((W * H) / 20000)); P = Array.from({ length: n }, () => ({ x: rand(0, W), y: rand(0, H), vx: rand(-14, 14), vy: rand(-14, 14), gold: Math.random() < 0.14, ph: rand(0, 6.3) })); },
    frame(t, dt) {
      ctx.clearRect(0, 0, W, H);
      for (const p of P) { p.x += p.vx * dt; p.y += p.vy * dt; if (p.x < -10) p.x = W + 10; else if (p.x > W + 10) p.x = -10; if (p.y < -10) p.y = H + 10; else if (p.y > H + 10) p.y = -10; }
      ctx.lineWidth = 1;
      for (let i = 0; i < P.length; i++) for (let j = i + 1; j < P.length; j++) {
        const dx = P[i].x - P[j].x, dy = P[i].y - P[j].y, d2 = dx * dx + dy * dy;
        if (d2 < LINK * LINK) { ctx.strokeStyle = rgba(cfg.rgb, (1 - Math.sqrt(d2) / LINK) * 0.4); ctx.beginPath(); ctx.moveTo(P[i].x, P[i].y); ctx.lineTo(P[j].x, P[j].y); ctx.stroke(); }
      }
      for (const p of P) { ctx.fillStyle = rgba(p.gold ? tint(cfg.rgb, .45) : cfg.rgb, 0.85); ctx.beginPath(); ctx.arc(p.x, p.y, 1.5 + 0.6 * Math.sin(t * 1.4 + p.ph), 0, 6.283); ctx.fill(); }
    },
  };
}

// ---- Starfield (Midnight): twinkling stars and an occasional shooting star ----------------------------------------------------
function starfield() {
  let S = [], shoot = null, next = 3;
  return {
    init() { const n = Math.min(cfg.lite ? 90 : 210, Math.round((W * H) / 8000)); S = Array.from({ length: n }, () => ({ x: rand(0, W), y: rand(0, H), r: rand(0.4, 1.5), ph: rand(0, 6.3), sp: rand(0.6, 2.4) })); },
    frame(t, dt) {
      ctx.clearRect(0, 0, W, H);
      for (const s of S) {
        s.x -= 2.5 * dt * (0.4 + s.r); if (s.x < -2) s.x = W + 2;
        ctx.fillStyle = rgba(tint(cfg.rgb), 0.2 + 0.8 * Math.abs(Math.sin(t * s.sp + s.ph)));
        if (s.r > 1.1) { ctx.beginPath(); ctx.arc(s.x, s.y, s.r, 0, 6.283); ctx.fill(); } else ctx.fillRect(s.x, s.y, s.r * 1.6, s.r * 1.6);
      }
      next -= dt;
      if (!shoot && next <= 0) { shoot = { x: rand(W * 0.3, W), y: rand(0, H * 0.4), vx: -rand(520, 760), vy: rand(220, 340), life: 1 }; next = rand(6, 12); }
      if (shoot) {
        shoot.x += shoot.vx * dt; shoot.y += shoot.vy * dt; shoot.life -= dt * 1.1;
        const len = 130, k = Math.hypot(shoot.vx, shoot.vy), tx = shoot.x - (shoot.vx / k) * len, ty = shoot.y - (shoot.vy / k) * len;
        const g = ctx.createLinearGradient(tx, ty, shoot.x, shoot.y); g.addColorStop(0, rgba(tint(cfg.rgb), 0)); g.addColorStop(1, rgba(tint(cfg.rgb), Math.max(0, shoot.life)));
        ctx.strokeStyle = g; ctx.lineWidth = 1.6; ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(shoot.x, shoot.y); ctx.stroke();
        if (shoot.life <= 0 || shoot.x < -200 || shoot.y > H + 200) shoot = null;
      }
    },
  };
}

// ---- Bubbles (Ocean): translucent bubbles rising and swaying ------------------------------------------------------------------
function bubbles() {
  let B = [];
  const make = (fresh) => { const r = rand(3, 16); return { r, x: rand(0, W), y: fresh ? rand(0, H) : H + r + rand(0, 80), vy: 10 + r * 2.2, amp: rand(4, 16), ph: rand(0, 6.3), sp: rand(0.5, 1.3) }; };
  return {
    init() { B = Array.from({ length: cfg.lite ? 18 : 38 }, () => make(true)); },
    frame(t, dt) {
      ctx.clearRect(0, 0, W, H);
      for (let i = 0; i < B.length; i++) {
        const b = B[i]; b.y -= b.vy * dt; if (b.y < -b.r - 4) { B[i] = make(false); continue; }
        const x = b.x + Math.sin(t * b.sp + b.ph) * b.amp;
        ctx.fillStyle = rgba(cfg.rgb, .07); ctx.strokeStyle = rgba(tint(cfg.rgb), .42); ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(x, b.y, b.r, 0, 6.283); ctx.fill(); ctx.stroke();
        ctx.strokeStyle = rgba(tint(cfg.rgb), .55); ctx.beginPath(); ctx.arc(x, b.y, b.r * 0.62, 3.6, 4.5); ctx.stroke();
      }
    },
  };
}

// ---- Embers (Crimson): glowing sparks drifting up from below ------------------------------------------------------------------
function embers() {
  const sprite = (c) => { const s = document.createElement('canvas'); s.width = s.height = 32; const x = s.getContext('2d'); const g = x.createRadialGradient(16, 16, 0, 16, 16, 16);
    g.addColorStop(0, rgba(c, 1)); g.addColorStop(0.35, rgba(c, .45)); g.addColorStop(1, rgba(c, 0)); x.fillStyle = g; x.fillRect(0, 0, 32, 32); return s; };
  let SP = [], spriteColor = '';
  const sprites = () => {
    const color = cfg.rgb.join(',');
    if (color !== spriteColor) { spriteColor = color; SP = [sprite(tint(cfg.rgb, .78)), sprite(tint(cfg.rgb, .38)), sprite(cfg.rgb)]; }
    return SP;
  };
  let E = [];
  const make = (fresh) => ({ x: rand(0, W), y: fresh ? rand(0, H) : H + 12, vx: rand(-8, 8), vy: -rand(26, 70), life: rand(4, 9), age: fresh ? rand(0, 4) : 0, size: rand(5, 16), ph: rand(0, 6.3) });
  return {
    init() { E = Array.from({ length: cfg.lite ? 36 : 80 }, () => make(true)); },
    frame(t, dt) {
      ctx.clearRect(0, 0, W, H); ctx.globalCompositeOperation = 'lighter';
      for (let i = 0; i < E.length; i++) {
        const e = E[i]; e.age += dt; e.x += (e.vx + Math.sin(t * 0.7 + e.ph) * 14) * dt; e.y += e.vy * dt;
        const k = e.age / e.life; if (k >= 1 || e.y < -20) { E[i] = make(false); continue; }
        ctx.globalAlpha = Math.min(1, (1 - k) * 1.4) * (0.65 + 0.35 * Math.sin(t * 8 + e.ph));
        ctx.drawImage(sprites()[k < 0.25 ? 0 : k < 0.6 ? 1 : 2], e.x - e.size / 2, e.y - e.size / 2, e.size, e.size);
      }
      ctx.globalAlpha = 1; ctx.globalCompositeOperation = 'source-over';
    },
  };
}

// ---- Circuit (Graphite): a faint grid with light pulses that travel along it and turn at the junctions ------------------------
function circuit() {
  const CELL = 56; let grid = null, gridRgb = '', pulses = [];
  const spawn = () => { const cx = Math.round(rand(0, W) / CELL) * CELL, cy = Math.round(rand(0, H) / CELL) * CELL; return { x: cx, y: cy, d: (Math.random() * 4) | 0, sp: rand(70, 150), run: 0 }; };
  const DIR = [[1, 0], [0, 1], [-1, 0], [0, -1]];
  const paintGrid = () => {
    const g = grid.getContext('2d');
    gridRgb = cfg.rgb.join(',');
    g.clearRect(0, 0, W, H);
    g.strokeStyle = rgba(cfg.rgb, .07); g.lineWidth = 1; g.beginPath();
    for (let x = 0; x <= W; x += CELL) { g.moveTo(x + 0.5, 0); g.lineTo(x + 0.5, H); } for (let y = 0; y <= H; y += CELL) { g.moveTo(0, y + 0.5); g.lineTo(W, y + 0.5); } g.stroke();
    g.fillStyle = rgba(cfg.rgb, .16); for (let x = 0; x <= W; x += CELL) for (let y = 0; y <= H; y += CELL) g.fillRect(x - 1, y - 1, 3, 3);
  };
  return {
    init() {
      grid = document.createElement('canvas'); grid.width = W; grid.height = H;
      paintGrid();
      pulses = Array.from({ length: cfg.lite ? 7 : 14 }, spawn);
    },
    frame(t, dt) {
      if (gridRgb !== cfg.rgb.join(',')) paintGrid();
      ctx.clearRect(0, 0, W, H); ctx.drawImage(grid, 0, 0); ctx.globalCompositeOperation = 'lighter'; ctx.lineWidth = 2; ctx.lineCap = 'round';
      for (let i = 0; i < pulses.length; i++) {
        const p = pulses[i], step = p.sp * dt, v = DIR[p.d]; p.x += v[0] * step; p.y += v[1] * step; p.run += step;
        if (p.run >= CELL) { p.run -= CELL; p.x = Math.round(p.x / CELL) * CELL; p.y = Math.round(p.y / CELL) * CELL; if (Math.random() < 0.35) p.d = (p.d + (Math.random() < 0.5 ? 1 : 3)) % 4; }
        if (p.x < -20 || p.y < -20 || p.x > W + 20 || p.y > H + 20) { pulses[i] = spawn(); continue; }
        const len = 110, tx = p.x - v[0] * len, ty = p.y - v[1] * len, g = ctx.createLinearGradient(tx, ty, p.x, p.y);
        g.addColorStop(0, rgba(cfg.rgb, 0)); g.addColorStop(1, rgba(cfg.rgb, 0.85)); ctx.strokeStyle = g; ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(p.x, p.y); ctx.stroke();
        ctx.fillStyle = rgba(tint(cfg.rgb), .9); ctx.beginPath(); ctx.arc(p.x, p.y, 2.2, 0, 6.283); ctx.fill();
      }
      ctx.globalCompositeOperation = 'source-over';
    },
  };
}

const EFFECTS = { royal: constellation, midnight: starfield, ocean: bubbles, emerald: matrix, crimson: embers, graphite: circuit };

// Why the effect is (not) running. The Appearance page shows this, so a missing effect is never a silent mystery.
let failed = '';
const FORCE = 'panzeron-fx-force';
const forced = () => { try { return localStorage.getItem(FORCE) === '1'; } catch { return false; } };
function why() {
  if (!cfg.anim) return 'off';
  if (!EFFECTS[cfg.bg]) return 'solid';
  if (reduce.matches && !forced()) return 'reduced-motion';     // Windows: Settings > Accessibility > Visual effects > Animation effects = Off
  if (failed) return 'error';
  if (!canvas && !ensureCanvas()) return 'no-canvas';
  return document.hidden ? 'hidden' : '';
}
export function effectStatus() { const reason = why(); return { running: !!raf, reason, error: failed, forced: forced(), reduceMotion: reduce.matches, name: cfg.bg }; }
export function setForceMotion(on) { try { if (on) localStorage.setItem(FORCE, '1'); else localStorage.removeItem(FORCE); } catch { /* storage unavailable */ } failed = ''; start(); }

function loop(now) {
  raf = requestAnimationFrame(loop);
  if (now - last < (cfg.lite ? 50 : 33)) return;
  const dt = Math.min(0.1, (now - last) / 1000); last = now;
  try { eff.frame(now / 1000, dt); } catch (e) { failed = String((e && e.message) || e).slice(0, 140); hide(); }
}
function stop() { cancelAnimationFrame(raf); raf = 0; }
function hide() { stop(); if (canvas) { ctx.clearRect(0, 0, canvas.width, canvas.height); canvas.style.display = 'none'; } }
function start() {
  stop();
  const r = why();
  if (r === 'hidden') return;                                  // keeps the picture; resumes when the window is visible again
  if (r) { hide(); return; }
  canvas.style.display = ''; eff = EFFECTS[cfg.bg](); size(); ctx.clearRect(0, 0, W, H); last = performance.now(); raf = requestAnimationFrame(loop);
}

export function setBackgroundEffect(next) {
  cfg = { ...cfg, ...next };
  const k = `${cfg.bg}|${cfg.anim}|${cfg.lite}`;
  if (k !== key) { key = k; start(); }                   // accent changes only recolour: no restart, so dragging the colour picker stays smooth
}
let resizeTimer = 0;
window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (canvas && eff && raf) size(); }, 150); });
document.addEventListener('visibilitychange', () => { if (document.hidden) stop(); else if (key) start(); });
if (reduce.addEventListener) reduce.addEventListener('change', () => { if (key) start(); });
