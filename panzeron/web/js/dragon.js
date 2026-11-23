// The Panzeron dragon: a rigged, animatable character, not a picture that moves.
//
//   <u-dragon pose="fly" size="120"></u-dragon>          drop it anywhere: a loader, an empty state, a header, the intro
//
// The artwork (img/dragon.png, a silhouette) is cut into a mesh. Every vertex is moved by a small rig, so the dragon itself deforms:
//   wing  : rotates about the shoulder, with the tip lagging behind the root (the wing bends as it beats)
//   head  : nods about the neck
//   tail  : swings about its root, the end lagging behind (a whip)
//   body  : a wave travels down the whole S-shaped body
// Poses ("fly", "glide", "hover", "idle") are just different settings for those joints; changing pose blends smoothly.
// It is painted in the accent colour (CSS variables --accent, --accent2, --accent-mid, --accent-rgb), so it follows Settings.
// It pauses when off screen or when the tab is hidden, and holds still when reduced motion is on or interface animations are off.
//
// JavaScript API:  const d = document.querySelector('u-dragon');  d.pose = 'glide';  d.setAttribute('static', '');
//                  orbitAround(host, opts) makes a <u-dragon> fly a banked loop around a point (the startup intro uses it).

const TEX_URL = '/img/dragon.png';
const COLS = 20, ROWS = 25;           // mesh resolution
const PAD = 0.3;                      // canvas margin around the dragon, for flapping wings and glow
const TAU = Math.PI * 2;

const clamp01 = (x) => Math.min(1, Math.max(0, x));
const ss = (a, b, x) => { const t = clamp01((x - a) / (b - a)); return t * t * (3 - 2 * t); };   // smoothstep; a > b gives a falling edge

// Joint pivots (fractions of the artwork) found on the silhouette: shoulder, neck, tail root.
const WING = [0.40, 0.40], HEAD = [0.57, 0.30], TAIL = [0.55, 0.60];

// flap/tail/head are angles in radians, bias raises (+) or lowers (-) the wings, wave is body ripple, bob is body lift (fraction of height).
export const POSES = {
  fly:   { flap: 0.62, flapHz: 2.2, bias: -0.02, wave: 1.0,  waveHz: 1.7, tail: 0.24, head: 0.10,  bob: 0.03,  breath: 0.006 },
  glide: { flap: 0.14, flapHz: 0.7, bias: 0.26,  wave: 0.45, waveHz: 0.9, tail: 0.09, head: 0.03,  bob: 0.012, breath: 0.006 },
  hover: { flap: 0.48, flapHz: 3.3, bias: 0.0,   wave: 0.6,  waveHz: 2.4, tail: 0.12, head: 0.05,  bob: 0.03,  breath: 0.006 },
  idle:  { flap: 0.05, flapHz: 0.5, bias: 0.04,  wave: 0.28, waveHz: 0.6, tail: 0.05, head: 0.025, bob: 0.006, breath: 0.012 },
};
const STILL = { flap: 0, flapHz: 0, bias: 0, wave: 0, waveHz: 0, tail: 0, head: 0, bob: 0, breath: 0 };    // the plain artwork, no motion

// ---- shared texture + mesh (built once) -----------------------------------------------------------------------------------
let shared = null;
function loadShared() {
  return shared ??= new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => {
      const W = img.naturalWidth, H = img.naturalHeight;
      const probe = document.createElement('canvas'); probe.width = W; probe.height = H;
      const pc = probe.getContext('2d', { willReadFrequently: true }); pc.drawImage(img, 0, 0);
      const px = pc.getImageData(0, 0, W, H).data, cw = W / COLS, ch = H / ROWS;
      const cells = [];                                              // only cells that contain artwork are ever drawn
      for (let j = 0; j < ROWS; j++) for (let i = 0; i < COLS; i++) {
        let hit = false;
        const x0 = Math.max(0, Math.floor(i * cw) - 1), x1 = Math.min(W, Math.ceil((i + 1) * cw) + 1);
        const y0 = Math.max(0, Math.floor(j * ch) - 1), y1 = Math.min(H, Math.ceil((j + 1) * ch) + 1);
        for (let y = y0; y < y1 && !hit; y += 2) for (let x = x0; x < x1; x += 2) if (px[(y * W + x) * 4 + 3] > 10) { hit = true; break; }
        if (hit) cells.push(j * COLS + i);
      }
      // per-vertex rig weights
      const n = (COLS + 1) * (ROWS + 1), wWing = new Float32Array(n), wHead = new Float32Array(n), wTail = new Float32Array(n);
      for (let j = 0; j <= ROWS; j++) for (let i = 0; i <= COLS; i++) {
        const u = i / COLS, v = j / ROWS, k = j * (COLS + 1) + i;
        const vLim = 0.64 + (0.54 - 0.64) * ss(0.10, 0.18, u);       // the wing tip reaches lower than the mane next to it
        wWing[k] = ss(0.44, 0.32, u) * ss(vLim + 0.04, vLim - 0.04, v);
        wHead[k] = ss(0.52, 0.62, u) * ss(0.44, 0.32, v);
        wTail[k] = ss(0.55, 0.80, v);
      }
      resolve({ img, W, H, cw, ch, cells, wWing, wHead, wTail });
    };
    img.onerror = () => { shared = null; reject(new Error('dragon texture failed to load')); };
    img.src = TEX_URL;
  });
}

// ---- colours from the user's accent ---------------------------------------------------------------------------------------
function accent() {
  const cs = getComputedStyle(document.documentElement), g = (n, d) => (cs.getPropertyValue(n).trim() || d);
  return { hi: g('--accent2', '#8fa8ff'), mid: g('--accent', '#4169e1'), lo: g('--accent-mid', '#2f4fc4'), rgb: g('--accent-rgb', '65,105,225') };
}

// ---- the one animation loop, shared by every dragon on the page ------------------------------------------------------------
const live = new Set();
let raf = 0, last = 0;
function loop(now) {
  const dt = Math.min(0.05, (now - last) / 1000 || 0.016); last = now;
  let any = false;
  for (const d of live) if (d._active()) { d._frame(dt); any = true; }
  raf = any ? requestAnimationFrame(loop) : 0;
}
const wake = () => { if (!raf) { last = performance.now(); raf = requestAnimationFrame(loop); } };

const motionAllowed = () => {
  try { if (matchMedia('(prefers-reduced-motion: reduce)').matches) return false; } catch { /* ignore */ }
  try { if (JSON.parse(localStorage.getItem('panzeron-prefs') || '{}').anim === false) return false; } catch { /* ignore */ }
  return true;
};

class UDragon extends HTMLElement {
  static get observedAttributes() { return ['pose', 'size', 'static', 'glow']; }

  constructor() {
    super();
    this._cur = { ...POSES.idle }; this._ph = { flap: 0, wave: 0 }; this._tex = null; this._visible = true; this._t = 0; this._colorAt = -1; this._col = null;
  }

  get pose() { return this.getAttribute('pose') || 'idle'; }
  set pose(v) { this.setAttribute('pose', v); }

  connectedCallback() {
    this.style.display = this.style.display || 'inline-block'; this.style.lineHeight = '0';
    this.setAttribute('aria-hidden', 'true');
    this._canvas = this._canvas || document.createElement('canvas'); this._buf = this._buf || document.createElement('canvas');
    if (!this._canvas.parentNode) this.appendChild(this._canvas);
    this._ctx = this._canvas.getContext('2d'); this._bctx = this._buf.getContext('2d');
    this._io = new IntersectionObserver((es) => { this._visible = es[es.length - 1].isIntersecting; if (this._visible) wake(); });
    this._io.observe(this);
    live.add(this); this._size();
    loadShared().then((s) => { this._tex = s; this._size(); this._frame(0); wake(); }).catch(() => { /* no artwork: the page works without the dragon */ });
  }
  disconnectedCallback() { live.delete(this); this._io && this._io.disconnect(); }
  attributeChangedCallback(name) { this._settled = false; if (name === 'size' && this._ctx) this._size(); wake(); }

  _active() { return this.isConnected && this._tex && this._visible && !document.hidden && !this._settled; }

  _size() {
    const s = this._tex; const w = parseFloat(this.getAttribute('size')) || 120;
    const h = s ? w * s.H / s.W : w * 1.25;
    this._cssW = w * (1 + PAD * 2); this._cssH = h + w * PAD * 2; this._dw = w;
    const dpr = Math.min(window.devicePixelRatio || 1, 2); this._dpr = dpr;
    for (const c of [this._canvas, this._buf]) { c.width = Math.round(this._cssW * dpr); c.height = Math.round(this._cssH * dpr); }
    this._canvas.style.cssText = `width:${this._cssW}px;height:${this._cssH}px;margin:${-h * 0 - w * PAD}px;display:block;pointer-events:none`;
    this.style.width = w + 'px'; this.style.height = h + 'px';
  }

  _frame(dt) {
    const s = this._tex; if (!s) return;
    const still = this.hasAttribute('static') || !motionAllowed();
    const target = still ? STILL : (POSES[this.pose] || POSES.idle);
    const rate = still ? 1 : Math.min(1, dt * 4);                       // blend into a new pose instead of snapping
    for (const k in target) this._cur[k] += (target[k] - this._cur[k]) * rate;
    const P = this._cur;
    this._settled = still && Object.keys(target).every((k) => Math.abs(P[k] - target[k]) < 1e-3);   // nothing will change: stop redrawing
    this._ph.flap += dt * TAU * P.flapHz; this._ph.wave += dt * TAU * P.waveHz; this._t += dt;

    const dpr = this._dpr, sc = (this._dw / s.W) * dpr, ox = this._dw * PAD * dpr, oy = this._dw * PAD * dpr;
    const W = s.W, H = s.H, nx = COLS + 1;
    const pos = this._pos || (this._pos = new Float32Array(nx * (ROWS + 1) * 2));
    const piv = (p) => [p[0] * W, p[1] * H];
    const [wx, wy] = piv(WING), [hx, hy] = piv(HEAD), [tx, ty] = piv(TAIL);
    const bob = -Math.cos(this._ph.flap) * P.bob * H, breathe = 1 + Math.sin(this._t * 1.6) * P.breath;

    for (let j = 0; j <= ROWS; j++) for (let i = 0; i <= COLS; i++) {
      const k = j * nx + i, u = i / COLS, v = j / ROWS;
      let x = u * W, y = v * H;
      // the S-shaped body ripples
      x += Math.sin(TAU * v * 1.15 - this._ph.wave) * P.wave * 0.016 * H * ss(0.05, 0.4, v + 0.1);
      y += Math.sin(TAU * v * 1.15 - this._ph.wave + 1.3) * P.wave * 0.005 * H;
      // tail whips: angle grows towards the tip and lags behind the root
      const wt = s.wTail[k];
      if (wt > 0) { const a = P.tail * Math.sin(this._ph.wave * 1.0 + 1 - 2.4 * (v - 0.6)) * wt; [x, y] = rot(x, y, tx, ty, a); }
      // head nods against the wing beat
      const wh = s.wHead[k];
      if (wh > 0) { const a = P.head * Math.sin(this._ph.flap + 1.6) * wh; [x, y] = rot(x, y, hx, hy, a); }
      // wing beats about the shoulder; further from the shoulder = later in the stroke, so the wing bends
      const ww = s.wWing[k];
      if (ww > 0) {
        const d = Math.hypot(u * W - wx, v * H - wy) / (0.45 * H);
        const sn = Math.sin(this._ph.flap - 2.4 * d), a = (P.bias + P.flap * sn) * ww;
        const ext = 1 + 0.2 * P.flap * sn * ww;                      // the wing spreads on the upstroke and folds on the downstroke
        x = wx + (x - wx) * ext; y = wy + (y - wy) * (1 + (ext - 1) * 0.6);
        [x, y] = rot(x, y, wx, wy, a);
      }
      // breathing and body lift
      x = W / 2 + (x - W / 2) * breathe; y = H / 2 + (y - H / 2) * breathe + bob;
      pos[k * 2] = x * sc + ox; pos[k * 2 + 1] = y * sc + oy;
    }

    // draw the warped mesh (white), tint it with the accent, then put it on screen with a soft glow
    const b = this._bctx; b.setTransform(1, 0, 0, 1, 0, 0); b.globalCompositeOperation = 'source-over'; b.clearRect(0, 0, this._buf.width, this._buf.height);
    b.imageSmoothingEnabled = true;
    const cw = s.cw, ch = s.ch, grow = 0.75 * dpr;
    for (const cell of s.cells) {
      const ci = cell % COLS, cj = (cell / COLS) | 0;
      const a = (cj * nx + ci) * 2, bb = a + 2, c = a + nx * 2, d = c + 2;
      const sx = ci * cw, sy = cj * ch;
      tri(b, s.img, sx, sy, cw, ch, pos[a], pos[a + 1], pos[bb], pos[bb + 1], pos[c], pos[c + 1], 0, grow);
      tri(b, s.img, sx, sy, cw, ch, pos[d], pos[d + 1], pos[c], pos[c + 1], pos[bb], pos[bb + 1], 1, grow);
    }
    if (this._t - this._colorAt > 0.4 || !this._col) { this._col = accent(); this._colorAt = this._t; }
    const col = this._col, g = b.createLinearGradient(0, 0, this._buf.width * 0.55, this._buf.height);
    g.addColorStop(0, col.hi); g.addColorStop(0.5, col.mid); g.addColorStop(1, col.lo);
    b.globalCompositeOperation = 'source-in'; b.fillStyle = g; b.fillRect(0, 0, this._buf.width, this._buf.height); b.globalCompositeOperation = 'source-over';

    const m = this._ctx; m.setTransform(1, 0, 0, 1, 0, 0); m.clearRect(0, 0, this._canvas.width, this._canvas.height);
    if (this.getAttribute('glow') !== 'off') { m.shadowColor = `rgba(${col.rgb},0.65)`; m.shadowBlur = 14 * dpr; }
    m.drawImage(this._buf, 0, 0); m.shadowBlur = 0;
  }
}

function rot(x, y, cx, cy, a) { const c = Math.cos(a), s = Math.sin(a), dx = x - cx, dy = y - cy; return [cx + dx * c - dy * s, cy + dx * s + dy * c]; }

// Draw one mesh triangle: the texture cell, affinely mapped onto the moved vertices (grown a little so neighbours overlap: no hairline seams).
// half 0 = triangle (a, b, c) = top-left; half 1 = triangle (d, c, b) = bottom-right.
function tri(ctx, img, sx, sy, cw, ch, x0, y0, x1, y1, x2, y2, half, grow) {
  let m11, m12, m21, m22;
  if (half === 0) { m11 = (x1 - x0) / cw; m12 = (y1 - y0) / cw; m21 = (x2 - x0) / ch; m22 = (y2 - y0) / ch; }
  else { m11 = -(x1 - x0) / cw; m12 = -(y1 - y0) / cw; m21 = -(x2 - x0) / ch; m22 = -(y2 - y0) / ch; }
  const ax = half === 0 ? sx : sx + cw, ay = half === 0 ? sy : sy + ch;         // source point that vertex 0 came from
  const e = x0 - m11 * ax - m21 * ay, f = y0 - m12 * ax - m22 * ay;
  const cx = (x0 + x1 + x2) / 3, cy = (y0 + y1 + y2) / 3;
  const ex = (x, y) => { const dx = x - cx, dy = y - cy, l = Math.hypot(dx, dy) || 1; return [x + dx / l * grow, y + dy / l * grow]; };
  const p0 = ex(x0, y0), p1 = ex(x1, y1), p2 = ex(x2, y2);
  ctx.save(); ctx.beginPath(); ctx.moveTo(p0[0], p0[1]); ctx.lineTo(p1[0], p1[1]); ctx.lineTo(p2[0], p2[1]); ctx.closePath(); ctx.clip();
  ctx.setTransform(m11, m12, m21, m22, e, f);
  ctx.drawImage(img, sx - 1, sy - 1, cw + 2, ch + 2, sx - 1, sy - 1, cw + 2, ch + 2);
  ctx.restore();
}

if (!customElements.get('u-dragon')) customElements.define('u-dragon', UDragon);
export { UDragon };

// ---- flight: make a dragon fly a banked loop around a point -----------------------------------------------------------------
// `host` is a <u-dragon> positioned absolutely at the centre of what it circles. The loop is a tipped ellipse: the dragon grows as it
// comes towards you, passes in front, then behind (host.style.zIndex flips so the circled object can hide it), banks into the turn,
// and turns to face the way it is travelling. Returns stop().
export function orbitAround(host, { rx = 164, ry = 30, period = 2.4, tilt = -12, delay = 0.8, enter = 0.9, minScale = 0.74, maxScale = 1.04 } = {}) {
  const t0 = performance.now() + delay * 1000; let id = 0, stopped = false;
  const ease = (x) => 1 - Math.pow(1 - x, 3), deg = 180 / Math.PI;
  const tick = (now) => {
    if (stopped) return;
    const t = (now - t0) / 1000;
    if (t < 0) { host.style.opacity = '0'; id = requestAnimationFrame(tick); return; }
    const e = ease(Math.min(1, t / enter)), p = TAU * t / period;
    const wob = 1 + 0.07 * Math.sin(p * 1.7 + 1);                          // the loop is not a perfect machine ellipse
    const R = rx * wob * e, r = ry * e;
    const x = -R * Math.cos(p), y = r * Math.sin(p);                        // y > 0 = nearer the viewer
    const vx = rx * Math.sin(p), vy = ry * Math.cos(p);                     // direction of travel
    const facing = Math.tanh(vx / (rx * 0.12));                             // +1 facing right ... -1 facing left, turning smoothly at the ends
    const bank = (vx >= 0 ? Math.atan2(vy, vx) : -Math.atan2(vy, -vx)) * deg * 0.38;
    const sc = (minScale + (maxScale - minScale) * (Math.sin(p) + 1) / 2) * (0.25 + 0.75 * e);
    host.style.opacity = String(Math.min(1, t / 0.35));
    host.style.zIndex = y > 0 ? '3' : '0';
    host.style.transform = `translate(-50%,-50%) rotate(${tilt}deg) translate(${x.toFixed(1)}px,${y.toFixed(1)}px) rotate(${(-tilt).toFixed(1)}deg) rotate(${bank.toFixed(1)}deg) scale(${(facing * sc).toFixed(3)},${sc.toFixed(3)})`;
    id = requestAnimationFrame(tick);
  };
  id = requestAnimationFrame(tick);
  return () => { stopped = true; cancelAnimationFrame(id); };
}
