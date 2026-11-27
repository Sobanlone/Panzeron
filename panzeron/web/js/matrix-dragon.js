// The startup dragon: a Matrix-code dragon in true 3D, flying around the glowing ball.
//
//   * It is a real 3D model made of glyph particles (katakana and digits): a long straight body, neck and head out front with horns
//     and jaws, a crest of spines, wings spread wide like the reference photo, legs tucked, and a tail that ends in a fin.
//   * It swims through the air like a fish: a wave runs from the head down to the tail, growing toward the tip, so the tail flaps while
//     the body stays a straight line pointing where it is going. The wings beat slowly with the tips lagging behind the roots.
//   * It flies a banked circle around the ball with perspective: nearer glyphs are bigger and brighter, farther ones smaller and dimmer.
//     Glyphs behind the ball are drawn on a canvas UNDER it and glyphs in front on a canvas OVER it, so it really passes behind and
//     in front of the ball.
//   * It assembles out of falling code at the start; code rain falls across the whole screen behind it.
// Everything is drawn locally on <canvas>. Nothing is read or sent. With reduced motion ("calm") it draws one still frame instead.
const TAU = Math.PI * 2, PI = Math.PI;
const GLYPHS = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789:=*+<>';
const GN = GLYPHS.length, CELL = 28;                 // atlas cell size in pixels
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const ss = (a, b, x) => { const t = clamp((x - a) / (b - a)); return t * t * (3 - 2 * t); };
const easeOut = (x) => 1 - Math.pow(1 - clamp(x), 3);

function buildAtlas() {                               // row 0: accent glyphs, row 1: brighter glyphs, row 2: a round glow
  const c = document.createElement('canvas'); c.width = CELL * GN; c.height = CELL * 3;
  const x = c.getContext('2d'); x.textAlign = 'center'; x.textBaseline = 'middle';
  x.font = `bold 21px "MS Gothic","Yu Gothic UI","Cascadia Mono",ui-monospace,monospace`;
  const accent = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
  const highlight = getComputedStyle(document.documentElement).getPropertyValue('--accent-hi').trim();
  const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(',');
  const [base, bright] = [accent, highlight].map(rgb);
  [[`rgb(${base})`, `rgba(${base},.9)`], [`rgb(${bright})`, `rgba(${bright},.95)`]].forEach(([fill, glow], row) => {
    x.fillStyle = fill; x.shadowColor = glow; x.shadowBlur = 5;
    for (let i = 0; i < GN; i++) x.fillText(GLYPHS[i], i * CELL + CELL / 2, row * CELL + CELL / 2 + 1);
  });
  x.shadowBlur = 0;
  const g = x.createRadialGradient(CELL / 2, CELL * 2.5, 0, CELL / 2, CELL * 2.5, CELL / 2);
  g.addColorStop(0, `rgba(${base},.95)`); g.addColorStop(0.62, `rgba(${base},.55)`); g.addColorStop(1, `rgba(${base},0)`);
  x.fillStyle = g; x.fillRect(0, CELL * 2, CELL, CELL);
  return c;
}

// ---- the dragon model (local units are pixels; x = forward, y = up, z = to the dragon's right) -------------------------------------
const L = 300, NOSE = 150;                            // body length and where the nose is
const PROFILE = [[0, 2.5], [0.06, 6], [0.11, 9], [0.15, 5.5], [0.24, 6.5], [0.34, 12], [0.42, 15], [0.52, 13], [0.62, 9.5], [0.75, 5.5], [0.9, 2.6], [1, 1]];
function radius(u) {                                  // body thickness at u (0 = nose, 1 = tail tip)
  return 1.22 * rawRadius(u) * (u < 0.15 ? 1.15 : 1);
}
function rawRadius(u) {
  for (let i = 1; i < PROFILE.length; i++) if (u <= PROFILE[i][0]) { const [u0, r0] = PROFILE[i - 1], [u1, r1] = PROFILE[i]; return r0 + (r1 - r0) * (u - u0) / (u1 - u0); }
  return 1;
}
function spine(u, t) {                                // centre line of the body: a straight line plus a travelling swimming wave
  const th = TAU * (0.75 * u - 1.05 * t), amp = 2.5 + 40 * Math.pow(u, 2.2);      // the wave grows toward the tail, so the tail flaps
  return [NOSE - L * u, amp * Math.sin(th) + 3 * Math.sin(t * 2.1), 0.42 * amp * Math.sin(th - 1.4)];
}
const SHOULDER = 0.34, WS = 138;

function buildModel(lite) {
  const P = [], add = (o) => { o.g = (Math.random() * GN) | 0; o.ph = Math.random(); P.push(o); };
  const dens = lite ? 0.6 : 1;
  const NU = lite ? 70 : 112;
  for (let i = 0; i < NU; i++) {                      // body: rings of glyphs around the centre line
    const u = (i / (NU - 1)) * 0.985 + 0.0075, r = radius(u), m = Math.max(3, Math.round(r * 0.62 * dens) + 2);
    for (let k = 0; k < m; k++) add({ kind: 'body', u, ang: (k / m) * TAU + i * 0.7, rf: 1, arr: u });
    if (r > 8 && !lite) add({ kind: 'body', u, ang: Math.random() * TAU, rf: 0.45, arr: u });
  }
  for (let u = 0.16; u < 0.87; u += lite ? 0.04 : 0.022) for (let k = 0; k < 3; k++) add({ kind: 'spike', u, k, arr: u });          // crest of spines
  for (let side of [-1, 1]) for (let i = 0; i <= 9; i++) add({ kind: 'horn', side, tau: i / 9, arr: 0.1 });
  for (let i = 0; i < 12; i++) for (let j of [-1, 1]) add({ kind: 'jaw', u: 0.005 + i * 0.008, j, arr: 0.04 });
  for (let side of [-1, 1]) add({ kind: 'eye', side, arr: 0.06 });
  for (const uL of [0.38, 0.54]) for (let side of [-1, 1]) for (let i = 0; i <= 5; i++) add({ kind: 'leg', u: uL, side, f: i / 5, arr: uL });           // tucked legs
  for (let i = 0; i < (lite ? 24 : 50); i++) add({ kind: 'fin', f: Math.random(), h: Math.random() * 2 - 1, arr: 0.97 });                              // tail fin
  for (let side of [-1, 1]) {                         // wings: leading arm, four fingers and the membrane between them
    for (let i = 0; i <= 28; i++) add({ kind: 'wing', side, a: i / 28, b: 0, bone: true, arr: SHOULDER + 0.03 });
    for (const af of [0.3, 0.52, 0.72, 0.9]) for (let i = 1; i <= 8; i++) add({ kind: 'wing', side, a: af, b: i / 8, bone: true, arr: SHOULDER + 0.03 });
    const NA = lite ? 18 : 32, NB = lite ? 5 : 9;
    for (let i = 1; i <= NA; i++) for (let j = 1; j <= NB; j++) add({ kind: 'wing', side, a: i / NA * 0.97, b: (j - 0.5) / NB + (Math.random() - 0.5) * 0.08, bone: false, arr: SHOULDER + 0.03 });
  }
  return P;
}

// local position of one particle at time t; returns [x, y, z, brightness]
function place(p, t) {
  switch (p.kind) {
    case 'body': { const [sx, sy, sz] = spine(p.u, t), r = radius(p.u) * p.rf; return [sx, sy + r * Math.cos(p.ang), sz + r * Math.sin(p.ang), 0.5 + 0.45 * (1 - ss(0, 0.32, p.u))]; }
    case 'spike': { const [sx, sy, sz] = spine(p.u, t), r = radius(p.u), tall = 2.4 + 2.2 * (1 - Math.min(1, Math.abs(p.u - 0.4) * 2.2)); return [sx - p.k * 2.2, sy + r + p.k * tall, sz, 0.85]; }
    case 'horn': { const [sx, sy, sz] = spine(0.115, t), tt = p.tau; return [sx - 26 * tt, sy + radius(0.115) * 0.8 + 14 * tt - 5 * tt * tt, sz + p.side * (4 + 8 * tt), 0.95]; }
    case 'jaw': { const [sx, sy, sz] = spine(p.u, t), open = 6 + 5 * Math.sin(TAU * 0.9 * t); return [sx, sy - radius(p.u) * 0.7 - open * (1 - p.u / 0.1) * 0.9, sz + p.j * 2.6 * (radius(p.u) / 9), 0.9]; }
    case 'eye': { const [sx, sy, sz] = spine(0.075, t); return [sx, sy + 5, sz + p.side * 5, 1.3]; }
    case 'leg': { const [sx, sy, sz] = spine(p.u, t), r = radius(p.u); return [sx - 16 * p.f, sy - r - 12 * p.f, sz + p.side * (r * 0.7 + 4 * p.f), 0.7]; }
    case 'fin': { const [sx, sy, sz] = spine(1, t), f = p.f, hh = 24 * Math.sin(PI * f) * (0.55 + 0.45 * Math.abs(p.h)); return [sx + 6 - 30 * f, sy + p.h * hh, sz, 0.75]; }
    default: {                                        // wing
      const [sx, sy, sz] = spine(SHOULDER, t), x0 = sx + 2, y0 = sy + radius(SHOULDER) * 0.7, a = p.a, b = p.b;
      const xle = x0 + 20 * Math.sin(PI * a * 0.8) - 38 * a * a * a;                                 // leading edge sweeps forward, then back to the tip
      const chord = (118 * Math.pow(Math.sin(PI * Math.pow(a, 0.7)), 0.9) * (1 - 0.15 * a) + 34 * (1 - a)) * (0.86 + 0.14 * Math.cos(TAU * 3 * a));   // scalloped
      const zrel = WS * a - b * chord * 0.14, beta = 0.14 + 0.5 * Math.sin(TAU * 0.62 * t - 1.7 * a);   // wingbeat: the tip lags the root
      return [xle - b * chord, y0 + zrel * Math.sin(beta), sz + p.side * (6 + zrel * Math.cos(beta)), p.bone ? 0.9 : 0.5];
    }
  }
}

export async function startMatrixDragon(boot, { calm = false, lite = false } = {}) {
  const back = boot.querySelector('.bo-cv.back'), front = boot.querySelector('.bo-cv.front'), rain = boot.querySelector('.boot-rain');
  if (!back || !front) throw new Error('intro canvases missing');
  const P = buildModel(lite), atlas = buildAtlas();

  const dpr = Math.min(window.devicePixelRatio || 1, lite ? 1 : 1.25);
  const S = 1200;                                       // css size of the dragon canvases (centred on the ball)
  for (const cv of [back, front]) { cv.width = cv.height = Math.round(S * dpr); }
  const bx = back.getContext('2d'), fx = front.getContext('2d');
  for (const x of [bx, fx]) x.setTransform(dpr, 0, 0, dpr, 0, 0);

  // rain across the whole screen, behind everything
  let rx = null, RW = 0, RH = 0, cols = [];
  const RS = 14;                                       // glyph size / column width
  const sizeRain = () => { if (!rain) return; RW = window.innerWidth; RH = window.innerHeight; rain.width = Math.round(RW * dpr); rain.height = Math.round(RH * dpr); rx = rain.getContext('2d'); rx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cols = Array.from({ length: Math.ceil(RW / RS) }, () => ({ y: -Math.random() * RH, v: 90 + Math.random() * 220, on: Math.random() < (lite ? 0.25 : 0.45), wait: Math.random() * 3 })); };
  sizeRain();

  const R = 190, D = 900, MS = 1.32;                  // orbit radius, camera distance, model scale                              // orbit radius around the ball, camera distance
  const OMEGA = TAU / 3.6;                             // one lap every 3.6 s
  const draw = (ctx, g, hot, X, Y, size, alpha) => { ctx.globalAlpha = alpha; ctx.drawImage(atlas, g * CELL, hot * CELL, CELL, CELL, X - size / 2, Y - size / 2, size, size); };

  function frame(t, dt) {
    bx.clearRect(0, 0, S, S); fx.clearRect(0, 0, S, S);
    const tt = calm ? 0.55 : t;                        // the pose/time that drives the swimming wave and the wingbeat
    // Where the dragon is on its circle (it crosses the front around t = 2 s, once it has assembled) and which way it faces: along the path.
    const phi = calm ? 0.5 : OMEGA * (t - 2.0), sphi = Math.sin(phi), cphi = Math.cos(phi);
    const Tx = cphi, Tz = -sphi;                       // forward = tangent of the circle
    const bank = 0.16, sb = Math.sin(bank), cb = Math.cos(bank);
    const ux = -sb * sphi, uy = cb, uz = -sb * cphi;   // up, leaning into the turn (toward the ball)
    const Zx = -Tz * uy, Zy = Tz * ux - Tx * uz, Zz = Tx * uy;      // right = forward x up
    const Cx = R * sphi, Cz = R * cphi;                // centre of the dragon on its circle
    const pitch = -0.1, cp0 = Math.cos(pitch), sp0 = Math.sin(pitch);                 // nose slightly down, like the reference
    const cam = 0.26 + 0.05 * Math.sin(t * 0.5), cc = Math.cos(cam), sc2 = Math.sin(cam), C = S / 2;   // we look down on the orbit a little
    const sweep = (t * 0.7) % 1.6 - 0.3;               // a bright pulse running from the head to the tail
    for (const p of P) {
      const arrive = calm ? 0 : 0.45 + 1.0 * p.arr + p.ph * 0.18, prog = calm ? 1 : clamp((t - arrive) / 0.5);
      if (prog <= 0) continue;
      if (!calm && Math.random() < dt * 2.2) p.g = (Math.random() * GN) | 0;                    // glyphs keep changing
      const l = place(p, tt), b0 = l[3];
      const x1 = (l[0] * cp0 - l[1] * sp0) * MS, y1 = (l[0] * sp0 + l[1] * cp0) * MS, z0 = l[2] * MS;
      const wx = Cx + x1 * Tx + y1 * ux + z0 * Zx;
      const wy = y1 * uy + z0 * Zy + (1 - easeOut(prog)) * 130;                               // falls in from above while assembling
      const wz = Cz + x1 * Tz + y1 * uz + z0 * Zz;
      const yc = wy * cc - wz * sc2, zc = wy * sc2 + wz * cc;                                  // tilt the whole scene toward the camera
      const sc = D / (D - zc), depth = clamp((zc + R + 110) / (2 * R + 220));
      const b = b0 + 0.5 * Math.exp(-Math.pow((p.arr - sweep) / 0.07, 2));
      const alpha = clamp(b * (0.4 + 0.6 * depth) * prog, 0, 1);
      const hot = prog < 0.95 || b > 1.0 ? 1 : 0;
      const ctx = zc < 0 ? bx : fx, X = C + wx * sc, Y = C - yc * sc;
      const size = (p.kind === 'wing' && !p.bone ? 6.8 : p.kind === 'eye' ? 10 : 7.8) * sc;
      draw(ctx, 0, 2, X, Y, size * 0.95, alpha * 0.55);                                        // soft glow under the glyph
      draw(ctx, p.g, hot, X, Y, size, Math.min(1, alpha * 1.15));
    }
    bx.globalAlpha = fx.globalAlpha = 1;
    if (rx && !calm) {
      rx.globalCompositeOperation = 'destination-out'; rx.fillStyle = 'rgba(0,0,0,.1)'; rx.fillRect(0, 0, RW, RH); rx.globalCompositeOperation = 'source-over';
      for (let i = 0; i < cols.length; i++) {
        const c = cols[i];
        if (!c.on) { c.wait -= dt; if (c.wait <= 0) { c.on = true; c.y = -20; c.v = 90 + Math.random() * 220; } continue; }
        const py = c.y; c.y += c.v * dt;
        for (let y = Math.floor(py / RS) + 1; y <= Math.floor(c.y / RS); y++) { rx.globalAlpha = 0.85; rx.drawImage(atlas, ((Math.random() * GN) | 0) * CELL, (y === Math.floor(c.y / RS) ? 1 : 0) * CELL, CELL, CELL, i * RS, y * RS, RS, RS); }
        rx.globalAlpha = 1;
        if (c.y > RH + 40) { c.on = Math.random() < 0.8; c.wait = Math.random() * 2.5; c.y = -20; }
      }
    }
  }

  let raf = 0, last = performance.now(), t0 = last, stopped = false;
  const loop = (now) => {
    if (stopped) return;
    raf = requestAnimationFrame(loop);
    if (now - last < 16) return;
    const dt = Math.min(0.08, (now - last) / 1000); last = now;
    frame((now - t0) / 1000, dt);
  };
  boot.classList.add('mx');                            // hides the plain CSS dragon: this one takes over
  if (calm) frame(0, 0); else raf = requestAnimationFrame(loop);
  const onResize = () => sizeRain();
  window.addEventListener('resize', onResize);
  return () => { stopped = true; cancelAnimationFrame(raf); window.removeEventListener('resize', onResize); bx.clearRect(0, 0, S, S); fx.clearRect(0, 0, S, S); if (rx) rx.clearRect(0, 0, RW, RH); };
}
