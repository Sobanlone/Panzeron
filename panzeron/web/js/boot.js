// Startup sequence: the orb ignites, a dragon in your accent colour circles it, the wordmark assembles, the curtains part and the
// interface rises in behind them. The progress bar is timed; "ready" is only shown once the local engine has really answered.
// A click or Esc skips it (not in the first moments). Nothing here can leave the interface hidden: every path ends in open() or unstick().
import { api } from './api.js';
import { orbitAround } from './dragon.js';

const root = document.documentElement;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MIN_MS = { full: 3200, calm: 1500 };     // long enough for the dragon to complete one lap; the calm still splash is shorter
const FAILSAFE_MS = 7000;                       // the intro never holds the interface longer than this, whatever the engine does
const INPUT_GRACE_MS = 900;                     // clicks/keys this soon after the intro appears are launch leftovers (a held Enter, a stray click), not a skip

function startMatrixDragon(calm = false) {
  const canvas = document.querySelector('#boot .matrix-dragon');
  if (!canvas) return () => {};
  const ctx = canvas.getContext('2d');
  const image = new Image();
  let stopped = false, raf = 0, tick = 0;
  const glyphs = 'ｱｲｳｴｵｶｷｸｹｺｻ01ZPXN82#@';
  const streams = Array.from({ length: 24 }, (_, i) => ({
    x: i * 15 + Math.random() * 8,
    y: Math.random() * 480,
    speed: 18 + Math.random() * 36,
  }));
  const frame = (now) => {
    if (stopped) return;
    const dt = Math.min(.05, (now - tick) / 1000 || .016); tick = now;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    if (image.complete && image.naturalWidth) {
      const scale = Math.max(canvas.width / image.naturalWidth, canvas.height / image.naturalHeight);
      const w = image.naturalWidth * scale, h = image.naturalHeight * scale;
      ctx.drawImage(image, (canvas.width - w) / 2, (canvas.height - h) / 2, w, h);
      ctx.globalCompositeOperation = 'screen';
      ctx.fillStyle = 'rgba(20,255,120,.10)';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.globalCompositeOperation = 'source-over';
    }
    ctx.font = '12px "Cascadia Mono", monospace';
    ctx.textBaseline = 'top';
    for (const stream of streams) {
      stream.y += stream.speed * dt;
      if (stream.y > 500) stream.y = -70;
      for (let y = stream.y; y > stream.y - 120; y -= 14) {
        if (y < 0 || y > 480) continue;
        const alpha = Math.max(0, 1 - Math.abs(y - stream.y) / 120);
        ctx.fillStyle = `rgba(120,255,170,${alpha * .48})`;
        ctx.fillText(glyphs[(stream.x + y + now * .03) % glyphs.length | 0], stream.x, y);
      }
    }
    if (!calm) raf = requestAnimationFrame(frame);
  };
  image.onload = () => {
    tick = performance.now();
    if (calm) frame(tick);
    else raf = requestAnimationFrame(frame);
  };
  image.src = '/img/matrix-dragon.jpg';
  return () => { stopped = true; cancelAnimationFrame(raf); };
}

const unstick = () => root.classList.remove('booting', 'revealing');

export async function runBoot() {
  if (!root.classList.contains('booting')) return;
  try {
    const el = document.getElementById('boot'), status = document.getElementById('boot-status');
    if (!el || !status) { unstick(); return; }
    try { sessionStorage.setItem('panzeron-booted', '1'); } catch { /* storage unavailable */ }
    const calm = root.classList.contains('calm');

    // A window that opens hidden or minimised (e.g. at sign-in) must not burn the intro while nobody can see it.
    if (document.visibilityState === 'hidden') await new Promise((res) => { document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') res(); }); setTimeout(res, 20000); });

    let opened = false, failsafe = 0, stopDragon = () => {}, stopMatrix = () => {};
    const shownAt = performance.now();
    const open = async () => {
      if (opened) return; opened = true; clearTimeout(failsafe);
      stopDragon();
      stopMatrix();
      el.classList.add('open');
      root.classList.replace('booting', 'revealing');      // interface becomes visible under the parting curtains
      await sleep(calm ? 500 : 1000);
      unstick();
    };
    el.addEventListener('click', open);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') open(); });
    failsafe = setTimeout(open, FAILSAFE_MS);

    el.classList.add('go');           // animations start now, after the accent colour has been applied (see app.js)
    stopMatrix = startMatrixDragon(calm);
    stopDragon = document.documentElement.classList.contains('calm') ? () => {} : orbitAround(
      document.querySelector('#boot .boot-orbit'),
      { rx: 188, ry: 54, period: 3.0, tilt: -8, delay: 0.25, enter: 1.0, minScale: 0.72, maxScale: 1.14 }
    );
    const ready = api.get('/api/summary').then(() => true, () => false);
    await Promise.all([ready, sleep(calm ? MIN_MS.calm : MIN_MS.full)]);
    if (opened) return;
    status.textContent = (await ready) ? 'Local engine ready' : 'Engine not responding';
    await sleep(350);
    open();
  } catch (e) {
    console.error(e);
    unstick();                         // an intro problem must never cost the user the app
  }
}
