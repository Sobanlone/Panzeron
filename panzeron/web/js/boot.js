// Startup sequence: the orb ignites, a dragon in your accent colour circles it, the wordmark assembles, the curtains part and the
// interface rises in behind them. The progress bar is timed; "ready" is only shown once the local engine has really answered.
// A click or Esc skips it (not in the first moments). Nothing here can leave the interface hidden: every path ends in open() or unstick().
import { api } from './api.js';
import { playSfx } from './sfx.js';

const root = document.documentElement;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const MIN_MS = { full: 4400, calm: 1500 };     // long enough for the code dragon to assemble and fly a lap; the calm still splash is shorter
const FAILSAFE_MS = 7000;                       // the intro never holds the interface longer than this, whatever the engine does
const INPUT_GRACE_MS = 900;                     // clicks/keys this soon after the intro appears are launch leftovers (a held Enter, a stray click), not a skip

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

    let opened = false, failsafe = 0, stopDragon = () => {};
    const shownAt = performance.now();
    const open = async () => {
      if (opened) return; opened = true; clearTimeout(failsafe);
      el.classList.add('open');
      root.classList.replace('booting', 'revealing');      // interface becomes visible under the parting curtains
      await sleep(calm ? 500 : 1000);
      stopDragon();
      unstick();
    };
    el.addEventListener('click', open);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') open(); });
    failsafe = setTimeout(open, FAILSAFE_MS);

    el.classList.add('go');           // animations start now, after the accent colour has been applied (see app.js)
    playSfx('boot');
    // The 3D code dragon (js/matrix-dragon.js). If it cannot start, the plain CSS dragon in the markup keeps working.
    import('./matrix-dragon.js').then((m) => m.startMatrixDragon(el, { calm, lite: root.dataset.fx === 'lite' || (navigator.hardwareConcurrency || 8) <= 2 }))
      .then((stop) => { stopDragon = stop; if (opened) stop(); }).catch((e) => console.warn('code dragon unavailable, using the plain one', e));
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
