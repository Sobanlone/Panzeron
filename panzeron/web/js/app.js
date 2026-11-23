import { api } from './api.js';
import { clear, h, icon, skeleton, toast } from './ui.js';
import { appearance } from './appearance.js';
import { runBoot } from './boot.js';
import * as command from './pages/command.js';
import * as shield from './pages/shield.js';
import * as privacy from './pages/privacy.js';
import * as threat from './pages/threat.js';
import * as graph from './pages/graph.js';
import * as response from './pages/response.js';
import * as history from './pages/history.js';
import * as settings from './pages/settings.js';

// The startup intro is painted in the user's accent colour, so the appearance variables are applied first. It is started before
// anything else in this file that could fail, so a later error can never leave the intro on screen.
appearance.init();
const intro = runBoot();

const ROUTES = [   // [id, friendly name, page, nav icon, one-line description shown under the title]
  ['command', 'Home', command, 'command', 'Your protection at a glance'], ['shield', 'Scan', shield, 'shield', 'Look for viruses and risky files'],
  ['privacy', 'Private info', privacy, 'privacy', 'Find passwords, IDs and personal details hiding in files'],
  ['threat', 'Check a message', threat, 'threat', 'Find out if a message, link or email is a scam'],
  ['graph', 'Connections', graph, 'graph', 'See how your exposed details link together'], ['response', 'Fix & review', response, 'response', 'Look at what was found and decide what to do'],
  ['history', 'History', history, 'history', 'Everything I have checked before'], ['settings', 'Settings', settings, 'settings', 'Make it look and feel the way you like'],
];
const view = document.getElementById('view');
const nav = document.getElementById('nav');
let current = null;
let token = 0;

let lastDetected = null;
async function refreshChrome() {
  try {
    const s = await api.get('/api/summary');   // tiny and instant: no probes
    if (lastDetected !== null && s.watcher.detected > lastDetected) toast('Downloads watcher flagged a new file. Review it in Fix & review.', true);
    lastDetected = s.watcher.detected;
    nav.querySelectorAll('a').forEach((a) => {
      const c = a.querySelector('.count'); if (c) c.remove();
      if (a.dataset.id === 'response' && s.open > 0) a.append(h('span', { class: 'count' }, s.open));
    });
    document.getElementById('sidefoot').replaceChildren(
      h('div', {}, h('span', { class: s.remote_ai ? 'dot warn' : 'dot' }), s.remote_ai ? 'AI messages go to a remote host you approved' : `Local only · ${location.hostname || '127.0.0.1'}`),
      h('div', {}, `v${s.version}`));
  } catch (e) { /* informational only */ }
}

export const ctx = { refreshChrome, navigate: (id) => { location.hash = `#/${id}`; } };

async function render() {
  const id = (location.hash.match(/^#\/(\w+)/) || [])[1] || 'command';
  const route = ROUTES.find((r) => r[0] === id) || ROUTES[0];
  const my = ++token;
  nav.querySelectorAll('a').forEach((a) => a.classList.toggle('on', a.dataset.id === route[0]));
  document.getElementById('title').textContent = route[1];
  document.getElementById('tagline').textContent = route[4] || '';
  document.title = `${route[1]} · Panzeron`;
  clear(document.getElementById('topright'));
  view.replaceChildren(skeleton());                 // responds immediately; real content swaps in when ready
  const stage = h('div', { class: 'stage' });
  const alive = () => my === token;
  try {
    await route[2].render(stage, ctx, alive);
  } catch (e) {
    stage.append(h('div', { class: 'notice bad' }, `This page failed to load: ${e.message}`, ' ',
      h('button', { class: 'ghost', onclick: render }, 'Retry')));
    console.error(e);
  }
  if (alive()) {
    stage.querySelectorAll('.card, .tile, .finding, .preset').forEach((el, i) => el.style.setProperty('--i', Math.min(i, 14)));
    view.replaceChildren(stage);
  }
  refreshChrome();
}

for (const [id, label, , ic] of ROUTES) nav.append(h('a', { href: `#/${id}`, dataset: { id }, title: label }, icon(ic), h('span', {}, label)));

// ---- light / dark: remembered on this device -------------------------------------------------------------------
const themeBtn = document.getElementById('theme');
function paintTheme() {
  const light = document.documentElement.dataset.theme === 'light';
  themeBtn.replaceChildren(icon(light ? 'moon' : 'sun'));
  themeBtn.setAttribute('aria-pressed', String(light));
}
themeBtn.addEventListener('click', () => {
  const light = document.documentElement.dataset.theme !== 'light';
  if (light) document.documentElement.dataset.theme = 'light'; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem('panzeron-theme', light ? 'light' : 'dark'); } catch { /* storage unavailable */ }
  paintTheme();
});
paintTheme();

// ---- appearance: glass quality adapts to the graphics hardware; everything else is user-controlled in Settings ----
appearance.syncFromServer();   // the engine keeps a copy, so appearance survives a cleared browser profile
intro.finally(() => appearance.autoDetect());   // measured after the intro: its own animation must not make a good GPU look slow

// ---- liquid-glass sheen: surfaces catch a highlight that follows the pointer --------------------------------
let raf = 0;
document.addEventListener('pointermove', (e) => {
  if (raf) return;
  raf = requestAnimationFrame(() => {
    raf = 0;
    const el = e.target.closest && e.target.closest('.card, .side, .finding, .modal, .top');
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${e.clientX - r.left}px`);
    el.style.setProperty('--my', `${e.clientY - r.top}px`);
  });
}, { passive: true });
window.addEventListener('hashchange', render);
render();

// Live alerts from the Downloads watcher (cheap, instant endpoint; paused while the window is hidden).
setInterval(() => { if (document.visibilityState === 'visible') refreshChrome(); }, 8000);
