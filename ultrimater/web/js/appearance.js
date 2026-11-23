// Appearance engine: every visual property is a validated preference applied live as CSS variables / data attributes.
// The validation rules mirror ultrimater/core/uiprefs.py (the server re-validates everything it stores).
import { api } from './api.js';
import { setBackgroundEffect } from './bgfx.js';

export const DEFAULTS = {
  accent: '#4169e1', bg: 'royal', pureBlack: false, fx: 'auto', blur: 22, glass: 50, sheen: true,
  density: 'comfortable', width: 'default', sidebar: 'expanded', font: 'system', textSize: 'default', anim: true,
};
const ENUMS = {
  bg: ['royal', 'midnight', 'ocean', 'emerald', 'crimson', 'graphite', 'solid'], fx: ['auto', 'full', 'lite'],
  density: ['compact', 'comfortable', 'spacious'], width: ['focused', 'default', 'full'],
  sidebar: ['expanded', 'compact'], font: ['system', 'humanist', 'serif', 'mono'], textSize: ['small', 'default', 'large', 'xl'],
};
const BOOLS = ['pureBlack', 'sheen', 'anim'];
const RANGES = { blur: [0, 40], glass: [0, 100] };
const HEX = /^#[0-9a-fA-F]{6}$/;

export function sanitize(raw) {
  const clean = { ...DEFAULTS }, rejected = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { clean, rejected: ['<not an object>'] };
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in DEFAULTS)) rejected.push(k);
    else if (k in ENUMS) (ENUMS[k].includes(v) ? (clean[k] = v) : rejected.push(k));
    else if (BOOLS.includes(k)) (typeof v === 'boolean' ? (clean[k] = v) : rejected.push(k));
    else if (k in RANGES) (typeof v === 'number' && Number.isFinite(v) ? (clean[k] = Math.round(Math.min(RANGES[k][1], Math.max(RANGES[k][0], v)))) : rejected.push(k));
    else if (k === 'accent') (typeof v === 'string' && HEX.test(v) ? (clean[k] = v.toLowerCase()) : rejected.push(k));
  }
  return { clean, rejected };
}

// Royal palette: blues, steel, a restrained champagne gold. No purple, no pink.
export const ACCENTS = [['Royal', '#4169e1'], ['Sapphire', '#1f6feb'], ['Steel', '#7a8fb3'], ['Teal', '#2bb5b0'], ['Emerald', '#2fb872'],
  ['Gold', '#c9a45c'], ['Crimson', '#d6455d'], ['Silver', '#b8c0cc']];

// Light fields behind the glass: soft, static, cool.
export const BACKGROUNDS = {
  royal: { label: 'Royal', fx: 'Constellation', colors: ['rgba(65,105,225,.50)', 'rgba(150,62,235,.62)', 'rgba(16,185,160,.50)', 'rgba(235,60,95,.52)'] },
  midnight: { label: 'Midnight', fx: 'Starfield', colors: ['rgba(40,70,140,.26)', 'rgba(15,30,80,.38)', 'rgba(90,110,150,.10)', 'rgba(10,20,50,.30)'] },
  ocean: { label: 'Ocean', fx: 'Bubbles', colors: ['rgba(0,122,255,.28)', 'rgba(0,160,170,.22)', 'rgba(50,100,200,.20)', 'rgba(90,170,220,.10)'] },
  emerald: { label: 'Emerald', fx: 'Matrix code', colors: ['rgba(47,184,114,.24)', 'rgba(0,130,110,.28)', 'rgba(90,160,120,.12)', 'rgba(20,70,70,.30)'] },
  crimson: { label: 'Crimson', fx: 'Embers', colors: ['rgba(214,69,93,.26)', 'rgba(120,20,40,.36)', 'rgba(200,110,100,.10)', 'rgba(60,10,25,.34)'] },
  graphite: { label: 'Graphite', fx: 'Circuit', colors: ['rgba(150,160,180,.16)', 'rgba(100,110,135,.18)', 'rgba(190,198,215,.08)', 'rgba(80,90,115,.18)'] },
  solid: { label: 'Solid', fx: 'Still', colors: ['transparent', 'transparent', 'transparent', 'transparent'] },
};

export const PRESETS = [
  { id: 'royal', name: 'Royal', prefs: {} },
  { id: 'sapphire', name: 'Sapphire', prefs: { accent: '#1f6feb', bg: 'ocean' } },
  { id: 'gold', name: 'Gold', prefs: { accent: '#c9a45c', bg: 'midnight' } },
  { id: 'emerald', name: 'Emerald', prefs: { accent: '#2fb872', bg: 'emerald' } },
  { id: 'platinum', name: 'Platinum', prefs: { accent: '#b8c0cc', bg: 'graphite' } },
  { id: 'obsidian', name: 'Obsidian', prefs: { accent: '#b8c0cc', bg: 'solid', pureBlack: true, blur: 14, glass: 30, sheen: false } },
  { id: 'crimson-ops', name: 'Crimson Ops', prefs: { accent: '#d6455d', bg: 'crimson', density: 'compact', blur: 12, glass: 35, sheen: false } },
];

const FONTS = {
  system: '"Segoe UI Variable Display","Segoe UI Variable Text","SF Pro Display",Inter,system-ui,-apple-system,"Segoe UI",sans-serif',
  humanist: 'Candara,"Segoe UI","Trebuchet MS",Verdana,sans-serif',
  serif: '"Iowan Old Style","Palatino Linotype",Georgia,Cambria,serif',
  mono: '"Cascadia Code","Cascadia Mono",Consolas,ui-monospace,monospace',
};
const TEXT = { small: 0.92, default: 1, large: 1.1, xl: 1.22 };
const DENSITY = { compact: 0.78, comfortable: 1, spacious: 1.25 };
const WIDTH = { focused: '1040px', default: '1280px', full: 'none' };

// ---- colour maths (accent -> readable link colour, gradient partner, text-on-accent) ------------------------------
const hexToRgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
function rgbToHsl([r, g, b]) {
  r /= 255; g /= 255; b /= 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2; let hh = 0, s = 0;
  if (mx !== mn) { const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); hh = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; hh *= 60; }
  return [hh, s, l];
}
function hslToHex(hh, s, l) {
  hh = ((hh % 360) + 360) % 360;
  const f = (n) => { const k = (n + hh / 30) % 12, a = s * Math.min(l, 1 - l); return Math.round(255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)))); };
  return '#' + [f(0), f(8), f(4)].map((v) => v.toString(16).padStart(2, '0')).join('');
}
const luminance = ([r, g, b]) => { const c = [r, g, b].map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };

const root = document.documentElement;
const LS = 'ultrimater-prefs';
let prefs = { ...DEFAULTS };
let saveTimer = null;
const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };

function loadLocal() {
  try { const raw = read(LS); if (raw) return sanitize(JSON.parse(raw)).clean; } catch { /* fall through */ }
  // migrate the older single-value keys, if present
  const old = {}; const f = read('ultrimater-fx');
  if (['auto', 'full', 'lite'].includes(f)) old.fx = f;
  return sanitize(old).clean;
}

// The tab/window icon is the dragon on the dark tile, painted in the accent colour (canvas -> PNG data URL; the CSP allows data: images).
let dragonImg = null, lastFav = null;
function setFavicon(hi, mid, lo) {
  lastFav = [hi, mid, lo];
  const link = document.querySelector('link[rel="icon"]') || Object.assign(document.createElement('link'), { rel: 'icon' });
  if (!link.isConnected) document.head.append(link);
  if (!dragonImg) {                                   // load the mask once, then redraw
    dragonImg = new Image(); dragonImg.onload = () => setFavicon(...lastFav); dragonImg.src = '/img/dragon.png';
    return;
  }
  if (!dragonImg.complete || !dragonImg.naturalWidth) return;
  const S = 64, c = document.createElement('canvas'); c.width = c.height = S;
  const x = c.getContext('2d'); if (!x) return;
  x.fillStyle = '#090a10'; x.beginPath(); x.roundRect(0, 0, S, S, 15); x.fill();
  const h = S * 0.84, w = h * dragonImg.naturalWidth / dragonImg.naturalHeight;
  const t = document.createElement('canvas'); t.width = t.height = S; const y = t.getContext('2d');
  const g = y.createLinearGradient(0, 0, 0, S); g.addColorStop(0, hi); g.addColorStop(0.45, mid); g.addColorStop(1, lo);
  y.fillStyle = g; y.fillRect(0, 0, S, S); y.globalCompositeOperation = 'destination-in';
  y.drawImage(dragonImg, (S - w) / 2, (S - h) / 2, w, h);
  x.drawImage(t, 0, 0);
  link.type = 'image/png'; link.href = c.toDataURL('image/png');
}

export function apply(p = prefs) {
  const st = root.style;
  root.dataset.pureblack = p.pureBlack ? 'on' : 'off';
  root.dataset.sheen = p.sheen ? 'on' : 'off';
  root.dataset.anim = p.anim ? 'on' : 'off';
  root.dataset.sidebar = p.sidebar;
  root.dataset.fx = p.fx === 'lite' || (p.fx === 'auto' && read('ultrimater-fx-auto') === 'lite') ? 'lite' : 'full';
  // accent
  const rgb = hexToRgb(p.accent), [hh, s, l] = rgbToHsl(rgb);
  st.setProperty('--accent', p.accent);
  st.setProperty('--accent-rgb', rgb.join(','));
  st.setProperty('--accent2', hslToHex(hh, s, Math.max(l, 0.68)));
  st.setProperty('--accent-grad', `linear-gradient(135deg, ${hslToHex(hh - 6, s, Math.min(0.62, l + 0.03))} 0%, ${hslToHex(hh + 28, s, Math.max(0.42, l - 0.05))} 100%)`);
  const hi = hslToHex(hh, Math.min(1, s), 0.86), mid = hslToHex(hh, s, Math.min(0.58, Math.max(0.4, l))), lo = hslToHex(hh + 8, s, 0.2);
  st.setProperty('--accent-hi', hi); st.setProperty('--accent-mid', mid); st.setProperty('--accent-lo', lo);
  setFavicon(hi, mid, lo);
  st.setProperty('--on-accent', luminance(rgb) > 0.5 ? '#101114' : '#ffffff');
  // glass
  st.setProperty('--blur', `${p.blur}px`);
  const ga = 0.01 + (p.glass / 50) * 0.06;
  st.setProperty('--ga', ga.toFixed(3));
  st.setProperty('--ga2', (ga * 1.57).toFixed(3));
  // shape, rhythm, type, layout
  st.setProperty('--d', DENSITY[p.density]); st.setProperty('--fs', TEXT[p.textSize]);
  st.setProperty('--maxw', WIDTH[p.width]); st.setProperty('--font', FONTS[p.font]);
  // Every background light field follows the user's accent, including when the accent is changed live.
  st.setProperty('--orb-a', `rgba(${rgb.join(',')},.50)`);
  st.setProperty('--orb-b', `rgba(${rgb.join(',')},.42)`);
  st.setProperty('--orb-c', `rgba(${rgb.join(',')},.38)`);
  st.setProperty('--orb-d', `rgba(${rgb.join(',')},.34)`);
  setBackgroundEffect({ bg: p.bg, anim: p.anim, lite: root.dataset.fx === 'lite', rgb });   // each theme's live effect (js/bgfx.js)
}

let dirty = false;
function persist() {
  write(LS, JSON.stringify(prefs));
  dirty = true;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(flush, 400);
}
// Also flushed when the window closes, so a change made just before quitting is never lost or overridden by an older engine copy.
function flush() {
  if (!dirty) return;
  dirty = false; clearTimeout(saveTimer);
  api.put('/api/ui-prefs', prefs, { keepalive: true }).catch(() => { /* local copy still applies */ });
}
window.addEventListener('pagehide', flush);
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') flush(); });

export const appearance = {
  get: () => ({ ...prefs }),
  init() { prefs = loadLocal(); apply();  },
  set(patch) { prefs = sanitize({ ...prefs, ...patch }).clean; apply(); persist(); return { ...prefs }; },
  applyPreset(id) { const pr = PRESETS.find((x) => x.id === id); if (!pr) return; prefs = sanitize({ ...DEFAULTS, fx: prefs.fx, sidebar: prefs.sidebar, ...pr.prefs }).clean; apply(); persist(); if (prefs.fx === 'auto') this.autoDetect(true); },
  reset() { prefs = { ...DEFAULTS }; try { localStorage.removeItem(LS); } catch { /* ignore */ } apply(); api.del('/api/ui-prefs').catch(() => {}); },
  exportText() { return JSON.stringify({ ultrimater_theme: 1, ...prefs }, null, 2); },
  importText(text) {                      // throws on invalid JSON; reports which keys were ignored
    let obj; try { obj = JSON.parse(text); } catch { throw new Error('That is not valid JSON.'); }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('A theme file must be a JSON object.');
    delete obj.ultrimater_theme;
    const { clean, rejected } = sanitize({ ...DEFAULTS, ...obj });
    prefs = clean; apply(); persist(); return rejected;
  },
  async syncFromServer() {                // the server copy survives a cleared browser profile; adopt it if present
    try {
      const { prefs: srv } = await api.get('/api/ui-prefs');
      if (srv) { const clean = sanitize(srv).clean; if (JSON.stringify(clean) !== JSON.stringify(prefs)) { prefs = clean; write(LS, JSON.stringify(prefs)); apply(); return true; } }
      else if (read(LS)) api.put('/api/ui-prefs', prefs).catch(() => {});
    } catch { /* offline engine: local prefs stay */ }
    return false;
  },
  // Measures real frame times once; slow graphics get the lighter material automatically (only when fx = auto).
  autoDetect(force = false) {
    if (prefs.fx !== 'auto') return;
    if (!force && read('ultrimater-fx-auto')) return;
    let last = performance.now(); const ds = [];
    const step = (t) => {
      ds.push(t - last); last = t;
      if (ds.length < 40) return requestAnimationFrame(step);
      ds.splice(0, 5); ds.sort((a, b) => a - b);
      write('ultrimater-fx-auto', ds[Math.floor(ds.length / 2)] > 26 ? 'lite' : 'full'); apply();
    };
    setTimeout(() => requestAnimationFrame(step), 900);
  },
};
