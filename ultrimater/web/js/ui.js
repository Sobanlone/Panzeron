// Safe DOM helpers: all dynamic text goes through textContent, never innerHTML (scam content is hostile).
export function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style' && typeof v === 'object') { for (const [sk, sv] of Object.entries(v)) { if (sk.startsWith('--')) el.style.setProperty(sk, sv); else el.style[sk] = sv; } }
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// Append children safely: flattens arrays and skips null/false (Element.append would print "null" / "[object HTMLDivElement]").
export function mount(parent, ...kids) {
  parent.append(...kids.flat(Infinity).filter((k) => k != null && k !== false));
  return parent;
}
export const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

export const sevBadge = (s) => h('span', { class: `badge sev-${s}` }, s);
export const tierLabel = (t) => h('span', { class: `tier ${t}`, title: TIER_HELP[t] }, t.replace('_', ' '));
export const TIER_HELP = {
  verified: 'Deterministic and reproducible (e.g. exact byte match, checksum).',
  derived: 'A fixed rule applied to verified facts.',
  ai_assessed: 'A language model’s judgement. Not verified.',
  speculative: 'A hypothesis. Not verified.',
};
export const SEV_COLOR = { info: 'var(--sev-info)', low: 'var(--sev-low)', medium: 'var(--sev-medium)', high: 'var(--sev-high)', critical: 'var(--sev-critical)' };

export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return isNaN(d) ? String(iso) : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}
export const fmtBytes = (n) => n == null ? '—' : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

export function toast(msg, isErr = false) {
  const t = h('div', { class: `toast${isErr ? ' err' : ''}` }, msg);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), isErr ? 7000 : 3800);
}

export function confirmDialog({ title, body, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const done = (v) => { bg.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') done(false); };
    const bg = h('div', { class: 'modal-bg', onclick: (e) => e.target === bg && done(false) },
      h('div', { class: 'modal', role: 'dialog', 'aria-modal': 'true' },
        h('h3', {}, title), h('p', { class: 'muted' }, body),
        h('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '16px' } },
          h('button', { class: 'ghost', onclick: () => done(false) }, 'Cancel'),
          h('button', { class: danger ? 'primary' : '', onclick: () => done(true) }, confirmLabel))));
    document.addEventListener('keydown', onKey);
    document.body.append(bg);
    bg.querySelector('button.primary, button:last-child').focus();
  });
}

export function statusPill(state, label) {
  return h('span', { class: `pill ${state === true ? 'ok' : state === false ? 'off' : 'na'}` }, label);
}
export const emptyState = (msg, ...extra) => h('div', { class: 'empty' }, msg, ...extra);
export const hbar = (label, n, max, color) => h('div', { class: 'hbar' }, h('span', { class: 'l' }, label),
  h('div', { class: 'bar' }, h('i', { style: { width: `${max ? Math.round(100 * n / max) : 0}%`, background: color || 'var(--accent)' } })), h('b', {}, n));

export function evidenceList(evidence) {
  return h('div', {}, evidence.map((e) => h('div', { class: 'evid' },
    h('div', {}, tierLabel(e.tier)),
    h('div', {}, e.description),
    h('div', { class: 'ref' }, `${e.source_ref}  ·  ${e.produced_by}`))));
}

// A finding card with expandable evidence and (optionally) response actions.
export function findingCard(f, { actions = null, onAction = null, open = false } = {}) {
  const card = h('div', { class: `finding${open ? ' open' : ''}` });
  const head = h('div', { class: 'head', tabindex: 0, role: 'button', onclick: () => card.classList.toggle('open'),
    onkeydown: (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), card.classList.toggle('open')) },
    h('span', { class: 'sevbar', style: { background: SEV_COLOR[f.severity] } }),
    h('div', { class: 't' }, h('b', {}, f.title), h('div', { class: 'small' }, `${f.module} · ${f.source}${f.status !== 'open' ? ' · ' + f.status.replace('_', ' ') : ''}`)),
    h('span', { class: 'badge', title: 'Confidence is ordinal (low/medium/high), not a probability.' }, `${f.confidence} confidence`),
    tierLabel(f.tier), sevBadge(f.severity));
  const body = h('div', { class: 'body' },
    h('p', {}, f.explanation),
    h('h2', { style: { marginTop: '14px' } }, 'Evidence'), evidenceList(f.evidence),
    f.entities.length ? h('div', { style: { marginTop: '12px' } }, h('h2', {}, 'Involved items (masked)'),
      h('div', { class: 'chips' }, f.entities.map((e) => h('span', { class: 'badge mono' }, `${e.kind}: ${e.display_masked}`)))) : null,
    f.recommended_actions.length ? h('div', { style: { marginTop: '12px' } }, h('h2', {}, 'Recommended'),
      h('ul', { style: { margin: 0, paddingLeft: '18px' } }, f.recommended_actions.map((a) => h('li', {}, a)))) : null);
  if (actions && onAction) {
    body.append(h('div', { class: 'row', style: { marginTop: '14px' } }, actions.map((a) =>
      h('button', { class: a.destructive ? 'danger' : '', title: a.description, onclick: () => onAction(a, f) }, a.label))));
  }
  card.append(head, body);
  return card;
}

export function severityChart(by) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const max = Math.max(1, ...order.map((k) => by[k] || 0));
  return h('div', {}, order.map((k) => hbar(k, by[k] || 0, max, SEV_COLOR[k])));
}

// ---- icons (SF-Symbols-style line icons, built with DOM APIs) --------------------------------------------
const ICONS = {
  command: [['rect', { x: 3, y: 3, width: 7, height: 9, rx: 2 }], ['rect', { x: 14, y: 3, width: 7, height: 5, rx: 2 }], ['rect', { x: 14, y: 12, width: 7, height: 9, rx: 2 }], ['rect', { x: 3, y: 16, width: 7, height: 5, rx: 2 }]],
  shield: [['path', { d: 'M12 3l7.5 3v6c0 4.6-3.2 7.6-7.5 9-4.3-1.4-7.5-4.4-7.5-9V6z' }], ['path', { d: 'M9 12l2.2 2.2L15.5 10' }]],
  privacy: [['path', { d: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  threat: [['path', { d: 'M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z' }], ['path', { d: 'M12 9.5v4M12 17h.01' }]],
  graph: [['circle', { cx: 6, cy: 6.5, r: 2.5 }], ['circle', { cx: 18, cy: 8.5, r: 2.5 }], ['circle', { cx: 12, cy: 18, r: 2.5 }], ['path', { d: 'M8.4 7l7.1 1.2M7.3 8.7l3.6 6.9M16.7 10.7l-3.6 5' }]],
  response: [['circle', { cx: 12, cy: 12, r: 9 }], ['circle', { cx: 12, cy: 12, r: 3.5 }], ['path', { d: 'M5.6 5.6l3.9 3.9M14.5 14.5l3.9 3.9M18.4 5.6l-3.9 3.9M9.5 14.5l-3.9 3.9' }]],
  history: [['circle', { cx: 12, cy: 12, r: 9 }], ['path', { d: 'M12 7v5l3 2' }]],
  bolt: [['path', { d: 'M13 2L4 14h7l-1 8 9-12h-7z' }]],
  user: [['circle', { cx: 12, cy: 8, r: 4 }], ['path', { d: 'M4 21c1-4 4.5-6 8-6s7 2 8 6' }]],
  computer: [['rect', { x: 3, y: 4, width: 18, height: 12, rx: 2 }], ['path', { d: 'M8 20h8M12 16v4' }]],
  folder: [['path', { d: 'M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z' }]],
  file: [['path', { d: 'M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8z' }], ['path', { d: 'M14 3v5h5' }]],
  lock: [['rect', { x: 5, y: 11, width: 14, height: 10, rx: 2 }], ['path', { d: 'M8 11V8a4 4 0 018 0v3' }]],
  check: [['path', { d: 'M5 12.5l4.5 4.5L19 7.5' }]],
  sun: [['circle', { cx: 12, cy: 12, r: 4 }], ['path', { d: 'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4' }]],
  moon: [['path', { d: 'M20 14.5A8 8 0 019.5 4 8 8 0 1020 14.5z' }]],
  settings: [['path', { d: 'M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1' }], ['circle', { cx: 15, cy: 6, r: 2 }], ['circle', { cx: 9, cy: 12, r: 2 }], ['circle', { cx: 17, cy: 18, r: 2 }]],
};
export function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs] of ICONS[name] || []) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.append(el);
  }
  return svg;
}

// Stacked bar of REAL severity counts (segments only for counts > 0), with a legend.
export function severityBar(by, total) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const bar = h('div', { class: 'sevstack', role: 'img', 'aria-label': order.map((k) => `${by[k] || 0} ${k}`).join(', ') },
    order.filter((k) => by[k]).map((k) => h('i', { style: { width: `${(100 * by[k]) / total}%`, background: SEV_COLOR[k] } })));
  const legend = h('div', { class: 'sevlegend' }, order.filter((k) => by[k]).map((k) => h('span', { style: { color: SEV_COLOR[k] } }, h('span', { style: { color: 'var(--muted)' } }, k), h('b', {}, by[k]))));
  return h('div', { class: 'stack', style: { gap: '12px' } }, bar, legend);
}

// Instant placeholder shown while a page loads, so a tab switch responds on the very next frame.
export function skeleton() {
  const bone = (w) => h('div', { class: 'skel-line', style: { width: w } });
  const card = () => h('div', { class: 'card' }, bone('34%'), bone('78%'), bone('58%'));
  return h('div', { class: 'skel', 'aria-busy': 'true', 'aria-label': 'Loading' }, h('div', { class: 'grid g3' }, card(), card(), card()), h('div', { style: { marginTop: '16px' } }, card()));
}

// Permission sheet: shown before Ultrimater reads anything beyond what you picked yourself.
// details = { label, summary, roots[], estimate, skipped[{pattern,reason}], promises[] }  (supplied by the engine, which also enforces consent)
export function permissionSheet(d, { allow = 'Allow and start', deny = 'Not now' } = {}) {
  return new Promise((resolve) => {
    const done = (v) => { bg.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
    const onKey = (e) => { if (e.key === 'Escape') done(false); };
    const seen = new Set();
    const skipped = (d.skipped || []).filter((s) => !seen.has(s.reason) && seen.add(s.reason));
    const bg = h('div', { class: 'modal-bg', onclick: (e) => e.target === bg && done(false) },
      h('div', { class: 'modal permission', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Permission request' },
        h('div', { class: 'perm-head' }, h('span', { class: 'perm-icon' }, icon('lock')), h('div', {}, h('div', { class: 'small muted', style: { letterSpacing: '.12em', textTransform: 'uppercase' } }, 'Permission needed'), h('h3', { style: { margin: 0 } }, d.label))),
        h('p', { class: 'muted', style: { margin: '14px 0 10px' } }, d.summary),
        h('h2', { style: { margin: '14px 0 8px' } }, 'Ultrimater will read'),
        h('div', { class: 'perm-roots' }, (d.roots || []).slice(0, 12).map((r) => h('div', { class: 'mono' }, r)), (d.roots || []).length > 12 ? h('div', { class: 'small faint' }, `+ ${d.roots.length - 12} more`) : null),
        h('h2', { style: { margin: '16px 0 8px' } }, 'Your guarantees'),
        h('ul', { class: 'perm-list' }, (d.promises || []).map((t) => h('li', {}, h('span', { class: 'tick' }, icon('check')), t))),
        skipped.length ? h('details', { style: { marginTop: '12px' } }, h('summary', { class: 'small muted' }, `Not scanned by default (${skipped.length})`), skipped.map((s) => h('div', { class: 'small faint', style: { margin: '6px 0' } }, `• ${s.reason}`))) : null,
        d.estimate ? h('p', { class: 'small faint', style: { margin: '12px 0 0' } }, `Time: ${d.estimate}.`) : null,
        h('div', { class: 'row', style: { justifyContent: 'flex-end', marginTop: '20px' } }, h('button', { class: 'ghost', onclick: () => done(false) }, deny), h('button', { class: 'primary', onclick: () => done(true) }, allow))));
    document.addEventListener('keydown', onKey);
    document.body.append(bg);
    bg.querySelector('button.primary').focus();
  });
}
