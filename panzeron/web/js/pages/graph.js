import { api } from '../api.js';
import { h, clear, evidenceList, tierLabel, sevBadge, emptyState, findingCard, mount } from '../ui.js';

const NS = 'http://www.w3.org/2000/svg';
const svgEl = (t, a = {}) => { const e = document.createElementNS(NS, t); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); return e; };
const KIND = { file: ['File', '#8fa3c7'], message: ['Message', '#6ea8ff'], entity: ['Sensitive item', '#e8ecf5'], threat_indicator: ['Threat indicator', '#e5524a'], privacy_finding: ['Privacy finding', '#ee8a3a'], inference: ['Inference', '#c9a45c'] };
const DASH = { verified: '', derived: '6 4', ai_assessed: '2 3', speculative: '2 4' };

// Fruchterman-Reingold with a cooling temperature (displacement is capped per step, so nodes cannot fly to the borders).
function layout(nodes, edges, W, H) {
  const n = nodes.length, idx = new Map(nodes.map((nd, i) => [nd.id, i]));
  const ring = { message: 0.12, file: 0.12, inference: 0.3, threat_indicator: 0.42, privacy_finding: 0.42, entity: 0.38 };
  nodes.forEach((nd, i) => { const a = (2 * Math.PI * i) / n, r = (ring[nd.kind] ?? 0.35) * Math.min(W, H); nd.x = W / 2 + Math.cos(a) * r; nd.y = H / 2 + Math.sin(a) * r; });
  const k = Math.sqrt((W * H) / Math.max(n, 1)) * 0.78;
  const links = edges.map((e) => [idx.get(e.src), idx.get(e.dst)]).filter(([a, b]) => a != null && b != null);
  const ITER = 350;
  for (let it = 0; it < ITER; it++) {
    const temp = (W / 9) * (1 - it / ITER) + 0.5;
    const dx = new Float64Array(n), dy = new Float64Array(n);
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      let x = nodes[i].x - nodes[j].x, y = nodes[i].y - nodes[j].y, d = Math.hypot(x, y);
      if (d < 0.01) { x = Math.random() - 0.5; y = Math.random() - 0.5; d = Math.hypot(x, y); }
      const f = (k * k) / d; x /= d; y /= d;
      dx[i] += x * f; dy[i] += y * f; dx[j] -= x * f; dy[j] -= y * f;
    }
    for (const [a, b] of links) {
      const x = nodes[a].x - nodes[b].x, y = nodes[a].y - nodes[b].y, d = Math.hypot(x, y) || 0.01, f = (d * d) / k;
      dx[a] -= (x / d) * f; dy[a] -= (y / d) * f; dx[b] += (x / d) * f; dy[b] += (y / d) * f;
    }
    for (let i = 0; i < n; i++) {
      dx[i] -= (nodes[i].x - W / 2) * 0.22; dy[i] -= (nodes[i].y - H / 2) * 0.3;       // gravity keeps components together
      const d = Math.hypot(dx[i], dy[i]) || 0.01, m = Math.min(d, temp);
      nodes[i].x = Math.min(W - 60, Math.max(60, nodes[i].x + (dx[i] / d) * m));
      nodes[i].y = Math.min(H - 54, Math.max(46, nodes[i].y + (dy[i] / d) * m));
    }
  }
}

export async function render(view, ctx, alive) {
  const data = await api.get('/api/graph');
  if (!alive()) return;
  if (!data.nodes.length) { mount(view, h('div', { class: 'card' }, emptyState('The graph is built from your findings, and there are none yet. Analyse files or messages (or load the demonstration data in Settings).'))); return; }
  const W = Math.max(560, Math.round(document.getElementById('view').clientWidth - 392)), H = 660;   // match the real panel so nothing is letterboxed
  const hidden = new Set();
  const byId = new Map(data.nodes.map((n) => [n.id, n]));
  const findings = new Map(data.inference_findings.map((f) => [f.id, f]));
  const side = h('div', { class: 'card', style: { overflow: 'auto', maxHeight: '620px' } }, h('div', { class: 'muted small' }, 'Select a node to see why it is here and the evidence behind it.'));
  const svg = svgEl('svg', { id: 'graph', viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Exposure graph' });
  let selected = null;
  layout(data.nodes, data.edges, W, H);

  const deg = new Map(); data.edges.forEach((e) => { deg.set(e.src, (deg.get(e.src) || 0) + 1); deg.set(e.dst, (deg.get(e.dst) || 0) + 1); });
  const radius = (n) => n.kind === 'inference' ? 11 : n.kind === 'entity' ? 7 + Math.min(5, deg.get(n.id) || 0) : 10;

  function draw() {
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const vis = (n) => !hidden.has(n.kind);
    const rel = new Set(); if (selected) { rel.add(selected); data.edges.forEach((e) => { if (e.src === selected) rel.add(e.dst); if (e.dst === selected) rel.add(e.src); }); }
    for (const e of data.edges) {
      const a = byId.get(e.src), b = byId.get(e.dst); if (!a || !b || !vis(a) || !vis(b)) continue;
      const dim = selected && !(e.src === selected || e.dst === selected);
      const ln = svgEl('line', { x1: a.x, y1: a.y, x2: b.x, y2: b.y, stroke: e.tier === 'speculative' ? '#e0a030' : e.tier === 'derived' ? '#6ea8ff' : 'rgba(150,160,190,.7)', 'stroke-width': 1.2, 'stroke-dasharray': DASH[e.tier] || '', opacity: dim ? 0.12 : 0.8 });
      const t = svgEl('title'); t.textContent = `${e.relation} · ${e.tier} · ${e.derived_by}`; ln.append(t); svg.append(ln);
    }
    for (const n of data.nodes) {
      if (!vis(n)) continue;
      const dim = selected && !rel.has(n.id), [, color] = KIND[n.kind] || ['', '#888'];
      const g = svgEl('g', { transform: `translate(${n.x},${n.y})`, tabindex: 0, role: 'button', style: 'cursor:pointer', opacity: dim ? 0.25 : 1, 'aria-label': `${n.kind}: ${n.label}` });
      const r = radius(n);
      const shape = n.kind === 'inference' ? svgEl('rect', { x: -r, y: -r, width: r * 2, height: r * 2, transform: 'rotate(45)', fill: 'rgba(201,164,92,.16)', stroke: color, 'stroke-width': 1.5, 'stroke-dasharray': n.tier === 'speculative' ? '3 2' : '' })
        : n.kind === 'entity' ? svgEl('rect', { x: -r, y: -r, width: r * 2, height: r * 2, fill: 'rgba(255,255,255,.10)', stroke: color, 'stroke-width': 1.5 })
        : svgEl('rect', { x: -r, y: -r, width: r * 2, height: r * 2, fill: color, stroke: n.id === selected ? '#fff' : 'rgba(255,255,255,.4)', 'stroke-width': 1.5 });
      if (n.id === selected) shape.setAttribute('stroke', '#fff');
      const lab = svgEl('text', { y: radius(n) + 14, 'text-anchor': 'middle', fill: 'currentColor', 'fill-opacity': .72, 'font-size': 10, 'pointer-events': 'none' });
      lab.textContent = n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label;
      g.append(shape, lab);
      const pick = () => { selected = selected === n.id ? null : n.id; draw(); detail(selected ? n : null); };
      g.addEventListener('click', pick); g.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), pick()));
      let drag = null;
      g.addEventListener('pointerdown', (e) => { drag = { moved: false }; g.setPointerCapture(e.pointerId); });
      g.addEventListener('pointermove', (e) => { if (!drag) return; const r = svg.getBoundingClientRect(); n.x = ((e.clientX - r.left) / r.width) * W; n.y = ((e.clientY - r.top) / r.height) * H; drag.moved = true; g.setAttribute('transform', `translate(${n.x},${n.y})`); });
      g.addEventListener('pointerup', () => { if (drag && drag.moved) draw(); drag = null; });
      svg.append(g);
    }
  }

  async function detail(n) {
    clear(side);
    if (!n) return mount(side, h('div', { class: 'muted small' }, 'Select a node to see why it is here and the evidence behind it.'));
    const [kl] = KIND[n.kind] || [n.kind];
    mount(side, h('div', { class: 'row between' }, h('b', {}, n.label), n.severity ? sevBadge(n.severity) : null), h('div', { class: 'small muted' }, kl + (n.entity_kind ? ` · ${n.entity_kind.replace('_', ' ')}` : '')));
    const links = data.edges.filter((e) => e.src === n.id || e.dst === n.id);
    mount(side, h('h2', { style: { marginTop: '16px' } }, 'Why it is connected'),
      links.length ? links.map((e) => { const o = byId.get(e.src === n.id ? e.dst : e.src); return h('div', { class: 'evid' }, h('div', {}, tierLabel(e.tier)), h('div', {}, `${e.relation.replace('_', ' ')} → ${o ? o.label : '?'}`), h('div', { class: 'ref' }, e.derived_by)); }) : h('div', { class: 'muted small' }, 'No links.'));
    const ids = n.finding_ids || [];
    for (const id of ids.slice(0, 4)) {
      try { const { finding } = await api.get(`/api/findings/${id}`); mount(side, h('h2', { style: { marginTop: '16px' } }, finding.title), h('p', { class: 'small' }, finding.explanation), evidenceList(finding.evidence)); } catch { /* finding may have been removed */ }
    }
  }

  const chips = h('div', { class: 'chips' }, Object.entries(KIND).map(([k, [label, color]]) => {
    const c = h('button', { class: 'chip on', onclick: () => { hidden.has(k) ? hidden.delete(k) : hidden.add(k); c.classList.toggle('on'); draw(); } }, h('i', { style: { display: 'inline-block', width: '8px', height: '8px', background: color, marginRight: '8px' } }), label);
    return c;
  }));
  const legend = h('div', { class: 'legend', style: { marginTop: '10px' } },
    h('span', {}, h('b', { style: { color: 'var(--muted)' } }, '━ '), 'verified link'), h('span', {}, h('b', { style: { color: 'var(--info)' } }, '┅ '), 'derived by rule'), h('span', {}, h('b', { style: { color: 'var(--warn)' } }, '┈ '), 'speculative hypothesis'), h('span', {}, '◆ inference'), h('span', {}, 'Drag nodes to rearrange'));

  const infl = data.inference_findings;
  mount(view, h('div', { class: 'row between', style: { marginBottom: '12px' } }, chips),
    h('div', { class: 'graphwrap' }, h('div', {}, svg, legend), side),
    h('p', { class: 'small faint' }, data.formula),
    h('h2', { style: { marginTop: '26px' } }, `Contextual inferences (${infl.length})`),
    infl.length ? infl.map((f) => findingCard(f)) : emptyState('No cross-source relationships found. Each source stands alone.'));
  draw();
}
