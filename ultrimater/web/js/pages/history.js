import { api } from '../api.js';
import { h, clear, fmtTime, toast, emptyState, statusPill, mount } from '../ui.js';

export async function render(view, ctx, alive) {
  let tab = 'scans';
  const body = h('div', {}), tabs = h('div', { class: 'tabs' });
  const defs = [['scans', 'Scans'], ['activity', 'Activity log'], ['export', 'Export report']];
  const drawTabs = () => mount(clear(tabs), ...defs.map(([id, l]) => h('button', { class: tab === id ? 'on' : '', onclick: () => { tab = id; drawTabs(); load(); } }, l)));

  async function load() {
    clear(body);
    if (tab === 'scans') {
      const { scans } = await api.get('/api/scans');
      mount(body, scans.length ? h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Started', 'Target', 'Status', 'Files', 'Findings', 'Unreadable'].map((t) => h('th', {}, t)))),
        h('tbody', {}, scans.map((s) => h('tr', {}, h('td', { class: 'small' }, fmtTime(s.started_at)), h('td', { class: 'mono small' }, s.target), h('td', {}, s.status), h('td', {}, s.summary.files_scanned),
          h('td', {}, (s.summary.finding_ids || []).length), h('td', {}, (s.summary.errors || []).length)))))) : emptyState('No scans recorded yet.'));
    } else if (tab === 'activity') {
      const a = await api.get('/api/audit?limit=300');
      mount(body, h('div', { class: `notice ${a.verification.ok ? 'good' : 'bad'}`, style: { marginBottom: '12px' } }, a.verification.ok ? `Hash chain verified: ${a.verification.entries} entries, none altered.` : `Tamper detected: the chain breaks at entry #${a.verification.first_broken_seq}.`),
        h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['#', 'Time', 'Actor', 'Event', 'Details', 'Hash'].map((t) => h('th', {}, t)))),
          h('tbody', {}, a.entries.map((e) => h('tr', {}, h('td', { class: 'faint' }, e.seq), h('td', { class: 'small' }, fmtTime(e.ts)), h('td', {}, e.actor), h('td', { class: 'mono small' }, e.event),
            h('td', { class: 'mono small faint' }, JSON.stringify(e.payload).slice(0, 110)), h('td', { class: 'mono small faint' }, e.hash.slice(0, 10))))))));
    } else {
      mount(body, h('div', { class: 'card' }, h('h2', {}, 'Export report'), h('p', { class: 'muted' }, 'A JSON report with findings, scans, actions and the audit log. It contains masked values only: Ultrimater never stores raw sensitive data, so the report cannot leak it.'),
        h('button', { class: 'primary', onclick: async () => {
          try { const r = await api.get('/api/report'); const url = URL.createObjectURL(new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }));
            const a = h('a', { href: url, download: `ultrimater-report-${new Date().toISOString().slice(0, 10)}.json` }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url); toast('Report downloaded'); }
          catch (e) { toast(e.message, true); } } }, 'Download JSON report')));
    }
  }
  mount(view, tabs, body); drawTabs(); await load();
}
