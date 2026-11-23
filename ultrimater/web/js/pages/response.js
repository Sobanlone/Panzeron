import { api } from '../api.js';
import { h, clear, mount, findingCard, fmtTime, toast, confirmDialog, emptyState, SEV_COLOR } from '../ui.js';
import { runAction } from '../actions.js';
import { segmented } from '../controls.js';

const PAGE = 25;
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const MODULES = [['', 'All areas'], ['shield', 'Shield'], ['vision', 'Privacy'], ['sentinel', 'Threats'], ['inference', 'Inference']];

export async function render(view, ctx, alive) {
  let tab = 'open';
  const body = h('div', {});
  const tabs = h('div', { class: 'tabs' });
  const defs = [['open', 'Open'], ['closed', 'Resolved'], ['quarantine', 'Quarantine'], ['history', 'Actions']];
  const drawTabs = () => clear(tabs).append(...defs.map(([id, l]) => h('button', { class: tab === id ? 'on' : '', onclick: () => { tab = id; drawTabs(); load(); } }, l)));

  // ---- findings list (search, filters, pagination, bulk) ----------------------------------------------------
  const st = { q: '', sev: new Set(), module: '', sort: 'severity', page: 0, selected: new Set(), allMatching: false };

  function query(status) {
    const p = new URLSearchParams({ status, sort: st.sort, offset: String(st.page * PAGE), limit: String(PAGE) });
    if (st.q) p.set('q', st.q); if (st.sev.size) p.set('severity', [...st.sev].join(',')); if (st.module) p.set('module', st.module);
    return `/api/findings/search?${p}`;
  }
  const filterBody = (status) => ({ q: st.q, severities: [...st.sev], modules: st.module ? [st.module] : [], status });

  async function findingsView(status) {
    const list = h('div', {}), bar = h('div', {}), bulk = h('div', {}), pager = h('div', { class: 'row between', style: { marginTop: '16px' } });
    let timer = null;
    const search = h('input', { type: 'text', placeholder: 'Search title or source…', value: st.q, 'aria-label': 'Search findings', style: { maxWidth: '320px' },
      oninput: (e) => { clearTimeout(timer); timer = setTimeout(() => { st.q = e.target.value; st.page = 0; st.selected.clear(); st.allMatching = false; refresh(); }, 250); } });
    const modSel = h('select', { 'aria-label': 'Area', style: { width: 'auto' }, onchange: (e) => { st.module = e.target.value; st.page = 0; st.selected.clear(); refresh(); } }, MODULES.map(([v, l]) => h('option', { value: v, selected: v === st.module }, l)));
    const sortSel = h('select', { 'aria-label': 'Sort', style: { width: 'auto' }, onchange: (e) => { st.sort = e.target.value; st.page = 0; refresh(); } },
      [['severity', 'Most severe first'], ['newest', 'Newest first'], ['oldest', 'Oldest first'], ['source', 'By source'], ['title', 'By title']].map(([v, l]) => h('option', { value: v, selected: v === st.sort }, l)));
    mount(clear(body), h('div', { class: 'row', style: { marginBottom: '14px' } }, search, modSel, sortSel), bar, bulk, list, pager);

    async function refresh() {
      let r; try { r = await api.get(query(status)); } catch (e) { return mount(clear(list), h('div', { class: 'notice bad' }, e.message)); }
      if (!alive()) return;
      // severity chips with real counts
      mount(clear(bar), h('div', { class: 'chips', style: { marginBottom: '14px' } }, SEVS.map((k) => {
        const n = r.counts.severity[k] || 0;
        return h('button', { class: `chip${st.sev.has(k) ? ' on' : ''}`, disabled: !n && !st.sev.has(k), onclick: () => { st.sev.has(k) ? st.sev.delete(k) : st.sev.add(k); st.page = 0; st.selected.clear(); st.allMatching = false; refresh(); } },
          h('i', { style: { display: 'inline-block', width: '8px', height: '8px', background: SEV_COLOR[k], marginRight: '8px' } }), `${k} ${n}`);
      })));
      const pages = Math.max(1, Math.ceil(r.total / PAGE));
      if (st.page >= pages) { st.page = pages - 1; return refresh(); }
      // bulk bar
      const pageIds = r.items.map((f) => f.id);
      const all = st.allMatching ? r.total : st.selected.size;
      mount(clear(bulk), h('div', { class: 'row between', style: { marginBottom: '12px' } },
        h('label', { class: 'row small muted' }, h('input', { type: 'checkbox', class: 'pick', 'aria-label': 'Select this page', checked: pageIds.length > 0 && pageIds.every((i) => st.selected.has(i)),
          onchange: (e) => { pageIds.forEach((i) => e.target.checked ? st.selected.add(i) : st.selected.delete(i)); st.allMatching = false; refresh(); } }), r.total ? `${st.page * PAGE + 1}–${Math.min(r.total, (st.page + 1) * PAGE)} of ${r.total}` : '0 results'),
        all ? h('div', { class: 'row' }, h('span', { class: 'small' }, `${all} selected`),
          st.selected.size === pageIds.length && !st.allMatching && r.total > pageIds.length ? h('button', { class: 'ghost', onclick: () => { st.allMatching = true; refresh(); } }, `Select all ${r.total} matching`) : null,
          ...(status === 'open' ? [h('button', { onclick: () => doBulk('resolve') }, 'Mark resolved'), h('button', { onclick: () => doBulk('false_positive') }, 'False positive'), h('button', { class: 'danger', onclick: quarantineSel }, 'Quarantine files…')]
            : [h('button', { onclick: () => doBulk('reopen') }, 'Reopen')]),
          h('button', { class: 'ghost', onclick: () => { st.selected.clear(); st.allMatching = false; refresh(); } }, 'Clear')) : null));
      // rows (actions are fetched lazily when a row is opened)
      mount(clear(list), r.items.length ? r.items.map((f) => {
        const card = findingCard(f); let loaded = false;
        card.querySelector('.head').addEventListener('click', async () => {
          if (loaded) return; loaded = true;
          try { const { actions } = await api.get(`/api/findings/${f.id}`);
            card.querySelector('.body').append(h('div', { class: 'row', style: { marginTop: '14px' } }, actions.map((a) => h('button', { class: a.destructive ? 'danger' : '', title: a.description, onclick: () => runAction(a, f, () => { refresh(); ctx.refreshChrome(); }) }, a.label)))); }
          catch (e) { loaded = false; }
        });
        return h('div', { style: { display: 'grid', gridTemplateColumns: '26px 1fr', gap: '10px', alignItems: 'start' } },
          h('input', { type: 'checkbox', class: 'pick', 'aria-label': `Select ${f.title}`, checked: st.allMatching || st.selected.has(f.id), style: { marginTop: '18px' },
            onchange: (e) => { e.target.checked ? st.selected.add(f.id) : st.selected.delete(f.id); st.allMatching = false; refresh(); } }), card);
      }) : emptyState(st.q || st.sev.size || st.module ? 'No findings match these filters.' : status === 'open' ? 'Nothing needs attention.' : 'Nothing resolved yet.'));
      mount(clear(pager), h('span', { class: 'small muted' }, pages > 1 ? `Page ${st.page + 1} of ${pages}` : ''),
        pages > 1 ? h('div', { class: 'row' }, h('button', { disabled: st.page === 0, onclick: () => { st.page--; refresh(); } }, '← Previous'), h('button', { disabled: st.page >= pages - 1, onclick: () => { st.page++; refresh(); } }, 'Next →')) : null);
    }
    async function doBulk(action) {
      try {
        const r = await api.post('/api/findings/bulk', st.allMatching ? { action, filter: filterBody(status) } : { action, ids: [...st.selected] });
        toast(`${r.changed} finding${r.changed === 1 ? '' : 's'} updated`); st.selected.clear(); st.allMatching = false; refresh(); ctx.refreshChrome();
      } catch (e) { toast(e.message, true); }
    }
    async function quarantineSel() {
      let ids = [...st.selected];
      if (st.allMatching) { const r = await api.get(query(status).replace(/limit=\d+/, 'limit=200').replace(/offset=\d+/, 'offset=0')); ids = r.items.map((f) => f.id); }
      if (!await confirmDialog({ title: `Quarantine files for ${ids.length} finding${ids.length === 1 ? '' : 's'}`, danger: true, confirmLabel: 'Quarantine',
        body: 'Files belonging to the selected findings are moved into Ultrimater’s vault after a hash-verified copy. Findings without a file are skipped. You can restore each file from the Quarantine tab.' })) return;
      try { const r = await api.post('/api/quarantine/bulk', { finding_ids: ids, confirm: true }); toast(`${r.quarantined.length} quarantined${r.failed.length ? `, ${r.failed.length} could not be (no file, or protected)` : ''}`, r.failed.length > 0 && !r.quarantined.length); st.selected.clear(); refresh(); ctx.refreshChrome(); }
      catch (e) { toast(e.message, true); }
    }
    refresh();
  }

  // ---- quarantine + history ---------------------------------------------------------------------------------
  async function load() {
    clear(body);
    if (tab === 'open' || tab === 'closed') { st.page = 0; st.selected.clear(); st.allMatching = false; return findingsView(tab); }
    if (tab === 'quarantine') {
      const { items } = await api.get('/api/quarantine');
      mount(body, items.length ? h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Original location', 'Quarantined', 'SHA-256', 'State', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, items.map((q) => h('tr', {}, h('td', { class: 'mono' }, q.original_path), h('td', { class: 'small' }, fmtTime(q.created_at)), h('td', { class: 'mono faint' }, q.sha256.slice(0, 16) + '…'),
          h('td', {}, q.restored_at ? `restored ${fmtTime(q.restored_at)}` : 'in vault'),
          h('td', {}, q.restored_at ? null : h('button', { onclick: async () => {
            if (!await confirmDialog({ title: 'Restore file', body: `The file will be returned to ${q.original_path} after an integrity check. An existing file there is never overwritten.`, confirmLabel: 'Restore' })) return;
            try { await api.post(`/api/quarantine/${q.id}/restore`, { confirm: true }); toast('Restored'); load(); ctx.refreshChrome(); } catch (e) { toast(e.message, true); } } }, 'Restore'))))))) : emptyState('The quarantine vault is empty.'));
    } else {
      const { actions } = await api.get('/api/actions');
      mount(body, actions.length ? h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['When', 'Action', 'Result', 'Detail'].map((t) => h('th', {}, t)))),
        h('tbody', {}, actions.map((a) => h('tr', {}, h('td', { class: 'small' }, fmtTime(a.created_at)), h('td', {}, a.type.replace(/_/g, ' ')), h('td', {}, a.status), h('td', { class: 'mono faint' }, Object.entries(a.detail).map(([k, v]) => `${k}: ${v}`).join(' · ').slice(0, 160))))))) : emptyState('No actions taken yet.'));
    }
  }
  mount(view, tabs, body); drawTabs(); await load();
}
