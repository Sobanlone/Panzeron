import { api, ApiError } from '../api.js';
import { h, clear, mount, findingCard, toast, confirmDialog, permissionSheet, statusPill, fmtBytes, fmtTime, emptyState, icon } from '../ui.js';
import { runAction } from '../actions.js';
import { segmented, toggle } from '../controls.js';
import { pickPaths } from '../pick.js';
import { buildBrowserCard } from './browser-card.js';

const VERDICT = {
  threats: ['Threats found', 'Findings need your attention. Nothing was changed.'],
  review: ['Needs review', 'Some items look unusual. Review them in the list below.'],
  test: ['Only antivirus test files found', 'These are harmless by design (like the EICAR test file). Nothing dangerous was found.'],
  clean: ['No threats found', 'Nothing matched. This is not a guarantee: Panzeron checks known signatures and static indicators, not behaviour.'],
  incomplete: ['Scan incomplete', 'The scan was cancelled or failed before it finished.'],
};
const fmtDur = (s) => (s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`);

export async function render(view, ctx, alive) {
  let mode = 'smart';
  const manualWrap = h('details', { class: 'small', style: { marginTop: '16px' } });
  const manualInput = h('input', { type: 'text', placeholder: 'e.g. C:\\Users\\you\\Downloads', 'aria-label': 'Path to scan' });
  const scanBox = h('div', {});
  const listBox = h('div', {});
  let polling = null;
  let currentIds = null;

  // ---- starting a scan (with the permission flow) ----------------------------------------------------------
  async function start(opts, consent = false) {
    try {
      const { scan_id } = await api.post('/api/scan', { ...opts, mode, consent });
      watchScan(scan_id);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.body.details) {          // the engine asks for permission; show exactly what will be read
        const ok = await permissionSheet(e.body.details, { allow: 'Allow and scan' });
        if (ok) return start(opts, true);
        toast('Scan not started. Nothing was read.');
        return;
      }
      toast(e.message, true);
    }
  }
  const reveal = () => { manualWrap.open = true; manualInput.focus(); };

  const tiles = [
    { ic: 'bolt', title: 'Quick scan', d: 'Downloads, Desktop, Documents, temporary and startup folders: where malware most often lands.', perm: true, run: () => start({ scope: 'quick' }) },
    { ic: 'user', title: 'My user folders', d: 'Everything in your Windows user profile.', perm: true, run: () => start({ scope: 'user' }) },
    { ic: 'computer', title: 'Entire computer', d: 'Every internal drive, except protected Windows system files.', perm: true, run: () => start({ scope: 'computer' }) },
    { ic: 'folder', title: 'Choose a folder…', d: 'Pick one folder with the Windows folder dialog.', perm: false, run: async () => { const p = await pickPaths('folder', 'Choose a folder to scan', 'all', reveal); if (p.length) start({ paths: p }); } },
    { ic: 'file', title: 'Choose files…', d: 'Pick one or more specific files.', perm: false, run: async () => { const p = await pickPaths('files', 'Choose files to scan', 'all', reveal); if (p.length) start({ paths: p }); } },
  ];
  const tileEls = h('div', { class: 'tiles' }, tiles.map((t) => h('button', { type: 'button', class: `tile${t.perm ? '' : ' free'}`, onclick: t.run },
    icon(t.ic), h('b', {}, t.title), h('span', { class: 'd' }, t.d),
    h('span', { class: 'perm' }, icon(t.perm ? 'lock' : 'check'), t.perm ? 'Asks your permission' : 'You choose: no extra prompt'))));

  mount(manualWrap, h('summary', { class: 'muted' }, 'Type a path instead'),
    h('div', { class: 'row', style: { marginTop: '10px', flexWrap: 'nowrap' } }, manualInput, h('button', { onclick: () => manualInput.value.trim() ? start({ paths: [manualInput.value.trim()] }) : toast('Enter a path first', true) }, 'Scan')));

  const modeSeg = segmented([['smart', 'Smart'], ['deep', 'Deep']], mode, (v) => { mode = v; modeHint.textContent = hint(); });
  const hint = () => mode === 'smart' ? 'Reads programs, scripts, documents and archives in full; quick-checks the start of large media files. Fast.' : 'Reads every byte of every file. Thorough but slower.';
  const modeHint = h('span', { class: 'small muted' }, hint());

  const hero = h('div', { class: 'card' }, h('h2', {}, 'Scan'), tileEls,
    h('div', { class: 'row', style: { marginTop: '18px' } }, h('span', { class: 'small muted' }, 'Scan depth'), modeSeg, modeHint), manualWrap);

  // ---- live scan HUD ---------------------------------------------------------------------------------------
  function scanView() {
    const radar = h('span', { class: 'led-square' });
    const title = h('b', { style: { fontSize: '18px', fontWeight: 600 } }, '');
    const sub = h('div', { class: 'small muted' }, '');
    const bar = h('i', { style: { width: '0%' } });
    const tick = h('div', { class: 'ticker' }, '');
    const stats = {};
    const mk = (key, label) => { stats[key] = h('div', { class: 'n' }, '0'); return h('div', { class: 'stat' }, stats[key], h('div', { class: 'l' }, label)); };
    const cancel = h('button', { class: 'ghost' }, 'Cancel');
    const banner = h('div', {});
    const cov = h('div', {});
    const el = h('div', { class: 'card', style: { marginTop: 'calc(20px*var(--d))' } },
      h('div', { class: 'scanhud' },
        h('div', { class: 'row between' }, h('div', {}, h('div', { class: 'row', style: { gap: 0, flexWrap: 'nowrap' } }, radar, title), sub), cancel),
        h('div', { class: 'bar' }, bar), tick,
        h('div', { class: 'statgrid' }, mk('files', 'Files checked'), mk('data', 'Data read'), mk('threats', 'Findings'), mk('time', 'Elapsed'))),
      banner, cov);
    return { el, radar, title, sub, bar, tick, stats, cancel, banner, cov };
  }

  function watchScan(id) {
    clearInterval(polling);
    const v = scanView();
    clear(scanBox); mount(scanBox, v.el);
    v.cancel.onclick = () => api.post(`/api/scan/${id}/cancel`);
    v.radar.classList.add('on');
    const tick = async () => {
      if (!alive()) return clearInterval(polling);
      let s; try { s = await api.get(`/api/scan/${id}`); } catch { return; }
      const done = s.files_scanned + s.files_excluded + s.errors.filter((e) => !e.error.startsWith('access denied (needs')).length;
      const pct = s.status !== 'running' ? 100 : s.enumerating ? Math.min(95, 5 + Math.round(done / 40)) : (s.files_total ? Math.round(100 * done / s.files_total) : 0);
      v.title.textContent = s.status === 'running' ? (s.enumerating ? 'Scanning · discovering files…' : 'Scanning…') : (VERDICT[s.verdict] || ['Scan finished'])[0];
      v.sub.textContent = `${s.scope === 'custom' ? 'Your selection' : s.scope === 'broad' ? 'Broad location' : ({ quick: 'Quick scan', user: 'My user folders', computer: 'Entire computer' })[s.scope] || s.scope} · ${s.mode} mode`;
      v.bar.style.width = `${pct}%`;
      v.stats.files.textContent = s.files_scanned.toLocaleString();
      v.stats.data.textContent = fmtBytes(s.bytes_scanned);
      v.stats.threats.textContent = Object.values(s.severity_counts).reduce((a, b) => a + b, 0);
      v.stats.time.textContent = s.status === 'running' ? '…' : fmtDur(s.duration_s);
      v.tick.textContent = s.status === 'running' ? s.current : (s.files_total ? `${s.files_total.toLocaleString()} file${s.files_total === 1 ? '' : 's'} discovered` : '');
      if (s.status !== 'running') {
        clearInterval(polling);
        v.radar.classList.remove('on'); v.radar.classList.add(s.verdict === 'incomplete' ? 'review' : s.verdict);
        v.cancel.remove();
        const [vt, vd] = VERDICT[s.verdict] || VERDICT.incomplete;
        const chips = ['critical', 'high', 'medium', 'low', 'info'].filter((k) => s.severity_counts[k]).map((k) => h('span', { class: `badge sev-${k}` }, `${s.severity_counts[k]} ${k}`));
        mount(clear(v.banner), h('div', { class: `verdict ${s.verdict}`, style: { marginTop: '16px' } }, h('div', { style: { flex: 1 } }, h('b', {}, vt), h('div', { class: 'small muted' }, vd)), chips.length ? h('div', { class: 'row', style: { gap: '6px' } }, chips) : null));
        mount(clear(v.cov), coverage(s));
        currentIds = s.finding_ids; loadFindings(currentIds); ctx.refreshChrome();
      }
    };
    tick(); polling = setInterval(tick, 500);
  }

  // Honest coverage: what was read, what was not, and why.
  function coverage(s) {
    const denied = s.errors.filter((e) => e.error.startsWith('access denied'));
    const other = s.errors.filter((e) => !e.error.startsWith('access denied'));
    return h('details', { class: 'small' }, h('summary', { class: 'muted' }, 'Coverage report: what was and was not scanned'),
      h('div', { class: 'kv', style: { marginTop: '10px' } },
        h('dt', {}, 'Read in full'), h('dd', {}, `${s.files_full.toLocaleString()} files`),
        h('dt', {}, 'Panzeron’s own files'), h('dd', {}, `${s.files_trusted.toLocaleString()} verified by hash against the shipped manifest (not flagged)`),
        h('dt', {}, 'Unchanged'), h('dd', {}, `${s.files_cached.toLocaleString()} skipped: unchanged since a previous clean scan (Deep mode re-reads them)`),
        h('dt', {}, 'Quick-checked'), h('dd', {}, `${s.files_quick.toLocaleString()} large files (first 64 KB; use Deep mode to read all)`),
        h('dt', {}, 'Excluded by you'), h('dd', {}, `${s.files_excluded.toLocaleString()}`),
        h('dt', {}, 'Speed'), h('dd', {}, `${s.throughput_mb_s} MB/s`),
        h('dt', {}, 'Access denied'), h('dd', {}, `${s.access_denied} (protected locations; run as administrator to include them)`),
        h('dt', {}, 'Other problems'), h('dd', {}, `${other.length}`)),
      s.skipped_dirs.length ? h('div', { style: { marginTop: '10px' } }, h('div', { class: 'muted' }, 'Skipped locations'), s.skipped_dirs.slice(0, 12).map((d) => h('div', { class: 'mono faint', style: { margin: '4px 0' } }, `${d.path} — ${d.reason}`))) : null,
      [...denied, ...other].length ? h('div', { style: { marginTop: '10px' } }, h('div', { class: 'muted' }, 'Could not read'), [...denied, ...other].slice(0, 15).map((e) => h('div', { class: 'mono faint', style: { margin: '4px 0' } }, `${e.path}: ${e.error}`))) : null);
  }

  // ---- findings list + bulk quarantine ----------------------------------------------------------------------
  async function loadFindings(ids) {
    const all = (await api.get('/api/findings?module=shield')).findings;
    const shown = ids ? all.filter((f) => ids.includes(f.id)) : all.filter((f) => f.status === 'open');
    const bad = shown.filter((f) => f.status === 'open' && f.source_path && ['high', 'critical'].includes(f.severity) && !f.category.startsWith('shield.startup') && !f.category.startsWith('shield.hosts'));
    clear(listBox);
    mount(listBox, h('div', { class: 'row between', style: { margin: 'calc(22px*var(--d)) 0 12px' } },
      h('h2', { style: { margin: 0 } }, ids ? `Findings from this scan (${shown.length})` : `Open Shield findings (${shown.length})`),
      bad.length ? h('button', { class: 'danger', onclick: async () => {
        const ok = await confirmDialog({ title: `Quarantine ${bad.length} file${bad.length > 1 ? 's' : ''}`, danger: true, confirmLabel: 'Quarantine all',
          body: `These high-severity files will be moved into Panzeron's vault after a hash-verified copy. You can restore each one from the Fix & review. ${bad.slice(0, 6).map((f) => f.source).join(', ')}${bad.length > 6 ? '…' : ''}` });
        if (!ok) return;
        try { const r = await api.post('/api/quarantine/bulk', { finding_ids: bad.map((f) => f.id), confirm: true }); toast(`${r.quarantined.length} quarantined${r.failed.length ? `, ${r.failed.length} failed` : ''}`, r.failed.length > 0); loadFindings(ids); ctx.refreshChrome(); }
        catch (e) { toast(e.message, true); }
      } }, `Quarantine all high-severity (${bad.length})`) : null),
      shown.length ? shown.map((f) => { const c = findingCard(f); loadActions(c, f); return c; })
        : emptyState(ids ? 'Nothing was flagged in this scan.' : 'No open Shield findings.'));
  }
  async function loadActions(card, f) {
    const { actions } = await api.get(`/api/findings/${f.id}`);
    card.querySelector('.body').append(h('div', { class: 'row', style: { marginTop: '14px' } }, actions.map((a) => h('button', { class: a.destructive ? 'danger' : '', title: a.description,
      onclick: () => runAction(a, f, () => { loadFindings(currentIds); ctx.refreshChrome(); }) }, a.label))));
  }

  // ---- right column: Windows Security, Downloads watcher, system review -------------------------------------
  const defCard = h('div', { class: 'card' });
  let defTimer = null;
  function paintDefender(def) {
    const st = def.status;
    clear(defCard);
    mount(defCard, h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'Windows Security'), h('button', { class: 'ghost', title: 'Re-check now', onclick: () => loadDefender(true) }, 'Refresh')),
      st.checking ? h('div', { class: 'notice info', style: { marginTop: '12px' } }, 'Checking Windows Security in the background… you can keep using Panzeron.')
      : st.available ? h('div', { style: { marginTop: '8px' } },
        h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Antivirus'), statusPill(st.antivirus_enabled, st.antivirus_enabled ? 'Enabled' : 'Disabled')),
        h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Real-time protection'), statusPill(st.realtime_protection, st.realtime_protection ? 'On' : 'Off')),
        h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Signatures'), h('span', { class: 'small' }, `${st.signature_version} · ${st.signature_updated}`)),
        def.detections && def.detections.available ? h('div', { class: 'small muted', style: { marginTop: '8px' } }, `${def.detections.detections.length} recent Defender detection(s) on record (read-only).`) : null)
      : h('div', { class: 'notice', style: { marginTop: '12px' } }, h('b', {}, 'Unavailable. '), st.reason),
      h('div', { class: 'row', style: { marginTop: '14px' } }, h('button', { disabled: !st.available, title: 'Asks Windows Defender to scan a folder you choose. May need administrator rights.',
        onclick: async () => {
          const p = await pickPaths('folder', 'Choose a folder for Windows Defender to scan');
          if (!p.length) return;
          const ok = await confirmDialog({ title: 'Ask Windows Defender to scan', body: `Defender will scan: ${p[0]}. Panzeron does not change any Defender setting.`, confirmLabel: 'Start Defender scan' });
          if (!ok) return;
          try { const r = await api.post('/api/defender/scan', { path: p[0], confirm: true }); toast(r.started ? r.reason : `Not started: ${r.reason}`, !r.started); } catch (e) { toast(e.message, true); }
        } }, 'Ask Defender to scan a folder…')));
  }
  async function loadDefender(refresh = false) {
    clearTimeout(defTimer); let tries = 0;
    const once = async () => {
      if (!alive()) return;
      try { const def = await api.get(`/api/defender${refresh && tries === 0 ? '?refresh=1' : ''}`); paintDefender(def); if (def.checking && ++tries < 40) defTimer = setTimeout(once, 1500); }
      catch (e) { paintDefender({ status: { available: false, reason: e.message } }); }
    };
    once();
  }

  const watchCard = h('div', { class: 'card' });
  async function paintWatcher() {
    let w; try { w = await api.get('/api/watcher'); } catch (e) { return; }
    if (!alive()) return;
    const sw = toggle(w.enabled && w.running, async (on) => {
      try { await api.post('/api/watcher', { enabled: on }); }
      catch (e) {
        if (e instanceof ApiError && e.status === 409 && e.body.details) {
          const ok = await permissionSheet(e.body.details, { allow: 'Allow watching' });
          if (ok) { try { await api.post('/api/watcher', { enabled: true, consent: true }); toast('Downloads watcher is on'); } catch (e2) { toast(e2.message, true); } }
        } else toast(e.message, true);
      }
      paintWatcher(); ctx.refreshChrome();
    });
    clear(watchCard);
    mount(watchCard, h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'Downloads watcher'), sw),
      h('p', { class: 'small muted', style: { margin: '10px 0' } }, w.note),
      w.running && !w.enabled ? h('div', { class: 'notice info', style: { marginBottom: '10px' } }, 'Watching your browser’s download folder because Browser protection is on. Turn that off to stop.') : null,
      w.running ? h('div', {}, w.paths.map((p) => h('div', { class: 'mono faint', style: { margin: '3px 0' } }, p)), h('div', { class: 'small muted', style: { marginTop: '8px' } }, `${w.scanned} new file${w.scanned === 1 ? '' : 's'} checked this session`),
        w.recent.slice(0, 4).map((r) => h('div', { class: 'status-line' }, h('span', { class: 'mono small', style: { overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '190px', whiteSpace: 'nowrap' } }, r.path.split(/[\\/]/).pop()), statusPill(r.result === 'clean' ? true : r.result === 'flagged' ? false : null, r.result === 'clean' ? 'clean' : r.result === 'flagged' ? 'flagged' : 'error')))) : null,
      h('div', { class: 'row', style: { marginTop: '12px' } }, h('button', { onclick: async () => {
        const p = await pickPaths('folder', 'Choose a folder to watch');
        if (!p.length) return;
        try { await api.post('/api/watcher', { enabled: true, paths: p }); }
        catch (e) { if (e instanceof ApiError && e.status === 409 && e.body.details) { if (await permissionSheet(e.body.details, { allow: 'Allow watching' })) await api.post('/api/watcher', { enabled: true, paths: p, consent: true }).catch((e2) => toast(e2.message, true)); } else toast(e.message, true); }
        paintWatcher();
      } }, 'Watch a different folder…')));
  }

  const sysCard = h('div', { class: 'card' });
  const sysResult = h('div', {});
  mount(sysCard, h('h2', {}, 'System review'),
    h('p', { class: 'small muted', style: { margin: '0 0 12px' } }, 'Looks at programs that start with Windows and at the hosts file (which malware edits to block antivirus updates). Read-only.'),
    h('button', { onclick: async (e) => {
      e.target.disabled = true;
      try {
        const r = await api.post('/api/shield/system-check');
        mount(clear(sysResult), r.available ? h('div', { class: `notice ${r.flagged ? '' : 'good'}`, style: { marginTop: '12px' } }, `Reviewed ${r.entries} startup item${r.entries === 1 ? '' : 's'}${r.hosts_checked ? ' and the hosts file' : ''}: ${r.flagged ? `${r.flagged} need${r.flagged === 1 ? 's' : ''} review (listed below).` : 'nothing unusual.'}`)
          : h('div', { class: 'notice', style: { marginTop: '12px' } }, r.reason));
        currentIds = null; loadFindings(null); ctx.refreshChrome();
      } catch (err) { toast(err.message, true); } finally { e.target.disabled = false; }
    } }, 'Review startup items & hosts file'), sysResult);

  mount(view, h('div', { class: 'shieldcols' },
    h('div', {}, hero, scanBox, listBox),
    h('div', { class: 'stack', style: { gap: 'calc(16px*var(--d))' } }, defCard, buildBrowserCard(ctx, alive), watchCard, sysCard)));
  loadDefender(); paintWatcher(); loadFindings(null);
  const wt = setInterval(() => { if (!alive()) return clearInterval(wt); paintWatcher(); }, 5000);
}
