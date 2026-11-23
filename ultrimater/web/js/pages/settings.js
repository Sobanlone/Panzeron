import { api } from '../api.js';
import { buildAppearancePanel } from './appearance-panel.js';
import { segmented } from '../controls.js';
import { pickPaths } from '../pick.js';
import { h, clear, toast, confirmDialog, statusPill, fmtTime, mount } from '../ui.js';

export async function render(view, ctx, alive) {
  const [{ settings: s, unimplemented }, st, ex] = await Promise.all([api.get('/api/settings'), api.get('/api/status'), api.get('/api/exclusions')]);
  if (!alive()) return;
  const f = (label, el, hint) => h('label', { class: 'field' }, label, el, hint ? h('span', { class: 'faint' }, hint) : null);
  const enabled = h('input', { type: 'checkbox', checked: s.ai_enabled });
  const host = h('input', { type: 'text', value: s.ollama_host });
  const model = h('input', { type: 'text', value: s.ollama_model });
  const remote = h('input', { type: 'checkbox', checked: s.allow_remote_processing });
  const tess = h('input', { type: 'text', value: s.tesseract_path, placeholder: 'Auto-detect' });
  const maxmb = h('input', { type: 'text', value: String(s.max_scan_file_mb) });
  let scanMode = s.scan_mode || 'smart';
  const aiDot = st.ai.available ? statusPill(true, 'Reachable') : statusPill(null, st.ai.enabled ? 'Not reachable' : 'Off');

  async function save() {
    try {
      const mb = parseInt(maxmb.value, 10);
      if (Number.isNaN(mb)) throw new Error('Maximum scan file size must be a number');
      await api.put('/api/settings', { ai_enabled: enabled.checked, ollama_host: host.value.trim(), ollama_model: model.value.trim(), allow_remote_processing: remote.checked, tesseract_path: tess.value.trim(), max_scan_file_mb: mb, scan_mode: scanMode });
      toast('Settings saved'); render(clear(view), ctx, alive);
    } catch (e) { toast(e.message, true); }
  }

  const exList = h('div', {});
  function drawEx(items) {
    mount(clear(exList), items.length ? h('table', {}, h('tbody', {}, items.map((e) => h('tr', {}, h('td', {}, e.kind), h('td', { class: 'mono small' }, e.pattern), h('td', { class: 'small faint' }, fmtTime(e.created_at)),
      h('td', {}, h('button', { class: 'ghost', onclick: async () => { try { drawEx((await api.del(`/api/exclusions/${e.id}`)).exclusions); toast('Exclusion removed'); } catch (err) { toast(err.message, true); } } }, 'Remove')))))) : h('div', { class: 'muted small' }, 'No exclusions. Shield scans everything you point it at.'));
  }
  const exKind = h('select', {}, h('option', { value: 'path' }, 'Path'), h('option', { value: 'hash' }, 'SHA-256'));
  const exPat = h('input', { type: 'text', placeholder: 'Path (wildcards allowed) or SHA-256 hash' });
  async function addExclusion(kind) {
    const p = await pickPaths(kind, kind === 'folder' ? 'Choose a folder to exclude from scans' : 'Choose a file to exclude from scans');
    if (!p.length) return;
    try { drawEx((await api.post('/api/exclusions', { kind: 'path', pattern: p[0] })).exclusions); toast(`Excluded: ${p[0]}`); } catch (e) { toast(e.message, true); }
  }
  drawEx(ex.exclusions);

  // ---- threat hash lists + detection rules (loaded without blocking the page) ----
  const hashCard = h('div', { class: 'card' }), rulesCard = h('div', { class: 'card' });
  async function paintHashes() {
    const hl = await api.get('/api/hashlist');
    clear(hashCard);
    mount(hashCard, h('h2', {}, 'Known-bad hash lists'),
      h('p', { class: 'small muted', style: { margin: '0 0 12px' } }, 'Import a list of SHA-256 hashes of known malware (for example an export from MalwareBazaar or your IT team). Files matching a hash are flagged whatever they are named. Lists stay on this computer.'),
      hl.total ? h('div', { class: 'status-line' }, h('span', { class: 'muted' }, `${hl.total.toLocaleString()} hashes`), h('span', { class: 'small faint' }, hl.sources.map((x) => `${x.source} (${x.n.toLocaleString()})`).join(', '))) : h('div', { class: 'small faint' }, 'No lists imported yet.'),
      h('div', { class: 'row', style: { marginTop: '12px' } },
        h('button', { onclick: async () => { const p = await pickPaths('file', 'Choose a hash list (.txt or .csv)', 'hashlist'); if (!p.length) return; try { const r = await api.post('/api/hashlist', { path: p[0] }); toast(`Imported ${r.imported.toLocaleString()} hashes`); paintHashes(); } catch (e) { toast(e.message, true); } } }, 'Import hash list…'),
        hl.total ? h('button', { class: 'danger', onclick: async () => { if (await confirmDialog({ title: 'Clear hash lists', body: 'Removes all imported hashes. The built-in EICAR entry stays.', confirmLabel: 'Clear', danger: true })) { await api.del('/api/hashlist'); paintHashes(); } } }, 'Clear') : null));
  }
  async function paintRules() {
    const r = await api.get('/api/rules');
    clear(rulesCard);
    mount(rulesCard, h('h2', {}, 'Detection rules'),
      h('p', { class: 'small muted', style: { margin: '0 0 10px' } }, `${r.builtin.length} built-in behaviour rules plus signature, hash, PE-structure and archive/macro checks. ${r.custom_count} custom rule${r.custom_count === 1 ? '' : 's'} loaded.`),
      h('details', { class: 'small' }, h('summary', { class: 'muted' }, 'Show built-in rules'), r.builtin.map((x) => h('div', { class: 'status-line' }, h('span', {}, x.name), h('span', { class: 'mono faint' }, x.tags.join(' '))))),
      h('p', { class: 'small faint', style: { margin: '12px 0 0' } }, 'Add your own rules as JSON files (literal text only, so a rule can never slow down or break a scan) in:'),
      h('div', { class: 'mono small', style: { margin: '6px 0' } }, r.custom_dir),
      r.custom_problems.length ? h('div', { class: 'notice', style: { marginTop: '8px' } }, r.custom_problems.map((x) => h('div', {}, x))) : null);
  }
  // ---- Ultrimater's own integrity (hash manifest) ----
  const integrityCard = h('div', { class: 'card' });
  const integrityOut = h('div', {});
  mount(integrityCard, h('h2', {}, 'Ultrimater’s own files'),
    h('p', { class: 'small muted', style: { margin: '0 0 12px' } }, 'Ultrimater recognises its own files by their SHA-256 hash (not by folder name), so scanning its folder does not flag the detection patterns inside it. A file that no longer matches is reported as modified, which also reveals tampering.'),
    h('div', { class: 'row' },
      h('button', { onclick: async (e) => { e.target.disabled = true; try { showIntegrity(await api.get('/api/integrity')); } catch (err) { toast(err.message, true); } finally { e.target.disabled = false; } } }, 'Verify Ultrimater’s files'),
      h('button', { class: 'ghost', title: 'Use after you edit Ultrimater yourself', onclick: async () => {
        if (!await confirmDialog({ title: 'Trust current files', body: 'Ultrimater will treat the files in its folder, exactly as they are now, as genuine. Only do this if you installed or edited them yourself.', confirmLabel: 'Trust these files' })) return;
        try { showIntegrity(await api.post('/api/integrity/rebuild', { confirm: true })); toast('Trust manifest rebuilt'); } catch (err) { toast(err.message, true); } } }, 'Trust my current files…')),
    integrityOut);
  function showIntegrity(v) {
    mount(clear(integrityOut), !v.manifest_found ? h('div', { class: 'notice', style: { marginTop: '12px' } }, 'No integrity manifest was found, so nothing is trusted automatically and scanning this folder may flag detection patterns. Use “Trust my current files…” if you installed it yourself.')
      : h('div', { class: `notice ${v.ok ? 'good' : 'bad'}`, style: { marginTop: '12px' } },
        v.ok ? `All ${v.checked} Ultrimater files match the shipped manifest.` : `${v.modified.length} file(s) differ from the manifest and ${v.unexpected_programs.length} unexpected program file(s) were found.`,
        [...v.modified.map((m) => h('div', { class: 'mono small' }, `modified: ${m}`)), ...v.unexpected_programs.map((m) => h('div', { class: 'mono small' }, `unexpected: ${m}`))]));
  }
  // ---- demonstration data: synthetic, labelled, removable ----
  const demoCard = h('div', { class: 'card' }, h('h2', {}, 'Demonstration data'),
    h('p', { class: 'small muted', style: { margin: '0 0 12px' } }, 'Synthetic sample files and messages about a fictional person, analysed by the real engine so you can see Ultrimater work. Nothing in it is real. Your own findings are never touched, and you can remove the demonstration at any time.'),
    h('div', { class: 'row' },
      h('button', { onclick: async (e) => { e.target.disabled = true; toast('Analysing the synthetic sample…'); try { const r = await api.post('/api/demo/load'); toast(`Loaded: ${r.privacy_files} sample files and ${r.messages.length} messages`); ctx.refreshChrome(); } catch (err) { toast(err.message, true); } finally { e.target.disabled = false; } } }, 'Load demonstration data'),
      h('button', { class: 'ghost', onclick: async () => {
        if (!await confirmDialog({ title: 'Remove demonstration data', body: 'Deletes the synthetic sample files and every finding that came from them. Your own findings are kept.', confirmLabel: 'Remove', danger: true })) return;
        try { const r = await api.del('/api/demo'); toast(`Removed ${r.removed} demonstration finding${r.removed === 1 ? '' : 's'}`); ctx.refreshChrome(); } catch (err) { toast(err.message, true); } } }, 'Remove demonstration data')));
  paintHashes(); paintRules();

  const general = h('div', {});
  const appearanceBox = buildAppearancePanel();
  mount(general, h('div', { class: 'grid g2' },
    h('div', { class: 'card' }, h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'AI model'), aiDot),
      h('div', { class: 'stack', style: { marginTop: '12px' } },
        h('label', { class: 'row' }, enabled, 'Use local AI for message commentary'),
        f('Ollama host', host, remote.checked ? 'Non-local host: data will leave this device.' : 'Loopback only unless you consent below.'),
        f('Model', model, st.ai.available ? '' : (st.ai.reason || '')),
        h('label', { class: 'row small' }, remote, 'I consent to sending message text to a non-local AI host'),
        h('div', { class: 'small faint' }, 'Privacy findings (Vision/Inference) never send content to any AI model: inference works from masked values only.'))),
    h('div', { class: 'card' }, h('h2', {}, 'Scanning & OCR'), h('div', { class: 'stack' },
      f('Maximum file size to scan (MB)', maxmb), f('Tesseract OCR program', h('div', { class: 'row', style: { flexWrap: 'nowrap' } }, tess, h('button', { type: 'button', onclick: async () => { const p = await pickPaths('file', 'Choose tesseract.exe', 'executables'); if (p.length) tess.value = p[0]; } }, 'Browse…')), st.ocr.available ? `Detected: ${st.ocr.path}` : st.ocr.reason),
      f('Default scan depth', segmented([['smart', 'Smart'], ['deep', 'Deep']], scanMode, (v) => { scanMode = v; }), 'Smart reads programs, scripts, documents and archives in full and quick-checks big media files. Deep reads everything.')))),
    h('div', { class: 'row', style: { margin: '16px 0' } }, h('button', { class: 'primary', onclick: save }, 'Save settings')),
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('h2', {}, 'Scan exclusions'), exList,
        h('div', { class: 'row', style: { marginTop: '12px' } },
          h('button', { onclick: () => addExclusion('file') }, 'Exclude a file…'), h('button', { onclick: () => addExclusion('folder') }, 'Exclude a folder…')),
        h('details', { class: 'small', style: { marginTop: '12px' } }, h('summary', { class: 'muted' }, 'Add by typing a path pattern or SHA-256'),
          h('div', { class: 'row', style: { marginTop: '8px', flexWrap: 'nowrap' } }, exKind, exPat, h('button', { onclick: async () => { try { drawEx((await api.post('/api/exclusions', { kind: exKind.value, pattern: exPat.value })).exclusions); exPat.value = ''; toast('Exclusion added'); } catch (e) { toast(e.message, true); } } }, 'Add'))),
        h('p', { class: 'small faint', style: { margin: '12px 0 0' } }, 'Excluded items are skipped by every scan and by the Downloads watcher. Remove an exclusion at any time.')),
      h('div', { class: 'card' }, h('h2', {}, 'Windows security integration'),
        h('p', { class: 'small muted' }, st.defender.checking ? 'Checking Windows Security in the background…' : st.defender.available ? 'Connected through documented Windows interfaces (Defender PowerShell module, Security Center). Ultrimater reads status and detection history, and can start a Defender scan only when you click. It never changes or disables Defender.' : `Not available here: ${st.defender.reason}`),
      )),
    h('div', { class: 'grid g2', style: { marginTop: '16px', alignItems: 'start' } }, hashCard, rulesCard),
    h('div', { style: { marginTop: '16px' } }, integrityCard),
    h('div', { style: { marginTop: '16px' } }, demoCard),
    h('div', { class: 'card', style: { marginTop: '16px' } }, h('h2', {}, 'Privacy controls'),
      h('p', { class: 'small muted' }, `All data lives in ${st.system.data_dir}. Raw sensitive values (emails, numbers, secrets) are never stored: only masked forms and salted hashes. Nothing leaves this device unless you configure a non-local AI host above.`),
      h('button', { class: 'danger', onclick: async () => {
        if (!await confirmDialog({ title: 'Delete all findings', body: 'This removes every recorded finding from Ultrimater’s database. Your files are not touched. The audit log is kept.', confirmLabel: 'Delete findings', danger: true })) return;
        try { await api.post('/api/privacy/clear', { confirm: true }); toast('Findings deleted'); ctx.refreshChrome(); } catch (e) { toast(e.message, true); } } }, 'Delete all recorded findings')));

  // ---- diagnostics: real checks on THIS computer, with a shareable report ----
  const diagBox = h('div', {});
  (function buildDiagnostics() {
    const out = h('div', {});
    const btn = h('button', { class: 'primary', onclick: () => run() }, 'Run checks');
    let report = '';
    const paint = (r) => {
      report = r.report || '';
      const c = r.counts || {};
      mount(clear(out),
        h('div', { class: `notice ${r.ok ? 'good' : 'bad'}`, style: { marginBottom: '14px' } }, r.ok ? `No failures: ${c.pass || 0} passed, ${c.warn || 0} warning${c.warn === 1 ? '' : 's'}.` : `${c.fail || 0} check${c.fail === 1 ? '' : 's'} failed. See below.`),
        r.checks.map((k) => h('div', { class: 'status-line', style: { alignItems: 'flex-start' } },
          h('span', { style: { display: 'flex', gap: '2px', flex: 1, minWidth: 0 } }, h('i', { class: `dx ${k.status}` }), h('span', {}, h('b', { style: { fontWeight: 600 } }, k.label), h('div', { class: 'small muted' }, k.detail))),
          h('span', { class: 'mono faint' }, `${k.ms} ms`))),
        h('div', { class: 'row', style: { marginTop: '16px' } },
          h('button', { onclick: async () => { try { await navigator.clipboard.writeText(report); toast('Report copied'); } catch { toast('Clipboard is not available here; use Save instead.', true); } } }, 'Copy report'),
          h('button', { onclick: () => { const url = URL.createObjectURL(new Blob([report], { type: 'text/plain' })); const a = h('a', { href: url, download: 'ultrimater-diagnostics.txt' }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url); } }, 'Save report')),
        h('p', { class: 'small faint' }, 'The report contains versions, timings and check results. Your user name and home folder are masked. No file contents or findings are included.'));
    };
    async function poll() {
      if (!alive()) return;
      const d = await api.get('/api/diagnostics');
      if (d.running) { setTimeout(poll, 700); return; }
      btn.disabled = false; if (d.result) paint(d.result);
    }
    async function run() {
      btn.disabled = true; mount(clear(out), h('div', { class: 'notice info' }, 'Running checks… PowerShell and Windows Security checks can take several seconds.'));
      try { await api.post('/api/diagnostics/run'); poll(); } catch (e) { btn.disabled = false; toast(e.message, true); }
    }
    mount(diagBox, h('div', { class: 'card' }, h('h2', {}, 'Diagnostics'),
      h('p', { class: 'small muted', style: { margin: '0 0 14px' } }, 'Checks what works on this computer, with real timings: app window, file dialogs, OCR, PowerShell, Windows Security, database, integrity, and a self-test of the scanner. If something does not work, run this and send the report.'),
      h('div', { class: 'row' }, btn), h('div', { style: { marginTop: '16px' } }, out)));
    api.get('/api/diagnostics').then((d) => { if (d.result && alive()) paint(d.result); if (d.running) poll(); }).catch(() => {});
  })();

  let tab = (location.hash.match(/tab=(\w+)/) || [])[1];
  tab = ['protection', 'diagnostics'].includes(tab) ? tab : 'appearance';
  const show = () => { appearanceBox.style.display = tab === 'appearance' ? '' : 'none'; general.style.display = tab === 'protection' ? '' : 'none'; diagBox.style.display = tab === 'diagnostics' ? '' : 'none'; };
  show();
  mount(view, h('div', { style: { marginBottom: '18px' } }, segmented([['appearance', 'Appearance'], ['protection', 'Protection & privacy'], ['diagnostics', 'Diagnostics']], tab, (v) => { tab = v; show(); })), appearanceBox, general, diagBox);
}
