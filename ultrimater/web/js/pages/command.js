import { api } from '../api.js';
import { h, mount, severityBar, statusPill, fmtTime, hbar, toast, icon } from '../ui.js';

const greeting = () => { const hr = new Date().getHours(); return hr < 5 ? 'Still up?' : hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening'; };
const MOODS = {
  calm: ['All quiet. I’m keeping watch.', 'You’re in good hands.', 'Nothing to worry about right now.', 'I’m here whenever you need me.'],
  alert: ['I found a few things. Let’s look at them together.', 'Tap “Show me what to fix” and I’ll guide you.'],
  new: ['Hi! I’m ready when you are.', 'Start with a quick scan. It’s easy.'],
};
let said = 0;

const line = (label, value) => h('div', { class: 'status-line' }, h('span', { class: 'muted' }, label), h('span', {}, value));

export async function render(view, ctx, alive) {
  const s = await api.get('/api/status');
  if (!alive()) return;
  const f = s.findings;

  // ---- header action: synthetic demo data (labelled, removable from Settings) -------------------------------
  const top = document.getElementById('topright');
  if (top) top.replaceChildren(h('button', { onclick: async (e) => {
    e.target.disabled = true; toast('Analysing the synthetic sample…');
    try { const r = await api.post('/api/demo/load'); toast(`Loaded: ${r.privacy_files} sample files and ${r.messages.length} messages`); location.reload(); }
    catch (err) { toast(err.message, true); e.target.disabled = false; }
  } }, 'Load synthetic demo data'));

  // ---- protection: what is actually on, from real sources ------------------------------------------------
  const buildProtection = (st) => {
    const d = st.defender;
    return h('div', { class: 'card' }, h('h2', {}, 'Protection'),
      line('Windows Security', d.checking ? statusPill(null, 'Checking…') : d.available ? statusPill(d.antivirus_enabled, d.antivirus_enabled ? 'Enabled' : 'Disabled') : statusPill(null, 'Unavailable')),
      line('Windows real-time protection', d.checking ? statusPill(null, 'Checking…') : d.available ? statusPill(d.realtime_protection, d.realtime_protection ? 'On' : 'Off') : statusPill(null, 'Unavailable')),
      line('Downloads watcher', st.watcher.running ? statusPill(true, `Watching ${st.watcher.paths.length} folder${st.watcher.paths.length === 1 ? '' : 's'}`) : statusPill(null, 'Off')),
      line('Browser protection', st.browser && st.browser.granted ? statusPill(true, `${st.browser.browser_name || st.browser.browser}${st.browser.automatic ? ' · automatic' : ''}`) : statusPill(null, 'Off')),
      line('Gmail protection', st.gmail && st.gmail.connected ? statusPill(true, `${st.gmail.account || 'Connected'}${st.gmail.automatic ? ' · automatic' : ''}`) : statusPill(null, 'Off')),
      line('Known-bad hash lists', st.hashlist.total ? statusPill(true, `${st.hashlist.total.toLocaleString()} hashes`) : statusPill(null, 'None imported')),
      line('Local AI (Ollama)', st.ai.checking ? statusPill(null, 'Checking…') : st.ai.available ? statusPill(true, st.ai.model) : statusPill(null, st.ai.enabled ? 'Not reachable' : 'Off')),
      line('OCR engine', st.ocr.available ? statusPill(true, 'Tesseract') : statusPill(null, 'Unavailable')),
      line('Audit log integrity', st.audit.ok ? statusPill(true, `Verified · ${st.audit.entries} ${st.audit.entries === 1 ? 'entry' : 'entries'}`) : statusPill(false, `Broken at #${st.audit.first_broken_seq}`)),
      d.available || d.checking ? null : h('p', { class: 'fine' }, `Windows Security: ${d.reason}`),
      h('p', { class: 'fine' }, st.monitoring.note));
  };
  let protection = buildProtection(s);

  // ---- the friendly top of the page: mascot + one clear sentence + one clear next step ---------------------
  const scanned = s.recent_scans.length > 0;
  const mood = f.open ? 'alert' : scanned ? 'calm' : 'new';
  const plural = f.open === 1 ? '' : 's';
  const headline = mood === 'alert' ? `${f.open} open finding${plural} need${f.open === 1 ? 's' : ''} attention`
    : mood === 'calm' ? 'You’re all set. Nothing needs attention.' : 'Welcome. Let’s get you protected.';
  const lead = mood === 'alert' ? 'Let’s go through them together and fix what matters first. It only takes a minute.'
    : mood === 'calm' ? `Your last scan was ${fmtTime(s.recent_scans[0].started_at)}. I’ll keep an eye on things.`
    : 'It takes about two minutes. Start with a first scan, then switch on the extra protection below.';
  const mascot = h('button', { class: `mascot mood-${mood}`, type: 'button', 'aria-label': 'Ultrimater, your protector. Tap to say hello.', onclick: (e) => {
    const m = e.currentTarget; m.classList.remove('pop'); void m.offsetWidth; m.classList.add('pop');
    const lines = MOODS[mood]; toast(lines[said++ % lines.length]);
  } }, h('span', { class: 'aura' }), h('span', { class: 'dragon' }));
  const hero = h('div', { class: `card hero mood-${mood} rise`, style: { '--i': 0 } }, mascot,
    h('div', { class: 'hero-text' },
      h('div', { class: 'hello' }, greeting()),
      h('div', { class: 'headline' }, headline),
      h('p', { class: 'lead' }, lead),
      f.open ? severityBar(f.by_severity, f.open) : null,
      h('div', { class: 'hero-actions' },
        mood === 'alert' ? h('button', { class: 'primary big', onclick: () => ctx.navigate('response') }, 'Show me what to fix') : h('button', { class: 'primary big', onclick: () => ctx.navigate('shield') }, scanned ? 'Scan again' : 'Start my first scan'),
        mood === 'alert' ? h('button', { class: 'big', onclick: () => ctx.navigate('shield') }, 'Scan again') : null)));

  // ---- getting started: a small checklist that disappears into a thank-you when it is complete -----------
  const steps = [
    { done: scanned, title: 'Scan your computer', desc: 'Look for viruses and risky files.', go: 'shield', ic: 'shield' },
    { done: !!(s.browser && s.browser.granted), title: 'Protect your browser', desc: 'Check your downloads, links and extensions.', go: 'shield', ic: 'computer' },
    { done: !!(s.gmail && s.gmail.connected), title: 'Protect your Gmail', desc: 'Spot scam emails in your inbox (read-only).', go: 'threat', ic: 'lock' },
    { done: Object.keys(s.threats.sentinel_verdicts).length > 0, title: 'Check something suspicious', desc: 'Paste a message or link and see if it’s a scam.', go: 'threat', ic: 'threat' },
  ];
  const doneN = steps.filter((x) => x.done).length;
  const setup = doneN === steps.length
    ? h('div', { class: 'card setup-done rise', style: { '--i': 1 } }, h('span', { class: 'ring ok' }, icon('check')), h('div', {}, h('b', {}, 'Everything is set up. Nice work!'), h('div', { class: 'small muted' }, 'You have every protection switched on.')))
    : h('div', { class: 'card setup rise', style: { '--i': 1 } },
        h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'Get protected in a few easy steps'), h('span', { class: 'small muted' }, `${doneN} of ${steps.length} done`)),
        h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': steps.length, 'aria-valuenow': doneN }, h('span', { style: { width: `${(doneN / steps.length) * 100}%` } })),
        h('div', { class: 'steps' }, steps.map((x) => h('button', { class: `step${x.done ? ' done' : ''}`, type: 'button', onclick: () => ctx.navigate(x.go) },
          h('span', { class: `ring${x.done ? ' ok' : ''}` }, icon(x.done ? 'check' : x.ic)),
          h('span', { class: 'step-text' }, h('b', {}, x.title), h('span', { class: 'small muted' }, x.desc)),
          h('span', { class: 'step-go' }, x.done ? 'Done' : 'Start →')))));

  // ---- what would you like to do? (always there, plain words) ---------------------------------------------
  const tile = (ic, title, desc, go, i) => h('button', { class: 'tile rise', type: 'button', style: { '--i': i }, onclick: () => ctx.navigate(go) },
    h('span', { class: 'tile-ic' }, icon(ic)), h('b', {}, title), h('span', { class: 'small muted' }, desc));
  const tiles = h('div', {}, h('h2', { class: 'section' }, 'What would you like to do?'), h('div', { class: 'tiles' },
    tile('shield', 'Scan my computer', 'Look for viruses and risky files.', 'shield', 2),
    tile('threat', 'Is this message safe?', 'Paste a message or link and I’ll check it.', 'threat', 3),
    tile('privacy', 'Find private info in a file', 'Spot passwords, IDs and personal details.', 'privacy', 4),
    tile('response', 'Fix what I found', f.open ? `${f.open} thing${plural} waiting for you.` : 'Nothing is waiting right now.', 'response', 5)));

  // ---- protection at a glance: four big, friendly chips ---------------------------------------------------
  const chip = (tone, label, state, go) => h('button', { class: `gchip ${tone}`, type: 'button', onclick: () => ctx.navigate(go) }, h('span', { class: 'gdot' }), h('span', { class: 'gtext' }, h('b', {}, label), h('span', { class: 'small' }, state)));
  const buildGlance = (st) => {
    const d = st.defender;
    const pc = d.checking ? ['neutral', 'Checking…'] : !d.available ? ['neutral', 'Not available here'] : d.antivirus_enabled && d.realtime_protection ? ['ok', 'On and protecting'] : ['warn', 'Needs attention'];
    return h('div', {}, h('h2', { class: 'section' }, 'Your protection at a glance'), h('div', { class: 'glance' },
      chip(pc[0], 'This computer', pc[1], 'shield'),
      chip(st.watcher.running ? 'ok' : 'off', 'Downloads', st.watcher.running ? 'Watching for new files' : 'Off · tap to turn on', 'shield'),
      chip(st.browser && st.browser.granted ? 'ok' : 'off', 'Browser', st.browser && st.browser.granted ? `${st.browser.browser_name || 'Protected'}` : 'Off · tap to turn on', 'shield'),
      chip(st.gmail && st.gmail.connected ? 'ok' : 'off', 'Gmail', st.gmail && st.gmail.connected ? 'Protected' : 'Off · tap to connect', 'threat')));
  };
  let glance = buildGlance(s);

  // ---- activity ------------------------------------------------------------------------------------------
  const scans = h('div', { class: 'card' }, h('h2', {}, 'Recent scans'),
    s.recent_scans.length ? s.recent_scans.slice(0, 4).map((r) => h('div', { class: 'status-line' },
      h('span', { class: 'mono', style: { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '55%' } }, r.target),
      h('span', { class: 'small muted' }, `${r.summary.files_scanned.toLocaleString()} files · ${(r.summary.finding_ids || []).length} finding${(r.summary.finding_ids || []).length === 1 ? '' : 's'} · ${fmtTime(r.started_at)}`)))
      : h('div', {}, h('div', { class: 'muted small' }, 'No scans yet.'), h('button', { class: 'link small', onclick: () => ctx.navigate('shield') }, 'Run a scan →')));
  const events = h('div', { class: 'card' }, h('h2', {}, 'Recent security events'),
    s.recent_events.length ? s.recent_events.slice(0, 6).map((e) => h('div', { class: 'evt' }, h('b', {}, e.event), h('span', {}, fmtTime(e.ts)))) : h('div', { class: 'muted small' }, 'No events recorded yet.'));

  // ---- exposure & messages: real counts -------------------------------------------------------------------
  const ek = Object.entries(s.privacy.entity_kinds).sort((a, b) => b[1] - a[1]);
  const exposure = h('div', { class: 'card' }, h('h2', {}, 'Privacy exposure'),
    ek.length ? h('div', {}, h('div', { class: 'muted small', style: { marginBottom: '8px' } }, `${s.privacy.distinct_entities} distinct items found (shown masked)`),
      ek.map(([k, n]) => hbar(k.replace('_', ' '), n, ek[0][1]))) : h('div', { class: 'muted small' }, 'Nothing analysed yet.'));
  const sv = Object.entries(s.threats.sentinel_verdicts);
  const messages = h('div', { class: 'card' }, h('h2', {}, 'Messages'),
    sv.length ? sv.map(([k, n]) => line(k.replace('_', ' '), n)) : h('div', { class: 'muted small' }, 'No suspicious messages found.'));

  const sys = s.system;
  const system = h('div', { class: 'card' }, h('h2', {}, 'This system'),
    h('div', { class: 'syskv' },
      h('div', {}, line('OS', sys.os), line('CPU threads', sys.cpu_threads ?? 'Unavailable'), line('Memory', sys.memory_gb != null ? `${sys.memory_gb} GB` : 'Unavailable')),
      h('div', {}, line('Free disk', `${sys.disk_free_gb} GB`), line('Data location', h('span', { class: 'mono' }, sys.data_dir)))));

  const tech = h('details', { class: 'tech' }, h('summary', {}, 'Technical details'),
    h('div', { class: 'cols' }, protection, h('div', { class: 'stack' }, scans, events)), h('div', { class: 'cols' }, exposure, messages), system);
  mount(view, hero, setup, tiles, glance, tech);

  if (s.defender.checking || s.ai.checking) {          // fill in slow Windows/AI probes when ready; never block the page
    let tries = 0;
    const timer = setInterval(async () => {
      if (!alive() || ++tries > 40) return clearInterval(timer);
      try { const n = await api.get('/api/status'); if (!n.defender.checking && !n.ai.checking) { clearInterval(timer); const fresh = buildProtection(n); protection.replaceWith(fresh); protection = fresh; const g = buildGlance(n); glance.replaceWith(g); glance = g; } } catch { /* retry */ }
    }, 1500);
  }
}
