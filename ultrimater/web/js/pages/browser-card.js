// Browser protection card (Shield page). Nothing is read until the user presses Allow and confirms the permission sheet; the engine enforces it too.
import { api, ApiError } from '../api.js';
import { h, clear, mount, toast, permissionSheet, statusPill, fmtTime } from '../ui.js';

export function buildBrowserCard(ctx, alive) {
  const card = h('div', { class: 'card' });
  let timer = null;
  const picks = { browser: null, caps: new Set(), automatic: true };

  async function grant(consent) {
    try {
      await api.post('/api/browser', { action: 'grant', browser: picks.browser, caps: [...picks.caps], automatic: picks.automatic, consent });
      toast('Browser protection is on'); ctx.refreshChrome(); paint(true);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.body.details) {
        if (await permissionSheet(e.body.details, { allow: 'Allow browser access', deny: 'Not now' })) await grant(true);
      } else toast(e.message, true);
    }
  }

  function setup(s) {
    if (!picks.browser) { picks.browser = s.main || (s.available[0] && s.available[0].id); s.capabilities.forEach((c) => picks.caps.add(c.id)); }
    const sel = h('select', { 'aria-label': 'Browser', onchange: (e) => { picks.browser = e.target.value; } },
      s.available.map((b) => h('option', { value: b.id, selected: b.id === picks.browser }, `${b.name}${b.is_main ? ' (your main browser)' : ''}`)));
    const rows = s.capabilities.map((c) => h('label', { class: 'row', style: { gap: '12px', margin: '10px 0', alignItems: 'flex-start', flexWrap: 'nowrap' } },
      h('input', { type: 'checkbox', checked: picks.caps.has(c.id), onchange: (e) => { e.target.checked ? picks.caps.add(c.id) : picks.caps.delete(c.id); } }),
      h('span', {}, h('b', {}, c.label), h('span', { class: 'small muted', style: { display: 'block' } }, `Reads ${c.reads}. ${c.does}`))));
    return h('div', {},
      h('p', { class: 'small muted', style: { margin: '10px 0' } }, `Let Ultrimater look after your main browser: it can check downloads, recent addresses, extensions and homepage settings, and do it automatically. ${s.main ? `Your main browser looks like ${s.available.find((b) => b.id === s.main).name} (${s.main_reason}).` : ''}`),
      s.available.length > 1 ? h('label', { class: 'field' }, 'Browser', sel) : null,
      rows,
      h('label', { class: 'row', style: { gap: '12px', margin: '10px 0', alignItems: 'flex-start', flexWrap: 'nowrap' } },
        h('input', { type: 'checkbox', checked: picks.automatic, onchange: (e) => { picks.automatic = e.target.checked; } }),
        h('span', {}, h('b', {}, 'Automatic'), h('span', { class: 'small muted', style: { display: 'block' } }, `Check at start-up and about every ${s.interval_minutes} minutes while Ultrimater is open, watch the browser’s download folder, and include it in Quick scans.`))),
      h('div', { class: 'notice info', style: { margin: '12px 0' } }, h('b', {}, 'Never read: '), s.never_read.join(', ').toLowerCase() + '. Those are what password-stealing malware takes, so Ultrimater stays away from them.'),
      h('button', { class: 'primary block', disabled: !s.available.length, onclick: () => { if (!picks.caps.size) return toast('Choose at least one kind of browser data', true); grant(false); } }, 'Allow browser protection…'));
  }

  function active(s) {
    const sum = s.last_summary;
    const stat = (label, n) => h('div', { class: 'status-line' }, h('span', { class: 'muted' }, label), h('span', { class: 'small' }, String(n)));
    return h('div', {},
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Browser'), statusPill(true, s.browser_name || s.browser)),
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Mode'), h('span', { class: 'small' }, s.automatic ? `Automatic · about every ${s.interval_minutes} min` : 'Only when you press Check now')),
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Allowed'), h('span', { class: 'small' }, s.capabilities.filter((c) => s.caps.includes(c.id)).map((c) => c.label).join(', '))),
      s.checking ? h('div', { class: 'notice info', style: { marginTop: '10px' } }, 'Checking your browser… you can keep using Ultrimater.')
      : sum ? h('div', { style: { marginTop: '10px' } },
        h('div', { class: 'small faint', style: { marginBottom: '4px' } }, `Last check ${fmtTime(s.last_check)}`),
        s.caps.includes('history') ? stat('Addresses screened', sum.history_screened) : null,
        s.caps.includes('downloads') ? stat('Downloads checked', sum.downloads_checked) : null,
        s.caps.includes('extensions') ? stat('Extensions reviewed', sum.extensions_reviewed) : null,
        s.caps.includes('settings') ? stat('Start-up pages checked', sum.startup_pages_checked) : null,
        (sum.since_allowing ? sum.since_allowing.flagged : sum.new_findings) ? h('div', { class: 'notice bad', style: { marginTop: '10px' } }, `${sum.since_allowing ? sum.since_allowing.flagged : sum.new_findings} finding${(sum.since_allowing ? sum.since_allowing.flagged : sum.new_findings) === 1 ? '' : 's'} since you allowed it. `, h('button', { class: 'link', onclick: () => ctx.navigate('response') }, 'Review in Fix & review →')) : h('div', { class: 'small muted', style: { marginTop: '8px' } }, 'Nothing needs attention.'),
        (sum.notes || []).map((n) => h('div', { class: 'small faint', style: { marginTop: '4px' } }, n)))
      : h('div', { class: 'small muted', style: { marginTop: '10px' } }, 'No check has finished yet.'),
      h('div', { class: 'row', style: { marginTop: '14px' } },
        h('button', { disabled: s.checking, onclick: async () => { try { await api.post('/api/browser', { action: 'check' }); paint(true); } catch (e) { toast(e.message, true); } } }, 'Check now'),
        h('button', { class: 'ghost', onclick: async () => { try { await api.post('/api/browser', { action: 'revoke' }); toast('Browser protection is off. Ultrimater no longer reads your browser.'); ctx.refreshChrome(); paint(true); } catch (e) { toast(e.message, true); } } }, 'Turn off')),
      h('p', { class: 'small faint', style: { margin: '10px 0 0' } }, s.note));
  }

  async function paint(poll = false) {
    clearTimeout(timer);
    let s; try { s = await api.get('/api/browser'); } catch (e) { return; }
    if (!alive()) return;
    clear(card);
    mount(card, h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'Browser protection'), s.granted ? statusPill(true, 'On') : statusPill(null, 'Off')),
      !s.available.length ? h('div', { class: 'notice', style: { marginTop: '12px' } }, 'No supported browser profile (Chrome, Edge, Brave, Vivaldi, Opera or Firefox) was found on this computer.')
      : s.granted ? active(s) : setup(s));
    if (poll && s.checking) timer = setTimeout(() => paint(true), 1500);
  }
  paint();
  return card;
}
