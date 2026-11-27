// Gmail protection card (Threat page). Read-only; nothing is read until the user connects and confirms the permission sheet.
import { api, ApiError } from '../api.js';
import { h, clear, mount, toast, permissionSheet, statusPill, fmtTime } from '../ui.js';

export function buildGmailCard(ctx, alive, onNewCheck = () => {}) {
  const card = h('div', { class: 'card', style: { marginTop: '16px' } });
  let timer = null, automatic = true, lastSeen;

  async function connect(consent) {
    try {
      const s = await api.post('/api/gmail', { action: 'connect', automatic, consent });
      toast('Finish signing in with Google in your browser…'); paint(true, s);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.body.details) {
        if (await permissionSheet(e.body.details, { allow: 'Allow and sign in with Google', deny: 'Not now' })) await connect(true);
      } else toast(e.message, true);
    }
  }

  function setup(s) {
    const id = h('input', { type: 'text', placeholder: '1234567890-abc….apps.googleusercontent.com', 'aria-label': 'Google client ID', autocomplete: 'off', spellcheck: 'false' });
    const secret = h('input', { type: 'password', placeholder: 'Client secret (if Google shows one)', 'aria-label': 'Google client secret', autocomplete: 'off' });
    return h('div', {},
      h('p', { class: 'small muted', style: { margin: '10px 0' } }, 'Panzeron can screen your inbox for phishing, read-only. You sign in on Google’s own page, and you create your own free Google client ID so the permission is between you and Google.'),
      h('details', { style: { margin: '8px 0 12px' } }, h('summary', { class: 'small muted' }, 'How to get a client ID (about 3 minutes)'), h('ol', { class: 'small muted', style: { margin: '8px 0 0 18px' } }, s.setup_steps.map((t) => h('li', { style: { margin: '4px 0' } }, t)))),
      h('div', { class: 'notice info', style: { marginBottom: '12px' } }, 'Already downloaded the JSON file from Google? Choose it here. It is read on this computer only.'),
      h('input', { type: 'file', accept: '.json,application/json', id: 'gm-json', style: { display: 'none' }, onchange: async (e) => {
        const f = e.target.files[0]; if (!f) return;
        try { await api.post('/api/gmail', { action: 'import_json', json_text: await f.text() }); toast('Google client file imported'); paint(); } catch (err) { toast(err.message, true); }
        e.target.value = ''; } }),
      h('button', { class: 'primary block', style: { marginBottom: '14px' }, onclick: () => document.getElementById('gm-json').click() }, 'Import the Google JSON file…'),
      h('div', { class: 'small faint', style: { margin: '2px 0 8px' } }, 'Or type the details yourself:'),
      h('label', { class: 'field' }, 'Client ID', id), h('label', { class: 'field' }, 'Client secret', secret),
      h('button', { class: 'block', onclick: async () => { try { await api.post('/api/gmail', { action: 'configure', client_id: id.value, client_secret: secret.value }); paint(); } catch (e) { toast(e.message, true); } } }, 'Save'));
  }

  function ready(s) {
    return h('div', {},
      h('p', { class: 'small muted', style: { margin: '10px 0' } }, 'Ready to connect. Panzeron will ask for read-only access (it cannot send, delete or change mail), and you will see exactly what that means before anything happens.'),
      s.connecting ? h('div', { class: 'notice info' }, 'Waiting for you to finish signing in with Google in your browser… ',
        s.auth_url ? h('a', { href: s.auth_url, target: '_blank', rel: 'noopener noreferrer' }, 'Open the sign-in page again') : null) : null,
      s.error ? h('div', { class: 'notice bad', style: { marginTop: '8px' } }, s.error) : null,
      h('label', { class: 'row', style: { gap: '12px', margin: '12px 0', alignItems: 'flex-start', flexWrap: 'nowrap' } },
        h('input', { type: 'checkbox', checked: automatic, onchange: (e) => { automatic = e.target.checked; } }),
        h('span', {}, h('b', {}, 'Automatic'), h('span', { class: 'small muted', style: { display: 'block' } }, `Check new mail at start-up and about every ${s.interval_minutes} minutes while Panzeron is open.`))),
      h('div', { class: 'row' }, h('button', { class: 'primary', disabled: s.connecting, onclick: () => connect(false) }, 'Connect Gmail…'),
        h('button', { class: 'ghost', onclick: async () => { try { await api.post('/api/gmail', { action: 'reset' }); paint(); } catch (e) { toast(e.message, true); } } }, 'Change client ID')));
  }

  function active(s) {
    const sum = s.last_summary;
    return h('div', {},
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Account'), statusPill(true, s.account || 'Connected')),
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Mode'), h('span', { class: 'small' }, s.automatic ? `Automatic · about every ${s.interval_minutes} min` : 'Only when you press Check now')),
      h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Access'), h('span', { class: 'small' }, 'Read-only')),
      s.checking ? h('div', { class: 'notice info', style: { marginTop: '10px' } }, 'Checking your inbox…')
      : sum ? h('div', { style: { marginTop: '10px' } }, h('div', { class: 'small faint', style: { marginBottom: '4px' } }, `Last check ${fmtTime(s.last_check)}`),
        h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Screened in the last check'), h('span', { class: 'small' }, String(sum.messages_screened))),
        sum.since_connecting ? h('div', { class: 'status-line' }, h('span', { class: 'muted' }, 'Since connecting'), h('span', { class: 'small' }, `${sum.since_connecting.screened} screened · ${sum.since_connecting.flagged} flagged`)) : null,
        (sum.since_connecting ? sum.since_connecting.flagged : sum.new_findings) ? h('div', { class: 'notice bad', style: { marginTop: '10px' } }, 'Suspicious email was found. It is in the list below. ', h('button', { class: 'link', onclick: () => ctx.navigate('response') }, 'Open Fix & review →')) : h('div', { class: 'small muted', style: { marginTop: '8px' } }, 'No suspicious mail found so far.'))
      : h('div', { class: 'small muted', style: { marginTop: '10px' } }, 'No check has finished yet.'),
      s.error ? h('div', { class: 'notice bad', style: { marginTop: '8px' } }, s.error) : null,
      h('div', { class: 'row', style: { marginTop: '14px' } },
        h('button', { disabled: s.checking, onclick: async () => { try { await api.post('/api/gmail', { action: 'check' }); paint(true); } catch (e) { toast(e.message, true); } } }, 'Check now'),
        h('button', { class: 'ghost', onclick: async () => { try { const r = await api.post('/api/gmail', { action: 'disconnect' }); toast(r.google_revoked ? 'Disconnected. Google was told to revoke access.' : 'Disconnected here. Also remove Panzeron at myaccount.google.com/permissions to be sure.'); ctx.refreshChrome(); paint(); } catch (e) { toast(e.message, true); } } }, 'Disconnect')),
      h('p', { class: 'small faint', style: { margin: '10px 0 0' } }, `${s.note} Sign-in is stored encrypted via ${s.protected_by || 'your account'}.`));
  }

  async function paint(poll = false, known = null) {
    clearTimeout(timer);
    let s = known; try { s = await api.get('/api/gmail'); } catch (e) { if (!s) return; }
    if (!alive()) return;
    if (lastSeen !== undefined && s.last_check !== lastSeen) { onNewCheck(); ctx.refreshChrome(); }
    lastSeen = s.last_check;
    clear(card);
    mount(card, h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, 'Gmail protection'), s.connected ? statusPill(true, 'Connected') : statusPill(null, 'Off')),
      s.connected ? active(s) : s.configured ? ready(s) : setup(s));
    if (poll && (s.connecting || s.checking)) timer = setTimeout(() => paint(true), 1500);
    else if (!s.connected && s.configured) ctx.refreshChrome();
  }
  paint();
  return card;
}
