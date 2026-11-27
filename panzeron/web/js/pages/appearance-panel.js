import { appearance, ACCENTS, BACKGROUNDS, PRESETS, DEFAULTS } from '../appearance.js';
import { effectStatus, setForceMotion } from '../bgfx.js';
import { h, clear, toast, mount, confirmDialog, tierLabel } from '../ui.js';
import { api } from '../api.js';
import { segmented, toggle, slider, row } from '../controls.js';

function presetTile(pr, current, onApplied) {
  const rgb = [1, 3, 5].map((i) => parseInt((pr.prefs.accent || DEFAULTS.accent).slice(i, i + 2), 16)).join(',');
  const colors = BACKGROUNDS[pr.prefs.bg || 'royal'].opacities.map((a) => `rgba(${rgb},${a})`);
  const base = pr.prefs.pureBlack ? '#000' : '#07080d';
  const bg = `radial-gradient(circle at 15% 20%, ${colors[0]}, transparent 55%), radial-gradient(circle at 85% 30%, ${colors[1]}, transparent 55%), radial-gradient(circle at 50% 100%, ${colors[2]}, transparent 60%), ${base}`;
  const accent = pr.prefs.accent || DEFAULTS.accent;
  const on = current.accent === accent && current.bg === (pr.prefs.bg || 'royal');
  return h('button', { type: 'button', class: `preset${on ? ' on' : ''}`, 'aria-label': `Apply ${pr.name} theme`, onclick: () => { appearance.applyPreset(pr.id); toast(`${pr.name} applied`); onApplied(); } },
    h('div', { class: 'pv', style: { background: bg } }, h('b'), h('i', { style: { background: accent, color: accent } })), h('span', {}, pr.name));
}

// A plain-language line saying whether the theme's live effect is running, and why not if it is not.
function fxStatusRow(p, refresh) {
  const st = effectStatus(), name = BACKGROUNDS[p.bg].fx;
  let text, action = null, tone = 'muted';
  if (st.reason === '' && st.running) { text = `Live effect running: ${name}.`; tone = 'ok'; }
  else if (st.reason === 'off') text = 'Live effects are off. Turn on “Animations & theme effects” further down to see them.';
  else if (st.reason === 'solid') text = 'The Solid theme is intentionally still. Pick another theme to see a live effect.';
  else if (st.reason === 'reduced-motion') {
    text = 'Windows is set to reduce motion (Settings → Accessibility → Visual effects → Animation effects), so the effect is paused.';
    action = h('button', { onclick: () => { setForceMotion(true); toast('Playing the effect anyway'); refresh(); } }, 'Play it anyway');
  } else if (st.reason === 'error') text = `The effect stopped because of an error: ${st.error}. Try another theme, or tell me this message.`;
  else if (st.reason === 'no-canvas') text = 'This window cannot draw the effect (no canvas support).';
  else text = 'The effect is starting…';
  if (st.forced && st.reduceMotion && st.running) action = h('button', { class: 'ghost', onclick: () => { setForceMotion(false); toast('Following the Windows motion setting again'); refresh(); } }, 'Follow Windows setting again');
  return h('div', { class: 'row between', style: { padding: '2px 0 14px', gap: '12px' } }, h('span', { class: `small ${tone === 'ok' ? '' : 'muted'}`, style: tone === 'ok' ? { color: 'var(--ok)' } : null }, text), action);
}

export function buildAppearancePanel() {
  const box = h('div', {});
  function build() {
    const p = appearance.get();
    const set = (patch) => appearance.set(patch);

    const accentRow = h('div', { class: 'swatches' },
      ACCENTS.map(([name, hex]) => h('button', { type: 'button', class: `swatch${p.accent === hex ? ' on' : ''}`, title: name, 'aria-label': `${name} accent`, style: { background: hex },
        onclick: (e) => { set({ accent: hex }); [...e.currentTarget.parentNode.querySelectorAll('.swatch')].forEach((s) => s.classList.toggle('on', s === e.currentTarget)); } })),
      h('input', { type: 'color', class: 'colorwell', value: p.accent, title: 'Custom colour', 'aria-label': 'Custom accent colour',
        oninput: (e) => { set({ accent: e.target.value }); document.querySelectorAll('.swatch.on').forEach((s) => s.classList.remove('on')); } }));

    const presets = h('div', { class: 'card' }, h('h2', {}, 'Themes'), h('div', { class: 'presets' }, PRESETS.map((pr) => presetTile(pr, p, refresh))),
      h('p', { class: 'small faint', style: { margin: '14px 0 0' } }, 'A theme is a starting point: everything below can still be adjusted, and every change applies instantly.'));

    const look = h('div', { class: 'card set-card' }, h('h2', {}, 'Colour & background'),
      row('Accent colour', 'Buttons, highlights and visual effects.', accentRow),
      row('Background', `An accent-tinted light field and live effect behind the glass: ${BACKGROUNDS[p.bg].fx}.`, segmented(Object.entries(BACKGROUNDS).map(([k, v]) => [k, v.label]), p.bg, (v) => set({ bg: v }))),
      fxStatusRow(p, refresh),
      row('Pure black', 'True black base (OLED).', toggle(p.pureBlack, (v) => set({ pureBlack: v }))));

    const glass = h('div', { class: 'card set-card' }, h('h2', {}, 'Glass'),
      row('Glass quality', 'Automatic switches to Lite on slower graphics.', segmented([['auto', 'Automatic'], ['full', 'Full'], ['lite', 'Lite']], p.fx, (v) => set({ fx: v }))),
      row('Blur', 'How strongly glass blurs what is behind it.', slider(0, 40, p.blur, (v) => set({ blur: v }), (v) => `${v}px`)),
      row('Glass tint', 'Clearer glass ↔ more opaque glass.', slider(0, 100, p.glass, (v) => set({ glass: v }), (v) => `${v}%`)),
      row('Pointer highlight', 'A soft highlight that follows your cursor.', toggle(p.sheen, (v) => set({ sheen: v }))));

    const layout = h('div', { class: 'card set-card' }, h('h2', {}, 'Layout & type'),
      row('Density', 'Spacing between elements.', segmented([['compact', 'Compact'], ['comfortable', 'Comfortable'], ['spacious', 'Spacious']], p.density, (v) => set({ density: v }))),
      row('Content width', null, segmented([['focused', 'Focused'], ['default', 'Standard'], ['full', 'Full width']], p.width, (v) => set({ width: v }))),
      row('Sidebar', 'Full labels, or icons only.', segmented([['expanded', 'Expanded'], ['compact', 'Icons only']], p.sidebar, (v) => set({ sidebar: v }))),
      row('Font', null, segmented([['system', 'System'], ['humanist', 'Humanist'], ['serif', 'Serif'], ['mono', 'Mono']], p.font, (v) => set({ font: v }))),
      row('Text size', null, segmented([['small', 'Small'], ['default', 'Default'], ['large', 'Large'], ['xl', 'Extra large']], p.textSize, (v) => set({ textSize: v }))),
      row('Animations & theme effects', 'Each theme has its own living background (Emerald is Matrix code rain). It shows best with a lower Glass blur. Turn off for a still, calm look.', toggle(p.anim, (v) => set({ anim: v }))),
      row('Sound effects', 'A soft startup cue, hover chime, click hum and sonar ping when a scan starts.', toggle(p.sound, (v) => set({ sound: v }))));

    // ---- startup: launch at sign-in (Windows, per-user) and the intro animation --------------------------------
    const lsGet = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
    const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };
    const autoBox = toggle(false, () => {}); autoBox.disabled = true;
    const autoHint = h('span', {}, 'Checking…');
    const autoRow = h('div', { class: 'set-row' }, h('div', { class: 'lab' }, h('b', {}, 'Start when I sign in to Windows'), autoHint), h('div', {}, autoBox));
    api.get('/api/autostart').then((st) => {
      autoBox.checked = !!st.enabled; autoBox.disabled = !st.available;
      const hint = (x) => !x.available ? (x.reason || 'Unavailable here.')
        : x.blocked_by_windows ? 'Windows has this switched off in Task Manager › Startup apps. Turn this on to switch it back on.'
        : x.enabled && x.current === false ? 'It points to another copy or an old location of Panzeron. Switch it off and on again to repair it.'
        : 'Opens Panzeron automatically. You can also manage it in Task Manager › Startup apps.';
      autoHint.textContent = hint(st);
      autoBox.onchange = async () => {
        autoBox.disabled = true;
        try { const r = await api.put('/api/autostart', { enabled: autoBox.checked }); autoBox.checked = !!r.enabled; autoHint.textContent = hint(r); toast(r.enabled ? 'Panzeron will start when you sign in' : 'Panzeron will no longer start automatically'); }
        catch (e) { autoBox.checked = !autoBox.checked; toast(e.message, true); }
        finally { autoBox.disabled = false; }
      };
    }).catch(() => { autoHint.textContent = 'Unavailable.'; });
    const startup = h('div', { class: 'card set-card' }, h('h2', {}, 'Startup'), autoRow,
      row('Startup animation', 'The intro where a dragon in your accent colour circles the orb. Click or press Esc to skip. With reduced motion in Windows it is a still splash; it stays off when interface animations are off.', toggle(lsGet('panzeron-intro') !== 'off', (v) => lsSet('panzeron-intro', v ? 'on' : 'off'))),
      row('Preview', null, h('button', { type: 'button', onclick: () => { try { sessionStorage.removeItem('panzeron-booted'); } catch { /* ignore */ } lsSet('panzeron-intro', 'on'); location.reload(); } }, 'Replay intro')));

    const preview = h('div', { class: 'card' }, h('h2', {}, 'Live preview'),
      h('div', { class: 'row between' }, h('div', {}, h('h3', {}, 'Combined details could make you identifiable'), h('div', { class: 'small muted' }, 'inference · 3 linked sources')),
        h('div', { class: 'row' }, tierLabel('speculative'), h('span', { class: 'badge sev-high' }, 'high'))),
      h('div', { class: 'row', style: { marginTop: '14px' } }, h('button', { class: 'primary' }, 'Primary action'), h('button', {}, 'Secondary'), h('button', { class: 'danger' }, 'Quarantine'),
        toggle(true, () => {}), h('a', { href: '#/settings' }, 'A link')),
      h('div', { class: 'bar', style: { marginTop: '16px' } }, h('i', { style: { width: '64%' } })));

    // ---- theme files ----------------------------------------------------------------------------------------
    const paste = h('textarea', { placeholder: 'Paste a Panzeron theme (JSON) here…', style: { minHeight: '110px' }, 'aria-label': 'Theme JSON' });
    const file = h('input', { type: 'file', accept: '.json,application/json', style: { display: 'none' }, onchange: async (e) => { const f = e.target.files[0]; if (f) { paste.value = await f.text(); apply(); } e.target.value = ''; } });
    function apply() {
      try {
        const rejected = appearance.importText(paste.value);
        toast(rejected.length ? `Theme applied. Ignored invalid settings: ${rejected.join(', ')}` : 'Theme applied');
        refresh();
      } catch (e) { toast(e.message, true); }
    }
    const files = h('div', { class: 'card' }, h('h2', {}, 'Share or back up your theme'),
      h('div', { class: 'row' },
        h('button', { onclick: () => { const text = appearance.exportText(); const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
          const a = h('a', { href: url, download: 'panzeron-theme.json' }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url); toast('Theme file saved'); } }, 'Export theme file'),
        h('button', { onclick: async () => { try { await navigator.clipboard.writeText(appearance.exportText()); toast('Theme copied to clipboard'); } catch { toast('Clipboard is not available here; use Export instead.', true); } } }, 'Copy theme'),
        h('button', { onclick: () => file.click() }, 'Import from file…'), file),
      h('div', { class: 'stack', style: { marginTop: '12px' } }, paste, h('div', { class: 'row' }, h('button', { class: 'primary', onclick: apply }, 'Apply pasted theme'))),
      h('p', { class: 'small faint' }, 'Imported themes are validated: unknown or invalid values are ignored, so a theme file can only change appearance, never anything else.'),
      h('div', { class: 'row', style: { marginTop: '8px' } }, h('button', { class: 'danger', onclick: async () => {
        if (!await confirmDialog({ title: 'Reset appearance', body: 'All appearance settings return to their defaults. Your findings and protection settings are not affected.', confirmLabel: 'Reset appearance', danger: true })) return;
        appearance.reset(); toast('Appearance reset'); refresh(); } }, 'Reset appearance to defaults')));

    mount(clear(box), h('div', { class: 'stack', style: { gap: '16px' } }, presets, h('div', { class: 'grid g2', style: { alignItems: 'start' } }, look, glass), h('div', { class: 'grid g2', style: { alignItems: 'start' } }, layout, h('div', { class: 'stack', style: { gap: '16px' } }, startup, preview, files))));
  }
  function refresh() { build(); }
  build();
  return box;
}
