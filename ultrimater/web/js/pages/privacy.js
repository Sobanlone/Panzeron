import { api } from '../api.js';
import { h, clear, findingCard, toast, emptyState, mount } from '../ui.js';
import { runAction } from '../actions.js';

export async function render(view, ctx, alive) {
  const status = await api.get('/api/status');
  if (!alive()) return;
  const out = h('div', {});
  const list = h('div', {});

  async function show(report) {
    mount(clear(out), h('div', { class: 'card', style: { marginTop: '16px' } },
      h('div', { class: 'row between' }, h('h2', { style: { margin: 0 } }, `Report: ${report.source}`), h('span', { class: 'small muted' }, `${report.kind} · ${report.chars_analysed} characters analysed${report.ocr_mean_confidence != null ? ` · OCR confidence ${report.ocr_mean_confidence}%` : ''}`)),
      ...report.notes.map((n) => h('div', { class: 'notice', style: { marginTop: '10px' } }, n)),
      report.findings.length ? h('div', { style: { marginTop: '12px' } }, report.findings.map((f) => cardWithActions(f)))
        : h('div', { class: 'empty' }, 'Nothing sensitive was detected by the available detectors. This is not a guarantee: names without labels and text OCR could not read are not detected.')));
    ctx.refreshChrome(); loadAll();
  }
  function cardWithActions(f) {
    const c = findingCard(f, { open: false });
    api.get(`/api/findings/${f.id}`).then(({ actions }) => {
      c.querySelector('.body').append(h('div', { class: 'row', style: { marginTop: '14px' } }, actions.map((a) => h('button', { title: a.description, class: a.destructive ? 'danger' : '',
        onclick: () => runAction(a, f, () => { loadAll(); ctx.refreshChrome(); }) }, a.label))));
    });
    return c;
  }
  async function loadAll() {
    const fs = (await api.get('/api/findings?module=vision&status=open')).findings;
    mount(clear(list), h('h2', { style: { marginTop: '26px' } }, `All open privacy findings (${fs.length})`), fs.length ? fs.map(cardWithActions) : emptyState('No open privacy findings.'));
  }
  async function upload(files) {
    for (const file of files) {
      try { toast(`Analysing ${file.name} locally…`); show(await api.upload(file)); } catch (e) { toast(e.message, true); }
    }
  }

  const input = h('input', { type: 'file', multiple: true, accept: '.png,.jpg,.jpeg,.bmp,.gif,.webp,.tif,.tiff,.pdf,.docx,.txt,.md,.csv,.log,.json,.eml,.env', style: { display: 'none' }, onchange: (e) => upload([...e.target.files]) });
  const drop = h('div', { class: 'drop', tabindex: 0, role: 'button', onclick: () => input.click(),
    ondragover: (e) => { e.preventDefault(); drop.classList.add('over'); }, ondragleave: () => drop.classList.remove('over'),
    ondrop: (e) => { e.preventDefault(); drop.classList.remove('over'); upload([...e.dataTransfer.files]); },
    onkeydown: (e) => e.key === 'Enter' && input.click() },
    h('div', {}, h('b', {}, 'Drop images, screenshots, PDFs, documents or text files here'), h('div', { class: 'small' }, 'or click to choose. Processed on this device only; originals are never modified.')), input);
  const text = h('textarea', { placeholder: 'Or paste text to check…', 'aria-label': 'Text to analyse' });

  mount(view, 
    !status.ocr.available ? h('div', { class: 'notice', style: { marginBottom: '14px' } }, h('b', {}, 'OCR unavailable: '), `${status.ocr.reason}. Images will still be checked for metadata (e.g. GPS), but text inside them will not be read.`) : null,
    h('div', { class: 'grid g2' },
      h('div', { class: 'card' }, h('h2', {}, 'Analyse a file'), drop),
      h('div', { class: 'card' }, h('h2', {}, 'Analyse text'), h('div', { class: 'stack' }, text,
        h('div', {}, h('button', { class: 'primary', onclick: async () => { try { show(await api.post('/api/vision/text', { text: text.value })); } catch (e) { toast(e.message, true); } } }, 'Analyse text'))))),
    out, list);
  loadAll();
}
