import { api } from '../api.js';
import { buildGmailCard } from './gmail-card.js';
import { h, clear, findingCard, tierLabel, toast, emptyState, mount } from '../ui.js';

const VERDICT = { likely_scam: 'Likely scam or phishing', suspicious: 'Suspicious', insufficient_evidence: 'Insufficient evidence', no_indicators_found: 'No indicators found' };

export async function render(view, ctx, alive) {
  const [{ ai }, br] = await Promise.all([api.get('/api/status'), api.get('/api/browser').catch(() => null)]);
  if (!alive()) return;
  const out = h('div', {}), list = h('div', {});
  const text = h('textarea', { placeholder: 'Paste a message, email (headers help), or a link…', 'aria-label': 'Message or URL' });
  const useAi = h('input', { type: 'checkbox', checked: ai.available, disabled: !ai.available });

  function result(a) {
    mount(clear(out), h('div', { class: 'card', style: { marginTop: '16px' } },
      h('div', { class: `assess ${a.verdict}` }, h('div', {}, h('div', { class: 'small muted' }, 'Assessment'), h('div', { class: 'v' }, VERDICT[a.verdict])),
        h('div', {}, h('div', { class: 'small muted' }, 'Confidence'), h('b', {}, a.confidence)),
        h('div', {}, h('div', { class: 'small muted' }, 'Score'), h('b', {}, `${a.score} (${a.distinct_categories} categories)`))),
      h('p', {}, a.explanation),
      h('div', { class: `notice ${a.verdict === 'likely_scam' ? 'bad' : a.verdict === 'no_indicators_found' ? 'info' : ''}` }, h('b', {}, 'Recommended action. '), a.recommended_action),
      a.ai_note ? h('div', { class: 'notice info', style: { marginTop: '10px' } }, h('span', { class: 'tier ai_assessed' }, 'AI'), '  ', a.ai_note) : null,
      a.ai ? h('div', { class: 'small', style: { marginTop: '8px' } }, h('b', {}, 'Model view: '), `${a.ai.likelihood} likelihood. ${a.ai.intent}`) : null,
      a.indicators.length ? h('div', { style: { marginTop: '16px' } }, h('h2', {}, 'Supporting evidence'),
        h('table', {}, h('thead', {}, h('tr', {}, ['Indicator', 'What was found', 'Where', 'Evidence'].map((t) => h('th', {}, t)))),
          h('tbody', {}, a.indicators.map((i) => h('tr', {}, h('td', {}, i.description), h('td', { class: 'mono small' }, i.evidence), h('td', { class: 'mono small faint' }, i.source_ref), h('td', {}, tierLabel(i.tier))))))) : null,
      h('details', { style: { marginTop: '14px' } }, h('summary', { class: 'small muted' }, 'How the score works'), h('p', { class: 'small muted' }, a.scoring_rule))));
  }
  async function loadList() {
    const fs = (await api.get('/api/findings?module=sentinel&status=open')).findings;
    mount(clear(list), h('h2', { style: { marginTop: '26px' } }, `Flagged messages (${fs.length})`), fs.length ? fs.map((f) => findingCard(f)) : emptyState('No flagged messages.'));
  }

  const btn = h('button', { class: 'primary', onclick: async () => {
    btn.disabled = true; btn.textContent = 'Analysing…';
    try { result(await api.post('/api/sentinel/analyze', { text: text.value, use_ai: useAi.checked })); ctx.refreshChrome(); loadList(); }
    catch (e) { toast(e.message, true); } finally { btn.disabled = false; btn.textContent = 'Analyse'; }
  } }, 'Analyse');

  mount(view, h('div', { class: 'card' }, h('div', { class: 'stack' }, text,
    h('div', { class: 'row between' }, h('label', { class: 'row small muted' }, useAi, ai.available ? `Add local AI commentary (${ai.model}, on this device)` : `Local AI unavailable: ${ai.reason}`), btn),
    h('p', { class: 'small faint', style: { margin: 0 } }, 'Verdicts come from fixed, inspectable rules. AI can add commentary or raise concern, never lower it, and never declares anything safe. Text is analysed on this device.'))),
    buildGmailCard(ctx, alive, () => loadList()), out, br && br.granted && br.caps.includes('history') ? h('div', { class: 'notice info', style: { marginTop: '16px' } }, h('b', {}, 'Your browser is screened automatically. '), `Risky addresses from ${br.browser_name || 'your browser'} appear in the list below; you do not need to paste them.`) : null, list);
  loadList();
}
