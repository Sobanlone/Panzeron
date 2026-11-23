import { h } from './ui.js';

// Segmented control: options = [[value, label], ...]
export function segmented(options, value, onChange) {
  const el = h('div', { class: 'seg', role: 'radiogroup' });
  const paint = (v) => [...el.children].forEach((b, i) => { b.classList.toggle('on', options[i][0] === v); b.setAttribute('aria-checked', String(options[i][0] === v)); });
  options.forEach(([v, label]) => el.append(h('button', { type: 'button', role: 'radio', onclick: () => { paint(v); onChange(v); } }, label)));
  paint(value);
  return el;
}

export function toggle(checked, onChange) {
  return h('input', { type: 'checkbox', checked, onchange: (e) => onChange(e.target.checked) });
}

export function slider(min, max, value, onInput, format = (v) => v) {
  const out = h('span', { class: 'rangeval' }, format(value));
  const inp = h('input', { type: 'range', min, max, step: 1, value, 'aria-valuemin': min, 'aria-valuemax': max,
    oninput: (e) => { const v = Number(e.target.value); out.textContent = format(v); onInput(v); } });
  return h('div', { class: 'row', style: { flexWrap: 'nowrap', gap: '14px' } }, inp, out);
}

export function row(title, hint, control) {
  return h('div', { class: 'set-row' }, h('div', { class: 'lab' }, h('b', {}, title), hint ? h('span', {}, hint) : null), h('div', {}, control));
}
