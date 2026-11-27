const root = document.documentElement;
let audio = null;
let pendingBoot = false;
let lastHover = 0;
let resumeTask = null;
let queued = [];
const SOUND_TARGETS = 'button:not(:disabled),a[href],[role="button"],[role="radio"],input[type="checkbox"]:not(:disabled),input[type="radio"]:not(:disabled),select:not(:disabled),summary';

function context() {
  if (!audio) {
    const Audio = window.AudioContext || window.webkitAudioContext;
    if (!Audio) return null;
    audio = new Audio();
  }
  return audio;
}

function tone(ctx, startHz, endHz, duration, delay = 0, volume = 0.045, type = 'sine') {
  const at = ctx.currentTime + delay;
  const osc = ctx.createOscillator(), gain = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(startHz, at);
  osc.frequency.exponentialRampToValueAtTime(Math.max(1, endHz), at + duration);
  gain.gain.setValueAtTime(0.0001, at);
  gain.gain.exponentialRampToValueAtTime(volume, at + Math.min(0.015, duration / 3));
  gain.gain.exponentialRampToValueAtTime(0.0001, at + duration);
  osc.connect(gain); gain.connect(ctx.destination);
  osc.start(at); osc.stop(at + duration + 0.02);
}

function play(ctx, kind) {
  if (root.dataset.sound !== 'on') { pendingBoot = false; return; }
  if (kind === 'hover') {
    tone(ctx, 1150, 880, 0.055, 0, 0.025, 'sine');
  } else if (kind === 'click') {
    tone(ctx, 190, 135, 0.085, 0, 0.035, 'sine');
  } else if (kind === 'scan') {
    tone(ctx, 1040, 620, 0.28, 0, 0.075, 'sine');
    tone(ctx, 1040, 620, 0.34, 0.42, 0.035, 'sine');
  } else if (kind === 'boot') {
    pendingBoot = false;
    tone(ctx, 220, 330, 0.2, 0, 0.035);
    tone(ctx, 330, 440, 0.24, 0.16, 0.035);
    tone(ctx, 440, 660, 0.36, 0.34, 0.04);
  }
}

function resume(ctx, kind) {
  if (ctx.state === 'running') {
    if (pendingBoot && kind !== 'boot') {
      pendingBoot = false;
      if (root.classList.contains('booting') || root.classList.contains('revealing')) play(ctx, 'boot');
    }
    play(ctx, kind);
    return;
  }
  if (kind === 'hover') {
    if (resumeTask) return;
  } else if (kind === 'boot') pendingBoot = true;
  else queued.push(kind);
  if (resumeTask) return;
  resumeTask = ctx.resume().then(() => {
    if (root.dataset.sound === 'on' && pendingBoot &&
        (root.classList.contains('booting') || root.classList.contains('revealing'))) play(ctx, 'boot');
    else pendingBoot = false;
    for (const queuedKind of queued) play(ctx, queuedKind);
    queued = [];
  }).catch(() => {
    queued = [];
  }).finally(() => { resumeTask = null; });
}

export function playSfx(kind) {
  if (root.dataset.sound !== 'on') return;
  if (kind === 'boot') pendingBoot = true;
  const ctx = context();
  if (!ctx) return;
  resume(ctx, kind);
}

export function installSfx() {
  document.addEventListener('pointerover', (event) => {
    const target = event.target instanceof Element ? event.target.closest(SOUND_TARGETS) : null;
    if (!target || (event.relatedTarget instanceof Node && target.contains(event.relatedTarget))) return;
    const now = performance.now();
    if (now - lastHover < 90) return;
    lastHover = now;
    playSfx('hover');
  });
  document.addEventListener('click', (event) => {
    if (event.target instanceof Element && event.target.closest(SOUND_TARGETS)) playSfx('click');
  }, true);
}
