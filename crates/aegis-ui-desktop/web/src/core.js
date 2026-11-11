'use strict';
/* Aegis 0.2.5 prototype: shared helpers. No framework; screens are plain
   functions that return elements. Strings come from i18n.rs through I18N. */

// ── DOM ──────────────────────────────────────────────────
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'indeterminate', 'muted', 'playsInline', 'tabIndex']);

function h(sel, props, ...kids) {
  let tag = 'div', id = '', cls = [];
  sel.replace(/([.#]?)([\w-]+)/g, (_, p, n) => { if (!p) tag = n; else if (p === '.') cls.push(n); else id = n; return ''; });
  const el = document.createElement(tag);
  if (id) el.id = id;
  if (cls.length) el.className = cls.join(' ');
  if (props != null && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) { kids.unshift(props); props = null; }
  for (const k in props) {
    const v = props[k];
    if (v == null || v === false) continue;
    if (k === 'class') el.className = (el.className + ' ' + v).trim();
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'text') el.textContent = v;
    else if (PROPS.has(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}
const tpl = document.createElement('template');
function frag(html) { tpl.innerHTML = html.trim(); return tpl.content.firstElementChild.cloneNode(true); }
function ico(name, cls = '') { return frag(`<svg class="i ${cls}" aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`); }
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const raf = () => new Promise(r => requestAnimationFrame(r));
const uid = (() => { let n = 0; return p => (p || 'u') + (++n).toString(36); })();

// ── i18n ─────────────────────────────────────────────────
// I18N is { key: [en, ru] }: real strings from i18n.rs and look_text.rs, plus
// the d.* keys of design-strings.json that the brief asks for and i18n.rs lacks.
const I18N = __I18N__;
let LANG = 'ru';
try { LANG = localStorage.getItem('aegis.lang') === 'en' ? 'en' : 'ru'; } catch (e) { LANG = 'ru'; }
function t(k) { const v = I18N[k]; return v ? v[LANG === 'en' ? 0 : 1] : k; }
function tf(k, vars) { return t(k).replace(/\{(\w+)\}/g, (_, n) => (vars && n in vars ? vars[n] : '')); }
// errors follow the app: text (detail); ok messages: text: detail
const errText = (k, d) => t(k) + (d != null && d !== '' ? ' (' + d + ')' : '');
const okText = (k, d) => t(k) + (d != null && d !== '' ? ': ' + d : '');

// ── motion ───────────────────────────────────────────────
const E = {
  scene: 'cubic-bezier(.16,1,.3,1)',
  out: 'cubic-bezier(.2,.7,.2,1)',
  soft: 'cubic-bezier(.65,0,.35,1)',
  back: 'cubic-bezier(.34,1.56,.64,1)',
};
/* A damped spring sampled into a CSS linear() easing, for WAAPI moves that should
   overshoot a little and settle like Spring does (k = stiffness, z = damping ratio). */
function springCurve(k, z) {
  const w = Math.sqrt(k), wd = w * Math.sqrt(1 - z * z), T = 5 / (z * w), n = 48;
  const x = s => 1 - Math.exp(-z * w * s) * (Math.cos(wd * s) + (z * w / wd) * Math.sin(wd * s));
  const pts = Array.from({ length: n + 1 }, (_, i) => (i === n ? 1 : +x(T * i / n).toFixed(4)));
  return { easing: `linear(${pts.join(',')})`, duration: Math.round(T * 1000) };
}
const RMQ = matchMedia('(prefers-reduced-motion: reduce)');
let reduced = RMQ.matches;
const motionSubs = new Set();
function setReduced(v) {
  reduced = !!v;
  document.documentElement.classList.toggle('rm', reduced);
  motionSubs.forEach(f => f(reduced));
}
/* The OS "reduce motion" switch only calms the flicker (html.calm: no glitch,
   CRT, grain); movement stays, because the prototype is about motion.
   Full stillness is the #still link or setReduced(true). */
const calmOS = () => document.documentElement.classList.toggle('calm', RMQ.matches);
RMQ.addEventListener('change', calmOS);
calmOS();
reduced = location.hash === '#still';
setReduced(reduced);

/* WAAPI wrapper: resolves when done, instant under reduced motion. */
function anim(el, frames, opts = {}) {
  if (!el || !el.animate) return Promise.resolve();
  const o = typeof opts === 'number' ? { duration: opts } : { ...opts };
  if (reduced) { o.duration = 1; o.delay = 0; }
  o.easing = o.easing || E.scene;
  const a = el.animate(frames, o);
  return a.finished.then(() => a, () => a);
}

/* Spring sampled into a CSS linear() easing, so WAAPI can play real springs.
   k is stiffness (the brief: 260-320), z the damping ratio. */
const LINEAR_OK = typeof CSS !== 'undefined' && CSS.supports && CSS.supports('animation-timing-function', 'linear(0, 1)');
const springCache = new Map();
function springEase(k = 280, z = 0.62) {
  const key = k + ':' + z;
  if (springCache.has(key)) return springCache.get(key);
  const c = 2 * Math.sqrt(k) * z, dt = 1 / 600;
  let x = 0, v = 0, t = 0;
  const pts = [0];
  while (t < 2.4) {
    for (let i = 0; i < 10; i++) { const a = -k * (x - 1) - c * v; v += a * dt; x += v * dt; t += dt; }
    pts.push(x);
    if (t > 0.2 && Math.abs(x - 1) < 0.0015 && Math.abs(v) < 0.02) break;
  }
  pts[pts.length - 1] = 1;
  const step = Math.max(1, Math.round(pts.length / 48));
  const thin = pts.filter((_, i) => i % step === 0 || i === pts.length - 1);
  const out = LINEAR_OK
    ? { easing: 'linear(' + thin.map(p => +p.toFixed(4)).join(',') + ')', duration: Math.round(t * 1000) }
    : { easing: E.back, duration: 520 };
  springCache.set(key, out);
  return out;
}

/* Numeric springs stepped by rAF, for things that follow the pointer
   (segment pill, list highlight, sheet drag release). */
class Spring {
  constructor(x = 0, k = 290, z = 0.7) { this.x = x; this.v = 0; this.to = x; this.k = k; this.c = 2 * Math.sqrt(k) * z; }
  step(h) { const a = -this.k * (this.x - this.to) - this.c * this.v; this.v += a * h; this.x += this.v * h; }
  get rest() { return Math.abs(this.v) < 0.05 && Math.abs(this.x - this.to) < 0.05; }
  snap(v) { if (v != null) this.to = v; this.x = this.to; this.v = 0; }
}
function runSprings(springs, render, done) {
  let last = performance.now(), id = 0, live = true;
  const f = now => {
    const dt = Math.min(0.034, (now - last) / 1000);
    last = now;
    const n = Math.ceil(dt / 0.004), hh = dt / n;
    for (const s of springs) for (let i = 0; i < n; i++) s.step(hh);
    if (reduced || springs.every(s => s.rest)) { springs.forEach(s => s.snap()); render(); live = false; done && done(); return; }
    render();
    id = requestAnimationFrame(f);
  };
  id = requestAnimationFrame(f);
  return { stop() { if (live) cancelAnimationFrame(id); live = false; }, get live() { return live; } };
}

// ── text effects ─────────────────────────────────────────
const GLYPHS = '█▓▒░#%&@';
const HEX = '0123456789abcdef';
/* glyph decode: block glyphs settle into the text, 1100 ms */
function decode(el, text, dur = 1100) {
  text = text == null ? el.textContent : String(text);
  if (el._dec) el._dec.cancel = true;
  if (reduced || !text) { el.textContent = text; return Promise.resolve(); }
  const chars = [...text];
  const at = chars.map((ch, i) => (/\s/.test(ch) ? 0 : (0.12 + 0.62 * (i / Math.max(1, chars.length - 1)) + Math.random() * 0.22) * dur));
  const job = { cancel: false };
  el._dec = job;
  el.setAttribute('aria-label', text);
  const t0 = performance.now();
  return new Promise(res => {
    let n = 0;
    const f = now => {
      if (job.cancel) return res();
      const e = now - t0;
      if (e >= dur) { el.textContent = text; el.removeAttribute('aria-label'); el._dec = null; return res(); }
      if (n++ % 2 === 0) el.textContent = chars.map((ch, i) => (e >= at[i] ? ch : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join('');
      requestAnimationFrame(f);
    };
    requestAnimationFrame(f);
  });
}
/* hex scramble on send: plain → cipher → plain, about 1.3 s */
function scramble(el, text, dur = 1300) {
  if (reduced) { el.textContent = text; return Promise.resolve(); }
  const chars = [...text], N = chars.length;
  if (N > 900) { el.textContent = text; return anim(el, [{ opacity: 0.4 }, { opacity: 1 }], { duration: 500 }).then(() => {}); }
  const a = chars.map(() => Math.random() * 0.34), b = chars.map(() => 0.62 + Math.random() * 0.34);
  const t0 = performance.now();
  return new Promise(res => {
    let n = 0;
    const f = now => {
      const p = (now - t0) / dur;
      if (p >= 1) { el.textContent = text; return res(); }
      if (n++ % 2 === 0) el.textContent = chars.map((ch, i) => (/\s/.test(ch) ? ch : p < a[i] || p > b[i] ? ch : HEX[(Math.random() * 16) | 0])).join('');
      requestAnimationFrame(f);
    };
    requestAnimationFrame(f);
  });
}
/* letters fall apart into ash, then the row collapses (1 s + 0.4 s) */
function ash(el, opts = {}) {
  const text = el.textContent;
  if (reduced || !text) return Promise.resolve();
  const max = opts.max || 220;
  el.textContent = '';
  const spans = [];
  const chars = [...text];
  chars.forEach((ch, i) => {
    if (i >= max) { if (i === max) el.append(h('span', { style: { opacity: 0.5 } }, chars.slice(max).join(''))); return; }
    if (ch === '\n') { el.append('\n'); return; }
    const s = h('span.ashc', ch === ' ' ? ' ' : ch);
    spans.push(s);
    el.append(s);
  });
  const cs = getComputedStyle(el), c0 = cs.color, rs = getComputedStyle(document.documentElement);
  const hot = rs.getPropertyValue('--bone').trim() || '#eeeef1', dim = rs.getPropertyValue('--dim').trim() || '#5b5c63';
  const jobs = spans.map((s, i) => {
    const dx = (Math.random() - 0.5) * 44, dy = -(18 + Math.random() * 46), r = (Math.random() - 0.5) * 140;
    return anim(s, [
      { transform: 'none', opacity: 1, filter: 'blur(0)', color: c0 },
      { offset: 0.25, color: hot },
      { transform: `translate(${dx}px,${dy}px) rotate(${r}deg) scale(.4)`, opacity: 0, filter: 'blur(2px)', color: dim },
    ], { duration: 640 + Math.random() * 220, delay: (i / Math.max(1, spans.length)) * 300 + Math.random() * 60, easing: E.out, fill: 'forwards' });
  });
  return Promise.all(jobs).then(() => {});
}
function collapse(el, dur = 400) {
  const r = el.getBoundingClientRect();
  el.style.overflow = 'hidden';
  return anim(el, [
    { height: r.height + 'px', opacity: getComputedStyle(el).opacity },
    { height: '0px', opacity: 0, paddingTop: '0px', paddingBottom: '0px', marginTop: '0px', marginBottom: '0px' },
  ], { duration: dur, easing: E.soft, fill: 'forwards' }).then(() => el.remove());
}
function shake(el) {
  if (!el) return;
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = `shake var(--d-shake) ${E.out}`;
  el.addEventListener('animationend', () => { el.style.animation = ''; }, { once: true });
}

// ── controls ─────────────────────────────────────────────
/* Segmented control with a spring pill that squashes with speed.
   el: .seg with buttons [data-v]; returns { set(v) } */
function seg(el, value, onChange) {
  let pill = el.querySelector('.pill');
  if (!pill) { pill = h('i.pill', { 'aria-hidden': 'true' }); el.prepend(pill); }
  const btns = () => [...el.querySelectorAll(':scope > button')];
  el.setAttribute('role', el.getAttribute('role') || 'radiogroup');
  const sx = new Spring(0, 290, 0.66), sw = new Spring(0, 290, 0.8);
  let run = null, first = true;
  const render = () => {
    const v = Math.abs(sx.v);
    const sq = Math.min(0.16, v / 5200);
    pill.style.width = Math.max(0, sw.x) + 'px';
    pill.style.transform = `translateX(${sx.x}px) scale(${1 + sq * 0.6},${1 - sq})`;
  };
  const place = (instant) => {
    const b = btns().find(x => x.dataset.v === String(value));
    if (!b) { pill.style.opacity = 0; return; }
    pill.style.opacity = 1;
    sx.to = b.offsetLeft; sw.to = b.offsetWidth;
    if (instant || first || reduced) { sx.snap(); sw.snap(); render(); first = false; return; }
    if (!run || !run.live) run = runSprings([sx, sw], render);
  };
  const mark = () => btns().forEach(b => {
    const on = b.dataset.v === String(value);
    b.setAttribute(el.getAttribute('role') === 'tablist' ? 'aria-selected' : 'aria-checked', on);
    b.setAttribute('role', el.getAttribute('role') === 'tablist' ? 'tab' : 'radio');
    b.tabIndex = on ? 0 : -1;
  });
  el.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b || b.parentElement !== el || b.disabled) return;
    if (b.dataset.v === String(value)) return;
    value = b.dataset.v; mark(); place(); onChange && onChange(value);
  });
  el.addEventListener('keydown', e => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
    const list = btns().filter(b => !b.disabled);
    let i = list.findIndex(b => b.dataset.v === String(value));
    i = e.key === 'Home' ? 0 : e.key === 'End' ? list.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + list.length) % list.length;
    list[i].focus(); list[i].click(); e.preventDefault();
  });
  mark();
  requestAnimationFrame(() => place(true));
  new ResizeObserver(() => place(true)).observe(el);
  return { set(v, silent) { value = v; mark(); place(); if (!silent && onChange) onChange(v); }, get value() { return value; }, place };
}

/* Liquid toggle: the fill grows from the knob, the knob stretches on press and drag. */
function toggle(on, onChange, label) {
  const el = h('button.tg', { type: 'button', role: 'switch', 'aria-checked': String(!!on), 'aria-label': label || null },
    h('i.tg-fill'), h('i.tg-knob'));
  let x0 = null, moved = false;
  const set = v => { on = !!v; el.setAttribute('aria-checked', String(on)); };
  el.addEventListener('pointerdown', e => { x0 = e.clientX; moved = false; el.classList.add('drag'); el.setPointerCapture(e.pointerId); });
  el.addEventListener('pointermove', e => {
    if (x0 == null) return;
    const dx = e.clientX - x0;
    if (Math.abs(dx) > 8 && !moved) moved = true;
    if (moved && (dx > 0) !== on) { set(dx > 0); onChange && onChange(on); x0 = e.clientX; }
  });
  const end = () => { el.classList.remove('drag'); x0 = null; };
  el.addEventListener('pointerup', end);
  el.addEventListener('pointercancel', end);
  el.addEventListener('click', e => { if (moved) { moved = false; e.preventDefault(); return; } set(!on); onChange && onChange(on); });
  el.set = set;
  return el;
}

/* Floating-label field. opts: { label, type, value, mono, area, max, auto, name, inputmode, oninput } */
function field(o) {
  const id = uid('f');
  const input = o.area
    ? h('textarea', { id, rows: o.rows || 3, placeholder: ' ', maxlength: o.hardMax || null, spellcheck: 'false' })
    : h('input', { id, type: o.type || 'text', placeholder: ' ', autocomplete: o.auto || 'off', inputmode: o.inputmode || null, spellcheck: 'false', autocapitalize: 'off', maxlength: o.hardMax || null, name: o.name || null });
  if (o.value != null) input.value = o.value;
  const lab = h('span', o.label);
  const wrap = h('label.fld' + (o.mono ? '.mono' : ''), { for: id }, input, lab);
  const msg = h('p.fmsg', { id: id + '-m', 'aria-live': 'polite' });
  input.setAttribute('aria-describedby', id + '-m');
  let cnt = null;
  if (o.max) {
    cnt = h('span.cnt', { 'aria-hidden': 'true' });
    wrap.append(cnt);
    const upd = () => { const n = [...input.value].length; cnt.textContent = n + '/' + o.max; cnt.classList.toggle('over', n > o.max); };
    input.addEventListener('input', upd); upd();
  }
  if (o.type === 'password') {
    const eye = h('button.ib.bare.eye', { type: 'button', 'aria-label': t('d.show_secret'), 'aria-pressed': 'false' }, ico('eye'));
    eye.addEventListener('click', e => { e.preventDefault(); const show = input.type === 'password'; input.type = show ? 'text' : 'password'; eye.setAttribute('aria-pressed', String(show)); input.focus(); });
    wrap.append(eye);
  }
  input.addEventListener('input', () => { if (wrap.classList.contains('err')) { wrap.classList.remove('err'); msg.textContent = ''; input.removeAttribute('aria-invalid'); } o.oninput && o.oninput(input.value); });
  const box = h('div.fbox', wrap, msg);
  box.input = input; box.wrap = wrap; box.msg = msg; box.label = lab;
  box.error = text => { wrap.classList.add('err'); msg.className = 'fmsg'; msg.textContent = text || ''; input.setAttribute('aria-invalid', 'true'); shake(wrap); };
  box.ok = text => { wrap.classList.remove('err'); msg.className = 'fmsg ok'; msg.textContent = text || ''; };
  box.clear = () => { wrap.classList.remove('err'); msg.textContent = ''; input.removeAttribute('aria-invalid'); };
  if (cnt) box.count = () => input.dispatchEvent(new Event('input'));
  return box;
}

/* Button → spinner: the width folds into a circle in 500 ms */
function busy(btn, on) {
  if (!btn) return;
  if (on) {
    if (btn._busy) return;
    btn._busy = true;
    const w = btn.offsetWidth, hgt = btn.offsetHeight;
    btn.dataset.w = w;
    btn.style.width = w + 'px';
    btn.classList.add('busy');
    btn.setAttribute('aria-busy', 'true');
    btn._a = btn.animate([{ width: w + 'px' }, { width: hgt + 'px' }], { duration: reduced ? 1 : 500, easing: E.soft, fill: 'forwards' });
  } else {
    if (!btn._busy) return;
    btn._busy = false;
    const w = +btn.dataset.w || btn.offsetWidth;
    if (btn._a) btn._a.cancel();
    const a = btn.animate([{ width: btn.offsetHeight + 'px' }, { width: w + 'px' }], { duration: reduced ? 1 : 380, easing: E.scene });
    btn.classList.remove('busy');
    btn.removeAttribute('aria-busy');
    a.finished.then(() => { btn.style.width = ''; }, () => {});
  }
}

// ── flash, live region ───────────────────────────────────
function announce(text) {
  const live = $('#live');
  if (!live) return;
  live.textContent = '';
  setTimeout(() => { live.textContent = text; }, 30);
}
function flash(text, kind = 'err', ms = 3800) {
  let box = $('.flashes');
  if (!box) { box = h('div.flashes'); ENTRY.append(box); }
  const el = h('div.flash' + (kind === 'ok' ? '.ok' : ''), { role: 'status' }, h('span', text));
  box.append(el);
  announce(text);
  anim(el, [{ opacity: 0, transform: 'translateY(14px) scale(.98)' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
  while (box.children.length > 3) box.firstElementChild.remove();
  setTimeout(() => anim(el, [{ opacity: 1 }, { opacity: 0, transform: 'translateY(8px)' }], { duration: 260, easing: E.out, fill: 'forwards' }).then(() => el.remove()), ms);
  return el;
}

// ── layer: sheets, dialogs, menus ────────────────────────
const isDesk = () => innerWidth >= 900;
const layer = () => $('#layer') || ENTRY;
let openSheets = [];
function trapFocus(root, e) {
  const f = $$('button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled]), select, [tabindex]:not([tabindex="-1"])', root).filter(x => x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
  else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
}
/* Sheet: bottom sheet with a spring and swipe-down on phones,
   a 440 px card in the middle on desktop, same spring. */
function sheet({ title, body, foot, onClose, cls = '', focus = true, label }) {
  const back = document.activeElement;
  const scrim = h('div.scrim');
  const close = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const grab = h('button.grab', { type: 'button', 'aria-label': t('common.close'), tabIndex: -1 });
  const head = h('div.sh-head', h('h2.t-sheet', { id: uid('sh') }, title), close);
  const el = h('div.sheet' + (cls ? '.' + cls : ''), { role: 'dialog', 'aria-modal': 'true' }, grab, head, h('div.sh-body', body), foot ? h('div.sh-foot', foot) : null);
  el.setAttribute('aria-labelledby', head.firstChild.id);
  if (label) el.setAttribute('aria-label', label);
  layer().append(scrim, el);
  const sp = springEase(isDesk() ? 300 : 270, isDesk() ? 0.72 : 0.78);
  anim(scrim, [{ opacity: 0 }, { opacity: 1 }], { duration: 300, easing: E.out });
  anim(el, isDesk()
    ? [{ opacity: 0, transform: 'translateY(26px) scale(.965)' }, { opacity: 1, transform: 'none' }]
    : [{ transform: 'translateY(100%)' }, { transform: 'none' }], { duration: sp.duration, easing: sp.easing });
  let done = false;
  const api = {
    el, body: el.querySelector('.sh-body'),
    async close(v) {
      if (done) return; done = true;
      openSheets = openSheets.filter(s => s !== api);
      document.removeEventListener('keydown', onKey, true);
      anim(scrim, [{ opacity: 1 }, { opacity: 0 }], { duration: 240, easing: E.out, fill: 'forwards' });
      await anim(el, isDesk()
        ? [{ opacity: 1, transform: getComputedStyle(el).transform === 'none' ? 'none' : getComputedStyle(el).transform }, { opacity: 0, transform: 'translateY(18px) scale(.97)' }]
        : [{ transform: getComputedStyle(el).transform === 'none' ? 'none' : getComputedStyle(el).transform }, { transform: 'translateY(105%)' }], { duration: 300, easing: E.soft, fill: 'forwards' });
      scrim.remove(); el.remove();
      if (back && back.isConnected) back.focus({ preventScroll: true });
      onClose && onClose(v);
    },
  };
  const onKey = e => {
    if (openSheets[openSheets.length - 1] !== api) return;
    if (e.key === 'Escape') { e.stopPropagation(); api.close(); }
    if (e.key === 'Tab') trapFocus(el, e);
  };
  document.addEventListener('keydown', onKey, true);
  scrim.addEventListener('click', () => api.close());
  close.addEventListener('click', () => api.close());
  grab.addEventListener('click', () => api.close());
  // swipe down to close (phone)
  let y0 = null, dy = 0, t0 = 0;
  const startDrag = e => { if (isDesk() || e.button > 0) return; y0 = e.clientY; dy = 0; t0 = performance.now(); el.setPointerCapture(e.pointerId); el.style.transition = 'none'; };
  [grab, head].forEach(x => x.addEventListener('pointerdown', e => { if (e.target.closest('button') && e.target !== grab) return; startDrag(e); }));
  el.addEventListener('pointermove', e => { if (y0 == null) return; dy = Math.max(0, e.clientY - y0); el.style.transform = `translateY(${dy}px)`; });
  const endDrag = () => {
    if (y0 == null) return;
    const v = dy / Math.max(1, performance.now() - t0);
    y0 = null;
    if (dy > el.offsetHeight * 0.28 || v > 0.6) api.close();
    else { const s = springEase(300, 0.7); anim(el, [{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: s.duration, easing: s.easing }).then(() => { el.style.transform = ''; }); }
  };
  el.addEventListener('pointerup', endDrag);
  el.addEventListener('pointercancel', endDrag);
  openSheets.push(api);
  if (focus) requestAnimationFrame(() => { const f = el.querySelector('.sh-body input, .sh-body textarea') || close; f.focus({ preventScroll: true }); });
  return api;
}
/* Dialog = a small sheet with a text and two buttons. Resolves true / false. */
function ask({ title, text, ok, danger = true, extra }) {
  return new Promise(res => {
    let val = false;
    const yes = h('button.btn.wide' + (danger ? '.danger' : ''), { type: 'button' }, ok);
    const no = h('button.btn.ghost.wide', { type: 'button' }, t('common.cancel'));
    const s = sheet({ title, body: [text ? h('p.note', text) : null, extra || null], foot: [yes, no], cls: 'dlg', onClose: () => res(val) });
    yes.addEventListener('click', async () => {
      if (extra && extra.check) { const okv = await extra.check(); if (!okv) return; }
      val = true; s.close(true);
    });
    no.addEventListener('click', () => s.close(false));
  });
}

/* Menu grows from the press point; items come in as a ladder (300-400 ms). */
let openMenu = null;
function menu(anchor, items, { align = 'end' } = {}) {
  if (openMenu) { const m = openMenu; m.close(); if (m.anchor === anchor) return; }
  const el = h('div.menu', { role: 'menu' });
  items.filter(Boolean).forEach(it => {
    if (it === '-') { el.append(h('hr')); return; }
    const b = h('button' + (it.danger ? '.danger' : ''), { type: 'button', role: 'menuitem' }, it.icon ? ico(it.icon) : null, h('span', it.label), it.value ? h('span.m-v', it.value) : null);
    b.addEventListener('click', () => { api.close(); it.run && it.run(); });
    el.append(b);
  });
  layer().append(el);
  const r = anchor.getBoundingClientRect(), mw = el.offsetWidth, mh = el.offsetHeight;
  let x = align === 'end' ? r.right - mw : r.left, y = r.bottom + 8;
  x = clamp(x, 12, innerWidth - mw - 12);
  if (y + mh > innerHeight - 12) y = Math.max(12, r.top - mh - 8);
  el.style.left = x + 'px';
  el.style.top = y + 'px';
  el.style.transformOrigin = `${clamp(r.left + r.width / 2 - x, 0, mw)}px ${r.top > y ? mh : 0}px`;
  anim(el, [{ opacity: 0, transform: 'scale(.55)' }, { opacity: 1, transform: 'none' }], { duration: 340, easing: E.scene });
  [...el.children].forEach((c, i) => anim(c, [{ opacity: 0, transform: 'translateY(-6px)' }, { opacity: 1, transform: 'none' }], { duration: 300, delay: 40 + i * 28, easing: E.out, fill: 'backwards' }));
  anchor.setAttribute('aria-expanded', 'true');
  const btns = () => $$('button', el);
  const onKey = e => {
    if (e.key === 'Escape') { api.close(); anchor.focus(); e.stopPropagation(); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const l = btns(); let i = l.indexOf(document.activeElement);
      i = (i + (e.key === 'ArrowDown' ? 1 : -1) + l.length) % l.length; l[i].focus(); e.preventDefault();
    }
    if (e.key === 'Tab') api.close();
  };
  const onDown = e => { if (!el.contains(e.target) && !anchor.contains(e.target)) api.close(); };
  document.addEventListener('keydown', onKey, true);
  setTimeout(() => document.addEventListener('pointerdown', onDown, true));
  const api = {
    anchor,
    close() {
      if (openMenu !== api) return;
      openMenu = null;
      anchor.setAttribute('aria-expanded', 'false');
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('pointerdown', onDown, true);
      anim(el, [{ opacity: 1 }, { opacity: 0, transform: 'scale(.92)' }], { duration: 160, easing: E.out, fill: 'forwards' }).then(() => el.remove());
    },
  };
  openMenu = api;
  requestAnimationFrame(() => btns()[0] && btns()[0].focus({ preventScroll: true }));
  return api;
}

/* Tilt card toward the pointer with a moving glare (card3d: ±14° / ±18°) */
function card3d(el, max = [14, 18]) {
  if (!el.querySelector(':scope > .glare')) el.append(h('i.glare', { 'aria-hidden': 'true' }));
  const rx = new Spring(0, 170, 0.75), ry = new Spring(0, 170, 0.75);
  let run = null;
  const render = () => { el.style.transform = `perspective(800px) rotateX(${rx.x}deg) rotateY(${ry.x}deg)`; };
  const go = () => { if (!run || !run.live) run = runSprings([rx, ry], render); };
  el.addEventListener('pointermove', e => {
    if (reduced || e.pointerType === 'touch') return;
    const r = el.getBoundingClientRect(), nx = (e.clientX - r.left) / r.width, ny = (e.clientY - r.top) / r.height;
    rx.to = (0.5 - ny) * 2 * max[0] * 0.5; ry.to = (nx - 0.5) * 2 * max[1] * 0.5;
    el.style.setProperty('--gx', nx * 100 + '%'); el.style.setProperty('--gy', ny * 100 + '%');
    go();
  });
  el.addEventListener('pointerleave', () => { rx.to = 0; ry.to = 0; go(); });
}

// ── time ─────────────────────────────────────────────────
const pad = (n, l = 2) => String(n).padStart(l, '0');
const hm = d => pad(d.getHours()) + ':' + pad(d.getMinutes());
const stamp = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
function dayLabel(d) {
  const now = new Date(), a = new Date(now.getFullYear(), now.getMonth(), now.getDate()), b = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diff = Math.round((a - b) / 864e5);
  if (diff === 0) return t('date.today');
  if (diff === 1) return t('date.yesterday');
  return d.toLocaleDateString(LANG === 'en' ? 'en-GB' : 'ru-RU', { day: 'numeric', month: 'long' });
}

// ── storage: only per-viewer conveniences (language, particles) ──
const store = {
  get(k, d) { try { const v = localStorage.getItem('aegis.' + k); return v == null ? d : v; } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem('aegis.' + k, v); } catch (e) { /* private mode */ } },
};

// ── clipboard: inside a click handler, with a select-text fallback ──
async function copyText(text, fallbackEl) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) {
    if (fallbackEl) {
      const r = document.createRange(); r.selectNodeContents(fallbackEl);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
    }
    return false;
  }
}
