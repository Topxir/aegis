'use strict';
/* Entry: splash, onboarding, auth, gate, PIN setup, lock.
   One "wow" per screen: splash = shield assembles, onb = object morph, auth = the card turns over,
   gate = the shield folds into the cube (creating or signing in), PIN = dots, lock = the lid closes. */

// ── shared helpers ───────────────────────────────────────
function enTimers() {
  const ids = new Set();
  return {
    after(ms, f) { const id = setTimeout(() => { ids.delete(id); f(); }, reduced ? 0 : ms); ids.add(id); return id; },
    clear() { ids.forEach(clearTimeout); ids.clear(); },
  };
}
function enLayout(cls, obj, kids) {
  return h('div.e' + cls, h('div.art', obj), h('div.pane', h('div.col', kids)));
}
function enLid(el) {
  if (reduced || !el) return Promise.resolve();
  const line = h('div.lidline', { 'aria-hidden': 'true' });
  ENTRY.append(line);
  anim(line, [{ transform: 'scaleX(0)', opacity: 0 }, { transform: 'scaleX(1)', opacity: 1, offset: 0.7 }, { transform: 'scaleX(1)', opacity: 0 }],
    { duration: 1200, easing: E.soft }).then(() => line.remove());
  return anim(el, [{ transform: 'none', filter: 'brightness(1)' }, { transform: 'scaleY(.004)', filter: 'brightness(2.2)' }],
    { duration: 900, easing: E.soft, fill: 'forwards' });
}
function enPinDots(n) {
  const el = h('div.pin', { 'aria-hidden': 'true' });
  el.size = k => { n = k; el.replaceChildren(...Array.from({ length: n }, () => h('i'))); };
  el.fill = k => [...el.children].forEach((d, i) => d.classList.toggle('on', i < k));
  el.state = s => { el.classList.remove('err', 'ok'); if (s) el.classList.add(s); if (s === 'err') shake(el); };
  el.size(n);
  return el;
}
/* Keypad: digits, a function key on the left, backspace on the right. */
function enKeypad(onKey, fn) {
  const key = (v, label) => h('button.key', { type: 'button', 'data-k': v, 'aria-label': label || null }, v);
  const pad = h('div.keypad', [1, 2, 3, 4, 5, 6, 7, 8, 9].map(d => key(String(d))),
    fn ? h('button.key.fn', { type: 'button', 'data-k': 'fn' }, fn) : h('span'),
    key('0'),
    h('button.key.fn', { type: 'button', 'data-k': 'del', 'aria-label': t('d.erase') }, ico('backspace')));
  pad.addEventListener('click', e => { const b = e.target.closest('button'); if (b) onKey(b.dataset.k); });
  const kb = e => {
    if ((e.target.closest && e.target.closest('input, textarea')) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (/^[0-9]$/.test(e.key)) { onKey(e.key); enPress(pad, e.key); }
    else if (e.key === 'Backspace') { onKey('del'); enPress(pad, 'del'); }
  };
  pad.listen = () => document.addEventListener('keydown', kb);
  pad.unlisten = () => document.removeEventListener('keydown', kb);
  return pad;
}
function enPress(pad, k) {
  const b = pad.querySelector(`[data-k="${k}"]`);
  if (b) anim(b, [{ transform: 'scale(.9)' }, { transform: 'none' }], { duration: 220, easing: E.out });
}
const enErr = e => (e && e.key) || 'err.network';

// ── splash ───────────────────────────────────────────────
function scrSplash() {
  const T = enTimers();
  const obj = h('div.obj3d');
  const word = h('div.sp-word', { role: 'img', 'aria-label': 'Aegis' }, [...'AEGIS'].map(c => h('span', { 'aria-hidden': 'true' }, c)));
  const bar = h('i');
  const a = h('span'), b = h('b');
  const line = h('p.sp-line.t-hud', a, ' ', b);
  const el = h('div.splash', { role: 'button', tabindex: '0', 'aria-label': t('guide.next') }, obj, word, h('div.sp-bar', { 'aria-hidden': 'true' }, bar), line);
  let left = false;
  const leave = () => {
    if (left) return;
    left = true;
    go(ENV.tab === 'unlock' ? 'auth' : 'onb', { tr: 'zoom' });
  };
  el.addEventListener('click', leave);
  el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); leave(); } });
  el._enter = () => {
    AegisScene.show('shield', obj, { assemble: true });
    [...word.children].forEach((s, i) => anim(s,
      [{ transform: 'translateY(.35em) rotateX(-80deg)', opacity: 0 }, { transform: 'none', opacity: 1 }],
      { duration: 760, delay: 260 + i * 70, easing: E.back, fill: 'backwards' }));
    anim(bar, [{ transform: 'scaleX(0)' }, { transform: 'scaleX(1)' }], { duration: 1700, delay: 300, easing: E.soft, fill: 'forwards' });
    T.after(500, () => decode(a, t('d.splash_a'), 800).then(() => decode(b, t('d.splash_b'), 800)));
    T.after(3200, leave);
  };
  el._off = () => T.clear();
  return el;
}

// ── onboarding: 3 slides, the object morphs shield → rings → ash ──
function scrOnb() {
  const OBJ = ['shield', 'rings', 'ash'];
  const DATA = [['d.onb1', 'auth.pwnote'], ['d.onb2', 'contact.safety_note'], ['d.onb3', 'conn.cover_note']];
  const obj = h('div.obj3d');
  const slides = h('div.onb-slides', DATA.map(([a, b], i) => h('article', { 'aria-roledescription': 'slide', 'aria-label': `${i + 1} / 3` },
    h('p.onb-n.t-hud', h('b', pad(i + 1)), ' / 03'),
    h('h1.e-title', t(a)),
    h('p.e-sub', t(b)))));
  const track = h('div.onb-track', slides);
  const dots = h('div.dots', { 'aria-hidden': 'true' }, DATA.map(() => h('i')));
  const next = h('button.btn', { type: 'button', 'data-autofocus': '' });
  const skip = h('button.btn.ghost.sm', { type: 'button' }, t('guide.skip'));
  const el = enLayout('.onb', obj, [
    h('div.e-top', h('span.e-word', 'Aegis'), skip),
    track,
    h('div.onb-foot', dots, next),
  ]);
  let i = -1;
  const set = k => {
    k = clamp(k, 0, 2);
    if (k === i) return;
    const first = i < 0;
    i = k;
    slides.style.transform = `translateX(${-i * 100 / 3}%)`;
    [...slides.children].forEach((s, j) => { s.inert = j !== i; });
    [...dots.children].forEach((d, j) => d.classList.toggle('on', j === i));
    next.textContent = i === 2 ? t('d.start') : t('guide.next');
    if (!first) { AegisScene.show(OBJ[i], obj, { morph: true }); announce(t(DATA[i][0])); }
  };
  const done = () => go('auth', { tr: 'push', tab: 'create' });
  next.addEventListener('click', () => (i === 2 ? done() : set(i + 1)));
  skip.addEventListener('click', done);
  // swipe
  let x0 = null;
  track.addEventListener('pointerdown', e => { x0 = e.clientX; });
  track.addEventListener('pointerup', e => {
    if (x0 == null) return;
    const dx = e.clientX - x0; x0 = null;
    if (Math.abs(dx) > 40) set(i + (dx < 0 ? 1 : -1));
  });
  const kb = e => {
    if (e.key === 'ArrowRight') set(i + 1);
    else if (e.key === 'ArrowLeft') set(i - 1);
  };
  set(0);
  el._enter = () => { AegisScene.show(OBJ[0], obj, { morph: true }); document.addEventListener('keydown', kb); };
  el._off = () => document.removeEventListener('keydown', kb);
  return el;
}

// ── auth: one card, three faces. All faces share one grid cell, so the card is as tall
//    as the tallest face (create) and keeps its size when it turns over. ──
const enFlip = springCurve(90, 0.74);
function scrAuth(o = {}) {
  const obj = h('div.obj3d');
  const copy = h('div.au-copy',
    h('span.eyebrow', t('auth.eyebrow')),
    h('h1', t('auth.headline')),
    h('p', t('auth.tagline')),
    h('div.au-chips', ['auth.chip1', 'auth.chip2', 'auth.chip3'].map(k => h('span', t(k)))),
    h('span.au-foot.t-small', t('auth.foot')));
  const TABS = ['unlock', 'create', 'import'];
  const ids = Object.fromEntries(TABS.map(v => [v, uid('au')]));
  const tabs = h('div.seg.tabs', { role: 'tablist' },
    TABS.map(v => h('button', { type: 'button', 'data-v': v, id: ids[v] + 't', 'aria-controls': ids[v] }, t({ unlock: 'auth.tab_unlock', create: 'auth.tab_create', import: 'auth.tab_import' }[v]))));

  const F = {
    // as in 0.2.5: usernames in mono, and the unlock field takes the password or the PIN
    unlock: { user: field({ label: t('f.username'), auto: 'username', name: 'username', mono: true }), pass: field({ label: t('f.secret'), type: 'password', auto: 'current-password' }) },
    create: {
      user: field({ label: t('f.username_new'), auto: 'username', hardMax: 24, mono: true }),
      display: field({ label: t('f.display'), max: 64 }),
      pass: field({ label: t('f.password_new'), type: 'password', auto: 'new-password' }),
      confirm: field({ label: t('f.confirm'), type: 'password', auto: 'new-password' }),
    },
    import: { path: field({ label: t('f.vault_path'), mono: true }), pass: field({ label: t('f.password'), type: 'password', auto: 'current-password' }) },
  };
  // above the button on every face: the password note (0.2.5 shows it under all three tabs),
  // replaced in the same place by the first field error or the progress (the card does not grow)
  const slot = () => {
    const msg = h('p.au-msg', { 'aria-hidden': 'true' });
    const box = h('div.au-say', h('p.au-note', t('auth.pwnote')), msg);
    box.msg = msg;
    return box;
  };
  const say = { unlock: slot(), create: slot(), import: slot() };
  const sync = v => {
    const bad = Object.values(F[v]).find(b => b.wrap.classList.contains('err'));
    if (bad) say[v].msg.textContent = bad.msg.textContent;
    say[v].classList.toggle('bad', !!bad);
  };
  const submit = label => h('button.btn.wide.au-go', { type: 'submit' }, label);
  const face = (v, kids) => h('form.au-face', { id: ids[v], role: 'tabpanel', 'aria-labelledby': ids[v] + 't', novalidate: true }, kids);
  const forms = {
    unlock: face('unlock', [F.unlock.user, F.unlock.pass, say.unlock, submit(t('auth.unlock'))]),
    create: face('create', [F.create.user, F.create.display, F.create.pass, F.create.confirm, say.create, submit(t('auth.create'))]),
    import: face('import', [F.import.path, F.import.pass, h('p.au-hint', t('auth.import_note')), say.import, submit(t('auth.import'))]),
  };
  TABS.forEach(v => forms[v].addEventListener('input', () => sync(v)));

  // the turn: the card sinks a little, rotates half a turn on a spring and comes back up;
  // the leaving face goes into shade, the arriving one comes out of it
  const card = h('div.au-card', h('div.au-flip', TABS.map(v => forms[v])));
  const flipper = card.firstChild;
  let cur = o.tab || (ENV.tab === 'unlock' ? 'unlock' : 'create');
  let rot = 0, turning = [];
  const show = (v, on) => { forms[v].style.visibility = on ? '' : 'hidden'; forms[v].inert = !on; };
  TABS.forEach(v => show(v, v === cur));
  const flip = to => {
    turning.forEach(a => a.finish());
    const from = cur, dir = TABS.indexOf(to) > TABS.indexOf(from) ? 1 : -1;
    const r0 = rot, r1 = rot + 180 * dir;
    cur = to; rot = r1;
    TABS.forEach(v => { if (v !== from && v !== to) show(v, false); });
    forms[to].style.transform = `rotateY(${-r1}deg)`;
    show(to, true);
    flipper.style.transform = `rotateY(${r1}deg)`;
    const opt = { duration: reduced ? 1 : enFlip.duration, easing: enFlip.easing };
    const a = flipper.animate([
      { transform: `translateZ(0) rotateY(${r0}deg)` },
      { transform: `translateZ(-120px) rotateY(${r0 + 90 * dir}deg)`, offset: 0.42 },
      { transform: `translateZ(0) rotateY(${r1}deg)` }], opt);
    turning = [a,
      forms[from].animate([{ filter: 'brightness(1)' }, { filter: 'brightness(.3)', offset: 0.42 }, { filter: 'brightness(.3)' }], opt),
      forms[to].animate([{ filter: 'brightness(.3)' }, { filter: 'brightness(.3)', offset: 0.42 }, { filter: 'brightness(1)' }], opt)];
    card.classList.remove('turning'); void card.offsetWidth; card.classList.add('turning');
    a.finished.catch(() => {}).then(() => {
      if (turning[0] !== a) return;
      turning = [];
      show(from, false);
      card.classList.remove('turning');
      if (isDesk()) forms[to].querySelector('input').focus({ preventScroll: true });
    });
  };
  seg(tabs, cur, flip);

  const run = (v, cmd, args, f) => {
    const btn = forms[v].querySelector('.au-go');
    busy(btn, true);
    ENV.wait = { fail(text) { busy(btn, false); f.error(text); sync(v); }, user: args.username || '' };
    send(cmd, args);
  };
  forms.unlock.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.unlock;
    if (!f.user.input.value.trim()) { f.user.error(t('err.username')); return sync('unlock'); }
    if (!f.pass.input.value) { f.pass.error(t('err.password')); return sync('unlock'); }
    run('unlock', 'unlock', { username: f.user.input.value.trim(), password: f.pass.input.value }, f.pass);
    f.pass.input.value = '';
  });
  // create: the engine checks the fields, then makes the keys and solves the puzzle on the gate
  forms.create.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.create;
    const u = f.user.input.value.trim(), d = f.display.input.value.trim();
    if (!u) { f.user.error(t('err.username')); return sync('create'); }
    if (!f.pass.input.value) { f.pass.error(t('err.password')); return sync('create'); }
    send('create', { username: u, display: d, password: f.pass.input.value, confirm: f.confirm.input.value });
    f.pass.input.value = ''; f.confirm.input.value = '';
    go('gate', { u, d, tr: 'push' });
  });
  forms.import.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.import;
    if (!f.path.input.value.trim()) { f.path.error(t('err.path')); return sync('import'); }
    run('import', 'import', { path: f.path.input.value.trim(), password: f.pass.input.value }, f.pass);
    f.pass.input.value = '';
  });
  ENV.cur = () => cur;

  // the language, as on the 0.2.5 sign-in screen; the screen is rebuilt in the new one
  const lang = h('div.seg.mono.au-lang', { 'aria-label': t('set.language') },
    ['ru', 'en'].map(v => h('button', { type: 'button', 'data-v': v }, v.toUpperCase())));
  seg(lang, LANG, v => {
    LANG = v; send('set_lang', { lang: v }); document.documentElement.lang = v;
    setTimeout(() => go('auth', { tr: 'none', tab: cur }), reduced ? 0 : 280);
  });

  const el = h('div.e.auth', { style: { '--art-h': '26vh' } }, lang,
    h('div.art', obj, copy),
    h('div.pane', h('div.col',
      h('div.au-mobile-head', h('span.eyebrow', t('auth.eyebrow')), h('h1', t('auth.headline'))),
      tabs, card)));
  // back from the gate with what was typed (the passwords are not kept)
  if (o.keep) { F.create.user.input.value = o.keep.u; F.create.display.input.value = o.keep.d; F.create.display.count(); }
  if (o.errorText && F[cur]) { const k = Object.keys(F[cur])[0]; setTimeout(() => { F[cur][k].error(o.errorText); sync(cur); }, 400); }
  el._enter = () => {
    AegisScene.show('shield', obj, { morph: true });
    if (isDesk()) setTimeout(() => forms[cur].querySelector('input').focus({ preventScroll: true }), reduced ? 0 : 450);
  };
  return el;
}

// ── gate: between the form and the app. The shield folds into the cube and the cube is
//    built from the real work: the keys, then the registration puzzle (create), or a short
//    settle after the vault opened (sign-in, import). No cancel, as in 0.2.5. ──
function scrGate(o) {
  const T = enTimers();
  const obj = h('div.obj3d');
  const making = !o.acct;
  const head = making ? t('d.gate_create') : t('d.gate_open');
  const title = h('h1.e-title', head);
  const who = h('div.gt-who', h('div.gt-id',
    h('b.mono', '@' + (making ? o.u : o.acct.username)), making && o.d ? h('span', o.d) : null));
  const fill = h('i');
  const bar = h('div.gt-bar.wait', { role: 'progressbar', 'aria-label': head }, fill);
  const step = h('span', t('busy.create'));
  let off = false;
  const done = (text, next) => {
    AegisScene.progress(1);
    AegisScene.pulse();
    decode(title, text);
    announce(text);
    T.after(1400, next);
  };
  // creating: the engine makes the keys and solves the puzzle; the cube builds while it works
  const create = () => {
    announce(t('busy.create'));
    const t0 = performance.now();
    const tick = now => {
      if (off) return;
      AegisScene.progress(0.9 * (1 - Math.exp(-(now - t0) / 9000)));
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    ENV.wait = {
      fail(text) { if (!off) go('auth', { tr: 'back', tab: 'create', errorText: text, keep: { u: o.u, d: o.d } }); },
      ok() { off = true; done(t('d.gate_done'), ENV.leave); },
    };
  };
  const open = () => {
    if (reduced) { AegisScene.progress(1); T.after(0, ENV.leave); return; }
    T.after(380, () => {
      const t0 = performance.now(), dur = 820;
      const tick = now => {
        if (off) return;
        const k = Math.min(1, (now - t0) / dur);
        AegisScene.progress(k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2);
        if (k < 1) requestAnimationFrame(tick);
        else T.after(420, () => { AegisScene.pulse(); T.after(460, ENV.leave); });
      };
      requestAnimationFrame(tick);
    });
  };

  const el = enLayout('.gate', obj, [
    h('div.e-top', h('span.e-word', 'Aegis')),
    title, who,
    making && [bar, h('div.gt-line', step)],
  ]);
  el._enter = () => {
    AegisScene.show('cube', obj, { morph: true });
    AegisScene.progress(0);
    if (making) create(); else open();
  };
  el._off = () => { off = true; T.clear(); };
  return el;
}

