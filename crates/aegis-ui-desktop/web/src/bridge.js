'use strict';
/* Connects the sign-in screens to the engine. The page only shows what the engine
   reports (signed in or not, busy, the last message) and sends the same commands as
   the old forms; nothing is checked or stored here. */
const ENTRY = document.getElementById('entry');
const ENV = { tab: 'create', wait: null, cur: null, leave: null };
let entryOn = false, booted = false, lastFlash = '';

function send(cmd, args) {
  window.ipc.postMessage(JSON.stringify({ cmd, args: args || {} }));
}

ENTRY.insertAdjacentHTML('beforeend', __SPRITE__);

// ENV.leave: the gate is done, the messenger shows through as the entry fades out
ENV.leave = () => {
  if (!entryOn) return;
  if (S.acct) { AegisScene.rest(700); go('main', { tr: 'zoom' }); return; }
  entryOn = false;
  ENV.wait = null;
  AegisScene.rest(700);
  anim(ENTRY, [{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'scale(1.04)' }], { duration: reduced ? 1 : 520, easing: E.scene, fill: 'forwards' })
    .then(() => {
      if (entryOn) return;
      ENTRY.hidden = true;
      ENTRY.getAnimations().forEach(a => a.cancel());
      if (curScr) { curScr._off && curScr._off(); curScr.remove(); curScr = null; scrName = ''; }
    });
};

const SCREENS = { splash: () => scrSplash(), onb: () => scrOnb(), auth: o => scrAuth(o), gate: o => scrGate(o), main: o => scrMain(o) };
let curScr = null, scrName = '';
function go(name, o = {}) {
  const app = $('#app');
  const prev = curScr;
  const next = SCREENS[name](o);
  next.classList.add('scr');
  next.dataset.scr = name;
  curScr = next; scrName = name;
  if (prev) { prev._off && prev._off(); prev.inert = true; }
  app.append(next);
  const tr = prev ? o.tr || 'fade' : 'none';
  const D = { duration: 560, easing: E.scene, fill: 'both' };
  let out = Promise.resolve();
  if (tr === 'push' || tr === 'back') {
    const s = tr === 'push' ? 1 : -1;
    anim(next, [{ transform: `translateX(${s * 100}%)` }, { transform: 'none' }], D);
    out = anim(prev, [{ transform: 'none', opacity: 1 }, { transform: `translateX(${-s * 24}%)`, opacity: 0.3 }], D);
  } else if (tr === 'zoom') {
    anim(next, [{ transform: 'scale(.94)', opacity: 0 }, { transform: 'none', opacity: 1 }], { ...D, duration: 700 });
    out = anim(prev, [{ transform: 'none', opacity: 1 }, { transform: 'scale(1.06)', opacity: 0 }], { ...D, duration: 500 });
  } else if (tr === 'fade') {
    anim(next, [{ opacity: 0 }, { opacity: 1 }], { duration: 420, easing: E.out, fill: 'both' });
    out = anim(prev, [{ opacity: 1 }, { opacity: 0 }], { duration: 300, easing: E.out, fill: 'both' });
  }
  next._enter && next._enter();
  if (prev) out.then(() => prev.remove());
}

function entryUpdate(s) {
  if (s.lang && s.lang !== LANG) {
    LANG = s.lang === 'en' ? 'en' : 'ru';
    try { localStorage.setItem('aegis.lang', LANG); } catch (e) { /* private mode */ }
    if (entryOn && scrName === 'auth' && !ENV.wait) go('auth', { tr: 'none', tab: ENV.cur ? ENV.cur() : ENV.tab });
  }
  ENV.tab = s.tab || ENV.tab;
  if (s.authed && s.m) {
    const sh = document.getElementById('shell');
    if (sh) sh.hidden = true;
    eng.update(s);
    if (!entryOn) { entryOn = true; booted = true; ENTRY.hidden = false; ENTRY.getAnimations().forEach(a => a.cancel()); go('main', { tr: 'fade' }); return; }
    if (scrName === 'main') return;
    lastFlash = s.flash ? JSON.stringify(s.flash) : '';
  } else if (scrName === 'main') {
    S.acct = null; eng.m = null; lookApply(null);
    $$('.scrim, .sheet, .menu', ENTRY).forEach(x => x.remove());
    go('auth', { tr: 'fade' });
  }
  const f = s.flash;
  const fk = f ? JSON.stringify(f) : '';
  if (fk !== lastFlash) {
    lastFlash = fk;
    if (f && !s.authed && entryOn) {
      const w = ENV.wait;
      ENV.wait = null;
      if (!f.ok && w) w.fail(f.text); else flash(f.text, f.ok ? 'ok' : 'err');
      send('dismiss_flash');
    }
  }
  if (!s.authed) {
    if (!entryOn) {
      entryOn = true;
      ENTRY.hidden = false;
      ENTRY.getAnimations().forEach(a => a.cancel());
      document.documentElement.lang = LANG;
      go(booted ? 'auth' : 'splash', { tr: 'fade' });
      booted = true;
    }
    return;
  }
  booted = true;
  if (!entryOn) return;
  const w = ENV.wait;
  ENV.wait = null;
  if (scrName === 'gate' && w && w.ok) w.ok();
  else if (scrName === 'auth') go('gate', { acct: { username: (w && w.user) || '' }, tr: 'push' });
  else ENV.leave();
}

window.aegisEntry = { update: entryUpdate };
