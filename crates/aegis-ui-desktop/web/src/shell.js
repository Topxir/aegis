'use strict';
/* The engine behind the prototype screens: the model it reports becomes S.acct, commands go
   out through send(), and the look (theme, wallpaper, screen effects) lands on #entry. */
let VERSION = '';
const DEFAULT_SERVER = '', DEFAULT_ONION = '';
const USER_RE = /^[a-z0-9_]{3,24}$/;
const S = {
  acct: null, look: null, tor: { state: 'off', p: 0 },
  set: { idle: 10, lock: true, lockMin: false, protect: true, hidden: false, notify: true, notifyName: false, taskbar: true, tor: true, bridges: 'off', bridgeLines: '', cover: 1, autoUpd: true, server: '', socks: '' },
};
const bus = {
  m: new Map(),
  on(ev, f) { if (!this.m.has(ev)) this.m.set(ev, new Set()); this.m.get(ev).add(f); return () => this.m.get(ev).delete(f); },
  emit(ev, d) { (this.m.get(ev) || []).forEach(f => f(d)); },
};
const lag = (a = 450, b = 900) => sleep(reduced ? 120 : a + Math.random() * (b - a));
let idleTimer = 0, pingAt = 0;
function idleReset() {
  const n = Date.now();
  if (S.acct && n - pingAt > 5000) { pingAt = n; send('ping'); }
}
['pointerdown', 'keydown', 'wheel'].forEach(ev => addEventListener(ev, idleReset, { passive: true, capture: true }));
function lockNow() { send('lock'); }

const unhex = s => new Uint8Array((String(s || '').match(/../g) || []).map(x => parseInt(x, 16)));

// ── jobs: a command, then the flash or the model says how it went ──
const eng = {
  m: null, waits: new Set(),
  until(f, ms = 20000, job = false) {
    return new Promise((res, rej) => {
      const w = { f, job, res, rej };
      w.t = setTimeout(() => { eng.waits.delete(w); rej({ key: 'err.network' }); }, ms);
      eng.waits.add(w);
    });
  },
  job(cmd, args, until, ms = 20000) {
    const p = eng.until(until || null, ms, true);
    send(cmd, args);
    return p;
  },
  done(w, ok, v) { clearTimeout(w.t); eng.waits.delete(w); (ok ? w.res : w.rej)(v); },
  err: e => (e && e.text) || t((e && e.key) || 'err.network'),
  nav(id, force) {
    if (!id || (!force && eng.m && eng.m.route === id)) return;
    const i = id.indexOf(':');
    send('nav', { to: id.slice(0, i), id: id.slice(i + 1) });
    if (eng.m) eng.m.route = id;
  },
  async lookup(u) {
    if (!mnContact(u)) await eng.job('add_contact', { username: u }, () => !!mnContact(u), 60000);
    return mnAddContact(mnContact(u));
  },
  async created(kind, cmd, args) {
    const before = new Set(S.acct.chats.map(c => c.id));
    const find = () => S.acct && S.acct.chats.find(c => (c.kind === kind || (kind === 'channel' && c.kind === 'official')) && !before.has(c.id));
    await eng.job(cmd, args, () => !!find(), 60000);
    return find() || eng.until(() => !!find(), 8000).then(find);
  },
  verify(c) { eng.nav(c.id || 'dm:' + c.username, true); send('verify', { on: true }); },
  update(s) {
    const m = s.m;
    if (m) { eng.m = m; mnSync(m); }
    const f = s.flash, fk = f ? JSON.stringify(f) : '';
    if (fk !== eng.lastFlash) {
      eng.lastFlash = fk;
      if (f) {
        const w = [...eng.waits].find(x => x.job);
        if (w) eng.done(w, f.ok, { text: f.text, key: f.ok ? null : 'err.network' });
        else flash(f.text, f.ok ? 'ok' : 'err');
        send('dismiss_flash');
      }
    }
    if (m) for (const w of [...eng.waits]) if (w.f) { let ok = false; try { ok = w.f(m); } catch (e) { /* stale */ } if (ok) eng.done(w, true, m); }
    if (s.look !== undefined) lookApply(s.look);
  },
};

// ── the model → the shapes the screens draw ──
const shKeys = new Map();
const shKey = x => { if (!shKeys.has(x)) shKeys.set(x, unhex(x)); return shKeys.get(x); };
function shMsg(o) {
  return {
    id: o.id, out: o.out, from: o.from, at: new Date(o.ts), ttl: o.ttl, exp: o.exp, state: o.state,
    text: o.sys || o.text || '', sys: !!o.sys,
    media: o.media ? [{ type: o.media.video ? 'video' : 'photo', url: o.media.url, w: o.media.w, h: o.media.h, dur: o.media.dur }] : [],
  };
}
function mnSync(m) {
  VERSION = m.version || VERSION;
  const was = S.acct;
  const a = was && was.username === m.me.u ? was : { username: m.me.u, chats: [], contacts: [] };
  Object.assign(a, { display: m.me.display, about: m.me.about, particles: m.me.particles, keys: { ed: shKey(m.me.ed), x: shKey(m.me.x) }, fp: m.me.fp, pin: m.pin || null, duress: m.duress || null });
  S.acct = a;
  Object.assign(S.set, m.set, { notify: m.set.taskbar });
  if (S.tor.state !== m.tor.state || S.tor.p !== m.tor.p) { S.tor = { ...m.tor }; bus.emit('tor', S.tor); }

  const ks = new Map(a.contacts.map(k => [k.username, k]));
  a.contacts = m.contacts.map(o => Object.assign(ks.get(o.u) || {}, { username: o.u, display: o.name === o.u ? '' : o.name, keys: { ed: shKey(o.ed), x: shKey(o.x) }, verified: o.verified, sn: o.sn, fp: o.fp, about: o.about, changed: o.changed }));

  const old = new Map(a.chats.map(c => [c.id, c]));
  const v = mn && mn.cv;
  const chats = m.chats.map(o => {
    const c = old.get(o.id) || { id: o.id, msgs: [] };
    old.delete(o.id);
    Object.assign(c, {
      kind: o.kind, peer: o.peer, title: o.title || '', owner: o.owner, about: o.about || '', mine: o.mine, warn: o.warn,
      members: [...(o.members || [])], subs: [...(o.subs || [])],
      pinned: o.pinned, muted: o.muted, ttl: o.ttl, unread: mn && mn.chat === o.id ? 0 : o.unread, at: new Date(o.last || 0),
    });
    const next = o.msgs.map(shMsg);
    if (v && v.c === c && o.full) shOpen(v, c, next);
    else if (o.full) { c.msgs = next; c.full = true; }
    else { const l = next[next.length - 1]; if (!l) c.msgs = []; else if (!c.msgs.length || c.msgs[c.msgs.length - 1].id !== l.id) c.msgs = [l]; c.full = false; }
    return c;
  });
  // a contact's chat with nothing in it yet stays while it is open
  for (const c of old.values()) if (c.kind === 'dm' && !c.msgs.some(x => !x.local) && mnContact(c.peer) && mn && mn.chat === c.id) chats.push(c);
  a.chats = chats;
  if (!was || was !== a) return;
  if (mn) {
    if (mn.chat && !mnChat(mn.chat)) { mn.chat = null; mnStage(mnEmpty()); mnDepth(0); }
    mnRenderList();
  }
}
/* the open chat: new messages fade in, sent ones take the place of their local copy,
   removed ones burn; the rest keep their nodes */
function shOpen(v, c, next) {
  if (!c.full) { c.msgs = next; c.full = true; mnFill(v); v.scroll.scrollTop = v.scroll.scrollHeight; return; }
  const have = new Map(c.msgs.filter(x => !x.local).map(x => [x.id, x]));
  const pend = c.msgs.filter(x => x.local);
  const nearEnd = v.scroll.scrollHeight - v.scroll.scrollTop - v.scroll.clientHeight < 80;
  const out = [];
  let added = false;
  for (const n of next) {
    let x = have.get(n.id);
    if (x) {
      have.delete(n.id);
      const st = x.state;
      Object.assign(x, n);
      if (st !== n.state) mnSetState(v, x);
    } else {
      const i = n.out ? pend.findIndex(p => p.text === n.text) : -1;
      if (i >= 0) {
        x = pend.splice(i, 1)[0];
        const node = v.nodes.get(x.id);
        v.nodes.delete(x.id);
        Object.assign(x, n, { local: false });
        if (node) { node.dataset.id = x.id; v.nodes.set(x.id, node); mnSetState(v, x); }
      } else {
        x = n;
        out.push(x); c.msgs = [...out];
        mnDayFor(v, x);
        const node = mnMsgNode(v, x);
        v.list.append(node);
        if (!reduced) anim(node, [{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
        added = true;
        continue;
      }
    }
    out.push(x);
  }
  for (const x of have.values()) if (mn.burn) mn.burn(x);
  c.msgs = [...out, ...pend];
  mnRuns(v);
  if (added && nearEnd) v.scroll.scrollTo({ top: v.scroll.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
}

// ── look: theme colors, wallpaper and screen effects ──
function lookStops(a, n) { const o = []; for (let i = 0; i < n; i++) o.push(a[Math.min(i, a.length - 1)]); return o; }
function lookApply(k) {
  S.look = k || null;
  const app = $('#app'), st = ENTRY.style;
  if (!k) { ['wall', 'wscope'].forEach(x => delete app.dataset[x]); fxSet('none', 'chat'); return; }
  const g = lookStops(k.bubble || ['#232328'], 3), ac = lookStops(k.accent || ['#c4302b'], 3);
  st.setProperty('--look-g', `linear-gradient(135deg, ${g.join(', ')})`);
  st.setProperty('--look-a', `linear-gradient(135deg, ${ac.join(', ')})`);
  st.setProperty('--look-a1', ac[0]);
  st.setProperty('--look-ink', k.ink || '#eeeef1');
  st.setProperty('--dim', String((k.dim || 0) / 100));
  if (k.photo) st.setProperty('--wall-img', `url("${k.photo}")`); else st.removeProperty('--wall-img');
  app.dataset.wall = k.photo || k.wall !== 'photo' ? k.wall : 'none';
  app.dataset.wscope = k.wall_scope || 'chat';
  app.dataset.theme = k.theme || 'mono';
  fxSet(reduced || k.motion === 'off' ? 'none' : k.fx || 'none', k.fx_scope || 'chat');
  bus.emit('look', k);
}
const fx = { kind: 'none', scope: 'chat', cv: null, ps: [], raf: 0, w: 0, h: 0, last: 0 };
function fxSet(kind, scope) {
  if (kind === fx.kind && scope === fx.scope) return;
  fx.kind = kind; fx.scope = scope; fx.ps = [];
  if (kind === 'none') { if (fx.cv) fx.cv.hidden = true; cancelAnimationFrame(fx.raf); fx.raf = 0; return; }
  if (!fx.cv) { fx.cv = h('canvas.fx-cv', { 'aria-hidden': 'true' }); ENTRY.append(fx.cv); }
  if (!fx.raf) { fx.last = 0; fx.raf = requestAnimationFrame(fxFrame); }
}
function fxSpawn(top) {
  const w = fx.w, ht = fx.h, k = fx.kind, R = Math.random;
  const p = { x: R() * w, y: top ? -10 : R() * ht, a: R() * 6.28 };
  if (k === 'rain') { p.v = 520 + R() * 380; p.l = 10 + R() * 14; p.o = 0.18 + R() * 0.25; }
  else if (k === 'snow') { p.v = 28 + R() * 44; p.r = 0.8 + R() * 2.2; p.o = 0.35 + R() * 0.5; }
  else if (k === 'dust') { p.v = 4 + R() * 10; p.r = 0.5 + R() * 1.3; p.o = 0.12 + R() * 0.3; p.dx = (R() - 0.5) * 10; }
  else if (k === 'embers') { if (top) p.y = ht + 10; p.v = -(24 + R() * 50); p.r = 0.7 + R() * 1.6; p.o = 0.4 + R() * 0.5; }
  else { p.v = 0; p.r = 0.4 + R() * 1.2; p.o = 0.2 + R() * 0.6; p.tw = 0.6 + R() * 2; }
  return p;
}
const FX_DENS = { rain: 5200, snow: 7000, dust: 9000, embers: 16000, stars: 5000 };
function fxFrame(now) {
  fx.raf = 0;
  if (fx.kind === 'none') return;
  fx.raf = requestAnimationFrame(fxFrame);
  const cv = fx.cv;
  if (document.hidden || ENTRY.hidden || scrName !== 'main') { cv.hidden = true; fx.last = 0; return; }
  let x0 = 0, y0 = 0, w = innerWidth, ht = innerHeight;
  if (fx.scope === 'chat') {
    const b = mn && mn.cv && mn.cv.scroll.getBoundingClientRect();
    if (!b || b.width < 2) { cv.hidden = true; return; }
    const pane = mn.cv.scroll.parentElement, hd = pane.querySelector('.ch-head'), cp = pane.querySelector('.ch-comp');
    const top = hd ? Math.max(b.top, hd.getBoundingClientRect().bottom) : b.top;
    const bot = cp ? Math.min(b.bottom, cp.getBoundingClientRect().top) : b.bottom;
    x0 = b.left; y0 = top; w = b.width; ht = Math.max(2, bot - top);
  }
  cv.hidden = false;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  if (fx.w !== w || fx.h !== ht || cv.width !== Math.round(w * dpr)) {
    fx.w = w; fx.h = ht;
    cv.width = Math.round(w * dpr); cv.height = Math.round(ht * dpr);
    cv.style.width = w + 'px'; cv.style.height = ht + 'px';
  }
  cv.style.transform = `translate(${x0}px,${y0}px)`;
  const dt = fx.last ? Math.min((now - fx.last) / 1000, 0.05) : 0;
  fx.last = now;
  const want = Math.min(420, Math.round(w * ht / (FX_DENS[fx.kind] || 8000)));
  while (fx.ps.length < want) fx.ps.push(fxSpawn(false));
  if (fx.ps.length > want) fx.ps.length = want;
  const c = cv.getContext('2d'), k = fx.kind;
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  c.clearRect(0, 0, w, ht);
  for (let i = 0; i < fx.ps.length; i++) {
    const p = fx.ps[i];
    p.a += dt;
    if (k === 'rain') {
      p.y += p.v * dt; p.x -= p.v * dt * 0.12;
      c.strokeStyle = `rgba(190,205,230,${p.o})`; c.lineWidth = 1;
      c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x + p.l * 0.12, p.y - p.l); c.stroke();
    } else if (k === 'stars') {
      c.fillStyle = `rgba(235,238,255,${p.o * (0.55 + 0.45 * Math.sin(p.a * p.tw))})`;
      c.fillRect(p.x, p.y, p.r * 1.6, p.r * 1.6);
      continue;
    } else {
      p.y += p.v * dt;
      p.x += (k === 'snow' ? Math.sin(p.a) * 18 : k === 'dust' ? p.dx : Math.sin(p.a * 2) * 12) * dt;
      c.fillStyle = k === 'embers' ? `rgba(255,120,60,${p.o})` : `rgba(230,232,240,${p.o})`;
      c.beginPath(); c.arc(p.x, p.y, p.r, 0, 6.283); c.fill();
    }
    if (p.y > ht + 20 || p.y < -30 || p.x < -30 || p.x > w + 30) fx.ps[i] = fxSpawn(true);
  }
}
