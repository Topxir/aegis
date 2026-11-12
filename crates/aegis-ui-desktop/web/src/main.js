'use strict';
/* Main: list, chat, contact HUD, media, sheets.
   Everything shown comes from what the user did in this session; nothing
   arrives on its own. The only unread posts are the four of the official channel.
   Layout: under 900 px three push panes (data-depth 0/1/2); 900-1239 list + stage,
   info as an overlay; from 1240 list / stage / info in a grid. */

// limits of 0.2.5 (media.rs MAX_INPUT, mp4clean.rs MAX_VIDEO, channel.rs, newgroup.note)
const MN_MAX_TEXT = 4096, MN_MAX_GROUP = 100, MN_MAX_SUBS = 200, MN_MAX_PHOTO = 40 << 20, MN_MAX_VIDEO = 31 << 20;
const MN_TTL = [
  { v: 0, k: 'ttl.off' }, { v: 30, k: 'ttl.30s' }, { v: 300, k: 'ttl.5m' },
  { v: 3600, k: 'ttl.1h' }, { v: 86400, k: 'ttl.1d' }, { v: 604800, k: 'ttl.7d' },
];
const MN_INV_RE = /^aegis:\/\/invite\/\S+$/;
const mnInvites = new Map();   // invites created this session: link → { used }
let mn = null;                 // the mounted main screen

// ── data ─────────────────────────────────────────────────
function mnSeed() {}
const mnNet = () => !S.set.tor || S.tor.state === 'ready';
const mnChat = id => S.acct && S.acct.chats.find(c => c.id === id);
const mnContact = u => S.acct && S.acct.contacts.find(c => c.username === u);
const mnLast = c => c.msgs[c.msgs.length - 1];
const mnOwner = c => c.kind === 'channel' && c.owner === S.acct.username;
// the official channel takes posts only from the account holding the compiled-in owner key
const mnCanWrite = c => c.kind === 'dm' || c.kind === 'group' || mnOwner(c) || (c.kind === 'official' && !!c.mine);
function mnTitle(c) {
  if (c.kind !== 'dm') return c.title;
  const k = mnContact(c.peer);
  return (k && k.display) || '@' + c.peer;
}
function mnText(m) { return m.post ? t(m.post) : m.text || ''; }
function mnPreview(m) {
  if (!m) return '';
  if (m.media && m.media.length) return (m.media[0].type === 'video' ? t('media.video') : t('media.photo')) + (m.media.length > 1 ? ' ×' + m.media.length : '');
  return mnText(m).replace(/\s+/g, ' ');
}
function mnTime(d) {
  const n = new Date();
  return d.toDateString() === n.toDateString() ? hm(d) : pad(d.getDate()) + '.' + pad(d.getMonth() + 1);
}
const mnActive = c => { const m = mnLast(c); return m ? +m.at : +c.at; };
/* avatars as in render.rs: a contact's own key; groups, channels and strangers get a key
   hashed from their id. The markup is kept per key: the list redraws on every keystroke */
const mnFaces = new Map();
const mnIdKey = id => sha256(cat(enc.encode('aegis ui avatar'), enc.encode(id)));
function mnKeyOf(u) {
  const k = mnContact(u);
  return k ? k.keys.ed : u === S.acct.username ? S.acct.keys.ed : mnIdKey(u);
}
function mnFace(key, cls = '') {
  const id = hex(key);
  if (!mnFaces.has(id)) mnFaces.set(id, identicon(key));
  return h('span.av.id' + cls, { 'aria-hidden': 'true', html: mnFaces.get(id) });
}
const mnAv = (c, cls = '') => mnFace(c.kind === 'dm' ? mnKeyOf(c.peer) : mnIdKey(c.id), cls);
function mnTtlLabel(v) { const o = MN_TTL.find(x => x.v === v) || MN_TTL[0]; return t(o.k); }
function mnAddContact(k) {
  const a = S.acct;
  let c = mnContact(k.username);
  if (!c) { c = { username: k.username, display: k.display || '', keys: k.keys, verified: false, about: k.about || '' }; a.contacts.push(c); }
  let ch = a.chats.find(x => x.kind === 'dm' && x.peer === c.username);
  if (!ch) { ch = { id: 'dm:' + c.username, kind: 'dm', peer: c.username, msgs: [], ttl: 0, pinned: false, muted: false, unread: 0, at: new Date() }; a.chats.push(ch); }
  return ch;
}
/* expired disappearing messages leave the data at once; the open chat burns its own */
function mnSweep() {
  if (!S.acct) return;
  const now = Date.now();
  let gone = false;
  for (const c of S.acct.chats) {
    const keep = c.msgs.filter(m => !(m.exp && m.exp <= now));
    if (keep.length !== c.msgs.length) {
      const dead = c.msgs.filter(m => !keep.includes(m));
      c.msgs = keep; gone = true;
      if (mn && mn.chat === c.id && mn.burn) dead.forEach(m => mn.burn(m));
      dead.forEach(mnFreeMedia);
    }
  }
  if (gone && mn) mnRenderList();
}
function mnFreeMedia(m) { (m.media || []).forEach(x => { try { URL.revokeObjectURL(x.url); } catch (e) { /* already gone */ } }); }

// ── shell ────────────────────────────────────────────────
function scrMain() {
  const a = S.acct;
  mnSeed(a);
  mnSweep();
  const el = h('div.main', { 'data-depth': '0', 'data-info': '0' });
  const paneL = h('div.pane-l'), paneS = h('div.pane-s'), paneI = h('div.pane-i');
  el.append(paneL, paneS, paneI);
  mn = { el, paneL, paneS, paneI, view: 'chats', filter: 'all', q: '', chat: null, sec: null, info: false, burn: null, offs: [], timers: new Set() };

  // list column
  const roll = h('h1.roll', { 'data-v': '0', 'aria-live': 'polite' }, h('span', t('d.chats')), h('span', t('nav.settings')));
  const setB = h('button.ib.bare', { type: 'button', 'aria-label': t('nav.settings'), 'aria-pressed': 'false' }, ico('sliders'));
  const moreB = h('button.ib.bare', { type: 'button', 'aria-label': t('menu.more'), 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, ico('menu'));
  const tabs = h('div.seg.tabs', { 'aria-label': t('d.chats') },
    h('button', { type: 'button', 'data-v': 'all' }, t('tab.all')),
    h('button', { type: 'button', 'data-v': 'groups' }, t('tab.groups')),
    h('button', { type: 'button', 'data-v': 'channels' }, t('tab.channels')));
  const q = h('input', { type: 'search', placeholder: t('list.filter'), 'aria-label': t('list.filter'), autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off' });
  const qx = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close'), hidden: true }, ico('close'));
  const list = h('div.ls-list', { role: 'list' });
  const setList = h('div.ls-list');
  const ls = h('div.ls', { 'data-view': 'chats' },
    h('div.ls-head', roll, setB, moreB),
    h('div.ls-body',
      h('div.ls-view.v-chats',
        h('div.ls-tools', tabs, h('div.find', ico('search'), q, qx)),
        h('div.ls-scroll', list)),
      h('div.ls-view.v-set', { inert: true }, h('div.ls-scroll.st-scroll', setList))));
  paneL.append(ls);
  Object.assign(mn, { ls, roll, setB, list, setList, qIn: q, qx });
  mnHl(list);

  const tabSeg = seg(tabs, 'all', v => { mn.filter = v; mnRenderList(); });
  mn.tabSeg = tabSeg;
  q.addEventListener('input', () => { mn.q = q.value; qx.hidden = !q.value; mnRenderList(); });
  q.addEventListener('keydown', e => {
    if (e.key === 'Escape' && q.value) { e.stopPropagation(); q.value = ''; q.dispatchEvent(new Event('input')); }
    if (e.key === 'Enter') { const r = list.querySelector('.row'); if (r) r.click(); }
  });
  qx.addEventListener('click', () => { q.value = ''; q.dispatchEvent(new Event('input')); q.focus(); });
  setB.addEventListener('click', () => mnSetView(mn.view === 'chats' ? 'settings' : 'chats'));
  moreB.addEventListener('click', () => menu(moreB, [
    { icon: 'at', label: t('nav.new_chat'), run: () => mnNewChat() },
    { icon: 'users', label: t('nav.new_group'), run: mnNewGroup },
    { icon: 'channel', label: t('nav.new_channel'), run: mnNewChannel },
    { icon: 'user', label: t('nav.contacts'), run: mnContacts },
    { icon: 'link', label: t('inv.title'), run: mnInvite },
    '-',
    { icon: 'lock', label: t('nav.lock'), run: lockNow },
  ]));
  list.addEventListener('click', e => {
    const r = e.target.closest('.row');
    if (!r) return;
    if (r.classList.contains('lookup')) mnLookup(r.dataset.u, r);
    else mnOpenChat(r.dataset.id);
  });

  // stage + info
  paneS.append(h('div.stage'));
  paneI.append(h('div.info-host'));
  mn.stage = paneS.firstChild;

  mnTorLine();
  mnRenderList();
  mnStage(mnEmpty());

  const onResize = () => mnScene();
  const onKey = e => {
    if (e.key !== 'Escape' || e.defaultPrevented || openSheets.length || openMenu || $('.viewer')) return;
    if (mn.info) { mnCloseInfo(); return; }
    if (mn.search) { mn.search.close(); return; }
    if (!isDesk() && (mn.chat || mn.sec)) mnBack();
  };
  addEventListener('resize', onResize);
  document.addEventListener('keydown', onKey);
  const sweepId = setInterval(mnSweep, 1000);
  mn.offs.push(
    () => removeEventListener('resize', onResize),
    () => document.removeEventListener('keydown', onKey),
    () => clearInterval(sweepId),
    bus.on('tor', () => { mnTorLine(); if (mn.onTor) mn.onTor(); }),
  );

  el._enter = () => mnScene();
  el._off = () => {
    const m = mn;
    if (!m) return;
    m.offs.forEach(f => f());
    m.timers.forEach(clearTimeout);
    if (m.stage.firstChild && m.stage.firstChild._off) m.stage.firstChild._off();
    if (m.vw) m.vw.close(true);
    mn = null;
  };
  return el;
}
function mnLater(ms, f) {
  const m = mn;
  const id = setTimeout(() => { m.timers.delete(id); if (mn === m) f(); }, ms);
  m.timers.add(id);
  return id;
}

/* the 3D shield lives on the empty desktop stage only; everywhere else in the shell the
   canvas is covered by opaque panes, so the scene stops drawing */
function mnScene() {
  if (!mn || !mn.stage || !mn.list) return;
  // a view that is fading out is already inert: it no longer holds the object
  const view = mn.stage.querySelector('.view:not([inert])');
  const obj = view && view.matches('.st-empty') ? view.querySelector('.obj3d') : null;
  // the appearance section lets the scene through, so a choice of particles is seen at once
  const thru = !!view && view.dataset.sec === 'look';
  mn.paneS.classList.toggle('thru', thru);
  const lobj = !isDesk() && (mn.el.dataset.depth || '0') === '0' && mn.view === 'chats' ? $('.ls-empty .obj3d', mn.list) : null;
  mn.paneL.classList.toggle('thru', !!lobj);
  if (obj && isDesk()) AegisScene.show('shield', obj, { morph: true });
  else if (lobj) AegisScene.show('shield', lobj, { morph: true });
  else if (thru) { AegisScene.scatter(); AegisScene.show(null, null); }
  else { AegisScene.scatter(); AegisScene.rest(900); }
}

/* depth: 0 list, 1 stage, 2 info (phones); info is its own flag on desktop */
function mnDepth(d) {
  mn.el.dataset.depth = String(d);
  const desk = isDesk();
  mn.paneL.inert = !desk && d > 0;
  mn.paneS.inert = !desk && d !== 1;
  mn.paneI.inert = desk ? !mn.info : d !== 2;
  mnScene();
}
function mnBack() {
  if (mn.info) return mnCloseInfo();
  // phone: the header avatar goes back into its row while the chat slides away
  const head = mn.chat && mn.cv && !isDesk() && !reduced ? $('.ch-who .av', mn.cv.el) : null;
  const id = mn.chat, a = head && head.getBoundingClientRect();
  mn.chat = null; mn.sec = null;
  mnDepth(0);
  mnMark();
  if (head && mn.view === 'chats') {
    const av = $(`.row[data-id="${id}"] .av`, mn.list), main = mn.el.getBoundingClientRect();
    const b = av && mnRest(av, mn.paneL, main), box = av && mnRest(av.closest('.ls-scroll'), mn.paneL, main);
    if (b && b.bottom > box.top + 4 && b.top < box.bottom - 4) mnLift(head, a, b, [head, av], 560);
  }
  mnLater(reduced ? 0 : 560, () => { if (!mn.chat && !mn.sec) mnStage(mnEmpty()); });
}

/* where an element inside a sliding pane sits once the pane is at rest: panes only move and
   scale, so its offset in the pane's current box is mapped onto the resting box */
function mnRest(el, pane, rest) {
  const r = el.getBoundingClientRect(), p = pane.getBoundingClientRect(), s = p.width / rest.width || 1;
  return new DOMRect(rest.left + (r.left - p.left) / s, rest.top + (r.top - p.top) / s, r.width / s, r.height / s);
}
/* shared element: a copy of `src` flies from box a to box b above the panes; what it stands
   for stays hidden until it lands */
function mnLift(src, a, b, hide, dur) {
  const ghost = src.cloneNode(true), cs = getComputedStyle(src);
  // the copy leaves its parent, so what the parent's rules gave it travels inline
  Object.assign(ghost.style, { position: 'fixed', left: a.left + 'px', top: a.top + 'px', width: a.width + 'px', height: a.height + 'px', margin: 0, zIndex: 90, pointerEvents: 'none', transformOrigin: '0 0',
    fontSize: cs.fontSize, borderRadius: cs.borderRadius, overflow: cs.overflow, opacity: 1 });
  ghost.classList.add('lift');
  ENTRY.append(ghost);
  hide.forEach(e => { e.style.opacity = '0'; });
  return anim(ghost, [{ transform: 'none' }, { transform: `translate(${b.left - a.left}px, ${b.top - a.top}px) scale(${b.width / a.width})` }],
    { duration: dur, easing: E.scene, fill: 'forwards' }).then(() => {
    ghost.remove();
    hide.forEach(e => { e.style.opacity = ''; });
  });
}

/* stage: one view at a time; desktop crossfades, phone pushes the pane */
function mnStage(node) {
  const st = mn.stage, old = st.firstElementChild;
  node.classList.add('view');
  st.append(node);
  if (old) {
    old._off && old._off();
    old.inert = true;
    if (isDesk() && !reduced) {
      anim(node, [{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { duration: 380, delay: 120, easing: E.scene, fill: 'backwards' });
      anim(old, [{ opacity: 1 }, { opacity: 0 }], { duration: 120, easing: E.out, fill: 'forwards' }).then(() => old.remove());
    } else if (!reduced && (mn.el.dataset.depth || '0') !== '0') {
      // the old view is gone before the new one shows: the two never overlap half-transparent
      anim(node, [{ opacity: 0, transform: 'translateX(18px)' }, { opacity: 1, transform: 'none' }], { duration: 280, delay: 100, easing: E.scene, fill: 'backwards' });
      anim(old, [{ opacity: 1 }, { opacity: 0 }], { duration: 100, easing: E.out, fill: 'forwards' }).then(() => old.remove());
    } else old.remove();
  }
  mnScene();
}
function mnEmpty() {
  const obj = h('div.obj3d');
  const nc = h('button.btn.sm.ghost', { type: 'button' }, ico('at'), t('nav.new_chat'));
  const inv = h('button.btn.sm.ghost', { type: 'button' }, ico('link'), t('inv.title'));
  nc.addEventListener('click', () => mnNewChat());
  inv.addEventListener('click', mnInvite);
  return h('div.st-empty', obj, h('p', t('main.pick')), h('div.chips', nc, inv));
}

// ── list ─────────────────────────────────────────────────
function mnSetView(v) {
  mn.view = v;
  mn.ls.dataset.view = v;
  mn.roll.dataset.v = v === 'settings' ? '1' : '0';
  mn.setB.setAttribute('aria-pressed', String(v === 'settings'));
  mn.setB.replaceChildren(ico(v === 'settings' ? 'back' : 'sliders'));
  mnMorphIn(mn.setB.firstChild);
  mn.setB.setAttribute('aria-label', v === 'settings' ? t('d.chats') : t('nav.settings'));
  const [vc, vs] = $$('.ls-view', mn.ls);
  vc.inert = v !== 'chats';
  vs.inert = v !== 'settings';
  if (v === 'settings') mn.setList.replaceChildren(stList(mnApi));
  else if (mn.sec) { mn.sec = null; if (isDesk()) mnStage(mnEmpty()); else mnBack(); }
}
const mnApi = {
  open: (id, from) => mnOpenSection(id, from),
  back: () => mnBack(),
  refresh: () => { if (!mn) return; mnTorLine(); mnRenderList(); if (mn.view === 'settings') mn.setList.replaceChildren(stList(mnApi)); },
  get section() { return mn && mn.sec; },
};
function mnOpenSection(id, from) {
  if (mn.view !== 'settings') mnSetView('settings');
  const same = mn.sec === id;
  mn.sec = id; mn.chat = null;
  if (mn.info) mnCloseInfo(true);
  const node = stSection(id, mnApi);
  const a = from && !same && !reduced ? from.getBoundingClientRect() : null;
  mnStage(node);
  $$('[data-sec]', mn.setList).forEach(b => b.setAttribute('aria-current', String(b.dataset.sec === id)));
  mnDepth(1);
  // your avatar in the list flies into the face of the profile
  const face = a && $('.hud > .av', node);
  if (face) {
    const b = isDesk() ? mnRest(face, node, mn.stage.getBoundingClientRect()) : mnRest(face, mn.paneS, mn.el.getBoundingClientRect());
    mnLift(from, a, b, [face], isDesk() ? 520 : 560);
  }
}

/* while Tor boots nothing can be sent: one hairline over the whole shell says how far it is;
   it leaves once Tor is up (the status itself lives in Settings, not in chips) */
function mnTorLine() {
  if (!mn) return;
  const on = S.set.tor && S.tor.state === 'start';
  let ln = mn.torLn;
  if (!on) {
    if (ln && !ln.classList.contains('done')) { ln.classList.add('done'); mnLater(reduced ? 0 : 700, () => { if (mn && mn.torLn === ln) { ln.remove(); mn.torLn = null; } }); }
    return;
  }
  if (!ln || ln.classList.contains('done')) {
    if (ln) ln.remove();
    ln = mn.torLn = h('div.tor-ln', { role: 'progressbar', 'aria-label': t('conn.tor_start'), 'aria-valuemin': '0', 'aria-valuemax': '100' }, h('i'));
    mn.el.append(ln);
  }
  ln.setAttribute('aria-valuenow', S.tor.p);
  ln.firstChild.style.transform = 'scaleX(' + Math.max(0.02, S.tor.p / 100) + ')';
}

function mnRenderList() {
  if (!mn || !S.acct) return;
  const a = S.acct, qv = mn.q.trim().toLowerCase();
  let chats = a.chats.slice();
  if (mn.filter === 'groups') chats = chats.filter(c => c.kind === 'group');
  if (mn.filter === 'channels') chats = chats.filter(c => c.kind === 'channel' || c.kind === 'official');
  if (qv) chats = chats.filter(c => (mnTitle(c) + ' ' + (c.peer || '') + ' ' + mnPreview(mnLast(c))).toLowerCase().includes(qv.replace(/^@/, '')));
  chats.sort((x, y) => (y.pinned - x.pinned) || (mnActive(y) - mnActive(x)));
  const rows = chats.map(mnRow);
  const u = qv.replace(/^@/, '');
  if (qv.startsWith('@') && USER_RE.test(u) && u !== a.username && !mnContact(u)) {
    rows.unshift(h('button.row.lookup', { type: 'button', role: 'listitem', 'data-u': u },
      h('span.av.look', { 'aria-hidden': 'true' }, ico('at')),
      h('span.r-body', h('span.r-top', h('span.r-name', h('b', '@' + u))), h('span.r-bot', h('span.r-prev', t('list.lookup') + ' @' + u)))));
  }
  const hl = mn.list.querySelector('.hl');
  // rows that stay slide to their new places (a chat that just got a message goes up); new ones fade in
  const was = !reduced && mn.view === 'chats' && (isDesk() || mn.el.dataset.depth === '0') ? new Map($$('.row[data-id]', mn.list).map(r => [r.dataset.id, r.getBoundingClientRect().top])) : null;
  mn.list.replaceChildren(...[hl, ...rows].filter(Boolean));
  if (was && was.size) for (const r of $$('.row[data-id]', mn.list)) {
    const y = was.get(r.dataset.id), d = y == null ? 0 : y - r.getBoundingClientRect().top;
    if (y == null) anim(r, [{ opacity: 0 }, { opacity: 1 }], { duration: 320, easing: E.out });
    else if (Math.abs(d) > 1) anim(r, [{ transform: `translateY(${d}px)` }, { transform: 'none' }], { duration: 460, easing: E.scene });
  }
  if (!qv && mn.filter === 'all' && !a.chats.some(c => c.kind !== 'official')) {
    const b = h('button.btn.sm', { type: 'button' }, ico('at'), t('nav.new_chat'));
    b.addEventListener('click', () => mnNewChat());
    mn.list.append(h('div.ls-empty', isDesk() ? null : h('div.obj3d'), h('p', t('list.empty')), b));
  }
  mnScene();
}
function mnRow(c) {
  const m = mnLast(c);
  const out = m && m.out;
  const name = h('span.r-name', h('b', mnTitle(c)), c.kind === 'official' ? h('span.tag', t('chan.official_tag')) : null,
    c.kind === 'group' ? ico('users') : c.kind === 'channel' ? ico('channel') : null);
  const prev = h('span.r-prev', out ? h('em', t('list.you') + ' ') : null, m ? mnPreview(m) : c.kind === 'dm' ? t('chat.empty') : '');
  const bot = h('span.r-bot', prev,
    c.ttl ? mnRing() : null,
    c.pinned ? ico('pin', 'pin-ico') : null,
    c.unread ? h('span.badge' + (c.muted ? '.muted' : ''), { 'aria-label': String(c.unread) }, c.unread) : null);
  return h('button.row', { type: 'button', role: 'listitem', 'data-id': c.id, 'aria-current': mn.chat === c.id ? 'true' : null },
    mnAv(c), h('span.r-body', h('span.r-top', name, h('time.r-time', m ? mnTime(m.at) : '')), bot));
}
function mnMark() { $$('.row[data-id]', mn.list).forEach(r => r.setAttribute('aria-current', String(r.dataset.id === mn.chat))); }

/* the highlight follows the pointer from row to row on a spring */
function mnHl(list) {
  const hl = h('i.hl', { 'aria-hidden': 'true' });
  list.append(hl);
  const sy = new Spring(0, 320, 0.8);
  let run = null, on = false;
  const render = () => { hl.style.transform = `translateY(${sy.x}px)`; };
  list.addEventListener('pointerover', e => {
    if (e.pointerType === 'touch') return;
    const r = e.target.closest('.row');
    if (!r || !list.contains(r)) return;
    if (!list.contains(hl)) list.prepend(hl);
    sy.to = r.offsetTop;
    hl.style.height = r.offsetHeight + 'px';
    if (!on) { sy.snap(); on = true; hl.style.opacity = '1'; render(); return; }
    if (!run || !run.live) run = runSprings([sy], render);
  });
  list.addEventListener('pointerleave', () => { on = false; hl.style.opacity = '0'; });
}

async function mnLookup(u, row) {
  const k = mnContact(u);
  if (k) return mnOpenChat(mnAddContact(k).id);
  if (!mnNet()) return flash(t('err.tor_boot'));
  const prev = row && row.querySelector('.r-prev');
  if (prev) prev.textContent = t('busy.lookup');
  try {
    const ch = await eng.lookup(u);
    if (!mn) return;
    mn.q = "";
    if (mn.qx) { mn.qx.hidden = true; }
    const qi = mn.ls.querySelector('.find input'); if (qi) qi.value = '';
    mnRenderList();
    mnOpenChat(ch.id);
  } catch (e) {
    if (prev) prev.textContent = t('list.lookup') + ' @' + u;
    flash(eng.err(e));
  }
}

// ── sheets: new chat, contacts, invite, group, channel ───
function mnNewChat(pre = '') {
  const f = field({ label: t('f.contact_username'), value: pre, mono: true, max: 24 });
  const ok = h('button.btn.wide', { type: 'button' }, t('newchat.add'));
  const s = sheet({ title: t('nav.new_chat'), body: [h('p.note', t('newchat.note')), f], foot: [ok] });
  const run = async () => {
    const u = f.input.value.trim().replace(/^@/, '').toLowerCase();
    if (!USER_RE.test(u)) return f.error(t('err.username'));
    if (u === S.acct.username) return f.error(t('err.self'));
    const have = mnContact(u);
    if (have) { s.close(); mnOpenChat(mnAddContact(have).id); return; }
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true);
    f.ok(t('busy.lookup'));
    try {
      const ch = await eng.lookup(u);
      busy(ok, false);
      s.close();
      if (mn) mnOpenChat(ch.id);
    } catch (e) { busy(ok, false); f.error(eng.err(e)); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

function mnContacts() {
  const cs = S.acct.contacts.slice().sort((x, y) => (x.display || x.username).localeCompare(y.display || y.username));
  let s = null;
  const body = cs.length
    ? h('div.grp', cs.map(k => {
      const b = h('button.set', { type: 'button' },
        mnFace(k.keys.ed, '.s36'),
        h('span.s-l', k.display || '@' + k.username, h('small', '@' + k.username + (k.verified ? ' · ' + t('contact.verified') : ''))),
        ico('chev', 'chev'));
      b.addEventListener('click', () => { s.close(); mnOpenChat(mnAddContact(k).id); });
      return b;
    }))
    : h('p.note', t('newgroup.no_contacts'));
  const nc = h('button.btn.ghost.wide', { type: 'button' }, ico('at'), t('nav.new_chat'));
  nc.addEventListener('click', () => { s.close(); mnNewChat(); });
  s = sheet({ title: t('nav.contacts'), body, foot: [nc] });
}

const mnQr = () => (S.invite && S.invite.qr ? Promise.resolve(S.invite.qr) : Promise.reject(new Error('qr')));
function mnInvite() {
  const qr = h('div.qr.wait', { 'aria-hidden': 'true' }, h('span.spin'));
  const link = h('code.link', { hidden: true });
  const msg = h('p.fmsg', { 'aria-live': 'polite' });
  const copy = h('button.btn.wide', { type: 'button', disabled: true }, ico('copy'), t('inv.copy'));
  const again = h('button.btn.ghost.wide', { type: 'button' }, ico('refresh'), t('inv.another'));
  const open = h('button.btn.ghost.wide', { type: 'button' }, t('inv.open_title'));
  const s = sheet({ title: t('inv.title'), body: [h('p.note', t('inv.note')), qr, link, msg], foot: [copy, again, open] });
  let cur = '';
  const make = async () => {
    msg.textContent = ''; msg.className = 'fmsg';
    if (!mnNet()) { qr.replaceChildren(); msg.textContent = t('err.tor_boot'); return; }
    busy(again, true);
    qr.className = 'qr wait'; qr.replaceChildren(h('span.spin')); copy.disabled = true; link.hidden = true;
    msg.textContent = t('busy.invite');
    try { await eng.job('create_invite', {}, m => m.invite && m.invite.link !== cur); }
    catch (e) { busy(again, false); qr.replaceChildren(); msg.textContent = eng.err(e); return; }
    cur = S.invite.link;
    mnInvites.set(cur, { used: false, at: Date.now() });
    link.textContent = cur; link.hidden = false; copy.disabled = false; msg.textContent = '';
    busy(again, false);
    try { const svg = await mnQr(cur); qr.className = 'qr'; qr.innerHTML = svg; qr.removeAttribute('aria-hidden'); qr.firstChild.setAttribute('aria-label', t('inv.title')); }
    catch (e) { qr.remove(); }
    if (!reduced) anim(link, [{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
    decode(link, cur, 900);
  };
  copy.addEventListener('click', async () => { const ok = await copyText(cur, link); if (ok) flash(t('d.copied'), 'ok', 2000); });
  again.addEventListener('click', make);
  open.addEventListener('click', () => { s.close(); mnOpenInvite(); });
  make();
}
function mnOpenInvite() {
  const f = field({ label: t('f.invite_link'), mono: true });
  const ok = h('button.btn.wide', { type: 'button' }, t('inv.open'));
  const s = sheet({ title: t('inv.open_title'), body: [h('p.note', t('inv.open_note')), f], foot: [ok] });
  const run = async () => {
    const v = f.input.value.trim();
    if (!MN_INV_RE.test(v)) return f.error(t('err.invite_link'));
    if (mnInvites.has(v)) return f.error(t('err.self'));
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true); f.ok(t('busy.invite'));
    try { await eng.job('redeem_invite', { link: v }); busy(ok, false); s.close(); }
    catch (e) { busy(ok, false); f.error(eng.err(e)); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  return s;
}

function mnPick(contacts, max, onChange) {
  const chosen = new Set();
  const n = h('span');
  const head = h('div.pick-n.t-label', h('span', t('newgroup.members')), n);
  const box = h('div.pick', { role: 'group', 'aria-label': t('newgroup.members') }, contacts.map(k => {
    const b = h('button', { type: 'button', role: 'checkbox', 'aria-checked': 'false' },
      mnFace(k.keys.ed, '.s36'),
      h('b', k.display || '@' + k.username), h('i', ico('check')));
    b.addEventListener('click', () => {
      const on = !chosen.has(k.username);
      if (on) chosen.add(k.username); else chosen.delete(k.username);
      b.setAttribute('aria-checked', String(on));
      upd();
    });
    return b;
  }));
  const upd = () => { n.textContent = chosen.size + ' / ' + max; onChange && onChange(chosen); };
  upd();
  return { el: h('div.stack', head, box), chosen };
}
function mnNewGroup() {
  const cs = S.acct.contacts;
  if (!cs.length) {
    const nc = h('button.btn.wide', { type: 'button' }, ico('at'), t('nav.new_chat'));
    const s0 = sheet({ title: t('nav.new_group'), body: [h('p.note', t('newgroup.no_contacts'))], foot: [nc] });
    nc.addEventListener('click', () => { s0.close(); mnNewChat(); });
    return;
  }
  const f = field({ label: t('f.group_title'), max: 64 });
  const p = mnPick(cs, MN_MAX_GROUP - 1);
  const err = h('p.fmsg', { 'aria-live': 'polite' });
  const ok = h('button.btn.wide', { type: 'button' }, t('newgroup.create'));
  const s = sheet({ title: t('nav.new_group'), body: [f, h('p.note', t('newgroup.note')), p.el, err], foot: [ok] });
  ok.addEventListener('click', async () => {
    const title = f.input.value.trim();
    err.textContent = '';
    if (!title || [...title].length > 64) return f.error(t('err.group_title'));
    if (!p.chosen.size) { err.textContent = t('err.group_members'); shake(p.el); return; }
    if (p.chosen.size > MN_MAX_GROUP - 1) { err.textContent = t('err.group_big'); return; }
    if (!mnNet()) { err.textContent = t('err.tor_boot'); return; }
    busy(ok, true); err.className = 'fmsg ok'; err.textContent = t('busy.group');
    let c;
    try { c = await eng.created('group', 'create_group', { title, members: [...p.chosen] }); }
    catch (e) { busy(ok, false); err.className = 'fmsg'; err.textContent = eng.err(e); return; }
    busy(ok, false);
    s.close();
    if (mn && c) { mnRenderList(); mnOpenChat(c.id); }
  });
}
function mnNewChannel() {
  const f = field({ label: t('f.channel_title'), max: 64 });
  const ok = h('button.btn.wide', { type: 'button' }, t('newchannel.create'));
  const s = sheet({ title: t('nav.new_channel'), body: [f, h('p.note', t('newchannel.note'))], foot: [ok] });
  const run = async () => {
    const title = f.input.value.trim();
    if (!title || [...title].length > 64) return f.error(t('err.channel_title'));
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true);
    let c;
    try { c = await eng.created('channel', 'create_channel', { title, about: '', members: [] }); }
    catch (e) { busy(ok, false); return f.error(eng.err(e)); }
    busy(ok, false);
    s.close();
    if (mn && c) { mnRenderList(); mnOpenChat(c.id); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// @@chat
function mnRing(m) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'ttl'); svg.setAttribute('viewBox', '0 0 12 12'); svg.setAttribute('aria-hidden', 'true');
  for (const c of ['tr', 'tv']) {
    const e = document.createElementNS(NS, 'circle');
    e.setAttribute('class', c); e.setAttribute('cx', '6'); e.setAttribute('cy', '6'); e.setAttribute('r', '5');
    svg.append(e);
  }
  if (m) mnRingSet(svg, m);
  return svg;
}
function mnRingSet(svg, m) {
  const left = m.exp ? Math.max(0, m.exp - Date.now()) / (m.ttl * 1000) : 1;
  svg.lastChild.style.strokeDashoffset = String(31.4 * (1 - left));
}

function mnOpenChat(id) {
  const c = mnChat(id);
  if (!c || !mn) return;
  eng.nav(id);
  // the row's avatar, if the row is on screen: the chat header takes it over
  let row = null;
  if (!reduced && mn.view === 'chats' && (isDesk() || mn.el.dataset.depth === '0')) {
    const av = $(`.row[data-id="${id}"] .av`, mn.list);
    const r = av && av.getBoundingClientRect(), box = av && av.closest('.ls-scroll').getBoundingClientRect();
    if (r && r.width && r.bottom > box.top + 4 && r.top < box.bottom - 4) row = { av, r };
  }
  if (mn.view !== 'chats') { mn.sec = null; mnSetView('chats'); }
  const was = mn.chat;
  mn.chat = id; mn.sec = null;
  c.unread = 0;
  mnRenderList();
  const fresh = was !== id || !mn.cv;
  if (fresh) mnStage(mnChatView(c));
  mnDepth(1);
  if (row && fresh && mn.cv) {
    const head = $('.ch-who .av', mn.cv.el);
    // desktop: the new view rises 10px as it fades in; phone: the whole pane slides in
    const b = isDesk() ? mnRest(head, mn.cv.el, mn.stage.getBoundingClientRect()) : mnRest(head, mn.paneS, mn.el.getBoundingClientRect());
    const now = $(`.row[data-id="${id}"] .av`, mn.list);
    mnLift(row.av, row.r, b, isDesk() || !now ? [head] : [head, now], isDesk() ? 520 : 560);
  }
  if (mn.info) { if (innerWidth >= 1240) mnOpenInfo(c, true); else mnCloseInfo(true); }
}

/* "1 участник, 3 участника, 5 участников" */
function mnMembers(n) {
  const one = n % 10 === 1 && n % 100 !== 11, few = n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14);
  if (LANG === 'en') return n + ' ' + (n === 1 ? t('group.members_1') : t('group.members_n'));
  return n + ' ' + (one ? t('group.members_1') : few ? t('group.members_2') : t('group.members_n'));
}
function mnSub(c) {
  if (c.kind === 'official') return [document.createTextNode(t('chan.official'))];
  if (c.kind === 'group') return [document.createTextNode(mnMembers(c.members.length))];
  if (c.kind === 'channel') return [document.createTextNode(t('chan.channel') + ' · ' + c.subs.length + ' ' + t('chan.subs_n'))];
  const k = mnContact(c.peer);
  const out = [k && k.verified ? h('span.vf', t('contact.verified')) : h('span', t('contact.unverified'))];
  if (c.ttl) out.push(document.createTextNode('·'), mnRing(), h('span', t('ttl.short') + ': ' + mnTtlLabel(c.ttl).toLowerCase()));
  return out;
}

function mnChatView(c) {
  const el = h('div.chat', { 'data-id': c.id });
  const back = h('button.ib.bare.back-phone', { type: 'button', 'aria-label': t('common.back') }, ico('back'));
  const sub = h('small');
  const who = h('button.ch-who', { type: 'button', 'aria-label': t('menu.info') + ': ' + mnTitle(c) }, mnAv(c, '.s40'), h('span', h('b', mnTitle(c)), sub));
  const more = h('button.ib.bare', { type: 'button', 'aria-label': t('menu.more'), 'aria-haspopup': 'menu' }, ico('more'));
  const head = h('div.ch-head.glass', back, who, more);
  const list = h('div.ch-list', { role: 'log', 'aria-label': mnTitle(c) });
  const scroll = h('div.ch-scroll', list);
  const drop = h('div.drop', { 'aria-hidden': 'true' }, h('span', t('chat.attach')));
  el.append(scroll, head, drop);
  const v = { c, el, list, scroll, sub, nodes: new Map() };

  const subUpd = () => sub.replaceChildren(...mnSub(c));
  subUpd();
  v.subUpd = subUpd;
  back.addEventListener('click', () => mnBack());
  who.addEventListener('click', () => mnOpenInfo(c));
  more.addEventListener('click', () => mnChatMenu(v, more));

  // composer, or one line saying who may write here
  if (mnCanWrite(c)) {
    const ta = h('textarea', { rows: 1, placeholder: t('chat.placeholder'), 'aria-label': t('chat.placeholder') });
    const n = h('span.cmp-n', { hidden: true });
    const send = h('button.ib.send', { type: 'button', 'aria-label': t('chat.send'), disabled: true }, ico('send'));
    const clip = h('button.ib.bare', { type: 'button', 'aria-label': t('chat.attach') }, ico('clip'));
    const file = h('input', { type: 'file', accept: 'image/*,video/*', multiple: true, hidden: true, tabIndex: -1 });
    const comp = h('div.ch-comp.glass', h('div.cmp', clip, h('div.cmp-box', ta, n), send), h('p.ch-hint', t('chat.hint')), file);
    el.append(comp);
    const fit = () => {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 160) + 'px';
      el.style.setProperty('--cp-h', comp.offsetHeight + 'px');
      const len = [...ta.value].length;
      n.hidden = len < MN_MAX_TEXT - 200;
      n.textContent = String(MN_MAX_TEXT - len);
      n.classList.toggle('over', len > MN_MAX_TEXT);
      send.disabled = !ta.value.trim();
    };
    ta.addEventListener('input', fit);
    ta.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send.click(); }
    });
    send.addEventListener('click', () => {
      const text = ta.value.trim();
      if (!text) return;
      if ([...text].length > MN_MAX_TEXT) { flash(t('err.too_long')); shake(comp.querySelector('.cmp-box')); return; }
      // where the first typed line sits, so the bubble can rise out of it
      const r = ta.getBoundingClientRect(), cs = getComputedStyle(ta);
      const from = { x: r.left + parseFloat(cs.paddingLeft), y: r.top + parseFloat(cs.paddingTop) - ta.scrollTop, ink: cs.color };
      ta.value = ''; fit();
      mnSend(v, { text }, from);
      ta.focus();
    });
    clip.addEventListener('click', () => { eng.nav(c.id); send('pick_media'); });
    v.ta = ta;
    requestAnimationFrame(fit);
  } else {
    el.append(h('div.ch-comp.glass', h('div.ch-ro', ico('lock'), h('span', t('err.channel_readonly')))));
  }

  mnFill(v);
  const tick = setInterval(() => {
    for (const [id, node] of v.nodes) {
      const r = node.querySelector('.meta .ttl'), m = c.msgs.find(x => x.id === id);
      if (r && m) mnRingSet(r, m);
    }
  }, 500);
  mn.burn = m => mnBurn(v, m);
  mn.cv = v;
  mn.onTor = null;
  el._off = () => {
    clearInterval(tick);
    if (mn && mn.cv === v) { mn.burn = null; mn.cv = null; if (mn.search) mn.search.close(true); }
  };
  requestAnimationFrame(() => { scroll.scrollTop = scroll.scrollHeight; });
  return el;
}

function mnFill(v) {
  const { c, list } = v;
  v.nodes.clear();
  const kids = [];
  if (!c.msgs.length) kids.push(h('p.sys.ch-empty', t('chat.empty')));
  if (c.ttl) kids.push(h('p.sys.ttl-on', t('chat.ttl_on')));
  let day = '';
  for (const m of c.msgs) {
    const d = dayLabel(m.at);
    if (d !== day) { day = d; kids.push(h('div.day', h('span', d))); }
    kids.push(mnMsgNode(v, m));
  }
  list.replaceChildren(...kids);
  mnRuns(v);
}
function mnTtlNote(v) {
  const was = $('.ttl-on', v.list);
  if (!v.c.ttl) { if (was) collapse(was, reduced ? 1 : 300); return; }
  if (was) return;
  const e = $('.ch-empty', v.list);
  if (e) e.after(h('p.sys.ttl-on', t('chat.ttl_on')));
  else v.list.prepend(h('p.sys.ttl-on', t('chat.ttl_on')));
}
function mnDayFor(v, m) {
  const prev = v.c.msgs[v.c.msgs.indexOf(m) - 1];
  const e = $('.ch-empty', v.list);
  if (e) e.remove();
  if (!prev || dayLabel(prev.at) !== dayLabel(m.at)) v.list.append(h('div.day', h('span', dayLabel(m.at))));
}
/* runs as in 0.2.5: neighbours from one sender on one side form a run; a date or a service
   line ends it. Inside a run the bubbles close up and only the last keeps the tail. Posts in
   channels stand alone */
function mnRuns(v) {
  const post = v.c.kind === 'channel' || v.c.kind === 'official';
  const side = n => (n && n.classList.contains('msg') ? n.dataset.side : null);
  for (const n of v.list.children) {
    if (!n.classList.contains('msg')) continue;
    n.classList.toggle('first', post || side(n.previousElementSibling) !== n.dataset.side);
    n.classList.toggle('last', post || side(n.nextElementSibling) !== n.dataset.side);
  }
}

function mnMeta(m) {
  const meta = h('span.meta');
  if (m.state === 'sending') meta.append(h('span', t('msg.sending')));
  else if (m.state === 'failed') {
    const r = h('button.retry', { type: 'button' }, t('msg.retry'));
    r.addEventListener('click', e => { e.stopPropagation(); mnRetry(m); });
    meta.append(h('span', t('msg.failed') + ' ·'), r);
  } else {
    if (m.exp) meta.append(mnRing(m));
    meta.append(h('time', hm(m.at)));
    if (m.out) meta.append(ico('lock', 'lk'));
  }
  return meta;
}
function mnMsgNode(v, m) {
  const post = v.c.kind === 'channel' || v.c.kind === 'official';
  const node = h('div.msg' + (m.out ? '.out' : '.in') + (post ? '.post' : '') + (m.state === 'failed' ? '.fail' : ''), { 'data-id': m.id, 'data-side': m.out ? 'out' : 'in:' + (m.from || '') });
  if (m.media && m.media.length) {
    node.classList.add('media');
    node.append(mnAlbum(v, m));
    if (m.cap) { node.classList.add('has-cap'); node.append(h('div.cap', m.cap)); }
  } else node.append(h('span.tx', mnText(m)));
  node.append(mnMeta(m));
  v.nodes.set(m.id, node);
  return node;
}
function mnSetState(v, m) {
  const node = v && v.nodes.get(m.id);
  if (!node) return;
  node.classList.toggle('fail', m.state === 'failed');
  node.querySelector('.meta').replaceWith(mnMeta(m));
}

/* send: the text appears as cipher, then resolves; the network decides the rest.
   From the composer (`from`: the first typed line) the bubble rises out of the field */
async function mnSend(v, part, from) {
  const c = v.c;
  const m = { id: uid('m'), out: true, at: new Date(), state: 'sending', ...part };
  c.msgs.push(m);
  if (m.text) { m.local = true; eng.nav(c.id); send('send', { text: m.text }); }
  while (c.msgs.length > 1000) mnFreeMedia(c.msgs.shift());
  const ref = v.list.lastElementChild, y0 = ref ? ref.getBoundingClientRect().top : 0;
  mnDayFor(v, m);
  const node = mnMsgNode(v, m);
  const tx = node.querySelector('.tx');
  const rise = !!(from && tx && !reduced);
  v.list.append(node);
  mnRuns(v);
  // cipher glyphs are not as wide as the letters: the bubble keeps its size while they resolve
  if (tx && !reduced) {
    const box = node.getBoundingClientRect();
    node.style.width = box.width + 'px';
    node.style.height = box.height + 'px';
    if (!rise) tx.textContent = '';
  }
  let landed = null;
  if (rise) landed = mnRise(v, node, from, ref, y0);
  else {
    if (!reduced) anim(node, [{ opacity: 0, transform: 'translateY(14px) scale(.98)' }, { opacity: 1, transform: 'none' }], { duration: 420, easing: E.scene });
    v.scroll.scrollTo({ top: v.scroll.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
  }
  mnRenderList();
  const cipher = () => (tx ? scramble(tx, m.text, 1300) : Promise.resolve());
  const free = () => { node.style.width = node.style.height = ''; };
  await (landed ? landed.then(cipher) : cipher()).then(free);
  return m;
}
/* the list jumps to the end at once and glides up from where it was; a copy of the new
   bubble flies from the typed line to its place, its body and time fading in on the way,
   and the real bubble takes over where the copy lands */
function mnRise(v, node, from, ref, y0) {
  v.scroll.scrollTop = v.scroll.scrollHeight;
  const b = node.getBoundingClientRect(), line = node.querySelector('.tx').getClientRects()[0] || b;
  const dy = ref && ref.isConnected ? y0 - ref.getBoundingClientRect().top : 0;
  if (dy > 1 && dy < 420) anim(v.list, [{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: 460, easing: E.scene });
  const ghost = node.cloneNode(true);
  ghost.classList.add('rise');
  ghost.removeAttribute('data-id');
  Object.assign(ghost.style, { position: 'fixed', left: b.left + 'px', top: b.top + 'px', width: b.width + 'px', height: b.height + 'px', margin: 0, zIndex: 90, pointerEvents: 'none' });
  const body = h('i.rise-bg', { 'aria-hidden': 'true' });
  ghost.prepend(body);
  ENTRY.append(ghost);
  node.style.opacity = '0';
  const ink = getComputedStyle(node).color;
  return Promise.all([
    anim(ghost, [{ transform: `translate(${from.x - line.left}px, ${from.y - line.top}px)`, color: from.ink }, { transform: 'none', color: ink }], { duration: 540, easing: E.scene }),
    anim(body, [{ opacity: 0, transform: 'scale(.94)' }, { opacity: 1, transform: 'none' }], { duration: 340, delay: 60, easing: E.out, fill: 'backwards' }),
    anim(ghost.querySelector('.meta'), [{ opacity: 0 }, { opacity: 1 }], { duration: 300, delay: 200, easing: E.out, fill: 'backwards' }),
  ]).then(() => {
    ghost.remove();
    node.style.opacity = '';
  });
}
function mnDeliver() {}
async function mnRetry(m) {
  const v = mn && mn.cv;
  if (!v) return;
  if (!mnNet()) { flash(t('err.tor_boot')); shake(v.nodes.get(m.id)); return; }
  m.state = 'sending';
  mnSetState(v, m);
  eng.nav(v.c.id);
  send('retry', { id: m.id });
}

/* disappearing: text turns to ash, media fades, then the row folds */
function mnBurn(v, m) {
  const node = v.nodes.get(m.id);
  if (!node) return;
  v.nodes.delete(m.id);
  const tx = node.querySelector('.tx');
  const out = tx ? ash(tx) : reduced ? Promise.resolve() : anim(node, [{ opacity: 1, filter: 'none' }, { opacity: 0, filter: 'blur(6px) grayscale(1)' }], { duration: 1000, easing: E.soft, fill: 'forwards' });
  out.then(() => collapse(node, reduced ? 1 : 400)).then(() => {
    for (const d of $$('.day', v.list)) { const nx = d.nextElementSibling; if (!nx || nx.classList.contains('day')) d.remove(); }
    if (mn && mn.cv === v) mnRuns(v);
  });
}

// ── chat menu ────────────────────────────────────────────
function mnChatMenu(v, btn) {
  const c = v.c;
  const end = c.kind === 'dm' ? { icon: 'trash', label: t('dlg.delete_chat'), danger: true, run: () => mnDeleteChat(c) }
    : c.kind === 'group' ? { icon: 'leave', label: t('group.leave'), danger: true, run: () => mnLeave(c) }
    : mnOwner(c) ? { icon: 'trash', label: t('chan.delete'), danger: true, run: () => mnLeave(c) }
    : null;
  menu(btn, [
    { icon: 'info', label: t('menu.info'), run: () => mnOpenInfo(c) },
    { icon: 'pin', label: t(c.pinned ? 'menu.unpin' : 'menu.pin'), run: () => { c.pinned = !c.pinned; eng.nav(c.id); send('pin'); mnRenderList(); } },
    { icon: 'bell', label: t(c.muted ? 'menu.unmute' : 'menu.mute'), run: () => { c.muted = !c.muted; eng.nav(c.id); send('mute'); mnRenderList(); } },
    c.kind === 'dm' ? { icon: 'timer', label: t('ttl.label'), run: () => mnTtlSheet(v) } : null,
    { icon: 'search', label: t('chat.search'), run: () => mnSearch(v) },
    c.kind !== 'official' && c.msgs.length ? { icon: 'archive', label: t('menu.clear'), run: () => mnClear(v) } : null,
    end ? '-' : null,
    end,
  ]);
}

function mnTtlSheet(v) {
  const c = v.c;
  let s = null;
  const box = h('div.grp', { role: 'radiogroup', 'aria-label': t('ttl.label') }, MN_TTL.map(o => {
    const b = h('button.radio', { type: 'button', role: 'radio', 'aria-checked': String(c.ttl === o.v) }, h('span', t(o.k)), o.v ? mnRing() : null, h('i'));
    b.addEventListener('click', () => {
      $$('.radio', box).forEach(x => x.setAttribute('aria-checked', String(x === b)));
      if (c.ttl !== o.v) {
        c.ttl = o.v;
        eng.nav(c.id); send('set_ttl', { ttl: o.v });
        v.subUpd(); mnRenderList();
        mnTtlNote(v);
        mnRuns(v);
        v.scroll.scrollTop = v.scroll.scrollHeight;
      }
      mnLater(reduced ? 0 : 260, () => s.close());
    });
    return b;
  }));
  s = sheet({ title: t('ttl.label'), body: [box, h('p.note', t('chat.ttl_on') + '…')] });
}

async function mnClear(v) {
  const c = v.c;
  const ok = await ask({ title: t('menu.clear'), text: t('dlg.clear_text'), ok: t('menu.clear') });
  if (!ok || !mn) return;
  eng.nav(c.id); send('open_dialog', { kind: 'clear_chat', id: '' }); send('clear_chat');
  const msgs = c.msgs.slice();
  c.msgs = [];
  const nodes = $$('.msg', v.list);
  await Promise.all(nodes.map((n, i) => sleep(reduced ? 0 : Math.min(i, 20) * 35).then(() => {
    const tx = n.querySelector('.tx');
    return tx ? ash(tx, { max: 120 }) : reduced ? null : anim(n, [{ opacity: 1 }, { opacity: 0 }], { duration: 700, fill: 'forwards' });
  })));
  msgs.forEach(mnFreeMedia);
  if (mn && mn.cv === v) mnFill(v);
  mnRenderList();
}

async function mnDeleteChat(c) {
  const ok = await ask({ title: t('dlg.delete_chat'), text: t('dlg.delete_chat_text'), ok: t('contact.delete') });
  if (ok && mn) mnDrop(c, true);
}
async function mnLeave(c) {
  const own = mnOwner(c), grp = c.kind === 'group';
  const label = own ? t('chan.delete') : grp ? t('group.leave') : t('chan.leave');
  const ok = await ask({ title: label, text: own ? t('dlg.clear_text') : grp ? t('group.leave_note') : t('chan.leave_note'), ok: label });
  if (ok && mn) mnDrop(c, false);
}
/* the row folds away; the stage returns to its empty view */
async function mnDrop(c, contact) {
  const a = S.acct, cid = c.id.slice(c.id.indexOf(':') + 1);
  const kind = c.kind === 'dm' ? 'delete_chat' : c.kind === 'group' ? 'leave_group' : 'leave_channel';
  send('open_dialog', { kind, id: cid }); send(kind);
  c.msgs.forEach(mnFreeMedia);
  a.chats = a.chats.filter(x => x !== c);
  if (contact && c.peer) a.contacts = a.contacts.filter(k => k.username !== c.peer);
  if (mn.info) mnCloseInfo(true);
  if (mn.chat === c.id) {
    mn.chat = null;
    if (isDesk()) mnStage(mnEmpty()); else mnBack();
  }
  const row = mn.list.querySelector(`.row[data-id="${c.id}"]`);
  if (row) await collapse(row, reduced ? 1 : 400);
  mnRenderList();
}

// ── search inside the chat: the header turns into a field ─
function mnSearch(v) {
  if (mn.search) return mn.search.input.focus();
  const head = $('.ch-head', v.el);
  const kept = [...head.children];
  const input = h('input', { type: 'search', placeholder: t('chat.search'), 'aria-label': t('chat.search'), autocomplete: 'off', spellcheck: 'false' });
  const hits = h('span.hits.t-time', { 'aria-live': 'polite' });
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const box = h('div.ch-find', h('div.find', ico('search'), input), hits, x);
  kept.forEach(k => { k.hidden = true; });
  head.append(box);
  if (!reduced) anim(box, [{ opacity: 0, transform: 'scaleX(.6)', transformOrigin: 'right center' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
  input.focus();
  let marks = [], cur = -1;
  const restore = () => {
    for (const [id, node] of v.nodes) {
      const tx = node.querySelector('.tx'), m = v.c.msgs.find(z => z.id === id);
      if (tx && m && tx.querySelector('mark')) tx.textContent = mnText(m);
    }
  };
  const step = i => {
    if (!marks.length) return;
    if (marks[cur]) marks[cur].classList.remove('cur');
    cur = (i + marks.length) % marks.length;
    marks[cur].classList.add('cur');
    marks[cur].scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' });
    hits.textContent = (cur + 1) + '/' + marks.length;
  };
  // marks are built from text nodes; message text never goes through innerHTML
  const run = () => {
    restore();
    marks = []; cur = -1;
    const q = input.value.trim().toLowerCase();
    if (q) for (const m of v.c.msgs) {
      const node = v.nodes.get(m.id), tx = node && node.querySelector('.tx');
      if (!tx) continue;
      const s = mnText(m), low = s.toLowerCase();
      let i = low.indexOf(q), from = 0;
      if (i < 0) continue;
      const parts = [];
      while (i >= 0) {
        parts.push(document.createTextNode(s.slice(from, i)));
        const mk = h('mark', s.slice(i, i + q.length));
        parts.push(mk); marks.push(mk);
        from = i + q.length; i = low.indexOf(q, from);
      }
      parts.push(document.createTextNode(s.slice(from)));
      tx.replaceChildren(...parts);
    }
    if (marks.length) step(marks.length - 1); else hits.textContent = q ? '0/0' : '';
  };
  const close = quick => {
    restore();
    box.remove();
    kept.forEach(k => { k.hidden = false; });
    if (mn) mn.search = null;
    if (!quick) $('.ch-who', head).focus();
  };
  input.addEventListener('input', run);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); step(cur + (e.shiftKey ? 1 : -1)); }
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  });
  x.addEventListener('click', () => close());
  mn.search = { input, close };
}

// @@info
// ── info pane: contact HUD, group, channel ───────────────
function mnOpenInfo(c, swap) {
  if (!mn) return;
  const from = !swap && mn.cv && mn.cv.c === c ? $('.ch-who .av', mn.cv.el) : null;
  const old = mn.paneI.firstElementChild;
  if (old && old._off) old._off();
  const node = c.kind === 'dm' ? mnHud(c) : mnGroupInfo(c);
  mn.paneI.replaceChildren(node);
  mn.info = true;
  mn.el.dataset.info = '1';
  mnDepth(isDesk() ? 1 : 2);
  if (from && !reduced) mnFlight(from, node);
  mnLater(reduced ? 0 : 300, () => { const f = $('.info-top .ib', node); if (f && isDesk()) f.focus({ preventScroll: true }); });
}
function mnCloseInfo(quick) {
  if (!mn || !mn.info) return;
  const node = mn.paneI.firstElementChild;
  // the face goes back into the chat header while the pane leaves
  const face = !quick && !reduced && node && mn.cv && mn.chat ? mnInfoFace(node) : null;
  const head = face && $('.ch-who .av', mn.cv.el), a = face && face.getBoundingClientRect();
  mn.info = false;
  mn.el.dataset.info = '0';
  mnDepth(mn.chat || mn.sec ? 1 : 0);
  if (head && a.bottom > 8 && a.top < innerHeight - 8) {
    const b = isDesk() ? head.getBoundingClientRect() : mnRest(head, mn.paneS, mn.el.getBoundingClientRect());
    mnLift(face, a, b, [face, head], 560);
  }
  mnLater(quick || reduced ? 0 : 560, () => { if (!mn.info && node && node.isConnected) { node._off && node._off(); node.remove(); } });
  if (!quick && mn.cv) $('.ch-who', mn.cv.el).focus({ preventScroll: true });
}

/* shared element: the header avatar flies into the info pane (a contact's key face, a group's
   or channel's avatar) and lands where the block settles */
function mnInfoFace(node) { return $('.hud .face', node) || $('.hud > .av', node); }
function mnFlight(from, node) {
  const face = mnInfoFace(node);
  if (!face) return;
  const a = from.getBoundingClientRect();
  const pane = mn.paneI.getBoundingClientRect(), main = mn.el.getBoundingClientRect();
  const f = face.getBoundingClientRect();
  // the block still sits 12px low (it rises as it fades in): aim where it settles
  const block = face.closest('.info-body > *');
  const rise = block ? new DOMMatrix(getComputedStyle(block).transform).m42 : 0;
  const finalLeft = isDesk() ? main.right - Math.min(380, main.width) : main.left;
  const b = new DOMRect(finalLeft + (f.left - pane.left), f.top - rise, f.width, f.height);
  mnLift(from, a, b, [face], 620).then(() => {
    if (face.isConnected) anim(face, [{ transform: 'scale(1.06)' }, { transform: 'none' }], { duration: 380, easing: E.out });
  });
}
function mnInfoTop(title) {
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico(isDesk() ? 'close' : 'back'));
  x.addEventListener('click', () => mnCloseInfo());
  return h('div.info-top', x, h('h2.t-sheet', title), h('span', { style: { width: '44px' } }));
}

// a label or icon that changes in place: the old state blurs out, the new one sharpens in
function mnMorphIn(el) {
  return anim(el, [{ opacity: 0, filter: 'blur(6px)', transform: 'scale(.8)' }, { opacity: 1, filter: 'blur(0)', transform: 'none' }], { duration: 320, easing: E.out });
}

function mnHud(c) {
  const k = mnContact(c.peer);
  const me = S.acct;
  const name = (k && k.display) || '@' + c.peer;
  const face = h('div.face', { html: identicon(k.keys.ed) });
  const st = h('span.st' + (k.verified ? '.ok' : ''), ico(k.verified ? 'check' : 'warn'), t(k.verified ? 'contact.verified' : 'contact.unverified'));
  const fp = (k.fp || '').split(' ');
  const hud = h('div.hud', face, h('h3', name), k && k.display ? h('span.sub', '@' + c.peer) : null, st);

  const act = (icon, label, pressed, run) => {
    const b = h('button.act', { type: 'button', 'aria-pressed': pressed == null ? null : String(pressed) }, ico(icon), h('span', label));
    b.addEventListener('click', () => run(b));
    return b;
  };
  const snBox = h('div.sn' + (k.verified ? '.ok' : ''), { 'aria-label': t('contact.safety') }, (k.sn || '').split(' ').filter(Boolean).map(g => h('span', [...g].map(d => h('b', d)))));
  const verB = k.verified ? null : h('button.btn.sm', { type: 'button' }, ico('check'), t('contact.mark_verified'));
  const snKv = h('div.kv', h('span.t-label', t('contact.safety')), snBox, h('p.note', t('contact.safety_note')), verB);
  const acts = h('div.acts',
    act('send', t('contacts.chat'), null, () => { if (!isDesk()) mnCloseInfo(); else if (mn.cv && mn.cv.ta) mn.cv.ta.focus(); }),
    act(c.muted ? 'sound-off' : 'sound', t('d.sound'), !c.muted, b => { c.muted = !c.muted; eng.nav(c.id); send('mute'); b.setAttribute('aria-pressed', String(!c.muted)); const i = ico(c.muted ? 'sound-off' : 'sound'); b.firstChild.replaceWith(i); mnMorphIn(i); mnRenderList(); }),
    act('shield', t('d.verify'), null, () => { snKv.scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' }); if (verB) mnLater(reduced ? 0 : 350, () => verB.focus()); }));

  if (verB) verB.addEventListener('click', async () => {
    verB.disabled = true;
    eng.verify(c);
    const cells = $$('b', snBox);
    await Promise.all(cells.map((b, i) => sleep(reduced ? 0 : i * 50).then(() => {
      mnLater(reduced ? 0 : 350, () => b.classList.add('ok'));
      return anim(b, [{ transform: 'rotateX(0)' }, { transform: 'rotateX(90deg)' }, { transform: 'rotateX(0)' }], { duration: 700, easing: E.soft });
    })));
    if (!mn) return;
    k.verified = true;
    snBox.classList.add('ok');
    verB.remove();
    st.className = 'st ok';
    st.replaceChildren(ico('check'), t('contact.verified'));
    mnMorphIn(st);
    if (mn.cv && mn.cv.c === c) mn.cv.subUpd();
    flash(t('contact.key_verified'), 'ok', 2400);
  });

  const del = h('button.btn.danger.wide', { type: 'button' }, ico('trash'), t('contact.delete'));
  del.addEventListener('click', () => mnDeleteChat(c));
  const body = h('div.info-body', hud, acts,
    h('div.grp',
      k.about ? h('div.kv', h('span.t-label', t('d.about_short')), h('p', k.about)) : null,
      snKv,
      h('div.kv', h('span.t-label', t('req.fingerprint')), h('p.t-fp', fp.join(' ')))),
    mnMediaTabs(c), del);
  const el = h('div.info', { role: 'complementary', 'aria-label': t('contact.title') }, mnInfoTop(t('contact.title')), body);
  if (!reduced) $$('.info-body > *', el).forEach((n, i) => anim(n, [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 480, delay: 120 + i * 60, easing: E.scene, fill: 'backwards' }));
  return el;
}

function mnMediaTabs(c) {
  const all = c.msgs.flatMap(m => (m.media || []).map(x => ({ x, m })));
  const tabs = h('div.seg.tabs', h('button', { type: 'button', 'data-v': 'img' }, t('media.photo')), h('button', { type: 'button', 'data-v': 'video' }, t('media.video')));
  const grid = h('div');
  const draw = v => {
    const items = all.filter(z => z.x.type === v);
    if (!items.length) { grid.className = 'mempty'; grid.replaceChildren(t('media.none')); return; }
    grid.className = 'mgrid';
    grid.replaceChildren(...items.map((z, i) => {
      const b = h('button', { type: 'button', 'aria-label': t(v === 'img' ? 'media.photo' : 'media.video') + ' ' + (i + 1) },
        z.x.type === 'video' ? h('video', { src: z.x.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: z.x.url, alt: '' }));
      b.addEventListener('click', () => mnViewer(items.map(q => q.x), i, b));
      return b;
    }));
    if (!reduced) [...grid.children].forEach((b, k) => anim(b, [{ opacity: 0, transform: 'scale(.9)' }, { opacity: 1, transform: 'none' }], { duration: 400, delay: Math.min(k, 11) * 26, easing: E.scene, fill: 'backwards' }));
  };
  const sg = seg(tabs, 'img', draw);
  draw(sg.value || 'img');
  return h('div.mtabs', h('span.t-label', t('info.media')), tabs, grid);
}

function mnGroupInfo(c) {
  const me = S.acct.username;
  const nameOf = u => u === me ? (S.acct.display || '@' + me) + ' · ' + t('group.you') : ((mnContact(u) || {}).display || '@' + u);
  const hd = h('div.hud', mnAv(c, '.s72'),
    h('h3', mnTitle(c)), h('span.sub', mnSub(c).map(n => n.textContent).join('')),
    c.kind === 'official' ? h('span.tag', t('chan.official_tag')) : null);
  const parts = [hd];
  const mute = h('button.act', { type: 'button', 'aria-pressed': String(!c.muted) }, ico(c.muted ? 'sound-off' : 'sound'), h('span', t('d.sound')));
  mute.addEventListener('click', () => { c.muted = !c.muted; eng.nav(c.id); send('mute'); mute.setAttribute('aria-pressed', String(!c.muted)); const i = ico(c.muted ? 'sound-off' : 'sound'); mute.firstChild.replaceWith(i); mnMorphIn(i); mnRenderList(); });
  const srch = h('button.act', { type: 'button' }, ico('search'), h('span', t('chat.search')));
  srch.addEventListener('click', () => { if (!isDesk()) mnCloseInfo(); if (mn.cv) mnSearch(mn.cv); });
  const pin = h('button.act', { type: 'button', 'aria-pressed': String(!!c.pinned) }, ico('pin'), h('span', t(c.pinned ? 'menu.unpin' : 'menu.pin')));
  pin.addEventListener('click', () => { c.pinned = !c.pinned; eng.nav(c.id); send('pin'); pin.setAttribute('aria-pressed', String(c.pinned)); pin.lastChild.textContent = t(c.pinned ? 'menu.unpin' : 'menu.pin'); mnRenderList(); });
  parts.push(h('div.acts', mute, srch, pin));

  if (c.kind === 'group') {
    const resend = h('button.btn.ghost.sm', { type: 'button' }, ico('refresh'), t('group.resend'));
    resend.addEventListener('click', async () => {
      if (!mnNet()) return flash(t('err.tor_boot'));
      send('nav', { to: 'group_info', id: c.id.slice(6) });
      c.members.filter(u => u !== me).forEach(u => send('resend_invite', { member: u }));
      eng.nav(c.id, true);
    });
    parts.push(h('div.grp',
      h('div.grp-h', h('span.t-label', t('newgroup.members')), h('span.grp-n', c.members.length + ' / ' + MN_MAX_GROUP)),
      h('div.members', c.members.map(u => h('div.member', mnFace(mnKeyOf(u), '.s36'), h('b', nameOf(u)), u === c.owner ? h('small.t-tag', t('group.creator')) : null)))),
    resend);
  }
  if (mnOwner(c)) {
    const free = S.acct.contacts.filter(k => !c.subs.includes(k.username));
    const sub = h('div.grp', h('div.grp-h', h('span.t-label', t('chan.subs_n')), h('span.grp-n', c.subs.length + ' / ' + MN_MAX_SUBS)),
      c.subs.length ? h('div.members', c.subs.map(u => h('div.member', mnFace(mnKeyOf(u), '.s36'), h('b', nameOf(u))))) : null);
    parts.push(sub);
    if (free.length) {
      const p = mnPick(free, MN_MAX_SUBS - c.subs.length);
      const inv = h('button.btn.wide', { type: 'button' }, ico('users'), t('chan.invite'));
      inv.addEventListener('click', async () => {
        if (!p.chosen.size) { shake(p.el); return; }
        if (c.subs.length + p.chosen.size > MN_MAX_SUBS) return flash(t('err.channel_big'));
        if (!mnNet()) return flash(t('err.tor_boot'));
        busy(inv, true);
        send('nav', { to: 'channel_info', id: c.id.slice(8) });
        try { await eng.job('invite_channel', { members: [...p.chosen] }); }
        catch (e) { busy(inv, false); eng.nav(c.id, true); return flash(eng.err(e)); }
        busy(inv, false); eng.nav(c.id, true);
        c.subs.push(...p.chosen);
        flash(okText('ok.invite_sent', [...p.chosen].map(u => '@' + u).join(', ')), 'ok', 3000);
        if (mn && mn.cv) mn.cv.subUpd();
        if (mn) mnOpenInfo(c, true);
      });
      parts.push(p.el, inv);
    }
  }
  parts.push(mnMediaTabs(c));
  if (c.kind !== 'official') {
    const label = mnOwner(c) ? t('chan.delete') : c.kind === 'group' ? t('group.leave') : t('chan.leave');
    const out = h('button.btn.danger.wide', { type: 'button' }, ico(mnOwner(c) ? 'trash' : 'leave'), label);
    out.addEventListener('click', () => mnLeave(c));
    parts.push(out);
  }
  const el = h('div.info', { role: 'complementary', 'aria-label': t(c.kind === 'group' ? 'group.info' : 'chan.manage') },
    mnInfoTop(t(c.kind === 'group' ? 'group.info' : c.kind === 'official' ? 'chan.official' : 'chan.manage')), h('div.info-body', parts));
  if (!reduced) $$('.info-body > *', el).forEach((n, i) => anim(n, [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 480, delay: 120 + i * 60, easing: E.scene, fill: 'backwards' }));
  return el;
}

// @@media
/* photos are re-encoded: longest side 1600 px, JPEG 80; that also drops EXIF */
async function mnPhoto(file) {
  const url0 = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url0; });
    const k = Math.min(1, 1600 / Math.max(img.naturalWidth, img.naturalHeight));
    const w = Math.max(1, Math.round(img.naturalWidth * k)), hh = Math.max(1, Math.round(img.naturalHeight * k));
    const cv = document.createElement('canvas');
    cv.width = w; cv.height = hh;
    cv.getContext('2d').drawImage(img, 0, 0, w, hh);
    const blob = await new Promise(res => cv.toBlob(res, 'image/jpeg', 0.8));
    if (!blob) throw new Error('enc');
    return { type: 'img', url: URL.createObjectURL(blob), w, h: hh, kb: Math.max(1, Math.round(blob.size / 1024)) };
  } finally { URL.revokeObjectURL(url0); }
}
async function mnVideo(file) {
  const url = URL.createObjectURL(file);
  const meta = await new Promise(res => {
    const v = document.createElement('video');
    v.preload = 'metadata'; v.muted = true;
    const done = ok => res(ok ? { w: v.videoWidth, h: v.videoHeight, dur: v.duration } : null);
    v.onloadedmetadata = () => done(true);
    v.onerror = () => done(false);
    setTimeout(() => done(false), 4000);
    v.src = url;
  });
  if (!meta) { URL.revokeObjectURL(url); throw new Error('bad'); }
  return { type: 'video', url, w: meta.w || 16, h: meta.h || 9, dur: meta.dur, kb: Math.round(file.size / 1024) };
}
async function mnAttach(v, files) {
  const media = [];
  for (const f of files) {
    const img = /^image\//.test(f.type), vid = /^video\//.test(f.type);
    if (!img && !vid) { flash(errText('err.media_type', f.name)); continue; }
    if (f.size > (img ? MN_MAX_PHOTO : MN_MAX_VIDEO)) { flash(errText('err.media_big', f.name)); continue; }
    try { media.push(await (img ? mnPhoto(f) : mnVideo(f))); } catch (e) { flash(errText('err.media_bad', f.name)); }
  }
  if (!media.length || !mn || mn.cv !== v) { media.forEach(x => URL.revokeObjectURL(x.url)); return; }
  const photos = media.filter(x => x.type === 'img');
  const cap = media.length === 1 && photos.length === 1 ? tf('d.compressed', { w: photos[0].w, h: photos[0].h, kb: photos[0].kb }) : '';
  mnSend(v, { media, cap });
}
const mnDur = s => (isFinite(s) ? Math.floor(s / 60) + ':' + pad(Math.floor(s % 60)) : '');
function mnAlbum(v, m) {
  const n = m.media.length, show = m.media.slice(0, 4);
  const alb = h('div.alb', { 'data-n': String(Math.min(n, 4)) });
  if (n === 1) alb.style.setProperty('--ar', m.media[0].w + ' / ' + m.media[0].h);
  show.forEach((x, i) => {
    const b = h('button', { type: 'button', 'aria-label': t(x.type === 'img' ? 'media.photo' : 'media.video') + ' ' + (i + 1) + '/' + n },
      x.type === 'video' ? h('video', { src: x.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: x.url, alt: '', decoding: 'async' }),
      x.type === 'video' ? h('span.vbadge', ico('play'), mnDur(x.dur)) : null,
      i === 3 && n > 4 ? h('span.more', '+' + (n - 4)) : null);
    b.addEventListener('click', () => mnViewer(m.media, i, b));
    alb.append(b);
  });
  if (m.state === 'sending' && !reduced) {
    // the seal: a line closes around the album while it is encrypted and sent
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'seal'); svg.setAttribute('aria-hidden', 'true');
    const r = document.createElementNS(NS, 'rect');
    r.setAttribute('x', '1'); r.setAttribute('y', '1'); r.setAttribute('rx', '15');
    r.setAttribute('width', 'calc(100% - 2px)'); r.setAttribute('height', 'calc(100% - 2px)');
    r.setAttribute('pathLength', '1'); r.style.strokeDasharray = '1';
    svg.append(r);
    alb.append(svg);
    $$('img,video', alb).forEach(e => anim(e, [{ filter: 'blur(14px) saturate(0)', transform: 'scale(1.08)' }, { filter: 'none', transform: 'none' }], { duration: 640, easing: E.scene }));
    anim(r, [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 1150, delay: 200, easing: E.soft, fill: 'forwards' })
      .then(() => anim(svg, [{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: 'forwards' })).then(() => svg.remove());
  }
  return alb;
}

// ── viewer: flies out of its cell; zoom, pan, pages, filmstrip; flies back into the cell of the current item ─
function mnViewer(items, i0, cell) {
  if (mn && mn.vw) mn.vw.close(true);
  let i = i0, cur = null, peek = null, holed = null, closed = false, out = false, tapT = 0, g = null;
  let lastTap = { at: 0, x: 0, y: 0 };
  const z = { s: 1, x: 0, y: 0 }, pts = new Map(), many = items.length > 1;
  const lim = (v, a, b) => Math.min(b, Math.max(a, v));
  const stage = h('div.v-stage'), shade = h('div.v-bg'), count = h('span.t-hud');
  const zb = h('button.ib.bare', { type: 'button', 'aria-label': t('d.zoom_in') }, ico('zoom'));
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const p = h('button.ib.v-nav.p', { type: 'button', 'aria-label': t('common.back') }, ico('back'));
  const nx = h('button.ib.v-nav.n', { type: 'button', 'aria-label': t('guide.next') }, ico('next'));
  const thumbs = many ? items.map((it, j) => {
    const b = h('button', { type: 'button', 'aria-label': t(it.type === 'img' ? 'media.photo' : 'media.video') + ' ' + (j + 1) + '/' + items.length },
      it.type === 'video' ? h('video', { src: it.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: it.url, alt: '', decoding: 'async' }));
    b.addEventListener('click', () => show(j));
    return b;
  }) : [];
  const strip = many ? h('div.v-strip') : null;
  if (strip) strip.append(...thumbs);
  const el = h('div.viewer.quiet', { role: 'dialog', 'aria-modal': 'true', 'aria-label': t('info.media') }, shade, stage, h('div.v-top', count, h('div.v-acts', zb, x)), p, nx, strip);

  // the cell an item came from (albums show four cells at most), and the gap it leaves there
  const cellAt = j => { const c = cell && cell.parentElement && cell.parentElement.children[j]; return c && c.tagName === 'BUTTON' ? c : null; };
  const hole = j => { const c = j < 0 ? null : cellAt(j); if (holed && holed !== c) holed.style.visibility = ''; holed = c; if (c) c.style.visibility = 'hidden'; };
  const pic = () => cur && cur.firstChild;
  const make = j => { const it = items[j]; return h('div.v-item', it.type === 'video' ? h('video', { src: it.url, controls: true, playsInline: true }) : h('img', { src: it.url, alt: '' })); };
  const run = () => { const m = pic(); if (m && m.tagName === 'VIDEO') { const q = m.play(); if (q && q.catch) q.catch(() => {}); } };
  const tfm = (b, r, s) => `translate(${r.left + r.width / 2 - b.left - b.width / 2}px, ${r.top + r.height / 2 - b.top - b.height / 2}px) scale(${s})`;
  // the part of the picture its cell shows (object-fit: cover), as a clip on the full picture
  const crop = (a, b, s, rad) => `inset(${Math.max(0, (b.height - a.height / s) / 2)}px ${Math.max(0, (b.width - a.width / s) / 2)}px round ${rad / s}px)`;
  const radOf = c => (c.parentElement.dataset.n === '1' ? 16 : 0);

  // ── zoom ──
  const apply = () => {
    const m = pic();
    if (!m) return;
    m.style.transform = z.s === 1 ? '' : `translate(${z.x}px, ${z.y}px) scale(${z.s})`;
    const on = z.s > 1;
    if (el.classList.contains('zoomed') === on) return;
    el.classList.toggle('zoomed', on);
    zb.replaceChildren(on ? ico('zoomout') : ico('zoom'));
    mnMorphIn(zb.firstChild);
    zb.setAttribute('aria-label', on ? t('d.zoom_out') : t('d.zoom_in'));
  };
  const zoomAt = (px, py, to) => {
    const m = pic();
    if (!m || m.tagName !== 'IMG') return;
    const ns = lim(to, 1, 5), r = stage.getBoundingClientRect(), k = ns / z.s;
    const cx = px == null ? 0 : px - r.left - r.width / 2, cy = py == null ? 0 : py - r.top - r.height / 2;
    const mx = Math.max(0, (m.offsetWidth * ns - r.width) / 2), my = Math.max(0, (m.offsetHeight * ns - r.height) / 2);
    z.x = lim(cx - (cx - z.x) * k, -mx, mx); z.y = lim(cy - (cy - z.y) * k, -my, my); z.s = ns;
    apply();
  };
  const zoomTo = (to, px, py) => {
    const m = pic();
    if (!m || m.tagName !== 'IMG') return;
    const from = m.style.transform || 'none';
    zoomAt(px, py, to);
    anim(m, [{ transform: from }, { transform: m.style.transform || 'none' }], { duration: 380, easing: E.scene });
  };

  // ── pages ──
  const sync = () => {
    const it = items[i], f = document.activeElement, dur = it.type === 'video' ? mnDur(it.dur) : '';
    count.textContent = (i + 1) + ' / ' + items.length + (it.type === 'img' ? ' · ' + it.w + '×' + it.h + ' · ' + it.kb + ' KB' : dur ? ' · ' + dur : '');
    p.hidden = i === 0; nx.hidden = i === items.length - 1; zb.hidden = it.type !== 'img';
    if ((f === p && p.hidden) || (f === nx && nx.hidden) || (f === zb && zb.hidden)) x.focus({ preventScroll: true });
    thumbs.forEach((b, j) => { if (j === i) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current'); });
    if (strip) { const b = thumbs[i]; strip.scrollTo({ left: b.offsetLeft - (strip.clientWidth - b.offsetWidth) / 2, behavior: reduced ? 'auto' : 'smooth' }); }
    if (out) hole(i);
  };
  const show = (j, dx = 0) => {
    if (closed || j === i || j < 0 || j >= items.length) return;
    const d = j > i ? 1 : -1, W = stage.clientWidth + 24, old = cur, reuse = peek && peek.j === j;
    const nw = reuse ? peek.el : make(j);
    if (peek && !reuse) peek.el.remove();
    peek = null;
    if (old.firstChild.tagName === 'VIDEO') old.firstChild.pause();
    z.s = 1; z.x = z.y = 0;
    i = j; cur = nw;
    if (!nw.isConnected) stage.append(nw);
    apply(); sync();
    old.style.pointerEvents = 'none';
    anim(old, [{ transform: `translateX(${dx}px)` }, { transform: `translateX(${-d * W}px)` }], { duration: 440, easing: E.scene, fill: 'forwards' }).then(() => old.remove());
    anim(nw, [{ transform: `translateX(${dx + d * W}px)` }, { transform: 'none' }], { duration: 440, easing: E.scene });
    old.style.transform = ''; nw.style.transform = '';
    run();
  };

  cur = make(i);
  stage.append(cur);
  ENTRY.append(el);
  const back = document.activeElement;
  sync();
  x.focus({ preventScroll: true });

  // ── fly out of the cell: from the crop the cell shows to the whole picture ──
  if (cell && !reduced) {
    const m = pic();
    let flown = false;
    m.style.opacity = '0';
    const fly = () => {
      if (flown || closed) return;
      flown = true;
      m.style.opacity = '';
      out = true;
      if (m !== pic()) return hole(i);
      const a = cell.getBoundingClientRect(), b = m.getBoundingClientRect();
      hole(i);
      if (!a.width || !b.width) return;
      const s = Math.max(a.width / b.width, a.height / b.height);
      anim(m, [{ transform: tfm(b, a, s), clipPath: crop(a, b, s, radOf(cell)) }, { transform: 'none', clipPath: crop(b, b, 1, 0) }], { duration: 620, easing: E.scene });
      run();
    };
    if (m.tagName === 'IMG' && !m.complete) m.addEventListener('load', fly, { once: true });
    else if (m.tagName === 'VIDEO' && !m.videoWidth) m.addEventListener('loadedmetadata', fly, { once: true });
    else requestAnimationFrame(fly);
    setTimeout(fly, 700);
    anim(shade, [{ opacity: 0 }, { opacity: 1 }], { duration: 420, easing: E.out });
    setTimeout(() => { if (!closed) el.classList.remove('quiet'); }, 260);
  } else {
    out = true; hole(i); run();
    requestAnimationFrame(() => el.classList.remove('quiet'));
  }

  const close = quick => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey, true);
    clearTimeout(tapT);
    if (mn) mn.vw = null;
    const fin = () => { el.remove(); hole(-1); if (back && back.isConnected && back.focus) back.focus({ preventScroll: true }); };
    if (quick || reduced) return fin();
    const m = pic(), src = cellAt(i), a = src && src.isConnected ? src.getBoundingClientRect() : null;
    el.classList.add('quiet');
    el.style.pointerEvents = 'none';
    if (m && m.tagName === 'VIDEO') { m.pause(); m.controls = false; }
    // back into the cell of the picture on screen, if that cell is in view
    if (m && a && a.width && a.bottom > 0 && a.top < innerHeight) {
      const r0 = m.getBoundingClientRect(), dim = getComputedStyle(shade).opacity;
      [cur, m, shade].forEach(n => n.getAnimations().forEach(q => q.cancel()));
      cur.style.transform = ''; m.style.transform = '';
      const b = m.getBoundingClientRect(), s = Math.max(a.width / b.width, a.height / b.height);
      anim(shade, [{ opacity: dim }, { opacity: 0 }], { duration: 420, easing: E.out, fill: 'forwards' });
      return anim(m, [{ transform: tfm(b, r0, r0.width / b.width), clipPath: crop(b, b, 1, 0) }, { transform: tfm(b, a, s), clipPath: crop(a, b, s, radOf(src)) }],
        { duration: 460, easing: E.scene, fill: 'forwards' }).then(fin);
    }
    if (m) anim(m, [{ opacity: 1 }, { opacity: 0 }], { duration: 220, easing: E.out, fill: 'forwards' });
    anim(el, [{ opacity: 1 }, { opacity: 0 }], { duration: 260, easing: E.out, fill: 'forwards' }).then(fin);
  };

  const onKey = e => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowLeft') show(i - 1);
    else if (e.key === 'ArrowRight') show(i + 1);
    else if (e.key === '+' || e.key === '=') zoomTo(z.s * 1.6);
    else if (e.key === '-') zoomTo(z.s / 1.6);
    else if (e.key === '0') zoomTo(1);
    else if (e.key === 'Tab') {
      el.classList.remove('quiet');
      const f = [zb, x, p, nx, ...thumbs].filter(b => !b.hidden), k = f.indexOf(document.activeElement);
      e.preventDefault();
      f[(k + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
    }
  };
  document.addEventListener('keydown', onKey, true);
  x.addEventListener('click', () => close());
  p.addEventListener('click', () => show(i - 1));
  nx.addEventListener('click', () => show(i + 1));
  zb.addEventListener('click', () => zoomTo(z.s > 1 ? 1 : 2.5));

  // ── pointers: one finger pans a zoomed picture, pages sideways or pulls down to close; two fingers pinch ──
  const settle = () => { if (peek) { peek.el.remove(); peek = null; } cur.style.transform = ''; shade.style.opacity = ''; };
  const span = () => { const [a, b] = [...pts.values()]; return { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }; };
  stage.addEventListener('dragstart', e => e.preventDefault());
  stage.addEventListener('wheel', e => { e.preventDefault(); zoomAt(e.clientX, e.clientY, z.s * Math.exp(-(e.deltaMode ? e.deltaY * 32 : e.deltaY) * 0.002)); }, { passive: false });
  stage.addEventListener('pointerdown', e => {
    if (closed || e.target.tagName === 'VIDEO' || (e.pointerType === 'mouse' && e.button !== 0)) return;
    try { stage.setPointerCapture(e.pointerId); } catch (err) { /* the pointer is already gone */ }
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pts.size === 2) { if (g && g.quiet === false) el.classList.remove('quiet'); settle(); g = { k: 'pinch', d: span().d, s: z.s }; }
    else if (pts.size === 1) g = { k: z.s > 1 ? 'pan' : '', x: e.clientX, y: e.clientY, zx: z.x, zy: z.y, at: performance.now(), moved: false, onPic: e.target === pic(), dx: 0, dy: 0 };
  });
  stage.addEventListener('pointermove', e => {
    const q = pts.get(e.pointerId);
    if (!q || !g) return;
    q.x = e.clientX; q.y = e.clientY;
    if (g.k === 'pinch') { if (pts.size > 1) { const c = span(); zoomAt(c.x, c.y, g.s * c.d / g.d); } return; }
    if (g.k === 'done') return;
    const dx = e.clientX - g.x, dy = e.clientY - g.y;
    if (!g.moved && Math.hypot(dx, dy) < 6) return;
    g.moved = true;
    if (g.k === 'pan') {
      const m = pic(), mx = Math.max(0, (m.offsetWidth * z.s - stage.clientWidth) / 2), my = Math.max(0, (m.offsetHeight * z.s - stage.clientHeight) / 2);
      z.x = lim(g.zx + dx, -mx, mx); z.y = lim(g.zy + dy, -my, my);
      return apply();
    }
    if (!g.k) {
      g.k = Math.abs(dy) > Math.abs(dx) && dy > 0 ? 'down' : 'side';
      if (g.k === 'down') { g.quiet = el.classList.contains('quiet'); el.classList.add('quiet'); }
    }
    if (g.k === 'down') {
      const k = lim(dy, 0, 320);
      g.dy = dy;
      cur.style.transform = `translateY(${Math.max(dy, 0)}px) scale(${1 - k / 1300})`;
      shade.style.opacity = String(1 - k / 420);
      return;
    }
    const d = dx < 0 ? 1 : -1, j = i + d, W = stage.clientWidth + 24;
    if (j < 0 || j >= items.length) {
      // nothing on that side: the picture resists
      if (peek) { peek.el.remove(); peek = null; }
      g.dx = dx * 0.3;
      cur.style.transform = `translateX(${g.dx}px)`;
      return;
    }
    if (!peek || peek.j !== j) { if (peek) peek.el.remove(); peek = { j, d, el: make(j) }; stage.append(peek.el); }
    g.dx = dx;
    cur.style.transform = `translateX(${dx}px)`;
    peek.el.style.transform = `translateX(${dx + d * W}px)`;
  });
  const tap = (e, q) => {
    const now = performance.now();
    if (e.pointerType === 'mouse' && !q.onPic) { if (z.s === 1) close(); return; }
    if (q.onPic && now - lastTap.at < 320 && Math.hypot(e.clientX - lastTap.x, e.clientY - lastTap.y) < 32) {
      clearTimeout(tapT); lastTap.at = 0;
      return zoomTo(z.s > 1 ? 1 : 2.5, e.clientX, e.clientY);
    }
    lastTap = { at: now, x: e.clientX, y: e.clientY };
    if (e.pointerType !== 'mouse') { clearTimeout(tapT); tapT = setTimeout(() => el.classList.toggle('quiet'), 320); }
  };
  const lift = e => {
    if (!pts.delete(e.pointerId) || !g) return;
    if (g.k === 'pinch') {
      if (pts.size === 1) { const [a] = [...pts.values()]; g = { k: z.s > 1 ? 'pan' : 'done', x: a.x, y: a.y, zx: z.x, zy: z.y, moved: true }; }
      else g = null;
      return;
    }
    const q = g;
    g = null;
    if (closed) return;
    if (!q.moved) { if (e.type === 'pointerup') tap(e, q); return; }
    if (q.k === 'down') {
      if (q.dy > 110 && e.type === 'pointerup') return close();
      anim(cur, [{ transform: cur.style.transform || 'none' }, { transform: 'none' }], { duration: 360, easing: E.back });
      anim(shade, [{ opacity: shade.style.opacity || 1 }, { opacity: 1 }], { duration: 260, easing: E.out });
      cur.style.transform = ''; shade.style.opacity = '';
      el.classList.toggle('quiet', !!q.quiet);
      return;
    }
    if (q.k !== 'side') return;
    const dx = q.dx, fast = Math.abs(dx) > 24 && Math.abs(dx) / Math.max(1, performance.now() - q.at) > 0.5;
    if (peek && e.type === 'pointerup' && (Math.abs(dx) > 70 || fast)) { cur.style.transform = ''; return show(peek.j, dx); }
    const pk = peek;
    peek = null;
    anim(cur, [{ transform: `translateX(${dx}px)` }, { transform: 'none' }], { duration: 380, easing: E.scene });
    cur.style.transform = '';
    if (pk) anim(pk.el, [{ transform: pk.el.style.transform || 'none' }, { transform: `translateX(${pk.d * (stage.clientWidth + 24)}px)` }], { duration: 320, easing: E.out, fill: 'forwards' }).then(() => pk.el.remove());
  };
  stage.addEventListener('pointerup', lift);
  stage.addEventListener('pointercancel', lift);
  if (mn) mn.vw = { close };
}
