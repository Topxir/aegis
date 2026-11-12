/* Settings: the eight sections of 0.2.5. Every control changes the real state of the
   prototype (S.set, S.acct, Tor, the lock timer); nothing here is for show. */
const ST_SECS = [
  { id: 'profile', k: 'set.profile', icon: 'user' },
  { id: 'account', k: 'acct.profile', icon: 'at' },
  { id: 'privacy', k: 'acct.privacy', icon: 'shield' },
  { id: 'notify', k: 'acct.notifications', icon: 'bell' },
  { id: 'look', k: 'acct.appearance', icon: 'spark' },
  { id: 'net', k: 'acct.connection', icon: 'onion' },
  { id: 'data', k: 'acct.data', icon: 'archive' },
  { id: 'about', k: 'set.about', icon: 'info' },
];
const ST_NAV = [['account', 'privacy', 'notify'], ['look', 'net'], ['data', 'about']];
const ST_PFX = { none: 'pfx.none', dust: 'pfx.dust', snow: 'pfx.snow', embers: 'pfx.embers', orbit: 'pfx.orbit', rain: 'pfx.rain' };
const ST_COVER = ['off', 'std', 'high'];
const ST_PIN = /^\d{4}(\d{2})?$/;
const ST_BRIDGE = /^([a-z0-9_]+\s+)?\[?[0-9a-fA-F.:]+\]?:\d{1,5}(\s+\S+)*$/;
const stNorm = u => u.trim().replace(/\/+$/, '');

// ── the list: who you are, then the sections ─────────────
function stList(api) {
  const a = S.acct;
  const me = h('button.me', { type: 'button', 'data-sec': 'profile', 'aria-label': t('set.profile') + ': ' + a.display, 'aria-current': String(api.section === 'profile') },
    mnFace(a.keys.ed), h('span.me-t', h('b', a.display), h('small', '@' + a.username)), ico('chev', 'chev'));
  me.addEventListener('click', () => api.open('profile', me.firstChild));
  const value = { look: () => t(ST_PFX[a.particles] || ST_PFX.none), about: () => VERSION };
  const row = id => {
    const s = ST_SECS.find(x => x.id === id);
    const b = h('button.set.ico', { type: 'button', 'data-sec': id, 'aria-current': String(api.section === id) },
      h('span.s-ico', ico(s.icon)), h('span.s-l', t(s.k)), value[id] ? h('span.s-v', value[id]()) : null, ico('chev', 'chev'));
    b.addEventListener('click', () => api.open(id));
    return b;
  };
  return h('div.st-nav', me, ST_NAV.map(g => h('div.grp', g.map(row))));
}

// ── building blocks ──────────────────────────────────────
function stBlock(label, body, note) {
  return h('section.stg', label ? h('h3.grp-h', label) : null, body, note ? h('p.grp-n', note) : null);
}
/* a row with a switch; the whole row is the target */
function stCheck(label, note, on, onChange) {
  const tg = toggle(on, onChange, label);
  const row = h('div.check', h('span', label, note ? h('small', note) : null), tg);
  row.addEventListener('click', e => { if (!e.target.closest('.tg') && !tg.disabled) tg.click(); });
  row.tg = tg;
  return row;
}
function stRadios(label, opts, value, onChange) {
  const box = h('div.radios', { role: 'radiogroup', 'aria-label': label });
  const btns = opts.map(([v, text]) => h('button.radio', { type: 'button', role: 'radio', 'data-v': v }, h('span', text), h('i')));
  const mark = () => btns.forEach(b => { const on = b.dataset.v === value; b.setAttribute('aria-checked', String(on)); b.tabIndex = on ? 0 : -1; });
  btns.forEach((b, i) => {
    b.addEventListener('click', () => { if (b.dataset.v === value) return; value = b.dataset.v; mark(); onChange(value); });
    b.addEventListener('keydown', e => {
      const d = e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : e.key === 'ArrowUp' || e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      const n = btns[(i + d + btns.length) % btns.length];
      n.focus(); n.click(); e.preventDefault();
    });
  });
  box.append(...btns);
  mark();
  box.set = v => { value = v; mark(); };
  return box;
}
function stStat(kind, icon, text) {
  const p = h('p.stat' + (kind ? '.' + kind : ''));
  if (icon) p.append(ico(icon));
  p.append(h('span', text));
  return p;
}
/* a small form in a sheet: `submit` gets the values and answers null or [field index, text] */
function stForm(title, labels, okLabel, submit, done) {
  const fs = labels.map(k => field({ label: t(k), type: 'password', inputmode: 'numeric', hardMax: 6, mono: true }));
  const okB = h('button.btn.wide', { type: 'button' }, okLabel);
  const no = h('button.btn.ghost.wide', { type: 'button' }, t('common.cancel'));
  const sh = sheet({ title, body: fs, foot: [okB, no] });
  let wait = false;
  const run = async () => {
    if (wait) return;
    wait = true;
    fs.forEach(f => f.clear());
    busy(okB, true);
    const bad = await submit(fs.map(f => f.input.value));
    busy(okB, false);
    wait = false;
    if (bad) { fs[bad[0]].error(bad[1]); fs[bad[0]].input.select(); return; }
    sh.close();
    done();
  };
  okB.addEventListener('click', run);
  no.addEventListener('click', () => sh.close());
  fs.forEach(f => f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); }));
}

// ── 1. profile ───────────────────────────────────────────
function stProfile(cx) {
  const a = S.acct;
  const name = h('h3', a.display);
  const fD = field({ label: t('f.display'), value: a.display, max: 64 });
  const fA = field({ label: t('f.about'), value: a.about, area: true, max: 140 });
  const save = h('button.btn', { type: 'button', disabled: true }, t('common.save'));
  const dirty = () => { save.disabled = fD.input.value.trim() === a.display && fA.input.value.trim() === a.about; };
  fD.input.addEventListener('input', dirty);
  fA.input.addEventListener('input', dirty);
  save.addEventListener('click', async () => {
    const d = fD.input.value.trim(), ab = fA.input.value.trim();
    if (!d || [...d].length > 64) return fD.error(t('err.display'));
    if ([...ab].length > 140) return fA.error(t('err.about_long'));
    busy(save, true);
    try { await eng.job('save_profile', { display: d, about: ab, particles: a.particles || 'dust' }); } catch (e) { busy(save, false); return fD.error(eng.err(e)); }
    busy(save, false);
    if (S.acct !== a) return;
    a.display = d; a.about = ab;
    fD.input.value = d; fA.input.value = ab; fD.count(); fA.count();
    name.textContent = d;
    dirty();
    flash(t('ok.saved'), 'ok', 2200);
    cx.api.refresh();
  });
  return [
    h('div.hud', mnFace(a.keys.ed), name, h('span.sub', '@' + a.username)),
    stBlock(null, h('div.grp', h('div.box', fD, fA, h('div.row2', save))), t('profile.note')),
  ];
}

// ── 2. account ───────────────────────────────────────────
function stAccount() {
  const a = S.acct;
  const lock = h('button.set.ico', { type: 'button' }, h('span.s-ico', ico('lock')), h('span.s-l', t('nav.lock')));
  lock.addEventListener('click', lockNow);
  return [
    h('div.grp',
      h('div.kv', h('span.t-label', t('f.username')), h('p', '@' + a.username)),
      h('div.kv', h('span.t-label', t('req.fingerprint')), h('p.t-fp', a.fp || ''))),
    h('div.grp', lock),
  ];
}

// ── 3. security and privacy ──────────────────────────────
function stPrivacy() {
  const a = S.acct;
  const pinBox = h('div.box');
  const act = (k, f) => { const b = h('button.btn.sm.ghost', { type: 'button' }, t(k)); b.addEventListener('click', f); return b; };
  const said = k => { flash(t(k), 'ok', 2400); draw(); };
  const setPin = () => stForm(t('priv.set_pin'), ['f.pin', 'f.pin_confirm'], t('common.save'), async ([p, again]) => {
    if (!ST_PIN.test(p)) return [0, t('err.pin_format')];
    if (p !== again) return [1, t('err.pin_mismatch')];
    try { await eng.job('pin_set', { pin: p, confirm: again }, m => m.pin); } catch (e) { return [0, eng.err(e)]; }
    return null;
  }, () => said('ok.pin_set'));
  const dropPin = () => {
    const gone = () => said('ok.pin_removed');
    // a PIN the server has already retired cannot be asked for
    if (a.pinGone) return gone();
    stForm(t('priv.remove_pin'), ['f.pin_current'], t('priv.remove_pin'), async ([p]) => {
      if (!ST_PIN.test(p)) return [0, t('err.pin_format')];
      try { await eng.job('pin_remove', { pin: p }, m => !m.pin); return null; } catch (e) { return [0, eng.err(e)]; }
    }, gone);
  };
  const setDuress = () => stForm(t('priv.set_duress'), ['f.pin_current', 'f.duress', 'f.pin_confirm'], t('common.save'), async ([cur, p, again]) => {
    if (!ST_PIN.test(cur)) return [0, t('err.pin_format')];
    if (!ST_PIN.test(p)) return [1, t('err.pin_format')];
    if (p === cur) return [1, t('err.duress_same')];
    if (p !== again) return [2, t('err.pin_mismatch')];
    try { await eng.job('duress_set', { pin: cur, duress: p }, m => m.duress); } catch (e) { return [1, eng.err(e)]; }
    return null;
  }, () => said('ok.duress_set'));
  const dropDuress = () => eng.job('duress_clear', {}, m => !m.duress).then(() => said('ok.duress_cleared'), e => flash(eng.err(e)));
  function draw() {
    const has = !!a.pin;
    pinBox.replaceChildren(
      ...(has ? [a.pinGone ? stStat('bad', 'warn', t('err.pin_gone')) : stStat('ok', 'check', t('priv.pin_on'))] : []),
      ...(has && a.duress ? [stStat('ok', 'check', t('priv.duress_on'))] : []),
      h('div.row2', has ? act('priv.remove_pin', dropPin) : act('priv.set_pin', setPin),
        has && !a.pinGone ? (a.duress ? act('priv.clear_duress', dropDuress) : act('priv.set_duress', setDuress)) : null));
  }
  draw();

  let pvT = 0;
  const savePriv = () => send('save_privacy', { idle_min: String(S.set.idle), protect: S.set.protect, app_lock: S.set.lock, lock_min: S.set.lockMin });
  const idle = field({ label: t('d.idle'), value: String(S.set.idle), inputmode: 'numeric', hardMax: 3, mono: true });
  idle.input.addEventListener('input', () => {
    const v = idle.input.value.trim();
    if (!/^\d{1,3}$/.test(v)) return;
    S.set.idle = +v; clearTimeout(pvT); pvT = setTimeout(savePriv, 700);
  });
  idle.input.addEventListener('change', () => { idle.input.value = String(S.set.idle); });
  const minRow = stCheck(t('priv.lock_min'), null, S.set.lockMin, v => { S.set.lockMin = v; savePriv(); });
  const dep = () => { idle.input.disabled = !S.set.lock; minRow.tg.disabled = !S.set.lock; };
  const lockRow = stCheck(t('priv.lock'), null, S.set.lock, v => { S.set.lock = v; dep(); savePriv(); });
  dep();

  return [
    stBlock(t('priv.pin'), h('div.grp', pinBox), t('priv.pin_note')),
    stBlock(t('priv.lock'), h('div.grp', lockRow, h('div.box', idle), minRow), t('priv.lock_note')),
    stBlock(null, h('div.grp', stCheck(t('priv.protect'), t('priv.protect_note'), S.set.protect, v => { S.set.protect = v; savePriv(); }))),
    stBlock(t('priv.lookup'), h('div.grp', stCheck(t('priv.hidden'), null, S.set.hidden, v => { S.set.hidden = v; send('save_hidden', { hidden: v }); })), t('priv.hidden_note')),
  ];
}

// ── 4. notifications ─────────────────────────────────────
function stNotify() {
  const a = S.acct;
  const dm = a.chats.find(c => c.kind === 'dm');
  const who = h('b'), text = h('p'), when = h('time');
  const card = h('div.notif', { 'aria-hidden': 'true' }, h('span.nk', ico('shield')), h('div', who, text), when);
  // the preview never invents a message: the text is shown as a bar, the sender is a contact
  // you really have (or a bar too)
  const draw = move => {
    const on = S.set.notify, named = on && S.set.notifyName;
    card.classList.toggle('off', !on);
    who.replaceChildren(named ? (dm ? mnTitle(dm) : h('i.bar.w40')) : 'Aegis');
    text.replaceChildren(named ? h('i.bar.w80') : t('notify.new'));
    when.textContent = hm(new Date());
    if (move) anim(card, [{ transform: 'translateY(-10px) scale(.97)', opacity: 0.2 }, { transform: 'none', opacity: on ? 1 : 0.35 }], { duration: 420, easing: E.scene });
  };
  const sv = () => send('save_notify', { on: S.set.notify, name: S.set.notifyName });
  const nameRow = stCheck(t('notify.name'), null, S.set.notifyName, v => { S.set.notifyName = v; sv(); draw(true); });
  const dep = () => { nameRow.tg.disabled = !S.set.notify; };
  const onRow = stCheck(t('notify.on'), null, S.set.notify, v => { S.set.notify = v; sv(); dep(); draw(true); });
  dep(); draw(false);
  return [
    h('div.grp', h('div.prev-wrap', card)),
    stBlock(null, h('div.grp', onRow, nameRow), t('notify.note')),
  ];
}

// ── 5. appearance ────────────────────────────────────────
function stLook(cx) {
  const a = S.acct;
  const radios = stRadios(t('f.particles'), Object.keys(ST_PFX).map(v => [v, t(ST_PFX[v])]), a.particles || 'dust', v => {
    store.set('particles', v); a.particles = v;
    send('save_profile', { display: a.display, about: a.about, particles: v });
    AegisScene.particles(v);
    cx.api.refresh();
  });
  const lang = h('div.seg.mono', { 'aria-label': t('set.language') },
    ['ru', 'en'].map(v => h('button', { type: 'button', 'data-v': v }, v.toUpperCase())));
  seg(lang, LANG, v => {
    LANG = v; store.set('lang', v); document.documentElement.lang = v; send('set_lang', { lang: v });
    // the shell is rebuilt in the new language and comes back to this section
    setTimeout(() => {
      if (!S.acct || scrName !== 'main') return;
      go('main', { tr: 'none' });
      mnSetView('settings');
      mnOpenSection('look');
    }, reduced ? 0 : 280);
  });
  return [
    ...stLookFx(cx),
    stBlock(t('f.particles'), h('div.grp', radios)),
    stBlock(null, h('div.grp', h('div.check', h('span', t('set.language'), h('small', t('set.lang_note'))), lang))),
  ];
}

// ── 6. network and Tor ───────────────────────────────────
/* what an observer of the line sees: without cover traffic the line is silent while you are
   not writing; with it, packets leave at an even pace whether you write or not */
function stCoverChart(cx, level) {
  const cv = h('canvas.cover', { role: 'img' });
  const gap = () => [0, 0.95, 0.38][level];
  let ticks = [], next = 0, last = 0, id = 0, w = 0, hgt = 0;
  const size = () => {
    const r = cv.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2);
    w = r.width; hgt = r.height;
    cv.width = Math.round(w * d); cv.height = Math.round(hgt * d);
    cv.getContext('2d').setTransform(d, 0, 0, d, 0, 0);
  };
  const paint = () => {
    const g = cv.getContext('2d'), mid = Math.round(hgt / 2) + 0.5;
    g.clearRect(0, 0, w, hgt);
    g.strokeStyle = '#26262b'; g.lineWidth = 1;
    g.beginPath(); g.moveTo(12, mid); g.lineTo(w - 12, mid); g.stroke();
    g.strokeStyle = '#eeeef1'; g.lineWidth = 2; g.lineCap = 'round';
    for (const k of ticks) {
      const x = w - 12 - k.age * 46;
      g.globalAlpha = Math.min(1, k.age * 5) * Math.min(1, Math.max(0, (x - 12) / 40)) * 0.85;
      g.beginPath(); g.moveTo(x, mid - 11); g.lineTo(x, mid + 11); g.stroke();
    }
    g.globalAlpha = 1;
  };
  const still = () => { ticks = []; if (level) for (let x = 0.2; x * 46 < w - 24; x += gap()) ticks.push({ age: x }); paint(); };
  const frame = now => {
    id = 0;
    if (!cv.isConnected) return;
    const dt = Math.min(0.1, (now - last) / 1000 || 0);
    last = now;
    ticks.forEach(k => { k.age += dt; });
    ticks = ticks.filter(k => k.age * 46 < w);
    if (level) { next -= dt; if (next <= 0) { ticks.push({ age: 0 }); next = gap(); } }
    paint();
    if (level || ticks.length) id = requestAnimationFrame(frame);
  };
  const wake = () => { if (reduced) return still(); if (!id) { last = performance.now(); id = requestAnimationFrame(frame); } };
  const ro = new ResizeObserver(() => { if (!cv.isConnected) return; size(); if (reduced) still(); else { paint(); wake(); } });
  ro.observe(cv);
  cx.off(() => { ro.disconnect(); cancelAnimationFrame(id); });
  cv.set = v => { level = v; next = 0; wake(); };
  return cv;
}
function stNet(cx) {
  const st = h('p.stat'), bar = h('div.torbar', h('i'));
  const shown = () => S.set.server;
  const conn = o => ({ endpoint: S.set.server, socks5: S.set.socks, tor: S.set.tor, cover: ST_COVER[S.set.cover] || 'std', bridges: S.set.bridges, bridge_lines: S.set.bridgeLines, ...o });
  const ep = field({ label: t('f.endpoint'), value: shown(), mono: true, inputmode: 'url' });
  const socks = field({ label: t('d.socks5'), value: S.set.socks, mono: true });
  const draw = () => {
    const k = !S.set.tor ? 'off' : S.tor.state;
    st.className = 'stat' + (k === 'ready' ? ' ok' : '');
    st.replaceChildren(ico(k === 'ready' ? 'check' : k === 'off' ? 'warn' : 'onion'),
      h('span', k === 'ready' ? t('conn.tor_ready') : k === 'off' ? t('conn.tor_off') : t('conn.tor_start') + ' · ' + S.tor.p + '%'));
    bar.hidden = k !== 'start';
    bar.style.setProperty('--p', S.tor.p / 100);
    socks.input.disabled = S.set.tor;
  };
  cx.off(bus.on('tor', draw));
  const torRow = stCheck(t('conn.tor'), null, S.set.tor, async v => {
    if (v) { S.set.tor = true; ep.input.value = shown(); ep.clear(); send('save_connection', conn()); return; }
    torRow.tg.set(true);
    const yes = await ask({ title: t('dlg.tor_off'), text: t('dlg.tor_off_text'), ok: t('dlg.tor_off_ok') });
    if (!yes || !S.acct) return;
    send('save_connection', conn({ tor: false })); send('confirm_tor_off');
    S.set.tor = false; torRow.tg.set(false); ep.input.value = shown(); ep.clear();
  });
  draw();

  // bridges
  const lines = field({ label: t('f.bridge_lines'), value: S.set.bridgeLines, area: true, mono: true });
  const keep = h('button.btn.sm', { type: 'button' }, t('common.save'));
  const lineBox = h('div.box', { hidden: S.set.bridges !== 'custom' }, lines, h('div.row2', keep));
  const brOpts = [['off', 'conn.bridges_off'], ['snowflake', 'conn.bridges_snowflake'], ['obfs4', 'conn.bridges_obfs4'], ['custom', 'conn.bridges_custom']];
  const bridges = stRadios(t('conn.bridges'), brOpts.map(([v, k]) => [v, t(k)]), S.set.bridges, v => {
    const open = v === 'custom';
    if (open !== !lineBox.hidden) {
      lineBox.hidden = !open;
      if (open) anim(lineBox, [{ opacity: 0, transform: 'translateY(-8px)' }, { opacity: 1, transform: 'none' }], { duration: 320, easing: E.out });
    }
    // own bridges take effect once their lines are saved
    if (open) return;
    S.set.bridges = v;
    send('save_connection', conn());
  });
  keep.addEventListener('click', async () => {
    const rows = lines.input.value.split('\n').map(x => x.trim()).filter(Boolean);
    if (!rows.length) return lines.error(t('err.bridges_empty'));
    if (rows.length > 20) return lines.error(t('err.bridges_many'));
    const bad = rows.findIndex(x => !ST_BRIDGE.test(x));
    if (bad >= 0) return lines.error(errText('err.bridge_line', bad + 1));
    busy(keep, true);
    try { await eng.job('save_connection', conn({ bridges: 'custom', bridge_lines: rows.join('\n') })); } catch (e) { busy(keep, false); return lines.error(eng.err(e)); }
    busy(keep, false);
    if (!S.acct) return;
    lines.input.value = S.set.bridgeLines;
    flash(t('ok.saved'), 'ok', 2200);
  });

  // server address, proxy, test
  const res = h('p.stat', { 'aria-live': 'polite', hidden: true });
  const say = (kind, icon, text) => { res.hidden = false; res.className = 'stat' + (kind ? ' ' + kind : ''); res.replaceChildren(...(icon ? [ico(icon)] : []), h('span', text)); };
  const save = h('button.btn.sm', { type: 'button' }, t('common.save'));
  const test = h('button.btn.sm.ghost', { type: 'button' }, t('set.test'));
  save.addEventListener('click', async () => {
    const url = stNorm(ep.input.value), sx = socks.input.value.trim();
    let ok = false;
    try { const u = new URL(url); ok = /^https?:$/.test(u.protocol) && !!u.hostname; } catch (e) { ok = false; }
    if (!ok) return ep.error(t('err.endpoint'));
    if (!S.set.tor && sx && !/^[^\s:/]+:\d{1,5}$/.test(sx)) return socks.error(t('err.socks'));
    busy(save, true);
    try { await eng.job('save_connection', conn({ endpoint: url, socks5: S.set.tor ? S.set.socks : sx })); } catch (e) { busy(save, false); return ep.error(eng.err(e)); }
    busy(save, false);
    if (!S.acct) return;
    res.hidden = true;
    flash(t('ok.saved'), 'ok', 2200);
  });
  test.addEventListener('click', async () => {
    say('', '', t('conn.running'));
    busy(test, true);
    let r = null;
    try { r = [true, await eng.job('test_conn', { endpoint: stNorm(ep.input.value), socks5: socks.input.value.trim(), tor: S.set.tor }, null, 60000)]; } catch (e) { r = [false, eng.err(e)]; }
    busy(test, false);
    if (!res.isConnected) return;
    if (r[0]) say('ok', 'check', r[1] || t('conn.ok')); else say('bad', 'warn', r[1]);
  });

  // cover traffic
  const chart = stCoverChart(cx, S.set.cover);
  const cvOpts = [['0', 'conn.cover_off'], ['1', 'conn.cover_std'], ['2', 'conn.cover_high']];
  const label = () => chart.setAttribute('aria-label', t('conn.cover') + ': ' + t(cvOpts[S.set.cover][1]));
  const cover = h('div.seg', { 'aria-label': t('conn.cover') }, cvOpts.map(([v, k]) => h('button', { type: 'button', 'data-v': v }, t(k))));
  seg(cover, String(S.set.cover), v => { S.set.cover = +v; chart.set(+v); label(); send('save_connection', conn()); });
  label();

  return [
    stBlock(null, h('div.grp', torRow, h('div.box', st, bar)), t('conn.tor_note')),
    stBlock(t('conn.bridges'), h('div.grp', bridges, lineBox), t('conn.bridges_note')),
    stBlock(t('d.server'), h('div.grp', h('div.box', ep, socks, h('div.row2', save, test), res)), t('set.conn_note')),
    stBlock(t('conn.cover'), h('div.grp', h('div.box', cover, chart)), t('conn.cover_note')),
  ];
}

// ── 7. backup and removal ────────────────────────────────
function stData() {
  const a = S.acct;
  const path = field({ label: t('f.export_path'), mono: true });
  const exp = h('button.btn.sm', { type: 'button' }, t('set.export'));
  exp.addEventListener('click', async () => {
    path.clear();
    busy(exp, true);
    try {
      path.ok(await eng.job('export', { path: path.input.value.trim() }, null, 120000));
    } catch (err) {
      path.error(eng.err(err));
    }
    busy(exp, false);
  });
  path.input.addEventListener('keydown', e => { if (e.key === 'Enter') exp.click(); });

  const del = h('button.btn.sm.danger', { type: 'button' }, t('d.delete_here'));
  del.addEventListener('click', async () => {
    const f = field({ label: t('f.confirm_name'), mono: true });
    f.check = () => {
      if (f.input.value.trim().replace(/^@/, '').toLowerCase() === a.username) return true;
      f.error(t('err.confirm_name'));
      return false;
    };
    const yes = await ask({ title: t('set.danger'), text: t('dlg.delete_account_text') + ' ' + a.username + '.', ok: t('d.delete_ok'), extra: f });
    if (!yes || S.acct !== a) return;
    send('open_dialog', { kind: 'delete_account' });
    send('delete_account', { confirm: a.username });
  });
  return [
    stBlock(null, h('div.grp', h('div.box', path, h('div.row2', exp))), t('set.backup_note')),
    stBlock(t('set.danger'), h('div.grp', h('div.box', h('p.note', t('set.delete_note')), h('div.row2', del)))),
  ];
}

// ── 8. about ─────────────────────────────────────────────
function stAbout() {
  const res = h('p.stat', { 'aria-live': 'polite', hidden: true });
  const chk = h('button.btn.sm.ghost', { type: 'button' }, t('upd.check'));
  chk.addEventListener('click', async () => {
    res.hidden = false; res.className = 'stat'; res.replaceChildren(h('span', t('upd.checking')));
    busy(chk, true);
    send('update_now');
    // a manual check also downloads; the build is ~16 MB in 1 MB chunks, slow over Tor, so show the progress
    const u = await eng.until(m => {
      if (/^Downloading/.test(m.update) && res.isConnected) res.replaceChildren(h('span', t('upd.downloading') + (m.update_pct != null ? ' · ' + m.update_pct + '%' : '')));
      return !/^(Idle|Checking|Downloading)/.test(m.update);
    }, 30 * 60000).then(m => m.update, () => 'Failed');
    busy(chk, false);
    if (!res.isConnected) return;
    const k = /^Current/.test(u) ? 'd.upd_none' : /^Ready/.test(u) ? 'upd.ready' : /^Available/.test(u) ? 'upd.available' : 'upd.failed';
    res.className = 'stat ' + (k === 'upd.failed' ? 'bad' : 'ok');
    res.replaceChildren(ico(k === 'upd.failed' ? 'warn' : 'check'), h('span', t(k)));
    if (k === 'upd.ready') { const ins = h('button.btn.sm', { type: 'button' }, t('upd.restart')); ins.addEventListener('click', () => send('install_update')); res.append(ins); }
  });
  return [
    h('div.grp',
      h('div.kv', h('span.t-label', t('upd.version')), h('p', 'Aegis ' + VERSION)),
      h('div.kv', h('p', t('set.about_text')), h('p.note', t('set.about_font')))),
    stBlock(t('upd.title'), h('div.grp',
      stCheck(t('upd.auto'), null, S.set.autoUpd, v => { S.set.autoUpd = v; send('save_updates', { auto_update: v }); }),
      h('div.box', h('div.row2', chk), res)), t('upd.note')),
  ];
}

const ST_BUILD = { profile: stProfile, account: stAccount, privacy: stPrivacy, notify: stNotify, look: stLook, net: stNet, data: stData, about: stAbout };

function stSection(id, api) {
  const s = ST_SECS.find(x => x.id === id) || ST_SECS[0];
  const offs = [];
  const back = h('button.ib.bare.back-phone', { type: 'button', 'aria-label': t('nav.settings') }, ico('back'));
  back.addEventListener('click', () => api.back());
  const blocks = ST_BUILD[s.id]({ api, off: f => offs.push(f) });
  const el = h('div.sec', { 'data-sec': s.id }, h('div.sec-in', h('div.sec-top', back, h('h2.t-sheet', t(s.k))), blocks));
  el._off = () => offs.forEach(f => f());
  // the blocks arrive as a ladder; the profile face is left alone, the avatar flies into it
  blocks.filter(b => b && !b.classList.contains('hud')).forEach((b, i) =>
    anim(b, [{ opacity: 0, transform: 'translateY(14px)' }, { opacity: 1, transform: 'none' }], { duration: 440, delay: 60 + i * 55, easing: E.out, fill: 'backwards' }));
  return el;
}

// ── look: theme, wallpaper, effects (the engine keeps them) ──
const ST_THEMES = ['mono', 'ocean', 'dusk', 'aurora', 'ember', 'slate'];
const ST_WALLS = ['none', 'solid', 'gradient', 'photo'];
const ST_FX = ['none', 'rain', 'snow', 'dust', 'embers', 'stars'];
function stLookFx(cx) {
  const L = () => S.look || {};
  const setL = (key, value) => send('set_look', { key, value: String(value) });
  const theme = h('div.seg.wrap', { 'aria-label': t('look.theme') }, ST_THEMES.map(v => h('button', { type: 'button', 'data-v': v }, t(`look.theme_${v}`))));
  const thS = seg(theme, L().theme || '', v => setL('theme', v));
  const walls = stRadios(t('look.wallpaper'), ST_WALLS.map(v => [v, t(`look.wallpaper_${v}`)]), L().wall || 'none', v => {
    if (v === 'photo') send('pick_wall'); else setL('wallpaper', v);
  });
  const pick = h('button.btn.sm.ghost', { type: 'button' }, t('look.photo_pick'));
  pick.addEventListener('click', () => send('pick_wall'));
  const scope = (key, cur) => {
    const b = h('div.seg', { 'aria-label': t('look.scope') }, ['chat', 'full'].map(v => h('button', { type: 'button', 'data-v': v }, t(`look.scope_${v}`))));
    b.s = seg(b, cur || 'chat', v => setL(key, v));
    return b;
  };
  const dim = h('input.range', { type: 'range', min: '0', max: '90', step: '1', value: String(L().dim || 0), 'aria-label': t('look.dim') });
  dim.addEventListener('input', () => ENTRY.style.setProperty('--dim', String(dim.value / 100)));
  dim.addEventListener('change', () => setL('wall_dim', dim.value));
  const fx = stRadios(t('look.effect'), ST_FX.map(v => [v, t(`look.fx_${v}`)]), L().fx || 'none', v => setL('effect', v));
  const anim = stCheck(t('look.animated'), null, !!L().animated, v => setL('animated', v ? 'on' : 'off'));
  const reset = h('button.btn.sm.ghost', { type: 'button' }, t('look.reset'));
  reset.addEventListener('click', () => send('reset_look'));
  const wS = scope('wall_scope', L().wall_scope), fS = scope('effect_scope', L().fx_scope);
  cx.off(bus.on('look', k => {
    walls.set(k.wall || 'none'); fx.set(k.fx || 'none');
    if (k.theme && thS.value !== k.theme) thS.set(k.theme, true);
    if (wS.s.value !== (k.wall_scope || 'chat')) wS.s.set(k.wall_scope || 'chat', true);
    if (fS.s.value !== (k.fx_scope || 'chat')) fS.s.set(k.fx_scope || 'chat', true);
    if (document.activeElement !== dim) dim.value = String(k.dim || 0);
  }));
  return [
    stBlock(t('look.theme'), h('div.grp', h('div.box', theme))),
    stBlock(t('look.wallpaper'), h('div.grp', walls, h('div.box', h('div.check', h('span', t('look.scope')), wS), h('label.check', h('span', t('look.dim')), dim), h('div.row2', pick)))),
    stBlock(t('look.effect'), h('div.grp', fx, h('div.box', h('div.check', h('span', t('look.scope')), fS)))),
    stBlock(null, h('div.grp', anim, h('div.box', h('div.row2', reset)))),
  ];
}
