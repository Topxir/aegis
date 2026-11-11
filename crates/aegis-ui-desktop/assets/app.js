'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var regions = ['auth', 'drawer', 'tabs', 'sidefoot', 'list', 'head', 'msgs', 'page', 'bar', 'info', 'overlay', 'toast', 'guide'];
  var last = {};
  var pkey = '';
  var lastPing = 0;
  var seen = Object.create(null);
  var fresh = true;
  var curTab = 'all';
  var lbl = { lookup: '', today: 'Today', yesterday: 'Yesterday' };
  var rm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');
  var look = null;
  var tiltEl = null;

  function send(cmd, args) {
    window.ipc.postMessage(JSON.stringify({ cmd: cmd, args: args || {} }));
  }

  function sameDay(a, b) { return a.toDateString() === b.toDateString(); }

  function fmtTime(ms, short) {
    var d = new Date(ms);
    if (isNaN(d.getTime())) { return ''; }
    var t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (sameDay(d, new Date())) { return t; }
    var ds = d.toLocaleDateString([], { day: 'numeric', month: 'short' });
    return short ? ds : ds + ' ' + t;
  }

  function stamp(root) {
    var els = root.querySelectorAll('time[data-ts]');
    for (var i = 0; i < els.length; i++) {
      els[i].textContent = fmtTime(Number(els[i].getAttribute('data-ts')), els[i].classList.contains('s'));
    }
  }

  function dayLabel(d) {
    var now = new Date();
    if (sameDay(d, now)) { return lbl.today; }
    var y = new Date(now.getTime() - 86400000);
    if (sameDay(d, y)) { return lbl.yesterday; }
    var o = { day: 'numeric', month: 'long' };
    if (d.getFullYear() !== now.getFullYear()) { o.year = 'numeric'; }
    return d.toLocaleDateString([], o);
  }

  function datePills(el) {
    var old = el.querySelectorAll('.dpill');
    for (var i = 0; i < old.length; i++) { old[i].remove(); }
    var ms = el.querySelectorAll('.m[data-ts]');
    var prev = null;
    for (var j = 0; j < ms.length; j++) {
      var d = new Date(Number(ms[j].getAttribute('data-ts')));
      if (isNaN(d.getTime())) { continue; }
      if (!prev || !sameDay(prev, d)) {
        var p = document.createElement('div');
        p.className = 'dpill';
        p.textContent = dayLabel(d);
        el.insertBefore(p, ms[j]);
      }
      prev = d;
    }
  }

  // ---- media ----------------------------------------------------------------

  function mediaKey(el) { return el.className + ' ' + el.getAttribute('data-media'); }

  function takeMedia(el) {
    var stash = {};
    var els = el.querySelectorAll('[data-media]');
    for (var i = 0; i < els.length; i++) {
      var n = els[i].querySelector('img,video');
      if (n) { stash[mediaKey(els[i])] = n; }
    }
    return stash;
  }

  function hydrate(root, stash) {
    var els = root.querySelectorAll('[data-media]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.querySelector('img,video')) { continue; }
      var url = el.getAttribute('data-media');
      var w = Number(el.getAttribute('data-w'));
      var h = Number(el.getAttribute('data-h'));
      if (w > 0 && h > 0 && el.classList.contains('media')) { el.style.aspectRatio = w + ' / ' + h; }
      var node = stash && stash[mediaKey(el)];
      if (!node) {
        if (el.hasAttribute('data-video')) {
          node = document.createElement('video');
          node.preload = 'metadata';
          node.muted = true;
          node.playsInline = true;
          node.src = url;
        } else {
          node = document.createElement('img');
          node.alt = '';
          node.decoding = 'async';
          node.src = url;
        }
        node.addEventListener('error', function (ev) {
          var p = ev.target.parentNode;
          if (p) { p.classList.add('broken'); }
        });
      }
      el.insertBefore(node, el.firstChild);
    }
  }

  function openLightbox(url, video) {
    var body = $('lbbody');
    body.textContent = '';
    var n;
    if (video) {
      n = document.createElement('video');
      n.controls = true;
      n.autoplay = true;
      n.playsInline = true;
    } else {
      n = document.createElement('img');
      n.alt = '';
    }
    n.src = url;
    body.appendChild(n);
    $('lightbox').hidden = false;
  }

  function closeLightbox() {
    var v = $('lbbody').querySelector('video');
    if (v) { v.pause(); v.removeAttribute('src'); v.load(); }
    $('lbbody').textContent = '';
    $('lightbox').hidden = true;
  }

  // ---- forms ----------------------------------------------------------------

  function saveForm(el) {
    var vals = {};
    var fields = el.querySelectorAll('input[name],textarea[name],select[name]');
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      if (f.type === 'checkbox') { vals[f.name + '=' + f.value] = f.checked; }
      else { vals[f.name] = f.value; }
    }
    var a = document.activeElement;
    var focus = null;
    if (a && el.contains(a) && a.name) {
      focus = { name: a.name, s: a.selectionStart, e: a.selectionEnd };
    }
    return { vals: vals, focus: focus };
  }

  function restoreForm(el, st) {
    var fields = el.querySelectorAll('input[name],textarea[name],select[name]');
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      if (f.type === 'checkbox') {
        var k = f.name + '=' + f.value;
        if (k in st.vals) { f.checked = st.vals[k]; }
      } else if (f.name in st.vals) {
        f.value = st.vals[f.name];
      }
    }
    if (st.focus) {
      var t = el.querySelector('[name="' + st.focus.name.replace(/"/g, '') + '"]');
      if (t) {
        t.focus();
        try { t.setSelectionRange(st.focus.s, st.focus.e); } catch (e) { /* not a text field */ }
      }
    }
  }

  // ---- sidebar --------------------------------------------------------------

  function query() { return $('filter').value.trim().replace(/^@/, '').toLowerCase(); }

  function applyFilter() {
    var q = query();
    var items = $('list').querySelectorAll('.item');
    for (var i = 0; i < items.length; i++) {
      var kindOk = curTab === 'all' || items[i].getAttribute('data-kind') === curTab;
      var hit = !q || (items[i].getAttribute('data-q') || '').indexOf(q) !== -1;
      items[i].hidden = !(kindOk && hit);
    }
    var lk = $('lookup');
    lk.hidden = !q;
    if (q) { lk.textContent = lbl.lookup + ' @' + q; }
  }

  function placeUl(animate) {
    var box = $('tabs');
    var ul = box.querySelector('.ul');
    var tbs = box.querySelectorAll('.tb');
    var on = null;
    for (var i = 0; i < tbs.length; i++) {
      var is = tbs[i].getAttribute('data-tab') === curTab;
      tbs[i].classList.toggle('on', is);
      if (is) { on = tbs[i]; }
    }
    if (!ul || !on) { return; }
    if (!animate) { ul.style.transition = 'none'; }
    ul.style.width = on.offsetWidth + 'px';
    ul.style.transform = 'translateX(' + on.offsetLeft + 'px)';
    if (!animate) { void ul.offsetWidth; ul.style.transition = ''; }
  }

  function doLookup() {
    var q = query();
    if (!q) { return; }
    $('filter').value = '';
    applyFilter();
    send('add_contact', { username: q });
  }

  function closeDrawer() {
    $('drawer').classList.remove('open');
    $('drawerscrim').hidden = true;
  }

  function toggleDrawer() {
    var open = !$('drawer').classList.contains('open');
    $('drawer').classList.toggle('open', open);
    $('drawerscrim').hidden = !open;
  }

  function closeMenus() {
    var ms = document.querySelectorAll('.menu');
    for (var i = 0; i < ms.length; i++) { ms[i].hidden = true; }
  }

  function applyMsgFilter() {
    var q = $('msgq').value.trim().toLowerCase();
    var ms = $('msgs').querySelectorAll('.m');
    for (var i = 0; i < ms.length; i++) {
      var t = ms[i].querySelector('.t');
      ms[i].hidden = !!q && !(t && t.textContent.toLowerCase().indexOf(q) !== -1);
    }
  }

  function closeMsgSearch() {
    $('msgbar').hidden = true;
    $('msgq').value = '';
    applyMsgFilter();
  }

  // ---- appearance -----------------------------------------------------------

  function motion() {
    if (rm && rm.matches) { return 'off'; }
    return look ? look.motion : 'subtle';
  }

  function stops(a, n) {
    var out = [];
    for (var i = 0; i < n; i++) { out.push(a[Math.min(i, a.length - 1)]); }
    return out;
  }

  var lookVars = ['--g1', '--g2', '--g3', '--a1', '--a2', '--a3', '--ink', '--on-accent', '--r', '--fs', '--listw', '--cols', '--rows', '--areas'];
  var lookAttrs = ['list', 'density', 'shape', 'wall', 'avatar', 'anim', 'depth'];

  function applyLook(k) {
    look = k || null;
    var r = document.documentElement;
    var st = r.style;
    r.setAttribute('data-motion', motion());
    if (!k) {
      for (var i = 0; i < lookVars.length; i++) { st.removeProperty(lookVars[i]); }
      for (var n = 0; n < lookAttrs.length; n++) { r.removeAttribute('data-' + lookAttrs[n]); }
      st.removeProperty('--wall-img');
      untilt();
      fxSet('none', 'chat');
      return;
    }
    var g = stops(k.bubble, 3);
    var a = stops(k.accent, 3);
    for (var j = 0; j < 3; j++) {
      st.setProperty('--g' + (j + 1), g[j]);
      st.setProperty('--a' + (j + 1), a[j]);
    }
    st.setProperty('--ink', k.ink);
    st.setProperty('--on-accent', k.on_accent);
    st.setProperty('--r', k.radius + 'px');
    st.setProperty('--fs', k.font + 'px');
    if (!drag) { st.setProperty('--listw', k.width + 'px'); }
    st.setProperty('--cols', k.cols);
    st.setProperty('--rows', k.rows);
    st.setProperty('--areas', k.areas);
    r.setAttribute('data-list', k.list);
    r.setAttribute('data-density', k.density);
    r.setAttribute('data-shape', k.shape);
    r.setAttribute('data-wall', k.wall);
    r.setAttribute('data-avatar', k.avatar);
    r.setAttribute('data-anim', k.animated ? 'on' : 'off');
    r.setAttribute('data-depth', k.depth ? 'on' : 'off');
    r.setAttribute('data-wscope', k.wall_scope || 'chat');
    st.setProperty('--dim', String((k.dim || 0) / 100));
    if (k.photo) { st.setProperty('--wall-img', 'url("' + k.photo + '")'); } else { st.removeProperty('--wall-img'); }
    if (!k.depth) { untilt(); }
    fxSet(motion() === 'off' ? 'none' : (k.fx || 'none'), k.fx_scope || 'chat');
  }

  // Screen effects: one canvas over the messages or over the whole window. Clicks pass through.
  var fx = { kind: 'none', scope: 'chat', cv: null, ps: [], raf: 0, w: 0, h: 0, last: 0 };

  function fxSet(kind, scope) {
    if (kind === fx.kind && scope === fx.scope) { return; }
    fx.kind = kind;
    fx.scope = scope;
    fx.ps = [];
    if (kind === 'none') {
      if (fx.cv) { fx.cv.hidden = true; }
      if (fx.raf) { cancelAnimationFrame(fx.raf); fx.raf = 0; }
      return;
    }
    if (!fx.cv) {
      fx.cv = document.createElement('canvas');
      fx.cv.className = 'fx';
      fx.cv.setAttribute('aria-hidden', 'true');
      document.body.appendChild(fx.cv);
    }
    fx.cv.hidden = false;
    if (!fx.raf) { fx.last = 0; fx.raf = requestAnimationFrame(fxFrame); }
  }

  function fxSpawn(top) {
    var w = fx.w, h = fx.h, k = fx.kind, R = Math.random;
    var p = { x: R() * w, y: top ? -10 : R() * h, a: R() * 6.28 };
    if (k === 'rain') { p.v = 520 + R() * 380; p.l = 10 + R() * 14; p.o = .18 + R() * .25; }
    else if (k === 'snow') { p.v = 28 + R() * 44; p.r = .8 + R() * 2.2; p.o = .35 + R() * .5; }
    else if (k === 'dust') { p.v = 4 + R() * 10; p.r = .5 + R() * 1.3; p.o = .12 + R() * .3; p.dx = (R() - .5) * 10; }
    else if (k === 'embers') { p.y = top ? h + 10 : p.y; p.v = -(24 + R() * 50); p.r = .7 + R() * 1.6; p.o = .4 + R() * .5; }
    else { p.v = 0; p.r = .4 + R() * 1.2; p.o = .2 + R() * .6; p.tw = .6 + R() * 2; }
    return p;
  }

  function fxFrame(t) {
    fx.raf = 0;
    if (fx.kind === 'none') { return; }
    fx.raf = requestAnimationFrame(fxFrame);
    if (document.hidden) { fx.last = 0; return; }
    var cv = fx.cv, x0 = 0, y0 = 0, w = innerWidth, h = innerHeight;
    if (fx.scope === 'chat') {
      var m = document.querySelector('#shell:not([hidden]) .msgs');
      var b = m && m.getBoundingClientRect();
      if (!b || b.width < 2) { cv.hidden = true; return; }
      x0 = b.left; y0 = b.top; w = b.width; h = b.height;
    }
    cv.hidden = false;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    if (fx.w !== w || fx.h !== h || cv.width !== Math.round(w * dpr)) {
      fx.w = w; fx.h = h;
      cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
      cv.style.width = w + 'px'; cv.style.height = h + 'px';
    }
    cv.style.transform = 'translate(' + x0 + 'px,' + y0 + 'px)';
    var dt = fx.last ? Math.min((t - fx.last) / 1000, .05) : 0;
    fx.last = t;
    var want = Math.round(w * h / ({ rain: 5200, snow: 7000, dust: 9000, embers: 16000, stars: 5000 }[fx.kind] || 8000));
    want = Math.min(want, 420);
    while (fx.ps.length < want) { fx.ps.push(fxSpawn(false)); }
    if (fx.ps.length > want) { fx.ps.length = want; }
    var c = cv.getContext('2d');
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, w, h);
    var k = fx.kind;
    for (var i = 0; i < fx.ps.length; i++) {
      var p = fx.ps[i];
      p.a += dt;
      if (k === 'rain') {
        p.y += p.v * dt; p.x -= p.v * dt * .12;
        c.strokeStyle = 'rgba(190, 205, 230,' + p.o + ')';
        c.lineWidth = 1;
        c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x + p.l * .12, p.y - p.l); c.stroke();
      } else if (k === 'stars') {
        c.fillStyle = 'rgba(235, 238, 255,' + (p.o * (.55 + .45 * Math.sin(p.a * p.tw))) + ')';
        c.fillRect(p.x, p.y, p.r * 1.6, p.r * 1.6);
        continue;
      } else {
        p.y += p.v * dt;
        p.x += (k === 'snow' ? Math.sin(p.a) * 18 : k === 'dust' ? p.dx : Math.sin(p.a * 2) * 12) * dt;
        c.fillStyle = k === 'embers' ? 'rgba(255, 120, 60,' + p.o + ')' : 'rgba(230, 232, 240,' + p.o + ')';
        c.beginPath(); c.arc(p.x, p.y, p.r, 0, 6.283); c.fill();
      }
      if (p.y > h + 20 || p.y < -30 || p.x < -30 || p.x > w + 30) { fx.ps[i] = fxSpawn(true); }
    }
  }

  function paintSwatches(root) {
    var sw = root.querySelectorAll('.sw[data-stops]');
    for (var i = 0; i < sw.length; i++) {
      var c = sw[i].querySelector('.swc');
      var v = sw[i].getAttribute('data-stops').split(' ').filter(function (x) { return /^#[0-9a-f]{6}$/i.test(x); });
      if (c && v.length) { c.style.background = 'linear-gradient(135deg, ' + stops(v, Math.max(v.length, 2)).join(', ') + ')'; }
    }
  }

  // Sliders and color pickers update the page while they move; the value is saved on change.
  function previewLook(el) {
    var key = el.getAttribute('data-look');
    var st = document.documentElement.style;
    if (key === 'radius' || key === 'font') {
      st.setProperty(key === 'radius' ? '--r' : '--fs', el.value + 'px');
      var rv = el.parentNode.querySelector('.rv');
      if (rv) { rv.textContent = el.value; }
    } else if (key === 'wall_dim') {
      st.setProperty('--dim', String(el.value / 100));
      var dv = el.parentNode.querySelector('.rv');
      if (dv) { dv.textContent = el.value; }
    } else if (/^c[123]$/.test(key)) {
      st.setProperty('--g' + key.charAt(1), el.value);
      st.setProperty('--a' + key.charAt(1), el.value);
    }
  }

  function untilt() {
    if (tiltEl) { tiltEl.style.transform = ''; tiltEl.classList.remove('tilt'); tiltEl = null; }
  }

  function tilt(e) {
    if (!look || !look.depth || motion() === 'off') { return; }
    var t = e.target.closest && e.target.closest('.bubble, .card, .item');
    if (t !== tiltEl) { untilt(); }
    if (!t) { return; }
    var b = t.getBoundingClientRect();
    if (!b.width || !b.height) { return; }
    var x = (e.clientX - b.left) / b.width - 0.5;
    var y = (e.clientY - b.top) / b.height - 0.5;
    var max = t.classList.contains('card') ? 1.5 : 3;
    tiltEl = t;
    t.classList.add('tilt');
    t.style.transform = 'perspective(800px) rotateX(' + (-y * max).toFixed(2) + 'deg) rotateY(' + (x * max).toFixed(2) + 'deg)';
  }

  function enter(el) {
    if (motion() === 'off') { return; }
    el.classList.remove('enter');
    void el.offsetWidth;
    el.classList.add('enter');
  }

  // ---- list width -----------------------------------------------------------

  var drag = null;

  function gripDown(e) {
    if (!look || look.list === 'top') { return; }
    e.preventDefault();
    drag = { side: document.querySelector('.side').getBoundingClientRect(), right: look.list === 'right', w: look.width };
    $('grip').setPointerCapture(e.pointerId);
    $('grip').classList.add('drag');
  }

  function gripMove(e) {
    if (!drag) { return; }
    var w = drag.right ? drag.side.right - e.clientX : e.clientX - drag.side.left;
    drag.w = Math.round(Math.max(260, Math.min(520, w)));
    document.documentElement.style.setProperty('--listw', drag.w + 'px');
  }

  function gripUp() {
    if (!drag) { return; }
    var w = drag.w;
    drag = null;
    $('grip').classList.remove('drag');
    if (look && w !== look.width) { send('set_look', { key: 'list_width', value: w }); }
  }

  // ---- tour -----------------------------------------------------------------

  function placeGuide(focus) {
    var g = $('guide');
    var card = g.querySelector('.gcard');
    if (!card) { g.classList.remove('aimed'); return; }
    var sel = card.getAttribute('data-target');
    var t = sel ? document.querySelector(sel) : null;
    var b = t ? t.getBoundingClientRect() : null;
    if (b && b.width && b.height) {
      var ring = g.querySelector('.gring');
      var pad = 6;
      ring.style.left = (b.left - pad) + 'px';
      ring.style.top = (b.top - pad) + 'px';
      ring.style.width = (b.width + pad * 2) + 'px';
      ring.style.height = (b.height + pad * 2) + 'px';
      g.classList.add('aimed');
      var cw = card.offsetWidth;
      var ch = card.offsetHeight;
      var top = b.bottom + 16;
      if (top + ch > window.innerHeight - 16) { top = Math.max(16, b.top - ch - 16); }
      card.style.left = Math.max(16, Math.min(window.innerWidth - cw - 16, b.left)) + 'px';
      card.style.top = top + 'px';
    } else {
      g.classList.remove('aimed');
      card.style.left = '';
      card.style.top = '';
    }
    if (focus) {
      var p = card.querySelector('[data-primary]');
      if (p) { p.focus(); }
    }
  }

  // ---- regions --------------------------------------------------------------

  function setRegion(id, html, keep) {
    var el = $(id);
    if (last[id] === html) { return; }
    last[id] = html;
    var st = keep ? saveForm(el) : null;
    var stash = (id === 'msgs' || id === 'info' || id === 'page') ? takeMedia(el) : null;
    var scroll = el.scrollTop;
    var stick = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    var fl = (id === 'list' || id === 'msgs') && motion() !== 'off' ? snap(el, id === 'list' ? '.item[data-id]' : '.m[data-mid]', id === 'list' ? 'data-id' : 'data-mid') : null;
    el.innerHTML = html;
    if (fl) { play(el, fl, id === 'msgs'); }
    if (id === 'head' && motion() !== 'off') { decode(el.querySelector('.t1')); }
    stamp(el);
    if (st) { restoreForm(el, st); }
    if (stash) { hydrate(el, stash); }
    if (id === 'msgs') {
      datePills(el);
      applyMsgFilter();
      el.scrollTop = (stick || !keep) ? el.scrollHeight : scroll;
    } else {
      el.scrollTop = scroll;
    }
    if (id === 'page') { paintSwatches(el); }
    if (id === 'guide') { placeGuide(true); }
    if (id === 'overlay' && html) {
      var first = el.querySelector('input,button[data-primary]');
      if (first) { first.focus(); }
    }
    if (id === 'list') { applyFilter(); }
    if (id === 'tabs') { placeUl(false); }
    if (id === 'msgs') { markArrivals(el); }
    if (id === 'auth') {
      // the entrance animation plays once per visit to the sign-in screen
      if (!html) { el.classList.remove('shown', 'played'); }
      else if (el.classList.contains('shown')) { el.classList.add('played'); }
      else { el.classList.add('shown'); }
    }
  }

  // Only messages that were not on screen before get the entrance animation.
  // Motion: nodes are only moved, never built here. Lists slide to their new places,
  // removed messages burn away, chat titles resolve from noise.
  function snap(el, sel, attr) {
    var out = {}, ns = el.querySelectorAll(sel);
    for (var i = 0; i < ns.length; i++) {
      var r = ns[i].getBoundingClientRect();
      if (!r.width || r.bottom < 0 || r.top > innerHeight) { continue; }
      out[ns[i].getAttribute(attr)] = { r: r, n: ns[i] };
    }
    out._sel = sel; out._attr = attr;
    return out;
  }

  function play(el, before, burn) {
    var ns = el.querySelectorAll(before._sel), keep = {}, moved = 0;
    for (var i = 0; i < ns.length; i++) {
      var k = ns[i].getAttribute(before._attr), b = before[k];
      keep[k] = true;
      if (!b) { continue; }
      moved++;
      var r = ns[i].getBoundingClientRect(), dy = b.r.top - r.top;
      if (Math.abs(dy) > 1 && Math.abs(dy) < innerHeight && !burn) {
        ns[i].animate([{ transform: 'translateY(' + dy + 'px)' }, { transform: 'none' }], { duration: 420, easing: 'cubic-bezier(.2,.8,.2,1)' });
      }
    }
    if (!burn || !moved) { return; }
    var gone = 0;
    for (var key in before) {
      if (key.charAt(0) === '_' || keep[key] || ++gone > 6) { continue; }
      var g = before[key].n.cloneNode(true), rr = before[key].r;
      g.classList.add('ash');
      g.style.left = rr.left + 'px'; g.style.top = rr.top + 'px'; g.style.width = rr.width + 'px';
      document.body.appendChild(g);
      g.animate([{ opacity: 1, filter: 'blur(0)', transform: 'none' },
        { opacity: .6, filter: 'blur(1px) sepia(1) saturate(4) hue-rotate(-30deg)', transform: 'translateY(-4px)', offset: .3 },
        { opacity: 0, filter: 'blur(6px)', transform: 'translateY(-26px) scale(.96)' }],
        { duration: 900, easing: 'cubic-bezier(.3,0,.2,1)' }).finished.then(remover(g), remover(g));
    }
  }

  function remover(g) { return function () { g.remove(); }; }

  var glyphs = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#%&@';
  function decode(t) {
    if (!t || t.dataset.dec === t.textContent) { return; }
    var txt = t.textContent, n = 0, steps = 14;
    t.dataset.dec = txt;
    (function tick() {
      if (t.dataset.dec !== txt) { return; }
      n++;
      var k = Math.floor(txt.length * n / steps), out = txt.slice(0, k);
      for (var i = k; i < txt.length; i++) { out += txt[i] === ' ' ? ' ' : glyphs[(Math.random() * glyphs.length) | 0]; }
      t.textContent = out;
      if (n < steps) { requestAnimationFrame(tick); } else { t.textContent = txt; }
    })();
  }

  function markArrivals(el) {
    var ms = el.querySelectorAll('.m[data-mid]');
    for (var i = 0; i < ms.length; i++) {
      var k = ms[i].getAttribute('data-mid');
      if (!fresh && !seen[k]) { ms[i].classList.add('new'); }
      seen[k] = true;
    }
  }

  function syncSend() {
    $('send').hidden = !$('input').value.trim();
  }

  function render(s) {
    document.documentElement.lang = s.lang;
    if (window.aegisEntry) {
      window.aegisEntry.update(s);
      document.getElementById('auth').hidden = true;
    }
    applyLook(s.look);
    var changedPage = s.pkey !== pkey;
    pkey = s.pkey;
    lbl.lookup = s.lbl_lookup || '';
    lbl.today = s.lbl_today || lbl.today;
    lbl.yesterday = s.lbl_yesterday || lbl.yesterday;
    $('auth').hidden = s.authed;
    $('shell').hidden = !s.authed;
    $('msgs').hidden = !s.chat;
    $('page').hidden = s.chat;
    $('composer').hidden = !s.compose;
    $('bar').hidden = !s.bar;
    $('info').hidden = !s.info;
    $('shell').classList.toggle('wi', !!s.info);
    $('overlay').hidden = !s.overlay;
    $('guide').hidden = !s.guide;
    $('filter').placeholder = s.ph_filter;
    $('filter').setAttribute('aria-label', s.ph_filter);
    $('msgq').placeholder = s.ph_msgq;
    $('msgq').setAttribute('aria-label', s.ph_msgq);
    $('input').placeholder = s.ph_msg;
    $('input').setAttribute('aria-label', s.ph_msg);
    $('send').setAttribute('aria-label', s.lbl_send);
    $('send').title = s.lbl_send;
    $('attach').setAttribute('aria-label', s.lbl_attach);
    $('attach').title = s.lbl_attach;
    $('burger').setAttribute('aria-label', s.lbl_menu);
    if (changedPage) {
      seen = Object.create(null);
      fresh = true;
      last.msgs = null;
      last.page = null;
      $('input').value = '';
      syncSend();
      closeDrawer();
      closeMenus();
      closeMsgSearch();
    }
    for (var i = 0; i < regions.length; i++) {
      var r = regions[i];
      setRegion(r, s[r] || '', !changedPage || r === 'auth' || r === 'toast');
    }
    fresh = false;
    if (changedPage && s.authed) { enter(s.chat ? $('msgs') : $('page')); }
    $('hint').textContent = s.hint || '';
    if (changedPage && s.compose) { $('input').focus(); }
  }

  window.aegis = { render: render };

  function collect(scope, el) {
    var args = {};
    var ds = el.dataset;
    for (var k in ds) {
      if (k !== 'act' && k !== 'q' && k !== 'scope' && k !== 'primary') { args[k] = ds[k]; }
    }
    if (scope) {
      var fields = scope.querySelectorAll('input[name],textarea[name],select[name]');
      for (var i = 0; i < fields.length; i++) {
        var f = fields[i];
        var n = f.name;
        if (f.disabled) { continue; }
        if (n.slice(-2) === '[]') {
          n = n.slice(0, -2);
          if (!args[n]) { args[n] = []; }
          if (f.checked) { args[n].push(f.value); }
        } else if (f.type === 'checkbox') {
          args[n] = f.checked;
        } else {
          args[n] = f.value;
        }
      }
    }
    return args;
  }

  function grow(t) {
    t.style.height = 'auto';
    t.style.height = Math.min(t.scrollHeight, 160) + 'px';
  }

  function sendInput() {
    var i = $('input');
    var v = i.value;
    if (!v.trim()) { return; }
    i.value = '';
    grow(i);
    syncSend();
    send('send', { text: v });
  }

  function act(el) {
    var name = el.getAttribute('data-act');
    if (name === 'send_current') { sendInput(); return; }
    send(name, collect(el.closest('[data-scope]'), el));
  }

  function ui(el) {
    var what = el.getAttribute('data-ui');
    if (what === 'drawer') { toggleDrawer(); }
    else if (what === 'tab') {
      curTab = el.getAttribute('data-tab') || 'all';
      placeUl(true);
      applyFilter();
    }
    else if (what === 'lookup') { doLookup(); }
    else if (what === 'menu') {
      var m = el.parentNode.querySelector('.menu');
      if (m) { var open = m.hidden; closeMenus(); m.hidden = !open; }
    }
    else if (what === 'msgsearch') {
      var bar = $('msgbar');
      bar.hidden = !bar.hidden;
      if (bar.hidden) { closeMsgSearch(); } else { $('msgq').focus(); }
    }
    else if (what === 'lbclose') { closeLightbox(); }
    else if (what === 'copy') {
      var c = el.parentNode.querySelector('input');
      if (c) { c.select(); document.execCommand('copy'); }
    }
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    if (!t.closest) { return; }
    if (t.id === 'lightbox') { closeLightbox(); return; }
    var uiEl = t.closest('[data-ui]');
    if (uiEl) { e.preventDefault(); ui(uiEl); return; }
    var el = t.closest('[data-act]');
    if (el && !el.disabled) {
      e.preventDefault();
      closeDrawer();
      closeMenus();
      act(el);
      return;
    }
    var mEl = t.closest('[data-media]');
    if (mEl && !mEl.classList.contains('broken')) {
      e.preventDefault();
      openLightbox(mEl.getAttribute('data-media'), mEl.hasAttribute('data-video'));
      return;
    }
    if (!t.closest('.menuwrap')) { closeMenus(); }
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
    var lk = el.getAttribute && el.getAttribute('data-look');
    if (lk) {
      send('set_look', { key: lk, value: el.type === 'checkbox' ? el.checked : el.value });
      return;
    }
    var cmd = el.getAttribute && el.getAttribute('data-change');
    if (!cmd) { return; }
    var key = el.getAttribute('data-key');
    var v = el.type === 'checkbox' ? el.checked : el.value;
    if (key === 'ttl') { v = Number(v); }
    var a = {};
    a[key] = v;
    send(cmd, a);
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      if (!$('lightbox').hidden) { closeLightbox(); return; }
      if (!$('guide').hidden) { send('guide', { step: 'skip' }); return; }
      if (!$('overlay').hidden) { send('close_dialog'); return; }
      if ($('drawer').classList.contains('open')) { closeDrawer(); return; }
      if (!$('msgbar').hidden) { closeMsgSearch(); return; }
      closeMenus();
      return;
    }
    if (e.key !== 'Enter' || e.isComposing) { return; }
    var t = e.target;
    if (t.id === 'input') {
      if (!e.shiftKey) { e.preventDefault(); sendInput(); }
      return;
    }
    if (t.id === 'filter') { e.preventDefault(); doLookup(); return; }
    if (t.id === 'msgq') { e.preventDefault(); return; }
    if (t.tagName === 'INPUT' && t.type !== 'checkbox') {
      var scope = t.closest('[data-scope]');
      var p = scope && scope.querySelector('[data-primary]');
      if (p && !p.disabled) { e.preventDefault(); act(p); }
    }
  });

  document.addEventListener('input', function (e) {
    if (e.target.getAttribute && e.target.getAttribute('data-look')) { previewLook(e.target); }
    if (e.target.id === 'input') { grow(e.target); syncSend(); }
    if (e.target.id === 'filter') { applyFilter(); }
    if (e.target.id === 'msgq') { applyMsgFilter(); }
  });

  function activity() {
    var n = Date.now();
    if (n - lastPing > 5000) { lastPing = n; send('ping'); }
  }
  ['keydown', 'mousedown', 'mousemove', 'wheel'].forEach(function (ev) {
    document.addEventListener(ev, activity, { passive: true });
  });

  window.addEventListener('resize', function () { placeUl(false); placeGuide(false); });
  document.addEventListener('pointermove', tilt, { passive: true });
  document.addEventListener('pointerleave', untilt);
  $('grip').addEventListener('pointerdown', gripDown);
  $('grip').addEventListener('pointermove', gripMove);
  $('grip').addEventListener('pointerup', gripUp);
  $('grip').addEventListener('pointercancel', gripUp);
  if (rm && rm.addEventListener) { rm.addEventListener('change', function () { applyLook(look); }); }

  document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  document.addEventListener('dragover', function (e) { e.preventDefault(); });
  document.addEventListener('drop', function (e) { e.preventDefault(); });

  send('ready', { lang: 'en' });
})();
