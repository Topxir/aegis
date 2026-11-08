'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var regions = ['auth', 'drawer', 'tabs', 'sidefoot', 'list', 'head', 'msgs', 'page', 'bar', 'info', 'overlay', 'toast'];
  var last = {};
  var pkey = '';
  var lastPing = 0;
  var seen = Object.create(null);
  var fresh = true;
  var curTab = 'all';
  var lbl = { lookup: '', today: 'Today', yesterday: 'Yesterday' };
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

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

  // ---- particles ------------------------------------------------------------

  function seed(i) {
    var x = Math.sin(i * 127.1 + 311.7) * 43758.5453;
    return x - Math.floor(x);
  }

  function particles(root) {
    var bs = root.querySelectorAll('.pbanner');
    for (var i = 0; i < bs.length; i++) {
      var b = bs[i];
      var kind = b.getAttribute('data-particles') || 'none';
      if (b.getAttribute('data-built') === kind) { continue; }
      b.textContent = '';
      b.setAttribute('data-built', kind);
      if (kind === 'none' || reduce) { continue; }
      for (var k = 0; k < 22; k++) {
        var s = document.createElement('span');
        s.className = 'pt';
        s.style.left = (seed(k + 1) * 100).toFixed(1) + '%';
        s.style.top = (seed(k + 41) * 100).toFixed(1) + '%';
        var size = 2 + seed(k + 81) * 3;
        s.style.width = size.toFixed(1) + 'px';
        s.style.height = size.toFixed(1) + 'px';
        s.style.animationDelay = (-seed(k + 121) * 8).toFixed(2) + 's';
        s.style.animationDuration = (5 + seed(k + 161) * 6).toFixed(2) + 's';
        b.appendChild(s);
      }
    }
  }

  function syncLive(root) {
    var sel = root.querySelectorAll('[data-live="particles"]');
    for (var i = 0; i < sel.length; i++) {
      var scope = sel[i].closest('[data-scope]') || root;
      var b = scope.querySelector('.pbanner.live');
      if (b) { b.setAttribute('data-particles', sel[i].value); }
    }
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

  // ---- regions --------------------------------------------------------------

  function setRegion(id, html, keep) {
    var el = $(id);
    if (last[id] === html) { return; }
    last[id] = html;
    var st = keep ? saveForm(el) : null;
    var stash = (id === 'msgs' || id === 'info' || id === 'page') ? takeMedia(el) : null;
    var scroll = el.scrollTop;
    var stick = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    el.innerHTML = html;
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
    if (id === 'page' || id === 'info') { syncLive(el); particles(el); }
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
    if (el.getAttribute && el.getAttribute('data-live')) { syncLive(document); particles(document); return; }
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

  window.addEventListener('resize', function () { placeUl(false); });

  document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  document.addEventListener('dragover', function (e) { e.preventDefault(); });
  document.addEventListener('drop', function (e) { e.preventDefault(); });

  send('ready', { lang: 'en' });
})();
