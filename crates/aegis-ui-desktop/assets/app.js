'use strict';
(function () {
  var $ = function (id) { return document.getElementById(id); };
  var regions = ['auth', 'sidetop', 'sideme', 'sidefoot', 'list', 'head', 'msgs', 'page', 'overlay', 'toast'];
  var last = {};
  var pkey = '';
  var lastPing = 0;
  var seen = Object.create(null);
  var fresh = true;

  function send(cmd, args) {
    window.ipc.postMessage(JSON.stringify({ cmd: cmd, args: args || {} }));
  }

  function fmtTime(ms) {
    var d = new Date(ms);
    if (isNaN(d.getTime())) { return ''; }
    var t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (d.toDateString() === new Date().toDateString()) { return t; }
    return d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ' ' + t;
  }

  function stamp(root) {
    var els = root.querySelectorAll('time[data-ts]');
    for (var i = 0; i < els.length; i++) {
      els[i].textContent = fmtTime(Number(els[i].getAttribute('data-ts')));
    }
  }

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

  function applyFilter() {
    var q = $('filter').value.trim().toLowerCase();
    var items = $('list').querySelectorAll('.item');
    for (var i = 0; i < items.length; i++) {
      var hit = !q || (items[i].getAttribute('data-q') || '').indexOf(q) !== -1;
      items[i].hidden = !hit;
    }
  }

  function setRegion(id, html, keep) {
    var el = $(id);
    if (last[id] === html) { return; }
    last[id] = html;
    var st = keep ? saveForm(el) : null;
    var scroll = el.scrollTop;
    var stick = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    el.innerHTML = html;
    stamp(el);
    if (st) { restoreForm(el, st); }
    if (id === 'msgs') {
      el.scrollTop = (stick || !keep) ? el.scrollHeight : scroll;
    } else {
      el.scrollTop = scroll;
    }
    if (id === 'overlay' && html) {
      var first = el.querySelector('input,button[data-primary]');
      if (first) { first.focus(); }
    }
    if (id === 'list') { applyFilter(); }
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

  function render(s) {
    document.documentElement.lang = s.lang;
    var changedPage = s.pkey !== pkey;
    pkey = s.pkey;
    $('auth').hidden = s.authed;
    $('shell').hidden = !s.authed;
    $('msgs').hidden = !s.chat;
    $('page').hidden = s.chat;
    $('composer').hidden = !s.chat;
    $('overlay').hidden = !s.overlay;
    $('filter').placeholder = s.ph_filter;
    $('filter').setAttribute('aria-label', s.ph_filter);
    $('input').placeholder = s.ph_msg;
    $('input').setAttribute('aria-label', s.ph_msg);
    $('send').setAttribute('aria-label', s.lbl_send);
    $('send').title = s.lbl_send;
    if (changedPage) {
      seen = Object.create(null);
      fresh = true;
      last.msgs = null;
      last.page = null;
      $('input').value = '';
    }
    for (var i = 0; i < regions.length; i++) {
      var r = regions[i];
      setRegion(r, s[r] || '', !changedPage || r === 'auth' || r === 'toast');
    }
    fresh = false;
    $('hint').textContent = s.hint || '';
    if (changedPage && s.chat) { $('input').focus(); }
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
    send('send', { text: v });
  }

  function act(el) {
    var name = el.getAttribute('data-act');
    if (name === 'send_current') { sendInput(); return; }
    send(name, collect(el.closest('[data-scope]'), el));
  }

  document.addEventListener('click', function (e) {
    var el = e.target.closest ? e.target.closest('[data-act]') : null;
    if (el && !el.disabled) { e.preventDefault(); act(el); }
  });

  document.addEventListener('change', function (e) {
    var el = e.target;
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
      if (!$('overlay').hidden) { send('close_dialog'); }
      return;
    }
    if (e.key !== 'Enter' || e.isComposing) { return; }
    var t = e.target;
    if (t.id === 'input') {
      if (!e.shiftKey) { e.preventDefault(); sendInput(); }
      return;
    }
    if (t.tagName === 'INPUT' && t.type !== 'checkbox' && t.id !== 'filter') {
      var scope = t.closest('[data-scope]');
      var p = scope && scope.querySelector('[data-primary]');
      if (p && !p.disabled) { e.preventDefault(); act(p); }
    }
  });

  document.addEventListener('input', function (e) {
    if (e.target.id === 'input') { grow(e.target); }
    if (e.target.id === 'filter') { applyFilter(); }
  });

  function activity() {
    var n = Date.now();
    if (n - lastPing > 5000) { lastPing = n; send('ping'); }
  }
  ['keydown', 'mousedown', 'mousemove', 'wheel'].forEach(function (ev) {
    document.addEventListener(ev, activity, { passive: true });
  });

  document.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  document.addEventListener('dragover', function (e) { e.preventDefault(); });
  document.addEventListener('drop', function (e) { e.preventDefault(); });

  send('ready', { lang: 'en' });
})();
