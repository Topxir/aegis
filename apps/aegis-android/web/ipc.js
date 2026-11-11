'use strict';
// Android host: the same window.ipc the desktop shell has, plus a note when the entry closes.
window.ipc = { postMessage: s => window.aegisNative.postMessage(String(s)) };
addEventListener('DOMContentLoaded', () => {
  const e = document.getElementById('entry');
  new MutationObserver(() => { if (e.hidden) window.aegisNative.postMessage('{"cmd":"entry_done"}'); })
    .observe(e, { attributes: true, attributeFilter: ['hidden'] });
});
