'use strict';
window.ipc = { postMessage: s => window.aegisNative.postMessage(String(s)) };
let lastChat = null;
setInterval(() => {
  const e = window.aegisEntry;
  if (!e || !e.inChat) return;
  const c = e.inChat();
  if (lastChat && !c) window.ipc.postMessage(JSON.stringify({ cmd: 'nav', args: { to: 'list' } }));
  lastChat = c;
}, 300);
