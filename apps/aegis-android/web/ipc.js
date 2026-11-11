'use strict';
window.ipc = { postMessage: s => window.aegisNative.postMessage(String(s)) };
const ipcSend = (cmd, args) => window.ipc.postMessage(JSON.stringify({ cmd, args }));
let ipcErr = 0;
const ipcFail = msg => { if (Date.now() - ipcErr > 5000) { ipcErr = Date.now(); ipcSend('js_error', { msg: String(msg) }); } };
addEventListener('error', e => ipcFail(e.message + ' @' + (e.filename || '').split('/').pop() + ':' + e.lineno));
addEventListener('unhandledrejection', e => { if (e.reason instanceof Error) ipcFail(e.reason.message); });
let lastChat = null;
setInterval(() => {
  const e = window.aegisEntry;
  if (!e || !e.inChat) return;
  const c = e.inChat();
  if (c === lastChat) return;
  ipcSend('viewing', { on: c });
  if (lastChat && !c) ipcSend('nav', { to: 'list' });
  lastChat = c;
}, 300);
