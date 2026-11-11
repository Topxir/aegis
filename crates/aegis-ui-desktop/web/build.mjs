// Builds assets/entry.js and assets/entry.css from web/src (sign-in screens, 3D scene).
// Usage: node web/build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const root = dirname(fileURLToPath(import.meta.url));
const src = f => readFileSync(join(root, 'src', f), 'utf8');
const out = f => join(root, '..', 'assets', f);

const I18N = { ...JSON.parse(src('strings.json')), ...JSON.parse(src('design-strings.json')) };
const LS = new RegExp(String.fromCharCode(0x2028, 124, 0x2029), 'g');
const i18nJson = JSON.stringify(I18N).replace(/</g, '\\u003c').replace(LS, c => '\\u' + c.charCodeAt(0).toString(16));

const ICONS = JSON.parse(src('icons.json'));
const sprite = '<svg xmlns="http://www.w3.org/2000/svg" class="sprite" aria-hidden="true" focusable="false">'
  + Object.entries(ICONS).map(([n, d]) => `<symbol id="i-${n}" viewBox="0 0 24 24">${d}</symbol>`).join('') + '</svg>';

// ── CSS: every rule is scoped to #entry so it cannot touch the messenger shell ──
const SCOPE = '#entry';
function scopeSel(sel) {
  return sel.split(',').map(s => {
    s = s.trim();
    if (!s || s.startsWith(SCOPE)) return s;
    if (/^(html|:root|body)$/.test(s) || s === 'html, body') return SCOPE;
    if (/^html\.(\w+)\s+(.*)$/.test(s)) return s.replace(/^html\.(\w+)\s+/, `html.$1 ${SCOPE} `);
    if (/^(html|body)\s+/.test(s)) return s.replace(/^(html|body)\s+/, SCOPE + ' ');
    if (/^:root/.test(s)) return s.replace(/^:root/, SCOPE);
    return SCOPE + ' ' + s;
  }).join(', ');
}
function scopeCss(css) {
  let i = 0, res = '';
  const n = css.length;
  while (i < n) {
    const open = css.indexOf('{', i);
    if (open < 0) { res += css.slice(i); break; }
    const head = css.slice(i, open).trim();
    let depth = 1, j = open + 1;
    while (j < n && depth) { if (css[j] === '{') depth++; else if (css[j] === '}') depth--; j++; }
    const body = css.slice(open + 1, j - 1);
    if (/^@(media|supports)/.test(head)) res += `${head}{${scopeCss(body)}}\n`;
    else if (head.startsWith('@')) res += `${head}{${body}}\n`;
    else res += `${scopeSel(head)}{${body}}\n`;
    i = j;
  }
  return res;
}
const strip = s => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\n\s*\n+/g, '\n');
let css = ['tokens.css', 'ui.css', 'fx.css', 'screens.css', 'bridge.css'].map(f => strip(src(f))).join('\n');
const frames = [...css.matchAll(/@keyframes\s+([\w-]+)/g)].map(m => m[1]);
for (const k of new Set(frames)) {
  css = css.replace(new RegExp(`(@keyframes\\s+)${k}\\b`, 'g'), `$1e-${k}`)
    .replace(new RegExp(`(animation(?:-name)?\\s*:[^;}]*?)(?<![\\w-])${k}(?![\\w-])`, 'g'), `$1e-${k}`);
}
css = scopeCss(css);
writeFileSync(out('entry.css'), css);

// ── JS: one closure; only window.aegisEntry leaves it ──
const files = ['core.js', 'scene3d.js', 'entry.js', 'bridge.js'];
let js = files.map(f => `// ${f}\n` + src(f).replace(/^'use strict';\n/, '')).join('\n');
js = js.replace('__I18N__', () => i18nJson).replace('__SPRITE__', () => JSON.stringify(sprite));
js = "'use strict';\n(() => {\n" + js + '\n})();\n';
writeFileSync(out('entry.js'), js);

// ── lint ──
const issues = [];
try { new vm.Script(js, { filename: 'entry.js' }); } catch (e) { issues.push('syntax: ' + String(e).split('\n')[0]); }
for (const bad of ['eval(', 'new Function', 'fetch(', 'XMLHttpRequest', 'WebSocket', 'document.write', "setAttribute('style'", 'https://', 'http://'])
  if (js.replace(/http:\/\/www\.w3\.org\/2000\/svg/g, '').includes(bad)) issues.push('forbidden: ' + bad);
if (/style=/.test(sprite)) issues.push('inline style in sprite');
const code = files.map(src).join('\n');
const used = new Set([...code.matchAll(/\b(?:t|tf|errText|okText)\(\s*'([a-z0-9_.]+)'/g)].map(m => m[1]));
const missing = [...used].filter(k => !I18N[k]);
if (missing.length) issues.push('missing i18n: ' + missing.join(', '));
const icons = new Set([...code.matchAll(/\bico\(\s*'([\w-]+)'/g)].map(m => m[1]));
const noIcon = [...icons].filter(k => !ICONS[k]);
if (noIcon.length) issues.push('missing icons: ' + noIcon.join(', '));
console.log(`entry.js ${(js.length / 1024).toFixed(0)} KB, entry.css ${(css.length / 1024).toFixed(0)} KB` + (issues.length ? '\n  ' + issues.join('\n  ') : ', ok'));
if (issues.length) process.exit(1);
