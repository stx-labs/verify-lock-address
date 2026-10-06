import './helpers/offline.mjs';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { JSDOM } from 'jsdom';

import { fill, h } from '../web/src/dom.ts';

const srcDir = fileURLToPath(new URL('../web/src/', import.meta.url));
const sources = readdirSync(srcDir, { recursive: true })
  .map(String)
  .filter(f => /\.(m?js|ts)$/.test(f))
  .map(f => ({ file: f, text: readFileSync(join(srcDir, f), 'utf8') }));

const HTML_SINKS = new RegExp(
  [
    '\\b(innerHTML|outerHTML|insertAdjacentHTML|createContextualFragment|srcdoc|setHTMLUnsafe|parseHTMLUnsafe|setHTML)\\b',
    '\\bDOMParser\\b',
    '\\bparseFromString\\b',
    '\\bcreateRange\\b|\\bnew\\s+Range\\b',
    '\\.write(ln)?\\s*\\(',
    '\\[\\s*[\'"`](write|writeln|innerHTML|outerHTML|insertAdjacentHTML|setHTMLUnsafe)[\'"`]\\s*\\]',
    '\\bnew\\s+Function\\b|\\bFunction\\s*\\(',
    '\\beval\\s*\\(',
    '\\bset(Timeout|Interval)\\s*\\(\\s*[\'"`]',
    '\\bexecCommand\\b|\\binsertHTML\\b',
    'javascript:',
    '\\.on[a-z]+\\s*=(?!=)',
    'setAttribute(NS)?\\s*\\(\\s*([^,]*,\\s*)?[\'"`]on',
    '\\[\\s*[\'"`]on[a-z]+[\'"`]\\s*\\]\\s*=(?!=)',
  ].join('|')
);

test('no file under web/src can parse a string as HTML', () => {
  assert.ok(sources.length >= 8, `scanned ${sources.map(s => s.file).join(', ')}`);
  for (const { file, text } of sources) {
    text.split('\n').forEach((line, i) => {
      assert.doesNotMatch(line, HTML_SINKS, `${file}:${i + 1}`);
    });
  }
});

test('the sink pattern catches every way of parsing a string as HTML or code', () => {
  for (const line of [
    'el.innerHTML = x',
    'el.outerHTML = x',
    "el.insertAdjacentHTML('beforeend', x)",
    'el.setHTMLUnsafe(x)',
    'Document.parseHTMLUnsafe(x)',
    'new DOMParser().parseFromString(x, "text/html")',
    'document.createRange().createContextualFragment(x)',
    'const d = document; d.write(x)',
    'd.writeln(x)',
    "document['write'](x)",
    'el["innerHTML"] = x',
    'frame.srcdoc = x',
    'new Function(x)()',
    'eval(x)',
    "setTimeout('alert(1)', 0)",
    "document.execCommand('insertHTML', false, x)",
    "el.setAttribute('onclick', x)",
    "el.setAttribute( 'onerror' , x)",
    "el.setAttributeNS(null, 'onload', x)",
    'el.onclick = x',
    'el.onerror=x',
    "el['onload'] = x",
    "a.href = 'javascript:alert(1)'",
    'const u = `javascript:${x}`',
  ]) {
    assert.match(line, HTML_SINKS, line);
  }
  for (const line of ['el.textContent = x', 'el.append(x)', 'setTimeout(() => x, 0)', 'writeText(x)', 'overwrite(x)', "el.setAttribute('aria-label', x)", "el.addEventListener('click', f)", 'if (x.once === y) f()', "el.dataset.label ??= x"]) {
    assert.doesNotMatch(line, HTML_SINKS, line);
  }
});

test('h() and fill() only ever create text from strings, and refuse event or URL attributes', () => {
  const { window } = new JSDOM('<!doctype html><body></body>');
  globalThis.document = window.document;

  const payload = '<img src=x onerror=globalThis.__pwn=1>';
  const el = h('div', { class: payload }, payload, 42, null, false, [payload, [payload]], h('span', null, payload));
  assert.equal(el.querySelectorAll('img').length, 0);
  assert.equal(el.childNodes[0].nodeType, window.Node.TEXT_NODE);
  assert.equal(el.textContent, `${payload}42${payload}${payload}${payload}`);
  assert.equal(el.getAttribute('class'), payload);

  for (const name of ['onclick', 'onerror', 'ONLOAD', 'href', 'src', 'srcdoc', 'formaction', 'xlink:href']) {
    assert.throws(() => h('a', { [name]: 'x' }), /not allowed/, name);
  }

  const box = window.document.createElement('div');
  fill(box, payload, { toString: () => payload });
  assert.equal(box.querySelectorAll('*').length, 0);
  assert.equal(box.textContent, payload + payload);
  assert.equal(window.__pwn, undefined);
});

test('the page shell has no inline event handler or javascript: URL', () => {
  const shell = readFileSync(fileURLToPath(new URL('../web/index.html', import.meta.url)), 'utf8');
  const tags = shell.match(/<[a-zA-Z][^>]*>/g) ?? [];
  assert.ok(tags.length > 50);
  for (const tag of tags) {
    assert.doesNotMatch(tag, /\son[a-z]+\s*=/i, tag);
    assert.doesNotMatch(tag, /javascript:/i, tag);
  }
  assert.match('<div onclick="x">', /\son[a-z]+\s*=/i);
});
