import { evaluate } from '../lib/sigma/index.ts';
import type { ConditionNode, FieldCheck, Trace } from '../lib/sigma/index.ts';
import { EXAMPLES, DEFAULT_EXAMPLE } from '../lib/examples.ts';
import { Dropdown } from './dropdown.ts';
import { animateDisclosures, initReveal, pulseOnChange } from './motion.ts';
import { initCursor } from './cursor.ts';

const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;

const ruleBox = $<HTMLTextAreaElement>('#rule');
const eventBox = $<HTMLTextAreaElement>('#event');
const pickerMount = $<HTMLElement>('#example-mount');
const verdictEl = $<HTMLElement>('#verdict');
const msgsEl = $<HTMLElement>('#msgs');
const blocksEl = $<HTMLElement>('#blocks');
const treeEl = $<HTMLElement>('#tree');
const noteEl = $<HTMLElement>('#example-note');
const shareBtn = $<HTMLButtonElement>('#share');

function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

/** Show where in the actual value the rule's expectation landed. */
function highlight(actual: unknown, check: FieldCheck): string {
  const text = String(actual ?? '');
  if (!check.matched || check.matchedValue === undefined) return esc(text);
  const needle = String(check.matchedValue);
  if (!needle || check.modifiers.includes('re')) return esc(text);
  // Wildcards make a substring search meaningless; mark the whole value instead.
  if (/[*?]/.test(needle)) return `<mark>${esc(text)}</mark>`;
  const at = text.toLowerCase().indexOf(needle.toLowerCase());
  if (at < 0) return `<mark>${esc(text)}</mark>`;
  return esc(text.slice(0, at)) + `<mark>${esc(text.slice(at, at + needle.length))}</mark>` +
    esc(text.slice(at + needle.length));
}

function fieldExpr(c: FieldCheck): string {
  const mods = c.modifiers.length ? `<span class="mod">|${esc(c.modifiers.join('|'))}</span>` : '';
  return `${esc(c.field)}${mods}`;
}

function shortExpected(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) {
    const head = v.slice(0, 3).map((x) => `'${String(x)}'`).join(', ');
    return v.length > 3 ? `[${head}, … ${v.length} values]` : `[${head}]`;
  }
  return `'${String(v)}'`;
}

function renderCheck(c: FieldCheck): string {
  const cls = c.unsupported ? 'unk' : c.matched ? 'on' : 'off';
  const mark = c.unsupported ? '?' : c.matched ? '✓' : '✗';
  const actualRow = c.unsupported ? '' : `
      <div class="vals">
        <span><span class="lab">rule wants </span><b>${esc(shortExpected(c.expected))}</b></span>
        <span><span class="lab">event has  </span><b>${c.actual === undefined ? '<i>field absent</i>' : highlight(c.actual, c)}</b></span>
      </div>`;
  return `
    <div class="chk ${cls}">
      <span class="mark" aria-hidden="true">${mark}</span>
      <span class="expr">${fieldExpr(c)}</span>
      ${actualRow}
      <span class="reason">${esc(c.reason)}</span>
    </div>`;
}

function renderBlocks(trace: Trace): string {
  if (!trace.blocks.length) return '<p class="reason">No search identifiers to show.</p>';
  return trace.blocks.map((b) => {
    const unref = trace.unreferenced.includes(b.name);
    const pill = b.hasUnsupported
      ? '<span class="pill warnp">UNKNOWN</span>'
      : `<span class="pill ${b.matched ? 't' : 'f'}">${b.matched ? 'TRUE' : 'FALSE'}</span>`;
    const kindLabel = b.kind === 'map'
      ? 'all fields must match'
      : b.kind === 'list-of-maps' ? 'any group may match' : 'keyword search';
    const groups = b.groups.map((g, i) => {
      const sep = b.groups.length > 1
        ? `<div class="group-sep">group ${i + 1} — ${g.matched ? 'matches' : 'does not match'}</div>` : '';
      return sep + g.checks.map(renderCheck).join('');
    }).join('');
    return `
      <details class="block ${unref ? 'unref' : ''}" ${b.matched || unref ? 'open' : ''}>
        <summary>
          <span class="bname">${esc(b.name)}</span>
          ${pill}
          <span class="kind">${kindLabel}</span>
        </summary>
        <div class="checks">${groups}</div>
      </details>`;
  }).join('');
}

function renderTree(n: ConditionNode | null): string {
  if (!n) return '<p class="reason">The condition could not be parsed.</p>';
  const tv = (v: boolean | undefined) =>
    `<span class="tv ${v ? 't' : 'f'}">${v ? 'true' : 'false'}</span>`;

  function node(x: ConditionNode): string {
    switch (x.type) {
      case 'id':
        return `<li><span class="node"><span class="nm ${x.missing ? 'bad' : ''}">${esc(x.name)}</span>${tv(x.value)}${
          x.missing ? '<span class="meta">not defined under detection:</span>' : ''}</span></li>`;
      case 'not':
        return `<li><span class="node"><span class="op">not</span>${tv(x.value)}</span><ul>${node(x.node)}</ul></li>`;
      case 'and':
      case 'or':
        return `<li><span class="node"><span class="op">${x.type}</span>${tv(x.value)}</span><ul>${node(x.left)}${node(x.right)}</ul></li>`;
      case 'quant': {
        const r = x.resolved ?? [];
        const hits = r.length ? `${r.length} block${r.length === 1 ? '' : 's'}: ${r.join(', ')}` : 'matches no block';
        return `<li><span class="node"><span class="op">${esc(x.count)} of</span><span class="nm">${esc(x.pattern)}</span>${tv(x.value)}<span class="meta">${esc(hits)}</span></span></li>`;
      }
    }
  }
  return `<ul class="tree-root">${node(n)}</ul>`;
}

function renderVerdict(trace: Trace) {
  const fatal = trace.errors.length > 0;
  verdictEl.className = 'verdict ' + (fatal ? 'is-error' : trace.alert ? 'is-alert' : 'is-quiet');
  const badge = fatal ? 'CANNOT EVALUATE' : trace.alert ? 'ALERT' : 'NO ALERT';
  let why: string;
  if (fatal) {
    why = 'Fix the problem below and the trace will update.';
  } else if (trace.alert) {
    why = 'This rule fires on this event.';
  } else {
    const trueBlocks = trace.blocks.filter((b) => b.matched).map((b) => b.name);
    why = trueBlocks.length
      ? `The condition is not satisfied. Blocks that did match: ${trueBlocks.join(', ')}.`
      : 'No search identifier matched this event.';
  }
  pulseOnChange(verdictEl, badge + '|' + why);
  verdictEl.innerHTML = `
    <span class="badge">${badge}</span>
    <span class="why">${esc(why)}</span>
    ${trace.title ? `<span class="rule-id">${esc(trace.title)}${trace.level ? ` · ${esc(trace.level)}` : ''}</span>` : ''}`;
}

function renderMsgs(trace: Trace) {
  const out: string[] = [];
  for (const e of trace.errors) {
    out.push(`<div class="msg err"><span class="k">error</span><span>${esc(e)}</span></div>`);
  }
  if (trace.unreferenced.length) {
    const names = trace.unreferenced.map((n) => `<code>${esc(n)}</code>`).join(', ');
    out.push(`<div class="msg dead"><span class="k">dead block</span><span>
      ${names} ${trace.unreferenced.length === 1 ? 'is' : 'are'} defined under <code>detection:</code>
      but the <code>condition:</code> line never refers to ${trace.unreferenced.length === 1 ? 'it' : 'them'}.
      ${trace.unreferenced.length === 1 ? 'It has' : 'They have'} no effect on the result.
      A filter written this way is valid YAML, passes every linter, and does nothing.</span></div>`);
  }
  for (const w of trace.warnings) {
    out.push(`<div class="msg warn"><span class="k">warning</span><span>${esc(w)}</span></div>`);
  }
  msgsEl.innerHTML = out.join('');
}

function run() {
  let trace: Trace;
  try {
    trace = evaluate(ruleBox.value, eventBox.value);
  } catch (e) {
    // The evaluator is supposed to report rather than throw. If it ever does
    // throw, say so plainly instead of showing a stale result.
    verdictEl.className = 'verdict is-error';
    verdictEl.innerHTML = `<span class="badge">CRASHED</span><span class="why">${esc((e as Error).message)}</span>`;
    msgsEl.innerHTML = '';
    blocksEl.innerHTML = '';
    treeEl.innerHTML = '';
    return;
  }
  renderVerdict(trace);
  renderMsgs(trace);
  blocksEl.innerHTML = renderBlocks(trace);
  treeEl.innerHTML = renderTree(trace.ast);
  document.body.dataset.alert = String(trace.alert);
}

let timer: number | undefined;
function schedule() {
  window.clearTimeout(timer);
  timer = window.setTimeout(run, 120);
}

let picker: Dropdown;

function loadExample(id: string) {
  const ex = EXAMPLES.find((e) => e.id === id) ?? DEFAULT_EXAMPLE;
  ruleBox.value = ex.rule;
  eventBox.value = ex.event;
  noteEl.textContent = ex.note;
  run();
}

/** Share link: state lives in the URL fragment, so it never reaches a server. */
function encodeState(): string {
  const payload = JSON.stringify({ r: ruleBox.value, e: eventBox.value });
  return btoa(unescape(encodeURIComponent(payload)));
}
function decodeState(hash: string): { r: string; e: string } | null {
  try {
    const obj = JSON.parse(decodeURIComponent(escape(atob(hash))));
    if (typeof obj?.r === 'string' && typeof obj?.e === 'string') return obj;
  } catch { /* a malformed link should just load the default example */ }
  return null;
}

function init() {
  picker = new Dropdown(pickerMount, 'example-label', (id) => loadExample(id));
  picker.setOptions(EXAMPLES.map((e) => ({ value: e.id, label: e.label })));
  animateDisclosures(blocksEl);

  const fromUrl = location.hash.startsWith('#s=') ? decodeState(location.hash.slice(3)) : null;
  if (fromUrl) {
    ruleBox.value = fromUrl.r;
    eventBox.value = fromUrl.e;
    noteEl.textContent = 'Loaded from a shared link.';
    run();
  } else {
    loadExample(DEFAULT_EXAMPLE.id);
  }

  ruleBox.addEventListener('input', schedule);
  eventBox.addEventListener('input', schedule);
  initReveal();
  if (document.documentElement.classList.contains('fx-cursor')) initCursor();

  shareBtn.addEventListener('click', async () => {
    const url = `${location.origin}${location.pathname}#s=${encodeState()}`;
    history.replaceState(null, '', url);
    const original = shareBtn.textContent;
    try {
      await navigator.clipboard.writeText(url);
      shareBtn.textContent = 'Link copied';
    } catch {
      shareBtn.textContent = 'Link is in the address bar';
    }
    window.setTimeout(() => { shareBtn.textContent = original; }, 1800);
  });
}

init();
