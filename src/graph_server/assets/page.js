// Interaction for the rule graph page. RULES and TOPDOWN are defined by
// the page: RULES maps a predicate to its statements ({loc, text}), and
// TOPDOWN says whether arrows point head -> body (else body -> head).
const nodes = {}, edges = [];
document.querySelectorAll('g.node').forEach(g => nodes[g.querySelector('title').textContent] = g);
// from/to are always data flow (body -> head), whichever way the arrows are drawn.
document.querySelectorAll('g.edge').forEach(g => {
  const [a, b] = g.querySelector('title').textContent.split('->');
  edges.push(TOPDOWN ? { g, from: b, to: a } : { g, from: a, to: b });
});
const panel = document.getElementById('panel-body');

// The same page re-centered on `name`, keeping the other parameters.
function focusUrl(name) {
  const params = new URLSearchParams(location.search);
  params.set('focus', name);
  return '/graph?' + params.toString();
}

// Panel resize/collapse. Width and collapsed state persist across pages.
const store = {
  get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
};
const panelBox = document.getElementById('panel'), splitter = document.getElementById('splitter');
const reopen = document.getElementById('reopen');
const DEFAULT_WIDTH = 520;
function setWidth(w) {
  w = Math.max(240, Math.min(w, window.innerWidth - 200));
  panelBox.style.width = w + 'px';
  store.set('mg.panelWidth', w);
}
function setCollapsed(c) {
  document.body.classList.toggle('collapsed', c);
  store.set('mg.panelCollapsed', c ? '1' : '0');
}
setWidth(Number(store.get('mg.panelWidth')) || DEFAULT_WIDTH);
setCollapsed(store.get('mg.panelCollapsed') === '1');
splitter.addEventListener('pointerdown', ev => {
  splitter.setPointerCapture(ev.pointerId);
  splitter.classList.add('dragging');
  const move = e => setWidth(window.innerWidth - e.clientX);
  const up = () => { splitter.classList.remove('dragging'); splitter.removeEventListener('pointermove', move); };
  splitter.addEventListener('pointermove', move);
  splitter.addEventListener('pointerup', up, { once: true });
});
splitter.addEventListener('dblclick', () => setWidth(DEFAULT_WIDTH));
document.getElementById('narrow').onclick = () => setWidth(panelBox.offsetWidth - 120);
document.getElementById('wide').onclick = () => setWidth(panelBox.offsetWidth + 120);
document.getElementById('collapse').onclick = () => setCollapsed(true);
reopen.onclick = () => setCollapsed(false);
document.addEventListener('keydown', ev => {
  if (ev.key === 'r' && !ev.ctrlKey && !ev.metaKey && !ev.altKey) setCollapsed(!document.body.classList.contains('collapsed'));
});
let pinned = null;

const esc = s => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
// Light highlighting: comments grey, negation red, known predicates clickable.
function highlight(text) {
  return text.split('\n').map(line => {
    const i = line.indexOf('#');
    const code = i >= 0 ? line.slice(0, i) : line, comment = i >= 0 ? line.slice(i) : '';
    const body = esc(code)
      .replace(/(^|[^:\w])(!?)([a-z_]\w*)(?=\s*\()/g, (m, pre, bang, name) => {
        const neg = bang ? '<span class="neg">!</span>' : '';
        if (!RULES[name] && !nodes[name]) return pre + neg + name;
        const where = nodes[name] ? 'here' : 'away';
        return `${pre}${neg}<span class="p ${where}" data-pred="${name}">${name}</span>`;
      });
    return body + (comment ? `<span class="c">${esc(comment)}</span>` : '');
  }).join('\n');
}
// Nodes in the files overview are rule files, not predicates.
const isPredicate = name => Object.hasOwn(RULES, name);
function showRules(name) {
  if (!isPredicate(name)) {
    panel.innerHTML = `<h3>${esc(name)}</h3><div class="meta">a rule file; hover shows which files it depends on and which use it</div>`;
    return;
  }
  const list = RULES[name];
  const isDecl = r => /^\s*(#.*\n\s*)*Decl\b/.test(r.text);
  const nRules = list.filter(r => !isDecl(r) && r.text.includes(':-')).length;
  const nFacts = list.filter(r => !isDecl(r) && !r.text.includes(':-')).length;
  const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const kind = nRules || nFacts
    ? [nRules && plural(nRules, 'rule'), nFacts && plural(nFacts, 'fact') + ' written in the rules'].filter(Boolean).join(', ')
    : 'supplied at runtime (EDB), no rules';
  const session = r => r.loc.startsWith('session #') ? '<span class="session">added this session</span>' : '';
  panel.innerHTML = `<h3>${esc(name)}<a href="${esc(focusUrl(name))}">focus here</a></h3>` +
    `<div class="meta">${kind}${nodes[name] ? '' : ' &middot; not drawn in this graph'}</div>` +
    list.map(r => `<div class="loc">${esc(r.loc)}${session(r)}</div><pre>${highlight(r.text)}</pre>`).join('');
  panel.scrollTop = 0;
}
panel.addEventListener('click', ev => {
  const name = ev.target.dataset && ev.target.dataset.pred;
  if (!name) return;
  ev.stopPropagation();
  if (nodes[name]) { pinned = name; show(name, false); nodes[name].scrollIntoView({ block: 'center', inline: 'center', behavior: 'smooth' }); }
  else { pinned = name; clear(); showRules(name); }
});

function clear() {
  document.querySelectorAll('.dim,.hot,.up,.sel').forEach(e => e.classList.remove('dim', 'hot', 'up', 'sel'));
}
function walk(start, dir) { // dir: 'up' follows inputs, 'down' follows users
  const seen = new Set([start]), q = [start];
  while (q.length) {
    const p = q.shift();
    for (const e of edges) {
      const next = dir === 'up' ? (e.to === p && e.from) : (e.from === p && e.to);
      if (next && !seen.has(next)) { seen.add(next); q.push(next); }
    }
  }
  return seen;
}
function show(name, chain) {
  clear();
  const up = chain ? walk(name, 'up') : new Set([name]);
  const down = chain ? walk(name, 'down') : new Set([name]);
  const keep = new Set([name]);
  for (const e of edges) {
    if (up.has(e.to) && (chain || e.to === name)) { e.g.classList.add('up'); keep.add(e.from); keep.add(e.to); }
    else if (down.has(e.from) && (chain || e.from === name)) { e.g.classList.add('hot'); keep.add(e.from); keep.add(e.to); }
    else e.g.classList.add('dim');
  }
  for (const [n, g] of Object.entries(nodes)) if (!keep.has(n)) g.classList.add('dim');
  nodes[name].classList.add('sel');
  showRules(name);
}
for (const [name, g] of Object.entries(nodes)) {
  g.addEventListener('mouseenter', () => { if (!pinned) show(name, false); });
  g.addEventListener('mouseleave', () => { if (!pinned) clear(); });
  // Shift-mousedown would otherwise start a text selection in the browser.
  g.addEventListener('mousedown', ev => { if (ev.shiftKey) ev.preventDefault(); });
  g.addEventListener('click', ev => { pinned = name; show(name, ev.shiftKey); ev.stopPropagation(); });
  g.addEventListener('dblclick', ev => { ev.stopPropagation(); if (isPredicate(name)) location.href = focusUrl(name); });
}
// The legend: hovering a file highlights its predicates, clicking keeps it.
// ORIGINS maps each drawn predicate to its file ('' for facts loaded from
// the cluster). In the files overview the nodes are the files themselves.
const legendItems = document.querySelectorAll('.legend-item');
// Collapsed by default; once opened (or closed again) it stays that way.
const legend = document.querySelector('details.legend');
if (legend) {
  legend.open = store.get('mg.legendOpen') === '1';
  legend.addEventListener('toggle', () => store.set('mg.legendOpen', legend.open ? '1' : '0'));
}
function originOf(name) {
  if (Object.hasOwn(ORIGINS, name)) return ORIGINS[name];
  return name === 'supplied at runtime (EDB)' ? '' : name;
}
function showOrigin(origin) {
  clear();
  const keep = new Set(Object.keys(nodes).filter(n => originOf(n) === origin));
  for (const [n, g] of Object.entries(nodes)) if (!keep.has(n)) g.classList.add('dim');
  for (const e of edges) if (!keep.has(e.from) || !keep.has(e.to)) e.g.classList.add('dim');
  legendItems.forEach(item => item.classList.toggle('sel', item.dataset.origin === origin));
}
legendItems.forEach(item => {
  const origin = item.dataset.origin;
  item.addEventListener('mouseenter', () => { if (!pinned) showOrigin(origin); });
  item.addEventListener('mouseleave', () => { if (!pinned) clearAll(); });
  item.addEventListener('click', () => {
    if (pinned === 'file:' + origin) { pinned = null; clearAll(); return; }
    pinned = 'file:' + origin;
    showOrigin(origin);
  });
});
function clearAll() {
  clear();
  legendItems.forEach(item => item.classList.remove('sel'));
}

// Help.
const help = document.getElementById('help');
const setHelp = open => help.classList.toggle('open', open);
document.getElementById('help-button').onclick = () => setHelp(true);
document.getElementById('help-close').onclick = () => setHelp(false);
help.addEventListener('click', ev => { if (ev.target === help) setHelp(false); });
document.addEventListener('keydown', ev => {
  if (ev.key === '?') setHelp(!help.classList.contains('open'));
});

document.getElementById('graph').addEventListener('click', () => { pinned = null; clearAll(); });
document.addEventListener('keydown', ev => {
  if (ev.key !== 'Escape') return;
  if (help.classList.contains('open')) { setHelp(false); return; }
  pinned = null;
  clearAll();
});
