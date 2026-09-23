'use strict';
/* Nukefy — логика интерфейса */
const api = window.nukefy;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const CATS = { virus: 'Вирусы', trojan: 'Трояны', miner: 'Майнеры', risk: 'Риски' };
const SRC = { file: 'Файл', process: 'Процесс', autorun: 'Автозапуск', hosts: 'hosts', network: 'Сеть', url: 'Ссылка' };

let STATE = null;
let scanUi = { active: false, mode: 'quick', results: [], cat: 'all' };
let selectedThreat = null;

/* ---------------- утилиты ---------------- */
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function fmtDate(iso) { if (!iso) return '—'; const d = new Date(iso); return d.toLocaleDateString('ru-RU') + ' ' + d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }); }
function fmtBytes(n) { if (!n && n !== 0) return ''; if (n < 1024) return n + ' Б'; if (n < 1048576) return (n / 1024).toFixed(1) + ' КБ'; if (n < 1073741824) return (n / 1048576).toFixed(1) + ' МБ'; return (n / 1073741824).toFixed(2) + ' ГБ'; }
let toastTimer = null;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  requestAnimationFrame(() => t.classList.add('show'));
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.classList.remove('show'); setTimeout(() => { t.hidden = true; }, 400); }, 3600);
}
function sevBar(sev) { return `<span class="sev-bar">${[1, 2, 3, 4].map((i) => `<i class="${i <= sev ? 'on' : ''}"></i>`).join('')}</span>`; }

/* ---------------- загрузочная анимация ---------------- */
const BOOT_STEPS = [
  ['Ядро детектирования', 500],
  ['Локальная база сигнатур', 900],
  ['Модули: процессы, автозапуск, сеть', 1400],
  ['Резидентная защита', 1900],
  ['Интерфейс', 2300],
];
function normalizeState() {
  if (!STATE || typeof STATE !== 'object' || STATE.ok === false) STATE = null;
  if (!STATE) STATE = {};
  STATE.version = STATE.version || '1.0.3';
  STATE.threats = Array.isArray(STATE.threats) ? STATE.threats : [];
  STATE.history = Array.isArray(STATE.history) ? STATE.history : [];
  STATE.counts = STATE.counts || { active: 0, quarantined: 0 };
  STATE.settings = STATE.settings || { cloud: {}, protection: {}, actions: {}, checks: {}, urlHistory: [] };
  STATE.settings.cloud = STATE.settings.cloud || {};
  STATE.settings.protection = STATE.settings.protection || {};
  STATE.settings.actions = STATE.settings.actions || {};
  STATE.settings.checks = STATE.settings.checks || {};
  STATE.settings.urlHistory = STATE.settings.urlHistory || [];
  return STATE;
}
async function boot() {
  const statePromise = api.state().then((s) => { STATE = s; return s; }).catch(() => { STATE = null; });
  BOOT_STEPS.forEach(([label, at], i) => {
    setTimeout(() => {
      const st = $('#bootStatus'); if (st) st.textContent = label + '…';
      const bar = $('#bootBar'); if (bar) bar.style.width = Math.round(((i + 1) / BOOT_STEPS.length) * 100) + '%';
    }, at);
  });
  await statePromise;
  normalizeState();
  await new Promise((r) => setTimeout(r, 2750));
  const app = $('#app');
  app.classList.remove('hidden');
  $('#boot').classList.add('gone');
  requestAnimationFrame(() => app.classList.add('in'));
  setTimeout(() => { const b = $('#boot'); if (b) b.remove(); }, 800);
  initApp();
}

/* ---------------- каркас ---------------- */
function initApp() {
  $('#tbVer').textContent = STATE ? STATE.version : '1.0.0';
  bindNav();
  bindTitlebar();
  bindScan();
  bindThreats();
  bindUrl();
  bindQuarantine();
  bindSettings();
  bindEvents();
  refreshAll();
}
function bindNav() {
  $$('.nav-item').forEach((b) => b.addEventListener('click', () => {
    $$('.nav-item').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    const v = b.dataset.view;
    $$('.view').forEach((x) => x.classList.remove('active'));
    $('#view-' + v).classList.add('active');
    if (v === 'dashboard') refreshDashboard();
    if (v === 'threats') renderThreats();
    if (v === 'quarantine') renderQuarantine();
    if (v === 'url') renderUrlHistory();
  }));
}
function bindTitlebar() {
  $('#btnMin').onclick = () => api.minimize();
  $('#btnFull').onclick = () => api.toggleFull();
  $('#btnQuit').onclick = () => api.quit();
}

/* ---------------- данные ---------------- */
async function refreshAll() {
  try { STATE = await api.state(); } catch (_) {}
  normalizeState();
  refreshDashboard();
  renderThreats();
  renderQuarantine();
  renderUrlHistory();
  fillSettings();
}
function activeThreats() { return (STATE && STATE.threats || []).filter((t) => t.status === 'new'); }
function refreshDashboard() {
  const act = activeThreats();
  $('#stActive').textContent = act.length;
  $('#stQuar').textContent = STATE ? STATE.counts.quarantined : 0;
  $('#stDb').textContent = STATE ? STATE.dbSignatures : '—';
  const hist = STATE ? STATE.history : [];
  $('#stFiles').textContent = hist.reduce((s, h) => s + (h.files || 0), 0).toLocaleString('ru-RU');
  const badge = $('#badgeThreats');
  badge.hidden = act.length === 0;
  badge.textContent = act.length;
  const prot = STATE && STATE.protection;
  $('#protState .prot-led').classList.toggle('on', !!(prot && prot.enabled));
  $('#protState').lastChild.textContent = prot && prot.enabled ? ' Резидентная защита активна' : ' Резидентная защита выключена';
  const ok = act.length === 0;
  $('#shieldVerdict').textContent = ok ? 'Защищено' : `Обнаружено угроз: ${act.length}`;
  $('#shieldNote').textContent = ok
    ? `База сигнатур ${STATE ? STATE.dbVersion : ''} · последняя проверка: ${hist[0] ? fmtDate(hist[0].at) : 'ещё не проводилась'}`
    : 'Откройте вкладку «Угрозы», чтобы вылечить или изолировать объекты';
  $('#tbStatus').textContent = ok ? 'Система защищена' : `Внимание: активных угроз — ${act.length}`;
  $('#tbStatus').classList.toggle('alert', !ok);
  $('#dashSummary').textContent = STATE
    ? `Nukefy ${STATE.version} · ${STATE.platform === 'win32' ? 'Windows' : STATE.platform} ${STATE.arch} · движок: локальные сигнатуры + эвристики + облако abuse.ch${STATE.vtKeySet ? ' + VirusTotal' : ''}`
    : '';
  const ev = $('#dashEvents');
  const rows = [];
  for (const t of (STATE ? STATE.threats : []).slice(0, 8)) {
    rows.push(listItem(t, true));
  }
  for (const h of (STATE ? STATE.history : []).slice(0, 4)) {
    rows.push(`<div class="list-item" style="cursor:default"><div class="li-body"><div class="li-title">Сканирование (${h.mode === 'quick' ? 'быстрое' : h.mode === 'full' ? 'полное' : h.mode})</div><div class="li-sub">${fmtDate(h.at)} · файлов: ${(h.files || 0).toLocaleString('ru-RU')} · угроз: ${h.threats || 0}${h.cancelled ? ' · остановлено' : ''}</div></div></div>`);
  }
  ev.innerHTML = rows.length ? rows.join('') : '<div class="empty-note">Пока пусто — запустите первую проверку</div>';
}

/* ---------------- сканирование ---------------- */
function bindScan() {
  $$('.mode-btn').forEach((b) => b.addEventListener('click', () => {
    if (scanUi.active) return;
    $$('.mode-btn').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    scanUi.mode = b.dataset.mode;
  }));
  $('#btnScanStart').onclick = async () => {
    let roots = null;
    if (scanUi.mode === 'custom') {
      const r = await api.pickFolders();
      if (!r.ok) return;
      roots = r.paths;
    }
    scanUi.active = true;
    scanUi.results = [];
    renderScanResults();
    $('#radar').classList.add('scanning');
    $('#btnScanStart').disabled = true;
    $('#btnScanCancel').disabled = false;
    $('#scanPct').textContent = '0%';
    $('#scanPhase').textContent = 'Подготовка…';
    $('#scanPath').textContent = '';
    $('#scanStats').textContent = '';
    await api.startScan({ mode: scanUi.mode, roots });
  };
  $('#btnScanCancel').onclick = async () => { await api.cancelScan(); };
  $$('#scanTabs .tab').forEach((t) => t.addEventListener('click', () => {
    $$('#scanTabs .tab').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    scanUi.cat = t.dataset.cat;
    renderScanResults();
  }));
  $('#btnQuickScan').onclick = async () => {
    document.querySelector('[data-view="scan"]').click();
    setTimeout(() => $('#btnScanStart').click(), 120);
  };
  $('#btnFullScan').onclick = async () => {
    document.querySelector('[data-view="scan"]').click();
    $$('.mode-btn').forEach((x) => x.classList.toggle('active', x.dataset.mode === 'full'));
    scanUi.mode = 'full';
    setTimeout(() => $('#btnScanStart').click(), 120);
  };
  $('#btnSelfTest').onclick = async () => {
    toast('Самопроверка: создаю тестовые объекты EICAR и майнер-конфиг…');
    document.querySelector('[data-view="scan"]').click();
    scanUi.active = true;
    $('#radar').classList.add('scanning');
    $('#scanPhase').textContent = 'Самопроверка движка…';
    const r = await api.selftest();
    toast(r.pass ? `Самопроверка пройдена: детектов ${r.threats} из ${r.expect} ожидаемых` : `Самопроверка НЕ пройдена: ${r.threats}/${r.expect}`);
  };
}
function renderScanResults() {
  const box = $('#scanResults');
  const rows = scanUi.results.filter((t) => scanUi.cat === 'all' || t.cat === scanUi.cat);
  box.innerHTML = rows.length ? rows.map((t) => listItem(t, false)).join('') : `<div class="empty-note">${scanUi.active ? 'Проверка идёт — находки появятся здесь' : 'Находок нет'}</div>`;
  $$('#scanResults .list-item').forEach((el) => el.onclick = () => {
    document.querySelector('[data-view="threats"]').click();
    selectThreat(el.dataset.id);
  });
}

/* ---------------- список угроз ---------------- */
function listItem(t, compact) {
  return `<div class="list-item" data-id="${esc(t.id)}">
    <div class="li-body">
      <div class="li-title">${esc(t.title)} ${helpQ(t)}
        <span class="cat-chip ${esc(t.cat)}">${CATS[t.cat] || t.cat}</span>${sevBar(t.sev)}</div>
      <div class="li-sub">${esc(SRC[t.source] || t.source)} · ${esc(t.path || t.url || (t.pid ? 'PID ' + t.pid : t.host || ''))} · ${fmtDate(t.foundAt)}${t.status !== 'new' ? ' · ' + statusRu(t.status) : ''}</div>
    </div>
    ${compact ? '' : `<div class="li-right"><span class="muted">${esc(t.kind === 'cloud' ? 'облако' : t.kind === 'heuristic' ? 'эвристика' : 'сигнатура')}</span></div>`}
  </div>`;
}
function statusRu(s) { return { healed: 'вылечено', quarantined: 'в карантине', deleted: 'удалено', ignored: 'игнорируется', whitelisted: 'в исключениях', dismissed: 'обработано' }[s] || s; }
function helpQ(t) {
  return `<span class="help-q" data-id="${esc(t.id)}" data-fam="${esc(t.fam || 'generic')}" tabindex="0">?</span>`;
}
const KNOWLEDGE_CACHE = {};
function popBody(k) {
  if (!k) return '<p>Справка недоступна.</p>';
  return `<h4>${esc(k.title)}</h4>
  <p>${esc(k.whatItDoes)}</p>
  <p><b>Чем опасен:</b> ${esc(k.whyDangerous)}</p>
  <div class="pop-row"><b>Появился</b><span>${esc(k.firstSeen)}</span></div>
  <div class="pop-row"><b>Откуда</b><span>${esc(k.whereFrom)}</span></div>
  <div class="pop-row"><b>Куда лезет</b><span>${esc(k.whereGoes)}</span></div>`;
}
async function loadKnowledge(t) {
  if (KNOWLEDGE_CACHE[t.id]) return KNOWLEDGE_CACHE[t.id];
  const k = await api.knowledge(t.id);
  if (k) KNOWLEDGE_CACHE[t.id] = k;
  return k;
}
/* плавающая карточка справки «?» — не режется overflow-контейнерами */
const kpop = document.createElement('div');
kpop.id = 'kpop'; kpop.className = 'kpop'; kpop.hidden = true;
document.body.appendChild(kpop);
let kpopFor = null;
function placeKpop(q) {
  const r = q.getBoundingClientRect();
  kpop.hidden = false;
  const w = 348, h = kpop.offsetHeight || 260;
  let left = r.right + 12;
  if (left + w > window.innerWidth - 8) left = Math.max(8, r.left - w - 12);
  let top = Math.min(Math.max(8, r.top - 12), window.innerHeight - h - 8);
  kpop.style.left = left + 'px';
  kpop.style.top = top + 'px';
}
document.addEventListener('mouseover', async (e) => {
  const q = e.target.closest && e.target.closest('.help-q');
  if (!q || q === kpopFor) return;
  kpopFor = q;
  kpop.innerHTML = '<p class="kpop-load">Загрузка справки…</p>';
  placeKpop(q);
  const t = findT(q.dataset.id) || scanUi.results.find((x) => x.id === q.dataset.id);
  let k = t ? await loadKnowledge(t) : null;
  if (!k) k = await api.knowledge(q.dataset.id, q.dataset.fam);
  if (kpopFor !== q) return;
  kpop.innerHTML = popBody(k);
  placeKpop(q);
});
document.addEventListener('mouseout', (e) => {
  const q = e.target.closest && e.target.closest('.help-q');
  if (q && !(e.relatedTarget && q.contains(e.relatedTarget))) { kpop.hidden = true; kpopFor = null; }
});

function bindThreats() {
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const id = btn.dataset.id;
    const action = btn.dataset.act;
    if (action === 'reveal') { const t = findT(id); if (t && t.path) api.reveal(t.path); return; }
    if (action === 'vtlink') { const t = findT(id); if (t && t.sha256) api.openExternal('https://www.virustotal.com/gui/file/' + t.sha256); return; }
    const r = await api.act(id, action);
    if (!r.ok) toast('Не удалось: ' + (r.error || 'неизвестная ошибка'));
    else {
      toast({ heal: 'Лечение выполнено', quarantine: 'Объект помещён в карантин', delete: 'Удалено безвозвратно', whitelist: 'Добавлено в исключения', ignore: 'Угроза будет игнорироваться', dismiss: 'Помечено обработанным' }[action] || 'Готово');
      if (r.follow === 'quarantine-suggested') toast('Рекомендуем также изолировать связанный файл');
    }
    await refreshAll();
    if (selectedThreat === id) selectThreat(id);
  });
}
function findT(id) { return (STATE.threats || []).find((x) => x.id === id); }
function renderThreats() {
  const box = $('#threatList');
  const items = (STATE ? STATE.threats : []).slice();
  items.sort((a, b) => (a.status === 'new' ? -1 : 1) - (b.status === 'new' ? -1 : 1) || (b.foundAt || '').localeCompare(a.foundAt || ''));
  box.innerHTML = items.length ? items.map((t) => listItem(t, false)).join('') : '<div class="empty-note">Угроз не обнаружено</div>';
  $$('#threatList .list-item').forEach((el) => el.onclick = (e) => {
    if (e.target.closest('.help-q')) return;
    $$('#threatList .list-item').forEach((x) => x.classList.remove('selected'));
    el.classList.add('selected');
    selectThreat(el.dataset.id);
  });
  if (selectedThreat) selectThreat(selectedThreat);
}
async function selectThreat(id) {
  selectedThreat = id;
  const t = findT(id);
  const box = $('#threatDetail');
  if (!t) { box.innerHTML = '<div class="td-empty">Выберите угрозу слева</div>'; return; }
  const k = await loadKnowledge(t);
  box.innerHTML = `
    <div class="td-title">${esc(t.title)} <span class="cat-chip ${esc(t.cat)}">${CATS[t.cat] || t.cat}</span>${sevBar(t.sev)}</div>
    <div class="td-row"><div class="k">Источник</div><div class="v">${esc(SRC[t.source] || t.source)}${t.pid ? ' · PID ' + t.pid : ''}</div></div>
    ${t.path ? `<div class="td-row"><div class="k">Объект</div><div class="v">${esc(t.path)}</div></div>` : ''}
    ${t.url ? `<div class="td-row"><div class="k">Адрес</div><div class="v">${esc(t.url)}</div></div>` : ''}
    ${t.command ? `<div class="td-row"><div class="k">Команда</div><div class="v">${esc(t.command)}</div></div>` : ''}
    <div class="td-row"><div class="k">Обнаружено</div><div class="v">${fmtDate(t.foundAt)} · ${esc(t.kind || '')} · статус: ${statusRu(t.status)}</div></div>
    <div class="td-row"><div class="k">Описание детекта</div><div class="v">${esc(t.desc || '')}</div></div>
    ${t.sha256 ? `<div class="td-row"><div class="k">SHA-256</div><div class="v">${esc(t.sha256)}</div></div>` : ''}
    ${k ? `<div class="know-card">
      <h3>${esc(k.title)} · что это и чем опасно</h3>
      <p>${esc(k.whatItDoes)}</p>
      <p>${esc(k.whyDangerous)}</p>
      <div class="know-row"><b>Дата появления</b><span>${esc(k.firstSeen)}</span></div>
      <div class="know-row"><b>Откуда приходит</b><span>${esc(k.whereFrom)}</span></div>
      <div class="know-row"><b>Куда прописывается</b><span>${esc(k.whereGoes)}</span></div>
      <div class="know-row"><b>Рекомендация</b><span>${esc(k.advice)}</span></div>
    </div>` : ''}
    <div class="td-actions">
      <button class="btn btn-primary" data-act="heal" data-id="${esc(t.id)}">Вылечить</button>
      <button class="btn" data-act="quarantine" data-id="${esc(t.id)}">В карантин</button>
      <button class="btn btn-danger" data-act="delete" data-id="${esc(t.id)}">Удалить</button>
      <button class="btn" data-act="whitelist" data-id="${esc(t.id)}">В исключения</button>
      <button class="btn" data-act="ignore" data-id="${esc(t.id)}">Игнорировать</button>
      ${t.path ? `<button class="btn" data-act="reveal" data-id="${esc(t.id)}">Открыть папку</button>` : ''}
      ${t.sha256 ? `<button class="btn" data-act="vtlink" data-id="${esc(t.id)}">VirusTotal</button>` : ''}
    </div>`;
}

/* ---------------- анализ ссылок ---------------- */
function bindUrl() {
  $('#btnUrlAnalyze').onclick = () => runUrl();
  $('#urlInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runUrl(); });
}
const URL_STEPS = [['url', 'Эвристики адреса'], ['rdap', 'Возраст домена'], ['fetch', 'Загрузка страницы'], ['html', 'Разбор HTML'], ['cloud', 'Репутационные базы']];
async function runUrl() {
  const url = $('#urlInput').value.trim();
  if (!url) return toast('Введите адрес ссылки или домен');
  const stepsBox = $('#urlSteps');
  stepsBox.innerHTML = URL_STEPS.map(([id, label]) => `<div class="url-step" data-s="${id}"><i></i>${label}</div>`).join('');
  $('#urlResult').innerHTML = '<div class="empty-note">Проверяю…</div>';
  stepsBox.querySelector('[data-s="url"]').classList.add('active');
  const off = api.onEvent((e) => {
    if (e.type !== 'url:step') return;
    const cur = stepsBox.querySelector(`[data-s="${e.step}"]`);
    $$('.url-step', stepsBox).forEach((s) => { if (s !== cur && s.classList.contains('active')) { s.classList.remove('active'); s.classList.add('done'); } });
    if (cur) cur.classList.add('active');
  });
  const r = await api.analyzeUrl(url);
  off();
  $$('.url-step', stepsBox).forEach((s) => { s.classList.remove('active'); s.classList.add('done'); });
  if (!r.ok) { $('#urlResult').innerHTML = `<div class="empty-note">Ошибка: ${esc(r.error)}</div>`; return; }
  renderUrlResult(r);
  renderUrlHistory();
  refreshDashboard();
}
function renderUrlResult(r) {
  const verdictText = { danger: 'Опасно: не переходите и не вводите данные', suspicious: 'Подозрительно: высокая вероятность обмана', caution: 'Есть замечания: будьте внимательны', clean: 'Явных признаков угрозы не найдено' }[r.verdict];
  const C = 2 * Math.PI * 40;
  const off = C * (1 - Math.min(100, r.score) / 100);
  const findings = (r.findings || []).map((f) => `<div class="finding">${sevBar(f.sev)}<div><h4>${esc(f.label)}</h4><p>${esc(f.detail)}</p></div></div>`).join('') || '<div class="empty-note">Замечаний нет</div>';
  $('#urlResult').innerHTML = `
    <div class="verdict-box">
      <div class="verdict-score"><svg width="92" height="92" viewBox="0 0 92 92">
        <circle class="track" cx="46" cy="46" r="40" fill="none" stroke-width="5"/>
        <circle class="val" cx="46" cy="46" r="40" fill="none" stroke-width="5" stroke-dasharray="${C}" stroke-dashoffset="${C}" id="vscore"/>
      </svg><b>${r.score}</b></div>
      <div class="verdict-text"><h2>${verdictText}</h2>
        <div class="muted">${esc(r.finalUrl || r.url)}${r.status ? ' · HTTP ' + r.status : ''}${r.ms ? ' · ' + (r.ms / 1000).toFixed(1) + ' с' : ''}${r.rdap && r.rdap.registered ? ' · домен с ' + r.rdap.registered : ''}</div>
      </div>
    </div>
    <div class="url-grid">
      <div class="panel"><div class="panel-head"><h2>Находки на странице и в адресе</h2></div>${findings}</div>
      <div class="panel"><div class="panel-head"><h2>Слежка и сторонние домены</h2></div>
        <div class="tracker-chips">${(r.trackers || []).length ? r.trackers.map((t) => `<span>${esc(t)}</span>`).join('') : '<span>трекеров не найдено</span>'}</div>
        <div class="td-row"><div class="k">Сторонние домены страницы</div><div class="v" style="font-size:12px">${esc((r.thirdParty || []).slice(0, 14).join(', ') || '—')}${(r.thirdParty || []).length > 14 ? ' …' : ''}</div></div>
        <div class="td-row"><div class="k">Облачные базы</div><div class="v" style="font-size:12px">${cloudSummary(r.cloud)}</div></div>
        ${r.redirects && r.redirects.length ? `<div class="td-row"><div class="k">Цепочка редиректов</div><div class="v" style="font-size:12px">${esc(r.redirects.map((x) => x.to).join(' → '))}</div></div>` : ''}
      </div>
    </div>`;
  requestAnimationFrame(() => { const el = $('#vscore'); if (el) el.style.strokeDashoffset = off; });
}
function cloudSummary(c) {
  if (!c) return '—';
  const parts = [];
  if (c.urlhausUrl && c.urlhausUrl.found) parts.push('URLhaus: URL в чёрной базе');
  if (c.urlhausHost && c.urlhausHost.found) parts.push('URLhaus: домен раздавал малварь');
  if (c.virustotal && c.virustotal.found) parts.push(`VirusTotal: ${c.virustotal.malicious}/${c.virustotal.total}`);
  if (c.virustotal && c.virustotal.available === false) parts.push('VirusTotal: ключ не задан');
  return parts.length ? parts.join(' · ') : 'чисто по данным abuse.ch';
}
function renderUrlHistory() {
  const hist = (STATE && STATE.settings && STATE.settings.urlHistory) || [];
  $('#urlHistory').innerHTML = hist.length ? hist.map((h) => `<div class="list-item" style="cursor:pointer" data-url="${esc(h.url)}"><div class="li-body"><div class="li-title">${esc(h.host)} <span class="cat-chip ${h.verdict === 'danger' ? 'virus' : h.verdict === 'clean' ? 'risk' : 'trojan'}">${{ danger: 'опасно', suspicious: 'подозрительно', caution: 'внимание', clean: 'чисто' }[h.verdict]}</span></div><div class="li-sub">${esc(h.url)} · ${fmtDate(h.at)} · оценка ${h.score}</div></div></div>`).join('') : '<div class="empty-note">История пуста</div>';
  $$('#urlHistory .list-item').forEach((el) => el.onclick = () => { $('#urlInput').value = el.dataset.url; runUrl(); });
}

/* ---------------- карантин ---------------- */
function bindQuarantine() {}
async function renderQuarantine() {
  const list = await api.quarantineList();
  $('#quarantineList').innerHTML = list.length ? list.map((q) => `<div class="list-item">
    <div class="li-body"><div class="li-title">${esc(q.name)} <span class="cat-chip ${esc(q.cat || 'risk')}">${CATS[q.cat] || 'объект'}</span></div>
    <div class="li-sub">${esc(q.original)} · изолирован ${fmtDate(q.at)} · ${fmtBytes(q.size)}</div></div>
    <div class="li-right">
      <button class="btn btn-sm" data-q="restore" data-id="${esc(q.id)}">Восстановить</button>
      <button class="btn btn-sm btn-danger" data-q="remove" data-id="${esc(q.id)}">Удалить</button>
    </div></div>`).join('') : '<div class="empty-note">Карантин пуст</div>';
  $$('#quarantineList [data-q]').forEach((b) => b.onclick = async () => {
    const r = b.dataset.q === 'restore' ? await api.quarantineRestore(b.dataset.id) : await api.quarantineRemove(b.dataset.id);
    toast(r.ok ? (b.dataset.q === 'restore' ? 'Восстановлено: ' + (r.path || '') : 'Удалено из карантина') : 'Ошибка: ' + (r.error || ''));
    renderQuarantine(); refreshDashboard();
  });
}

/* ---------------- настройки ---------------- */
function bindSettings() {
  const save = async (patch) => { await api.setSettings(patch); STATE = await api.state(); refreshDashboard(); };
  $('#btnVtTest').onclick = async () => {
    const key = $('#setVtKey').value.trim();
    if (!key) return toast('Вставьте ключ');
    toast('Проверяю ключ…');
    const r = await api.testVt(key);
    toast(r.ok ? `Ключ принят (аккаунт: ${r.name})` : r.error);
    if (r.ok) { await save({ vtKey: key }); $('#vtNote').textContent = 'Ключ сохранён: облачные проверки VirusTotal включены'; }
  };
  $('#setMb').onchange = (e) => save({ cloud: { ...STATE.settings.cloud, malwarebazaar: e.target.checked } });
  $('#setUh').onchange = (e) => save({ cloud: { ...STATE.settings.cloud, urlhaus: e.target.checked } });
  $('#setProt').onchange = async (e) => { await api.setProtection(e.target.checked); STATE = await api.state(); refreshDashboard(); };
  $('#setProtInt').onchange = (e) => save({ protection: { ...STATE.settings.protection, intervalSec: parseInt(e.target.value, 10) || 300 } });
  $('#setOnThreat').onchange = (e) => save({ actions: { onThreat: e.target.value } });
  $('#setAuto').onchange = (e) => api.setAutostart(e.target.checked);
  $('#chkProc').onchange = (e) => save({ checks: { ...STATE.settings.checks, processes: e.target.checked } });
  $('#chkPers').onchange = (e) => save({ checks: { ...STATE.settings.checks, persistence: e.target.checked } });
  $('#chkNet').onchange = (e) => save({ checks: { ...STATE.settings.checks, network: e.target.checked } });
  $('#chkHash').onchange = (e) => save({ checks: { ...STATE.settings.checks, hashScan: e.target.checked } });
}
function fillSettings() {
  if (!STATE) return;
  const s = STATE.settings;
  $('#setVtKey').value = s.vtKey || '';
  $('#setMb').checked = s.cloud.malwarebazaar !== false;
  $('#setUh').checked = s.cloud.urlhaus !== false;
  $('#setProt').checked = !!s.protection.enabled;
  $('#setProtInt').value = s.protection.intervalSec;
  $('#setOnThreat').value = s.actions.onThreat;
  $('#setAuto').checked = !!s.autostart;
  $('#chkProc').checked = s.checks.processes !== false;
  $('#chkPers').checked = s.checks.persistence !== false;
  $('#chkNet').checked = s.checks.network !== false;
  $('#chkHash').checked = s.checks.hashScan !== false;
  $('#aboutBox').innerHTML = `<b>Nukefy ${esc(STATE.version)}</b> · сборка ${esc(STATE.platform)}/${esc(STATE.arch)}<br>
  База сигнатур: <b>${esc(STATE.dbVersion)}</b>, правил: <b>${STATE.dbSignatures}</b><br>
  Облако: MalwareBazaar и URLhaus (abuse.ch) — бесплатно без ключа; VirusTotal — по вашему бесплатному ключу.<br>
  Данные и карантин: <span style="word-break:break-all">${esc(STATE.dataDir)}</span>`;
}

/* ---------------- события движка ---------------- */
function fmtDur(sec) {
  sec = Math.max(0, Math.round(sec));
  const m = Math.floor(sec / 60), s = sec % 60;
  return m + ':' + String(s).padStart(2, '0');
}
function scanTicker() {
  if (scanUi.tick) return;
  scanUi.tick = setInterval(() => {
    if (!scanUi.active || !scanUi.last) return;
    const el = (Date.now() - scanUi.startedAt) / 1000;
    const { done, total, threats } = scanUi.last;
    const speed = el > 0.5 ? done / el : 0;
    const eta = speed > 1 ? (total - done) / speed : 0;
    $('#scanStats').textContent = `файлов: ${done.toLocaleString('ru-RU')} из ${total.toLocaleString('ru-RU')} · угроз: ${threats || 0} · ${Math.round(speed).toLocaleString('ru-RU')} ф/с · прошло ${fmtDur(el)} · осталось ~${fmtDur(eta)}`;
  }, 500);
}
function bindEvents() {
  api.onEvent(async (e) => {
    if (e.type === 'scan:start') {
      scanUi.active = true;
      scanUi.startedAt = Date.now();
      scanUi.last = null;
      $('#radar').classList.add('scanning');
      $('#btnScanStart').disabled = true; $('#btnScanCancel').disabled = false;
      scanTicker();
    }
    if (e.type === 'phase') {
      $('#scanPhase').textContent = e.message || '';
    }
    if (e.type === 'progress') {
      const pct = e.total ? Math.round((e.done / e.total) * 100) : 0;
      $('#scanPct').textContent = pct + '%';
      scanUi.last = { done: e.done || 0, total: e.total || 0, threats: e.threats || 0 };
      if (e.path) {
        const pEl = $('#scanPath');
        pEl.textContent = e.path.length > 96 ? '…' + e.path.slice(-95) : e.path;
        pEl.title = e.path;
      }
    }
    if (e.type === 'threat') {
      scanUi.results.unshift(e.threat);
      renderScanResults();
      toast(`Найдено: ${e.threat.title} (${CATS[e.threat.cat] || e.threat.cat})`);
    }
    if (e.type === 'scan:finished') {
      scanUi.active = false;
      if (scanUi.tick) { clearInterval(scanUi.tick); scanUi.tick = null; }
      $('#radar').classList.remove('scanning');
      $('#btnScanStart').disabled = false; $('#btnScanCancel').disabled = true;
      $('#scanPct').textContent = '100%';
      $('#scanPhase').textContent = e.cancelled ? 'Остановлено' : 'Проверка завершена';
      $('#scanStats').textContent = `файлов: ${(e.stats.files || 0).toLocaleString('ru-RU')} · угроз: ${e.stats.threats || 0} · ${(e.stats.ms / 1000).toFixed(1)} с`;
      if (!e.selftest) toast(e.cancelled ? 'Проверка остановлена' : `Проверка завершена: угроз — ${e.stats.threats}`);
      await refreshAll();
    }
    if (e.type === 'protection:alert') {
      toast(`Резидентная защита: ${e.threat.title}${e.auto ? ' — файл изолирован автоматически' : ''}`);
      await refreshAll();
    }
    if (e.type === 'threats:changed') await refreshAll();
  });
}

boot();
