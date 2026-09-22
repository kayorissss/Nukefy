'use strict';
/* Демо-мост: используется ТОЛЬКО когда приложение открыто в обычном браузере
   (превью интерфейса). Внутри Electron эти функции предоставляет preload. */
if (!window.nukefy) {
  const K = {
    eicar: { title: 'EICAR — тестовый файл', whatItDoes: 'Безвредная тестовая строка-стандарт: её единственная задача — пойматься антивирусом.', whyDangerous: 'Не опасен. Официальный тест ассоциации EICAR.', firstSeen: '1990 (стандарт EICAR)', whereFrom: 'Создаётся самопроверкой Nukefy.', whereGoes: 'Никуда.', advice: 'Удалить после теста.' },
    'generic-miner': { title: 'Майнер (общий класс)', whatItDoes: 'Грузит CPU/GPU и майнит криптовалюту в чужой кошелёк через протокол stratum.', whyDangerous: 'Перегрев, износ оборудования, лаги, рост счетов за электричество.', firstSeen: 'волна 2017–2018', whereFrom: 'Кряки, читы, взломанные серверы RDP/SSH.', whereGoes: 'Автозапуск, планировщик, папки Temp/AppData.', advice: 'Карантин + проверка автозапуска.' },
    'hidden-autorun': { title: 'Скрытая запись автозапуска', whatItDoes: 'Запускает программу при входе в систему.', whyDangerous: 'Так закрепляются 9 из 10 вредоносов.', firstSeen: 'приём с 2000-х', whereFrom: 'Установщики «бесплатного» софта.', whereGoes: 'Реестр Run, папка «Автозагрузка».', advice: 'Удалить запись и проверить файл.' },
    generic: { title: 'Неизвестная угроза', whatItDoes: 'Объект совпал с эвристическими признаками вредоносной активности.', whyDangerous: 'Возможна кража данных или загрузка дополнительных модулей.', firstSeen: 'неизвестно', whereFrom: 'Письма, пиратские сборки, флешки.', whereGoes: 'Автозапуск, браузер, документы.', advice: 'Изолировать и перепроверить в облаке.' },
  };
  const listeners = [];
  const emit = (e) => listeners.forEach((l) => l(e));
  let threats = [];
  let seq = 0;
  const settings = {
    version: 1, vtKey: '', cloud: { malwarebazaar: true, urlhaus: true, virustotal: 'auto' },
    checks: { processes: true, persistence: true, network: true, startupFiles: true, hashScan: true },
    scan: {}, protection: { enabled: true, intervalSec: 300 }, actions: { onThreat: 'notify' },
    whitelist: [], ignored: [], urlHistory: [], autostart: false,
  };
  const state = () => ({
    version: '1.0.2', platform: 'demo', arch: 'web', dataDir: '(демо-режим браузера)',
    dbVersion: '2026.09.22', dbSignatures: 22, protection: { enabled: settings.protection.enabled, intervalSec: 300, lastRun: null },
    counts: { active: threats.filter((t) => t.status === 'new').length, quarantined: QUAR.length },
    settings, threats, history: HIST, vtKeySet: !!settings.vtKey,
  });
  const QUAR = [];
  const HIST = [{ id: 'h1', mode: 'quick', at: new Date(Date.now() - 3600e3).toISOString(), files: 4821, threats: 0, ms: 12400 }];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  window.nukefy = {
    state: async () => state(),
    startScan: async ({ mode }) => {
      emit({ type: 'scan:start', scanId: 'demo', mode });
      emit({ type: 'phase', message: 'Сбор списка файлов…' });
      await sleep(700);
      const total = mode === 'full' ? 240 : 90;
      emit({ type: 'phase', message: 'Сканирование…', total });
      const demoThreats = [
        { at: 0.35, t: { source: 'file', kind: 'signature', cat: 'virus', sev: 1, fam: 'eicar', title: 'Win32.EICAR-Test', desc: 'Стандартная тестовая строка EICAR', path: 'C:\\Users\\demo\\Downloads\\eicar-com-test.txt', size: 68 } },
        { at: 0.6, t: { source: 'file', kind: 'signature', cat: 'miner', sev: 3, fam: 'generic-miner', title: 'Miner.Stratum.Generic', desc: 'Обращение к пулу майнинга по протоколу stratum', path: 'C:\\Users\\demo\\AppData\\Local\\Temp\\svc-update\\config.json', size: 412 } },
        { at: 0.8, t: { source: 'autorun', kind: 'heuristic', cat: 'trojan', sev: 3, fam: 'hidden-autorun', title: 'Autorun.TempTarget', desc: 'Автозапуск файла из временной папки', command: 'C:\\Users\\demo\\AppData\\Local\\Temp\\svc-update\\svchost.exe', key: 'HKCU\\...\\Run', name: 'svc-update' } },
      ];
      for (let i = 0; i <= total; i++) {
        await sleep(mode === 'full' ? 26 : 34);
        emit({ type: 'progress', done: i, total, files: i * 137, threats: threats.length });
        for (const d of demoThreats) {
          if (!d.done && i / total >= d.at) {
            d.done = true;
            const th = { id: 't' + (++seq), status: 'new', foundAt: new Date().toISOString(), scanId: 'demo', ...d.t };
            threats.unshift(th);
            emit({ type: 'threat', threat: th });
          }
        }
      }
      HIST.unshift({ id: 'h' + Date.now(), mode, at: new Date().toISOString(), files: total * 137, threats: demoThreats.filter((d) => d.done).length, ms: total * 34 });
      emit({ type: 'scan:finished', scanId: 'demo', stats: { files: total * 137, threats: demoThreats.filter((d) => d.done).length, ms: total * 34 }, cancelled: false });
      return { ok: true, scanId: 'demo' };
    },
    cancelScan: async () => ({ ok: true }),
    systemCheck: async () => ({ ok: true, threats: [] }),
    threats: async () => threats,
    act: async (id, action) => {
      const t = threats.find((x) => x.id === id);
      if (!t) return { ok: false, error: 'нет' };
      t.status = { heal: 'healed', quarantine: 'quarantined', delete: 'deleted', whitelist: 'whitelisted', ignore: 'ignored', dismiss: 'dismissed' }[action] || 'dismissed';
      if (action === 'quarantine' && t.path) QUAR.unshift({ id: 'q' + id, name: t.path.split(/[\\/]/).pop(), original: t.path, at: new Date().toISOString(), size: t.size || 1024, cat: t.cat });
      return { ok: true };
    },
    knowledge: async (id) => { const t = threats.find((x) => x.id === id); return K[t ? t.fam : 'generic'] || K.generic; },
    quarantineList: async () => QUAR,
    quarantineRestore: async (id) => { const i = QUAR.findIndex((q) => q.id === id); if (i >= 0) QUAR.splice(i, 1); return { ok: true }; },
    quarantineRemove: async (id) => { const i = QUAR.findIndex((q) => q.id === id); if (i >= 0) QUAR.splice(i, 1); return { ok: true }; },
    getSettings: async () => settings,
    setSettings: async (p) => Object.assign(settings, p),
    testVt: async (k) => (k.length > 10 ? { ok: true, name: 'demo' } : { ok: false, error: 'Ключ отклонён (401).' }),
    analyzeUrl: async (url) => {
      const steps = [['url', 200], ['rdap', 500], ['fetch', 900], ['html', 400], ['cloud', 600]];
      for (const [s] of steps) { emit({ type: 'url:step', step: s }); await sleep(steps.find((x) => x[0] === s)[1]); }
      let u;
      try { u = new URL(url.includes('://') ? url : 'https://' + url); } catch (_) { return { ok: false, error: 'Не удалось разобрать адрес' }; }
      const f = [];
      let score = 0;
      const add = (sev, w, label, detail) => { f.push({ sev, w, label, detail }); };
      if (u.protocol === 'http:') { add(2, 14, 'Нет шифрования (HTTP)', 'Трафик читается и подменяется по пути.'); score += 14; }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.hostname)) { add(3, 18, 'Адрес вместо домена', 'Сайт открыт по IP — так прячутся от репутационных баз.'); score += 18; }
      if (/\.(xyz|top|click|zip|lol)$/.test(u.hostname)) { add(2, 12, 'Подозрительная доменная зона', 'Зона массово используется для фишинга.'); score += 12; }
      if (/(paypal|google|apple|sberbank|gosuslugi|binance)/.test(u.hostname) && !/(paypal\.com|google\.com|apple\.com|sberbank\.ru|gosuslugi\.ru|binance\.com)$/.test(u.hostname)) { add(3, 20, 'Имитация бренда', 'Имя бренда в чужом домене — классический фишинг.'); score += 20; }
      const trackers = /youtube|google|yandex|vk\.com|facebook|instagram/.test(u.hostname) ? ['Google Analytics', 'Google Tag Manager', 'Яндекс.Метрика'] : (/shop|store|market/.test(u.hostname) ? ['Google Analytics', 'Meta Pixel'] : []);
      if (trackers.length) add(1, 3, `Трекеры: ${trackers.length}`, trackers.join(', '));
      score = Math.min(100, score);
      const verdict = score >= 60 ? 'danger' : score >= 30 ? 'suspicious' : score >= 10 ? 'caution' : 'clean';
      settings.urlHistory.unshift({ url: u.toString(), host: u.hostname, score, verdict, at: new Date().toISOString() });
      return { ok: true, url: u.toString(), host: u.hostname, finalUrl: u.toString(), status: 200, findings: f, trackers, thirdParty: trackers.length ? ['cdn.example-analytics.com'] : [], redirects: [], rdap: { registered: '2019-04-12' }, cloud: {}, score, verdict, ms: 2400 };
    },
    pickFolders: async () => ({ ok: true, paths: ['/demo/downloads'] }),
    openExternal: async (u) => { window.open(u, '_blank'); return { ok: true }; },
    reveal: async () => ({ ok: true }),
    openPath: async () => ({ ok: true }),
    selftest: async () => {
      emit({ type: 'scan:start', scanId: 'st', mode: 'selftest' });
      await sleep(900);
      const th = { id: 't' + (++seq), status: 'new', foundAt: new Date().toISOString(), source: 'file', kind: 'signature', cat: 'virus', sev: 1, fam: 'eicar', title: 'Win32.EICAR-Test', desc: 'Тест EICAR', path: '(демо) eicar-com-test.txt', size: 68 };
      threats.unshift(th); emit({ type: 'threat', threat: th });
      emit({ type: 'scan:finished', scanId: 'st', stats: { files: 2, threats: 2, ms: 900 }, cancelled: false, selftest: true });
      return { ok: true, files: 2, threats: 2, expect: 2, pass: true };
    },
    setProtection: async (on) => { settings.protection.enabled = on; return { ok: true }; },
    setAutostart: async (on) => { settings.autostart = on; return { ok: true }; },
    quit: async () => { document.body.innerHTML = '<div style="color:#888;display:flex;height:100vh;align-items:center;justify-content:center;font-family:sans-serif">Демо-сессия завершена</div>'; return { ok: true }; },
    minimize: async () => ({ ok: true }),
    toggleFull: async () => { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen().catch(() => {}); return { ok: true }; },
    onEvent: (cb) => { listeners.push(cb); return () => { const i = listeners.indexOf(cb); if (i >= 0) listeners.splice(i, 1); }; },
  };
}
