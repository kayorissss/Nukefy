'use strict';
/* UI-смоук: рендерер Nukefy в jsdom (демо-мост) — проверяет, что после заставки
   приложение реально видимо и основные сценарии работают. node test/ui.smoke.js */
const path = require('path');
const { JSDOM } = require('jsdom');

const PAGE = path.join(__dirname, '..', 'src', 'renderer', 'index.html');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms, label) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (fn()) return true;
    await sleep(120);
  }
  throw new Error('таймаут: ' + label);
}

(async () => {
  const dom = await JSDOM.fromFile(PAGE, {
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const doc = window.document;
  window.addEventListener('error', (e) => { console.log('  window error: ' + e.message); });

  await until(() => doc.getElementById('app') && !doc.getElementById('app').classList.contains('hidden'), 9000, 'app стал видимым после заставки');
  console.log('  ok  приложение видимо после загрузочной анимации');

  if (doc.getElementById('bootSteps')) throw new Error('список шагов загрузки не удалён');
  console.log('  ok  списка шагов на заставке нет');

  await until(() => doc.getElementById('boot') === null || doc.getElementById('boot').classList.contains('gone'), 3000, 'заставка скрыта');
  console.log('  ok  заставка скрыта');

  // навигация
  doc.querySelector('[data-view="scan"]').click();
  await until(() => doc.getElementById('view-scan').classList.contains('active'), 2000, 'вкладка сканирования');
  console.log('  ok  навигация работает');

  // запуск быстрой проверки на демо-мосту
  doc.getElementById('btnScanStart').click();
  await until(() => doc.querySelectorAll('#scanResults .list-item').length >= 3, 20000, 'находки сканирования');
  console.log('  ok  сканирование даёт находки: ' + doc.querySelectorAll('#scanResults .list-item').length);

  await until(() => !doc.getElementById('radar').classList.contains('scanning'), 8000, 'сканирование завершено');
  console.log('  ok  сканирование завершается, радар остановлен');

  // угрозы: список + карточка знаний
  doc.querySelector('[data-view="threats"]').click();
  await until(() => doc.querySelectorAll('#threatList .list-item').length >= 3, 4000, 'список угроз');
  doc.querySelector('#threatList .list-item').click();
  await until(() => doc.querySelector('#threatDetail .know-card'), 4000, 'карточка знаний «?»');
  const know = doc.querySelector('#threatDetail .know-card').textContent;
  if (!/опасн/i.test(know)) throw new Error('в карточке нет описания опасности');
  console.log('  ok  карточка угрозы со справкой (что делает / чем опасен / даты)');

  // плавающая справка «?» не обрезается и грузится
  const q = doc.querySelector('#threatList .help-q');
  q.dispatchEvent(new window.MouseEvent('mouseover', { bubbles: true }));
  await until(() => doc.getElementById('kpop') && !doc.getElementById('kpop').hidden && /опас/i.test(doc.getElementById('kpop').textContent), 4000, 'справка «?» открылась');
  q.dispatchEvent(new window.MouseEvent('mouseout', { bubbles: true }));
  await until(() => doc.getElementById('kpop').hidden, 2000, 'справка «?» закрылась');
  console.log('  ok  справка «?» — плавающая карточка, грузится и закрывается');

  // действия: карантин
  const qBtn = doc.querySelector('#threatDetail [data-act="quarantine"]');
  qBtn.click();
  await until(() => /quarantined|в карантине/i.test(doc.getElementById('threatDetail').textContent), 4000, 'действие карантин');
  console.log('  ok  действие «В карантин» применяется');

  // анализ ссылки
  doc.querySelector('[data-view="url"]').click();
  doc.getElementById('urlInput').value = 'http://192.168.0.7/login';
  doc.getElementById('btnUrlAnalyze').click();
  await until(() => doc.querySelector('#urlResult .verdict-box'), 8000, 'результат анализа ссылки');
  const score = doc.querySelector('#urlResult .verdict-score b').textContent;
  if (!(parseInt(score, 10) > 0)) throw new Error('оценка не посчитана');
  console.log('  ok  анализ ссылки: оценка ' + score + '/100');

  console.log('\nUI-смоук пройден');
  window.close();
  process.exit(0);
})().catch((e) => { console.error('FAIL: ' + (e && e.message || e)); process.exit(1); });
