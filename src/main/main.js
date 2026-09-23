'use strict';
/**
 * Nukefy — главный процесс Electron.
 * Полноэкранное окно, плавный ступенчатый запуск, IPC-мост к движку.
 */
const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');

const { Settings, dataDir } = require('./engine/settings');
const { SignatureDB, knowledgeFor } = require('./engine/signatures');
const { Quarantine } = require('./engine/quarantine');
const { ThreatStore } = require('./engine/store');
const { FileScanner } = require('./engine/scanner');
const { Protection } = require('./engine/protection');
const { listProcesses, listConnections, analyzeProcesses } = require('./engine/procscan');
const { collectAutorun, analyzeAutorun, checkHosts, analyzeHostsText, restoreHosts } = require('./engine/persistence');
const { isTrustedPath } = require('./engine/constants');
const { analyzeUrl } = require('./engine/webanalyze');
const { vtTestKey } = require('./engine/reputation');
const { writeJson } = require('./engine/util');

let win = null;
let settings = null;
let db = null;
let quarantine = null;
let store = null;
let protection = null;
let scanSession = null;

const VERSION = require('../../package.json').version;

function selfDirs() {
  const dirs = new Set();
  try { dirs.add(path.dirname(process.execPath)); dirs.add(process.execPath); } catch (_) {}
  try { const { app } = require('electron'); dirs.add(app.getAppPath()); dirs.add(path.dirname(app.getAppPath())); } catch (_) {}
  return [...dirs];
}

function emit(evt) {
  if (win && !win.isDestroyed()) win.webContents.send('nukefy:evt', evt);
}

async function ensureInit() {
  if (store) return;
  settings = new Settings();
  await settings.load();
  db = new SignatureDB();
  db.load();
  quarantine = await new Quarantine(path.join(dataDir(), 'quarantine')).init();
  store = new ThreatStore(path.join(dataDir(), 'threats.json'), { quarantine, settings, db });
  await store.init();
  // миграция 1.0.4: чистим ложные срабатывания старых версий
  store.purge((t) => (
    (t.source === 'process' && ['Trojan.Dropper.ScriptDropper', 'Proc.Masquerade', 'Proc.TempRun'].includes(t.title)) ||
    (t.source === 'hosts' && analyzeHostsText(t.line || '').length === 0) ||
    (t.source === 'autorun' && isTrustedPath(t.command || t.path))
  ));
  protection = new Protection({ db, settings, store, emit, selfPaths: selfDirs() });
  if (protection.enabled()) protection.start();
}

function createWindow() {
  win = new BrowserWindow({
    fullscreen: true,
    frame: false,
    transparent: false,
    backgroundColor: '#08080a',
    show: false,
    autoHideMenuBar: true,
    title: 'Nukefy',
    icon: path.join(__dirname, '..', '..', 'assets', 'icon.png'),
    webPreferences: {
      preload: path.join(__dirname, '..', 'preload', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      spellcheck: false,
    },
  });
  win.once('ready-to-show', () => win.show());
  win.setMenuBarVisibility(false);
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.on('closed', () => { win = null; });
  // внешние ссылки — в системный браузер
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
}

/* ------------------------- сканирование ------------------------- */
function startScan(opts) {
  if (scanSession && !scanSession.done) return { ok: false, error: 'Сканирование уже идёт' };
  const mode = opts.mode === 'quick' ? 'quick' : opts.mode === 'custom' ? 'custom' : 'full';
  const roots = mode === 'quick' ? settings.get().scan.quickRoots
    : mode === 'custom' ? (opts.roots || [])
    : settings.get().scan.fullRoots;
  const scanId = crypto.randomUUID();
  const session = { id: scanId, mode, done: false, startedAt: Date.now(), threatsBefore: store.active().length };
  scanSession = session;
  emit({ type: 'scan:start', scanId, mode, roots });
  const scanner = new FileScanner({
    db, settings: settings.get(), scanId, mode, roots,
    singleFile: opts.singleFile || null,
    excludePrefixes: selfDirs(),
    onEvent: (e) => emit({ ...e, scanId }),
  });
  session.scanner = scanner;
  scanner.run().then(async (r) => {
    session.done = true;
    store.addHistory({
      id: scanId, mode, at: new Date().toISOString(),
      files: r.stats.files, threats: r.stats.threats, ms: r.stats.ms, cancelled: r.cancelled,
    });
    emit({ type: 'scan:finished', scanId, stats: r.stats, cancelled: r.cancelled });
  }).catch((e) => {
    session.done = true;
    emit({ type: 'scan:error', scanId, error: String(e && e.message) });
  });
  return { ok: true, scanId };
}

/* ------------------------- IPC ------------------------- */
function registerIpc() {
  const H = (ch, fn) => ipcMain.handle(ch, async (_e, ...args) => {
    try { return await fn(...args); }
    catch (e) { return { ok: false, error: String(e && e.message || e) }; }
  });

  H('app:state', async () => {
    await ensureInit();
    return {
      version: VERSION,
      platform: process.platform,
      arch: process.arch,
      dataDir: dataDir(),
      dbVersion: db.version,
      dbSignatures: db.signatures.length,
      dbSource: db.loadedFrom,
      protection: { enabled: protection.enabled(), intervalSec: settings.get().protection.intervalSec, lastRun: protection.lastRun },
      counts: { active: store.active().length, quarantined: quarantine.list().length },
      settings: settings.get(),
      threats: store.all(),
      history: store.historyList(),
      vtKeySet: !!settings.get().vtKey,
    };
  });

  H('scan:start', async (opts = {}) => { await ensureInit(); return startScan(opts); });
  H('scan:cancel', async () => { if (scanSession && scanSession.scanner) scanSession.scanner.cancel(); return { ok: true }; });

  H('system:check', async (which) => {
    await ensureInit();
    const out = { ok: true, threats: [] };
    if (which === 'processes' || which === 'all') {
      const [procs, conns] = await Promise.all([listProcesses(), listConnections()]);
      out.processes = procs.length;
      out.connections = conns.length;
      for (const t of analyzeProcesses(procs, conns, db, { selfPaths: selfDirs() })) {
        const rec = store.add({ ...t, source: t.reason === 'pool-port' ? 'network' : 'process' });
        out.threats.push(rec);
      }
    }
    if (which === 'persistence' || which === 'all') {
      const items = await collectAutorun();
      out.autorun = items.length;
      for (const t of analyzeAutorun(items, db)) {
        const rec = store.add({ ...t, source: 'autorun' });
        out.threats.push(rec);
      }
    }
    if (which === 'hosts' || which === 'all') {
      const hosts = await checkHosts();
      out.hostsOk = hosts.ok;
      for (const issue of hosts.issues) {
        const rec = store.add({ source: 'hosts', cat: 'risk', sev: 2, fam: 'hosts-hijack', title: 'Hosts.Hijack', desc: issue.reason + ': ' + issue.line, host: issue.host, line: issue.line, path: hosts.path });
        out.threats.push(rec);
      }
    }
    await store.save();
    return out;
  });

  H('threat:list', async () => { await ensureInit(); return store.all(); });
  H('threat:act', async (id, action) => {
    await ensureInit();
    const r = await store.act(id, action);
    if (r.ok) emit({ type: 'threats:changed' });
    return r;
  });
  H('threat:knowledge', async (id, fam) => { await ensureInit(); const t = store.get(id); if (t) return store.knowledge(t); return knowledgeFor(fam || 'generic'); });

  H('quarantine:list', async () => { await ensureInit(); return quarantine.list(); });
  H('quarantine:restore', async (id) => { await ensureInit(); const r = await quarantine.restore(id); emit({ type: 'threats:changed' }); return r; });
  H('quarantine:remove', async (id) => { await ensureInit(); return quarantine.remove(id); });

  H('settings:get', async () => { await ensureInit(); return settings.get(); });
  H('settings:set', async (patch) => {
    await ensureInit();
    const next = await settings.set(patch);
    if (patch.protection) { protection.enabled() ? protection.start() : protection.stop(); }
    return next;
  });
  H('settings:testVt', async (key) => vtTestKey(key));

  H('url:analyze', async (url) => {
    await ensureInit();
    const r = await analyzeUrl(url, settings.get(), (s) => emit({ type: 'url:step', ...s, url }));
    if (r.ok) {
      const hist = settings.get().urlHistory || [];
      hist.unshift({ url: r.url, host: r.host, score: r.score, verdict: r.verdict, at: new Date().toISOString() });
      await settings.set({ urlHistory: hist.slice(0, 50) });
      if (r.verdict === 'danger') {
        store.add({ source: 'url', cat: 'trojan', sev: 4, fam: 'generic', title: 'Web.Dangerous', desc: `Ссылка получила оценку опасности ${r.score}/100`, url: r.url });
        await store.save();
        emit({ type: 'threats:changed' });
      }
    }
    return r;
  });

  H('files:pick', async () => {
    const r = await dialog.showOpenDialog(win, { properties: ['openDirectory', 'multiSelections'] });
    return r.canceled ? { ok: false } : { ok: true, paths: r.filePaths };
  });
  H('shell:openExternal', async (url) => { if (/^https?:/.test(url)) await shell.openExternal(url); return { ok: true }; });
  H('shell:reveal', async (p) => { try { shell.showItemInFolder(p); return { ok: true }; } catch (e) { return { ok: false, error: String(e.message) }; } });
  H('shell:openPath', async (p) => { const r = await shell.openPath(p); return { ok: r ? false : true, error: r || null }; });

  H('misc:selftest', async () => {
    await ensureInit();
    const dir = path.join(dataDir(), 'selftest');
    await fsp.mkdir(dir, { recursive: true });
    const eicar = path.join(dir, 'eicar-com-test.txt');
    await fsp.writeFile(eicar, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');
    const miner = path.join(dir, 'pool-config.json');
    await fsp.writeFile(miner, JSON.stringify({ url: 'stratum+tcp://pool.supportxmr.com:3333', user: 'x', pass: 'x' }));
    // отдельная сессия самопроверки по каталогу selftest
    if (scanSession && scanSession.scanner && !scanSession.done) scanSession.scanner.cancel();
    const scanId = crypto.randomUUID();
    const scanner = new FileScanner({ db, settings: settings.get(), scanId, mode: 'custom', roots: [dir], excludePrefixes: selfDirs(), onEvent: (e) => emit({ ...e, scanId }) });
    scanSession = { id: scanId, mode: 'selftest', done: false, scanner };
    emit({ type: 'scan:start', scanId, mode: 'selftest', roots: [dir] });
    const r = await scanner.run();
    scanSession.done = true;
    emit({ type: 'scan:finished', scanId, stats: r.stats, cancelled: false, selftest: true });
    return { ok: true, files: 2, threats: r.stats.threats, expect: 2, pass: r.stats.threats >= 2 };
  });

  H('protection:set', async (enabled) => {
    await ensureInit();
    await settings.set({ protection: { ...settings.get().protection, enabled: !!enabled } });
    enabled ? protection.start() : protection.stop();
    return { ok: true, enabled: protection.enabled() };
  });

  H('autostart:set', async (on) => {
    try {
      app.setLoginItemSettings({ openAtLogin: !!on, openAsHidden: false });
      await settings.set({ autostart: !!on });
      return { ok: true };
    } catch (e) { return { ok: false, error: String(e && e.message) }; }
  });

  H('app:quit', async () => { app.quit(); return { ok: true }; });
  H('app:minimize', async () => { if (win) win.minimize(); return { ok: true }; });
  H('app:toggleFull', async () => { if (win) win.isFullScreen() ? win.setFullScreen(false) : win.setFullScreen(true); return { ok: true }; });
}

app.whenReady().then(async () => {
  registerIpc();
  createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
process.on('uncaughtException', (e) => { try { emit({ type: 'app:error', error: String(e && e.message) }); } catch (_) {} });
