'use strict';
/**
 * Nukefy — резидентная защита.
 * Цикл: процессы+сеть → автозапуск → hosts → (опц.) быстрые папки.
 * Новые угрозы → событие protection:alert; при настройке actions.onThreat=quarantine
 * файлы изолируются автоматически.
 */
const { listProcesses, listConnections, analyzeProcesses } = require('./procscan');
const { collectAutorun, analyzeAutorun, checkHosts } = require('./persistence');
const { FileScanner } = require('./scanner');
const { listTempModuleThreats } = require('./procscan');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

class Protection {
  constructor(deps) {
    this.deps = deps; // {db, settings, store, emit, selfPaths, onSchedule}
    this.timer = null;
    this.running = false;
    this.lastRun = null;
    this.canaries = [];   // [{path, hash, watcher}]
    this.lastScheduleDay = null;
  }
  start() {
    const sec = Math.max(30, (this.deps.settings.get().protection || {}).intervalSec || 300);
    this.stop();
    this.timer = setInterval(() => { this.tick().catch(() => {}); this.checkSchedule(); }, sec * 1000);
    this.ensureCanaries();
    this.tick().catch(() => {});
    return true;
  }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; this.stopCanaries(); }

  /* ---- ransomware-канарейки: приманки в пользовательских папках ---- */
  canaryDirs() {
    const env = process.env;
    if (process.platform === 'win32') {
      return [env.USERPROFILE && path.join(env.USERPROFILE, 'Documents'), env.USERPROFILE && path.join(env.USERPROFILE, 'Desktop'), env.USERPROFILE && path.join(env.USERPROFILE, 'Pictures')].filter(Boolean);
    }
    return [path.join(os.homedir(), 'Documents'), os.homedir()].filter((d) => { try { fs.accessSync(d); return true; } catch (_) { return false; } });
  }
  ensureCanaries() {
    if ((this.deps.settings.get().protection || {}).canary === false) return;
    this.stopCanaries();
    for (const dir of this.canaryDirs()) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        const name = 'nukefy-canary-' + crypto.randomBytes(4).toString('hex') + '.txt';
        const file = path.join(dir, name);
        const content = 'Nukefy ransomware canary. Do not edit. ' + crypto.randomBytes(8).toString('hex');
        fs.writeFileSync(file, content);
        const rec = { path: file, hash: crypto.createHash('sha256').update(content).digest('hex'), watcher: null };
        rec.watcher = fs.watch(dir, (_evt, fname) => {
          if (String(fname || '') !== name) return;
          setTimeout(() => this.checkCanary(rec), 400);
        });
        this.canaries.push(rec);
      } catch (_) {}
    }
  }
  stopCanaries() {
    for (const c of this.canaries) { try { c.watcher && c.watcher.close(); } catch (_) {} try { fs.rmSync(c.path, { force: true }); } catch (_) {} }
    this.canaries = [];
  }
  checkCanary(rec) {
    try {
      const buf = fs.readFileSync(rec.path);
      const h = crypto.createHash('sha256').update(buf).digest('hex');
      if (h === rec.hash) return;
      // канарейку изменили/переименовали/удалили → поведение шифровальщика
      const t = this.deps.store.add({ source: 'file', cat: 'virus', sev: 4, fam: 'ransomware', title: 'Ransom.Canary', desc: `Изменён файл-приманка защиты от шифровальщиков: ${rec.path}. Проверьте недавние процессы и файлы в этой папке.`, path: rec.path });
      this.deps.store.addEvent('detect', { title: t.title, path: rec.path });
      this.deps.emit({ type: 'protection:alert', threat: t, auto: false });
      // восстанавливаем приманку
      const content = 'Nukefy ransomware canary. Do not edit. ' + crypto.randomBytes(8).toString('hex');
      fs.writeFileSync(rec.path, content);
      rec.hash = crypto.createHash('sha256').update(content).digest('hex');
    } catch (_) {
      // файл удалён/переименован — тоже признак
      const t = this.deps.store.add({ source: 'file', cat: 'virus', sev: 4, fam: 'ransomware', title: 'Ransom.Canary', desc: `Файл-приманка защиты исчез или переименован: ${rec.path}`, path: rec.path });
      this.deps.emit({ type: 'protection:alert', threat: t, auto: false });
      this.ensureCanaries();
    }
  }

  /* ---- расписание сканирований ---- */
  checkSchedule() {
    const sch = this.deps.settings.get().schedule || {};
    if (!sch.enabled) return;
    const now = new Date();
    const today = now.toISOString().slice(0, 10);
    const [hh, mm] = String(sch.time || '03:00').split(':').map((x) => parseInt(x, 10) || 0);
    const due = now.getHours() > hh || (now.getHours() === hh && now.getMinutes() >= mm);
    if (!due || this.lastScheduleDay === today) return;
    this.lastScheduleDay = today;
    this.deps.store.addEvent('scan', { message: 'Сканирование по расписанию: ' + (sch.mode || 'quick') });
    if (this.deps.onSchedule) this.deps.onSchedule(sch.mode || 'quick');
  }
  enabled() { return !!(this.deps.settings.get().protection || {}).enabled; }

  async tick() {
    if (this.running) return;
    this.running = true;
    const { db, settings, store, emit } = this.deps;
    try {
      const found = [];
      if (settings.get().checks.processes !== false) {
        const [procs, conns] = await Promise.all([listProcesses(), listConnections()]);
        found.push(...analyzeProcesses(procs, conns, db, { selfPaths: this.deps.selfPaths || [] }).map((t) => ({ ...t, source: t.reason === 'pool-port' ? 'network' : 'process' })));
      }
      if (settings.get().checks.persistence !== false) {
        const items = await collectAutorun();
        found.push(...analyzeAutorun(items, db).map((t) => ({ ...t, source: 'autorun' })));
      }
      if (settings.get().checks.modules !== false && process.platform === 'win32') {
        for (const t of await listTempModuleThreats()) {
          const rec = store.add(t);
          if (!store.isIgnored(rec) && !store.isWhitelisted(rec) && rec.status === 'new') found.push(rec);
        }
      }
      if (settings.get().checks.network !== false) {
        const hosts = await checkHosts();
        for (const issue of hosts.issues) {
          found.push({ source: 'hosts', cat: 'risk', sev: 2, fam: 'hosts-hijack', title: 'Hosts.Hijack', desc: issue.reason + ': ' + issue.line, host: issue.host, line: issue.line, path: hosts.path });
        }
      }
      const fresh = [];
      for (const t of found) {
        const rec = store.add({ ...t, status: 'new' });
        if (!store.isIgnored(rec) && !store.isWhitelisted(rec) && rec.status === 'new') fresh.push(rec);
      }
      if (fresh.length) {
        await store.save();
        const auto = (settings.get().actions || {}).onThreat === 'quarantine';
        for (const t of fresh) {
          if (auto && t.path) {
            const r = await store.act(t.id, 'quarantine');
            if (r.ok) t.status = 'quarantined';
          }
          emit({ type: 'protection:alert', threat: t, auto: auto && !!t.path });
        }
      }
      this.lastRun = new Date().toISOString();
    } finally {
      this.running = false;
    }
  }
}

module.exports = { Protection };
