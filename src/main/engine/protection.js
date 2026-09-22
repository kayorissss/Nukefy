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

class Protection {
  constructor(deps) {
    this.deps = deps; // {db, settings, store, emit}
    this.timer = null;
    this.running = false;
    this.lastRun = null;
  }
  start() {
    const sec = Math.max(30, (this.deps.settings.get().protection || {}).intervalSec || 300);
    this.stop();
    this.timer = setInterval(() => { this.tick().catch(() => {}); }, sec * 1000);
    this.tick().catch(() => {});
    return true;
  }
  stop() { if (this.timer) clearInterval(this.timer); this.timer = null; }
  enabled() { return !!(this.deps.settings.get().protection || {}).enabled; }

  async tick() {
    if (this.running) return;
    this.running = true;
    const { db, settings, store, emit } = this.deps;
    try {
      const found = [];
      if (settings.get().checks.processes !== false) {
        const [procs, conns] = await Promise.all([listProcesses(), listConnections()]);
        found.push(...analyzeProcesses(procs, conns, db).map((t) => ({ ...t, source: t.reason === 'pool-port' ? 'network' : 'process' })));
      }
      if (settings.get().checks.persistence !== false) {
        const items = await collectAutorun();
        found.push(...analyzeAutorun(items, db).map((t) => ({ ...t, source: 'autorun' })));
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
