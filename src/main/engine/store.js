'use strict';
/**
 * Nukefy — хранилище угроз и действий над ними.
 * Угроза: {id, scanId, source: file|process|autorun|hosts|network|url, cat, sev, fam,
 *          title, desc, path, pid, url, command, foundAt, status, cloud}
 * Действия: heal | quarantine | delete | whitelist | ignore | dismiss.
 */
const fsp = require('fs').promises;
const path = require('path');
const { writeJson, readJson, uuid, nowIso } = require('./util');
const { knowledgeFor } = require('./signatures');

class ThreatStore {
  constructor(file, deps) {
    this.file = file;
    this.deps = deps; // {quarantine, settings, db}
    this.threats = [];
    this.history = []; // завершённые сканирования
  }
  async init() {
    const data = await readJson(this.file, { threats: [], history: [] });
    this.threats = data.threats || [];
    this.history = data.history || [];
    return this;
  }
  async save() { try { await writeJson(this.file, { threats: this.threats, history: this.history }); } catch (_) {} }

  add(threat) {
    const t = { ...threat, id: threat.id || uuid(), foundAt: threat.foundAt || nowIso(), status: threat.status || 'new' };
    // дедупликация по ключу
    const key = this.keyOf(t);
    const ex = this.threats.find((x) => this.keyOf(x) === key && x.status !== 'deleted');
    if (ex) { Object.assign(ex, t, { id: ex.id }); return ex; }
    this.threats.unshift(t);
    if (this.threats.length > 2000) this.threats.length = 2000;
    return t;
  }
  keyOf(t) {
    if (t.source === 'file') return `f:${t.path}:${t.title}`;
    if (t.source === 'process') return `p:${t.pid}:${t.title}`;
    if (t.source === 'autorun') return `a:${t.key}:${t.name}`;
    if (t.source === 'hosts') return `h:${t.host || t.line}`;
    if (t.source === 'url') return `u:${t.url}:${t.title}`;
    return `x:${t.title}:${t.path || t.pid || ''}`;
  }
  ignoredKeys() { return new Set(this.deps.settings.get().ignored || []); }
  isIgnored(t) { return this.ignoredKeys().has(this.keyOf(t)); }
  isWhitelisted(t) {
    const wl = this.deps.settings.get().whitelist || [];
    if (t.sha256 && wl.some((w) => w.hash === t.sha256)) return true;
    if (t.path && wl.some((w) => w.path && w.path.toLowerCase() === String(t.path).toLowerCase())) return true;
    return false;
  }
  active() {
    return this.threats.filter((t) => ['new', 'quarantined-pending'].includes(t.status) && !this.isIgnored(t) && !this.isWhitelisted(t));
  }
  all() { return this.threats.slice(); }
  get(id) { return this.threats.find((t) => t.id === id) || null; }
  setStatus(id, status, extra = {}) {
    const t = this.get(id);
    if (!t) return null;
    t.status = status;
    Object.assign(t, extra, { resolvedAt: nowIso() });
    this.save();
    return t;
  }
  addHistory(rec) {
    this.history.unshift(rec);
    if (this.history.length > 60) this.history.length = 60;
    this.save();
  }
  historyList() { return this.history.slice(); }

  knowledge(t) { return knowledgeFor(t.fam); }

  /**
   * Выполнить действие над угрозой.
   * heal:
   *   file      → карантин (лечение файла невозможно без сигнатурного инструмента) + пометка healed,
   *                но для webshell/script: тоже карантин (нейтрализация = изоляция);
   *   process   → завершить процесс;
   *   autorun   → удалить запись автозапуска;
   *   hosts     → восстановить hosts (копия в карантине);
   *   network   → завершить процесс-владелец;
   * quarantine → переместить файл; process/autorun: сначала лечим, затем файл в карантин если есть путь;
   * delete     → безвозвратно удалить файл / запись / процесс;
   * whitelist  → добавить hash/path в исключения;
   * ignore     → игнорировать ключ;
   * dismiss    → пометить обработанной без действий.
   */
  async act(id, action, opts = {}) {
    const t = this.get(id);
    if (!t) return { ok: false, error: 'Угроза не найдена' };
    const q = this.deps.quarantine;
    const settings = this.deps.settings;
    const { removeAutorunEntry, restoreHosts } = require('./persistence');
    const { killProcess } = require('./procscan');

    switch (action) {
      case 'heal': {
        if (t.source === 'process' || t.source === 'network') {
          const r = await killProcess(t.pid);
          if (!r.ok) return { ok: false, error: r.error };
          // если известен файл процесса — предлагаем изоляцию следом
          this.setStatus(id, 'healed', { note: 'Процесс завершён' });
          return { ok: true, follow: t.path ? 'quarantine-suggested' : null };
        }
        if (t.source === 'autorun') {
          const r = await removeAutorunEntry(t);
          if (!r.ok) return { ok: false, error: r.error };
          this.setStatus(id, 'healed', { note: 'Запись автозапуска удалена' });
          return { ok: true, follow: t.command && /\.(exe|dll|scr|bat|cmd|vbs|js|ps1)/i.test(t.command) ? 'quarantine-suggested' : null };
        }
        if (t.source === 'hosts') {
          const r = await restoreHosts(path.join(q.dir, 'backups'));
          if (!r.ok) return { ok: false, error: r.error };
          for (const h of this.threats.filter((x) => x.source === 'hosts' && x.status === 'new')) this.setStatus(h.id, 'healed', { note: 'hosts восстановлен' });
          return { ok: true };
        }
        if (t.source === 'file') {
          // «Вылечить» для файла = обезвредить: изолируем, чтобы код не мог выполниться
          const r = await q.quarantineFile(t.path, { title: t.title, cat: t.cat, healed: true });
          if (!r.ok) return { ok: false, error: r.error };
          this.setStatus(id, 'healed', { quarantineId: r.id, note: 'Объект обезврежен и изолирован (восстановление возможно из карантина)' });
          return { ok: true };
        }
        return { ok: false, error: 'Для этого типа лечение не применимо' };
      }
      case 'quarantine': {
        if (t.source === 'file') {
          const r = await q.quarantineFile(t.path, { title: t.title, cat: t.cat });
          if (!r.ok) return { ok: false, error: r.error };
          this.setStatus(id, 'quarantined', { quarantineId: r.id });
          return { ok: true };
        }
        if ((t.source === 'process' || t.source === 'network') && t.path) {
          await killProcess(t.pid);
          const r = await q.quarantineFile(t.path, { title: t.title, cat: t.cat });
          if (!r.ok) return { ok: false, error: r.error };
          this.setStatus(id, 'quarantined', { quarantineId: r.id });
          return { ok: true };
        }
        if (t.source === 'autorun') {
          await removeAutorunEntry(t);
          const target = extractPath(t.command);
          if (target) {
            const r = await q.quarantineFile(target, { title: t.title, cat: t.cat });
            if (r.ok) { this.setStatus(id, 'quarantined', { quarantineId: r.id }); return { ok: true }; }
            return { ok: true, warning: 'Запись удалена, файл изолировать не удалось: ' + r.error };
          }
          this.setStatus(id, 'healed');
          return { ok: true };
        }
        return { ok: false, error: 'Нечего изолировать' };
      }
      case 'delete': {
        if (t.source === 'file') {
          try {
            if (t.path && /quarantine|\.quar$/i.test(t.path)) { await q.remove(t.quarantineId); }
            else await fsp.rm(t.path, { force: true });
          } catch (e) { return { ok: false, error: String(e && e.message) }; }
          this.setStatus(id, 'deleted');
          return { ok: true };
        }
        if (t.source === 'process' || t.source === 'network') {
          const r = await killProcess(t.pid);
          this.setStatus(id, r.ok ? 'deleted' : 'new');
          if (t.path) { try { await fsp.rm(t.path, { force: true }); } catch (_) {} }
          return r;
        }
        if (t.source === 'autorun') {
          const r = await removeAutorunEntry(t);
          const target = extractPath(t.command);
          if (target) { try { await fsp.rm(target, { force: true }); } catch (_) {} }
          this.setStatus(id, r.ok ? 'deleted' : 'new');
          return r;
        }
        if (t.source === 'hosts') {
          const r = await restoreHosts(path.join(q.dir, 'backups'));
          this.setStatus(id, r.ok ? 'deleted' : 'new');
          return r;
        }
        return { ok: false, error: 'Не поддерживается' };
      }
      case 'whitelist': {
        const s = settings.get();
        const wl = s.whitelist || [];
        wl.push({ hash: t.sha256 || null, path: t.path || null, title: t.title, addedAt: nowIso() });
        await settings.set({ whitelist: wl });
        this.setStatus(id, 'whitelisted');
        return { ok: true };
      }
      case 'ignore': {
        const s = settings.get();
        const ig = new Set(s.ignored || []);
        ig.add(this.keyOf(t));
        await settings.set({ ignored: [...ig] });
        this.setStatus(id, 'ignored');
        return { ok: true };
      }
      case 'dismiss': {
        this.setStatus(id, 'dismissed');
        return { ok: true };
      }
      default:
        return { ok: false, error: 'Неизвестное действие' };
    }
  }
}

function extractPath(command) {
  const m = String(command || '').match(/"?([A-Za-z]:\\[^\s"]+\.[A-Za-z0-9]{2,4}|\/[^\s"]+\.[A-Za-z0-9]{2,4})"?/);
  return m ? m[1] : null;
}

module.exports = { ThreatStore, extractPath };
