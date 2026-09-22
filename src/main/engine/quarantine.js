'use strict';
/**
 * Nukefy — карантин: безопасное перемещение объектов в userData/quarantine
 * с журналом для восстановления. Файл шифруется XOR-маской (не защита,
 * а предотвращение случайного запуска), метаданные — в journal.json.
 */
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { writeJson, readJson } = require('./util');

class Quarantine {
  constructor(dir) {
    this.dir = dir;
    this.journalFile = path.join(dir, 'journal.json');
    this.journal = [];
  }
  async init() {
    await fsp.mkdir(this.dir, { recursive: true });
    this.journal = (await readJson(this.journalFile, [])) || [];
    return this;
  }
  async save() { await writeJson(this.journalFile, this.journal); }

  async quarantineFile(filePath, meta = {}) {
    try {
      const id = crypto.randomUUID();
      const name = path.basename(filePath);
      const dest = path.join(this.dir, id + '.quar');
      const buf = await fsp.readFile(filePath);
      await fsp.writeFile(dest, mask(buf));
      // удаляем оригинал (сначала пробуем rm, если занято — переименовываем в .nukefy-dead)
      try { await fsp.rm(filePath, { force: true }); }
      catch (_) {
        try { await fsp.rename(filePath, filePath + '.nukefy-dead'); } catch (e2) { throw new Error('Файл занят процессом: завершите процесс и повторите'); }
      }
      const rec = { id, name, original: filePath, at: new Date().toISOString(), size: buf.length, ...meta };
      this.journal.unshift(rec);
      await this.save();
      return { ok: true, id, name };
    } catch (e) {
      return { ok: false, error: String(e && e.message) };
    }
  }

  async restore(id) {
    const rec = this.journal.find((r) => r.id === id);
    if (!rec) return { ok: false, error: 'Запись не найдена' };
    const src = path.join(this.dir, id + '.quar');
    try {
      const buf = await fsp.readFile(src);
      await fsp.mkdir(path.dirname(rec.original), { recursive: true });
      await fsp.writeFile(rec.original, mask(buf));
      await fsp.rm(src, { force: true });
      this.journal = this.journal.filter((r) => r.id !== id);
      await this.save();
      return { ok: true, path: rec.original };
    } catch (e) { return { ok: false, error: String(e && e.message) }; }
  }

  async remove(id) {
    const src = path.join(this.dir, id + '.quar');
    try { await fsp.rm(src, { force: true }); } catch (_) {}
    this.journal = this.journal.filter((r) => r.id !== id);
    await this.save();
    return { ok: true };
  }

  list() { return this.journal.slice(); }
}

function mask(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ 0x5a;
  return out;
}

module.exports = { Quarantine };
