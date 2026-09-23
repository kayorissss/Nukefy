'use strict';
/**
 * Nukefy — обновление баз сигнатур и знаний из официального репозитория.
 * Источник: https://raw.githubusercontent.com/kayorissss/Nukefy/main/nukefy-db/
 * Целостность: manifest.json с SHA-256 каждого файла; без совпадения хеша обновление отклоняется.
 */
const https = require('https');
const fsp = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

const BASE = 'https://raw.githubusercontent.com/kayorissss/Nukefy/main/nukefy-db/';
const FILES = ['signatures.json', 'knowledge.json'];

function get(url, cap = 8 * 1024 * 1024) {
  return new Promise((resolve) => {
    try {
      const req = https.get(url, { timeout: 15000, headers: { 'User-Agent': 'Nukefy-updater/1.1' } }, (res) => {
        if (res.statusCode !== 200) { res.resume(); return resolve({ ok: false, status: res.statusCode }); }
        const chunks = []; let size = 0;
        res.on('data', (d) => { if (size < cap) { chunks.push(d); size += d.length; } });
        res.on('end', () => resolve({ ok: true, buf: Buffer.concat(chunks) }));
        res.on('error', () => resolve({ ok: false }));
      });
      req.on('timeout', () => { try { req.destroy(); } catch (_) {} });
      req.on('error', () => resolve({ ok: false }));
    } catch (_) { resolve({ ok: false }); }
  });
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

function overrideDir() {
  try { const { app } = require('electron'); return path.join(app.getPath('userData'), 'db'); }
  catch (_) { return path.join(process.env.NUKEFY_DATA || path.join(require('os').homedir(), '.nukefy'), 'db'); }
}

/** Проверить и применить обновление. Возвращает {updated, version, error?}. */
async function checkAndUpdate(opts = {}) {
  const dir = overrideDir();
  const man = await get(BASE + 'manifest.json');
  if (!man.ok) return { updated: false, error: man.status ? `HTTP ${man.status}` : 'сеть недоступна' };
  let manifest;
  try { manifest = JSON.parse(man.buf.toString('utf8')); } catch (_) { return { updated: false, error: 'битый manifest' }; }
  const current = opts.currentVersion || '0';
  if (!(manifest.version > current)) return { updated: false, version: current, already: true };
  const downloaded = {};
  for (const f of FILES) {
    const r = await get(BASE + f);
    if (!r.ok) return { updated: false, error: `не удалось скачать ${f}` };
    const h = sha256(r.buf);
    if (!manifest.sha256 || manifest.sha256[f] !== h) return { updated: false, error: `хеш ${f} не совпал — обновление отклонено` };
    try { JSON.parse(r.buf.toString('utf8')); } catch (_) { return { updated: false, error: `${f} не парсится` }; }
    downloaded[f] = r.buf;
  }
  await fsp.mkdir(dir, { recursive: true });
  for (const [f, buf] of Object.entries(downloaded)) await fsp.writeFile(path.join(dir, f), buf);
  await fsp.writeFile(path.join(dir, 'manifest.json'), man.buf);
  return { updated: true, version: manifest.version };
}

async function localOverrideVersion() {
  try {
    const m = JSON.parse(await fsp.readFile(path.join(overrideDir(), 'manifest.json'), 'utf8'));
    return m.version || null;
  } catch (_) { return null; }
}

module.exports = { checkAndUpdate, overrideDir, localOverrideVersion, BASE };
