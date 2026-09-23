'use strict';
/**
 * Nukefy — загрузка и компиляция локальной базы сигнатур.
 * Поддерживает: ascii (регистронезависимо), wide (UTF-16LE), hex с масками ??,
 * логика "any" | "all". Сигнатуры компилируются один раз при старте.
 */
const fs = require('fs');
const path = require('path');

function dbPath() {
  // 0) обновлённая база из userData/db (ставится updater-ом)
  const candidates = [];
  try {
    const { overrideDir } = require('./updater');
    candidates.push(path.join(overrideDir(), 'signatures.json'));
  } catch (_) {}
  try {
    const { app } = require('electron');
    candidates.push(path.join(process.resourcesPath || path.dirname(app.getAppPath()), 'nukefy-db', 'signatures.json'));
    candidates.push(path.join(app.getAppPath(), 'nukefy-db', 'signatures.json'));
  } catch (_) {}
  candidates.push(path.join(__dirname, '..', '..', '..', 'nukefy-db', 'signatures.json'));
  candidates.push(path.join(__dirname, '..', '..', 'nukefy-db', 'signatures.json'));
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch (_) {}
  }
  return null;
}

function knowledgePath() {
  const candidates = [];
  try {
    const { overrideDir } = require('./updater');
    candidates.push(path.join(overrideDir(), 'knowledge.json'));
  } catch (_) {}
  try {
    const { app } = require('electron');
    candidates.push(path.join(process.resourcesPath || '', 'nukefy-db', 'knowledge.json'));
    candidates.push(path.join(app.getAppPath(), 'nukefy-db', 'knowledge.json'));
  } catch (_) {}
  candidates.push(path.join(__dirname, '..', '..', '..', 'nukefy-db', 'knowledge.json'));
  candidates.push(path.join(__dirname, '..', '..', 'nukefy-db', 'knowledge.json'));
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch (_) {}
  }
  return null;
}

function asciiBuf(s) { return Buffer.from(s.toLowerCase(), 'latin1'); }
function wideBuf(s) {
  const b = Buffer.from(s, 'utf16le');
  return { buf: b, wide: true };
}
function hexBuf(hex) {
  // '4D 5A ?? 00' -> {bytes, mask}
  const parts = hex.trim().split(/[\s]+/);
  const bytes = Buffer.alloc(parts.length);
  const mask = Buffer.alloc(parts.length);
  parts.forEach((p, i) => {
    if (p === '??' || p === '?') { bytes[i] = 0; mask[i] = 0; }
    else { bytes[i] = parseInt(p, 16) & 0xff; mask[i] = 1; }
  });
  return { bytes, mask };
}

function indexOfPattern(hayLower, needleLower, from = 0) {
  return hayLower.indexOf(needleLower, from);
}

class SignatureDB {
  constructor() {
    this.signatures = [];
    this.hashIndex = new Map();
    this.pools = { ports: [] };
    this.version = 'unknown';
    this.loadedFrom = null;
  }
  load() {
    const p = dbPath();
    if (!p) return false;
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      this.version = raw.version || 'unknown';
      this.pools = raw.pools || { ports: [] };
      this.hashIndex = new Map((raw.hashes || []).map((h) => [String(h.sha256).toLowerCase(), h]));
      this.signatures = (raw.signatures || []).map((s) => {
        const compiled = {
          id: s.id, fam: s.fam || 'generic', cat: s.cat || 'risk', sev: s.sev || 2,
          desc: s.desc || '', exts: (s.exts || ['*']).map((e) => e.toLowerCase().replace(/^\./, '')),
          logic: s.logic || 'any',
          patterns: (s.patterns || []).map((pat) => {
            if (pat.t === 'hex') { const h = hexBuf(pat.v); return { type: 'hex', bytes: h.bytes, mask: h.mask }; }
            if (pat.t === 'wide') return { type: 'wide', needle: Buffer.from(pat.v, 'utf16le') };
            return { type: 'ascii', needle: Buffer.from(pat.v.toLowerCase(), 'latin1'), original: pat.v };
          }),
        };
        return compiled;
      });
      this.loadedFrom = p;
      return true;
    } catch (e) {
      this.error = String(e && e.message);
      return false;
    }
  }
  /** Найти сигнатуры в буфере файла с учётом расширения. */
  match(buf, extNoDot) {
    const hits = [];
    const lower = Buffer.isBuffer(buf) ? buf.toString('latin1').toLowerCase() : '';
    for (const sig of this.signatures) {
      if (!sig.exts.includes('*') && !sig.exts.includes(extNoDot)) continue;
      let matched = sig.logic === 'all';
      let matchedPattern = null;
      for (const pat of sig.patterns) {
        let ok = false;
        if (pat.type === 'ascii') ok = lower.includes(pat.needle.toString('latin1'));
        else if (pat.type === 'wide') ok = buf.includes(pat.needle);
        else if (pat.type === 'hex') ok = hexFind(buf, pat.bytes, pat.mask);
        if (sig.logic === 'any' && ok) { matched = true; matchedPattern = pat; break; }
        if (sig.logic === 'all' && !ok) { matched = false; break; }
        if (sig.logic === 'all' && ok) matchedPattern = pat;
      }
      if (matched) hits.push({ sig, matchedPattern });
    }
    return hits;
  }
  /** Быстрые паттерны для текстовых проверок (командные строки, автозапуск): по id. */
  matchText(text, ids) {
    const t = String(text || '').toLowerCase();
    const found = [];
    for (const sig of this.signatures) {
      if (ids && !ids.includes(sig.id)) continue;
      for (const pat of sig.patterns) {
        if (pat.type === 'ascii' && t.includes(pat.needle.toString('latin1'))) { found.push(sig); break; }
      }
    }
    return found;
  }
  /** Logic-aware сопоставление для текста (командные строки процессов):
      учитывает logic any/all и список допустимых категорий. */
  matchTextSmart(text, opts = {}) {
    const t = String(text || '').toLowerCase();
    const cats = opts.cats || null;
    const excludeFams = opts.excludeFams || [];
    const found = [];
    for (const sig of this.signatures) {
      if (cats && !cats.includes(sig.cat)) continue;
      if (excludeFams.includes(sig.fam)) continue;
      let hit = sig.logic === 'all';
      for (const pat of sig.patterns) {
        if (pat.type !== 'ascii') continue;
        const ok = t.includes(pat.needle.toString('latin1'));
        if (sig.logic === 'any' && ok) { hit = true; break; }
        if (sig.logic === 'all' && !ok) { hit = false; break; }
      }
      if (hit) found.push(sig);
    }
    return found;
  }
}

function hexFind(buf, bytes, mask) {
  const n = bytes.length;
  if (buf.length < n) return false;
  outer: for (let i = 0; i <= buf.length - n; i++) {
    for (let j = 0; j < n; j++) {
      if (mask[j] && buf[i + j] !== bytes[j]) continue outer;
    }
    return true;
  }
  return false;
}

let _knowledge = null;
function knowledge() {
  if (_knowledge) return _knowledge;
  const p = knowledgePath();
  try { _knowledge = p ? JSON.parse(fs.readFileSync(p, 'utf8')) : { families: {} }; }
  catch (_) { _knowledge = { families: {} }; }
  return _knowledge;
}
function knowledgeFor(fam) {
  const k = knowledge();
  return (k.families && (k.families[fam] || k.families.generic)) || null;
}

module.exports = { SignatureDB, knowledge, knowledgeFor, dbPath, knowledgePath };
