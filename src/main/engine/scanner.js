'use strict';
/**
 * Nukefy — файловый сканер (вкладки «Вирусы», «Трояны», «Майнеры»).
 * Проходит корневые каталоги, читает файлы порциями, прогоняет:
 *   1) локальные сигнатуры (ascii/wide/hex, any/all),
 *   2) эвристики: исполняемый во временных папках, упаковщики, высокая энтропия + PE,
 *      скрипт-дроперы, майнер-конфиги,
 *   3) облачную репутацию по SHA-256 (MalwareBazaar / VirusTotal по ключу).
 * Эмиттит прогресс и находки через回调 onEvent.
 */
const path = require('path');
const { walkFiles, readFileCapped, sha256, entropy, isPe, fileStatsSafe } = require('./util');
const { reputationForFile } = require('./reputation');
const { parsePE, peHeuristics } = require('./pe');
const { unzipEntries, isZip, isRar, is7z } = require('./archives');
const { knowledgeFor } = require('./signatures');

const TEMP_MARKERS = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp', '/tmp/', '/var/tmp/', '\\downloads\\', '/downloads/'];
const EXEC_EXTS = ['exe', 'dll', 'scr', 'com', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'hta', 'msi', 'jar', 'sh', 'py', 'lnk'];
const SCAN_EXTS = null; // сканируем всё, но с лимитом размера
const SCRIPT_EXTS = ['vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'bat', 'cmd', 'hta', 'lnk'];

function isTempPath(p) {
  const lp = String(p).toLowerCase();
  return TEMP_MARKERS.some((m) => lp.includes(m));
}

class FileScanner {
  constructor(opts) {
    this.db = opts.db;                 // SignatureDB
    this.settings = opts.settings;   // объект настроек (data)
    this.onEvent = opts.onEvent || (() => {});
    this.cancelled = false;
    this.stats = { files: 0, bytes: 0, threats: 0, skipped: 0 };
    this.scanId = opts.scanId;
    this.cloud = opts.cloud !== false;
    this.mode = opts.mode || 'full';
    this.roots = opts.roots || [];
    this.singleFile = opts.singleFile || null;
    this.excludePrefixes = (opts.excludePrefixes || []).map((x) => String(x).toLowerCase());
    this._seenHash = new Set();
    this.paused = false;
  }
  pause() { this.paused = true; }
  resume() { this.paused = false; }
  static sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
  cancel() { this.cancelled = true; }

  async run() {
    const t0 = Date.now();
    const cfg = this.settings.scan || {};
    const maxBytes = (cfg.maxFileMb || 128) * 1024 * 1024;
    let files = [];
    if (this.singleFile) {
      files = [this.singleFile];
    } else {
      this.onEvent({ type: 'phase', phase: 'collect', message: 'Сбор списка файлов…' });
      for (const root of this.roots) {
        if (this.cancelled) break;
        const found = await walkFiles(root, {
          maxSize: maxBytes,
          maxFiles: (cfg.maxFilesFull || 160000),
          skipDirs: cfg.excludeDirs || [],
        });
        files = files.concat(found);
        this.onEvent({ type: 'phase', phase: 'collect', message: `Каталог: ${root} (+${found.length})` });
      }
    }
    if (this.excludePrefixes.length) {
      files = files.filter((f) => !this.excludePrefixes.some((pr) => f.toLowerCase().startsWith(pr)));
    }
    const total = files.length;
    this.onEvent({ type: 'phase', phase: 'scan', total, message: 'Сканирование…' });
    const concurrency = 4;
    let idx = 0;
    const workers = [];
    for (let w = 0; w < concurrency; w++) {
      workers.push((async () => {
        while (!this.cancelled) {
          if (this.paused) { await FileScanner.sleep(200); continue; }
          const i = idx++;
          if (i >= total) return;
          const file = files[i];
          await this.scanOne(file, maxBytes);
          if ((i & 15) === 0) {
            this.onEvent({ type: 'progress', done: i + 1, total, files: this.stats.files, threats: this.stats.threats, path: file });
          }
        }
      })());
    }
    await Promise.all(workers);
    this.onEvent({ type: 'progress', done: total, total, files: this.stats.files, threats: this.stats.threats });
    this.onEvent({ type: 'done', stats: { ...this.stats, ms: Date.now() - t0 }, cancelled: this.cancelled });
    return { stats: this.stats, cancelled: this.cancelled };
  }

  async scanOne(file, maxBytes) {
    const ext = path.extname(file).replace(/^\./, '').toLowerCase();
    const st = fileStatsSafe(file);
    if (!st) { this.stats.skipped++; return; }
    this.stats.files++;
    this.stats.bytes += st.size;

    const buf = await readFileCapped(file, maxBytes);
    if (!buf) { this.stats.skipped++; return; }

    const findings = [];

    // 1) сигнатуры
    let hits = [];
    try { hits = this.db.match(buf, ext); } catch (_) { hits = []; }
    for (const h of hits) {
      findings.push({
        kind: 'signature',
        cat: h.sig.cat,
        sev: h.sig.sev,
        fam: h.sig.fam,
        title: h.sig.id,
        desc: h.sig.desc,
      });
    }

    // 1.5) хеш-сигнатуры и PE-статика
    let sha = null;
    const execish = ['exe', 'dll', 'scr', 'com', 'sys'].includes(ext) || isPe(buf);
    if (execish || this.db.hashIndex.size) {
      if (st.size <= 64 * 1024 * 1024) {
        try { sha = await sha256(file); } catch (_) {}
        if (sha && this.db.hashIndex.has(sha)) {
          const h = this.db.hashIndex.get(sha);
          findings.push({ kind: 'signature', cat: h.cat, sev: h.sev, fam: h.fam, title: h.id, desc: h.desc || 'Хеш-сигнатура' });
        }
      }
    }
    if (isPe(buf)) {
      const pe = parsePE(buf);
      for (const f of peHeuristics(buf, pe, { path: file, entropyAll: entropy(buf) })) findings.push(f);
    }
    // 1.7) архивы: zip рекурсивно
    if (isZip(buf)) {
      for (const ent of unzipEntries(buf)) {
        const eHits = this.db.match(ent.buf, ent.name.split('.').pop().toLowerCase());
        for (const h of eHits) {
          findings.push({ kind: 'signature', cat: h.sig.cat, sev: h.sig.sev, fam: h.sig.fam, title: h.sig.id, desc: h.sig.desc + ` (в архиве: ${ent.name})`, inArchive: ent.name });
        }
        const epe = parsePE(ent.buf);
        for (const f of peHeuristics(ent.buf, epe, { path: file + '::' + ent.name, entropyAll: entropy(ent.buf) })) {
          if (f.sev >= 3) findings.push({ ...f, desc: f.desc + ` (в архиве: ${ent.name})`, inArchive: ent.name });
        }
      }
    } else if (isRar(buf) || is7z(buf)) {
      findings.push({ kind: 'info', cat: 'risk', sev: 1, fam: 'generic', title: 'Archive.Unsupported', desc: 'Архив RAR/7z не распаковывается движком Nukefy; проверен по хешу и эвристикам контейнера' });
    }

    // 2) эвристики
    const lp = file.toLowerCase();
    if (EXEC_EXTS.includes(ext) && isTempPath(file) && st.size > 0) {
      // исполняемый/скрипт во временной или загрузочной папке
      const suspiciousName = /(^|[\\/])(svchost|csrss|lsass|services|smss|winlogon|update|upd|setup|install|crack|keygen|activator|kms)\d*\.exe$/.test(lp);
      findings.push({
        kind: 'heuristic',
        cat: 'risk',
        sev: suspiciousName ? 3 : 2,
        fam: 'temp-exec',
        title: 'Heur.TempExec' + (suspiciousName ? '.Masquerade' : ''),
        desc: 'Исполняемый файл во временной/загрузочной папке' + (suspiciousName ? ' с именем-маской системного процесса' : ''),
      });
    }
    if (isPe(buf)) {
      const e = entropy(buf);
      const packed = this.db.matchText(buf.toString('latin1'), ['PUA.Packer.KnownProtectors']).length > 0;
      if (e > 7.2 && st.size < 4 * 1024 * 1024 && !packed) {
        findings.push({ kind: 'heuristic', cat: 'risk', sev: 2, fam: 'packed', title: 'Heur.HighEntropyPE', desc: `PE с аномально высокой энтропией (${e.toFixed(2)}) — вероятно упакован/шифрован` });
      }
    }
    if (SCRIPT_EXTS.includes(ext)) {
      const text = buf.toString('latin1').toLowerCase();
      const dl = /(downloadstring|downloadfile|webclient|invoke-expression|iex\s*\(|frombase64string)/.test(text);
      const hide = /(-windowstyle hidden|-w hidden|hidden window|conhost|--nologo)/.test(text);
      const enc = /(-enc |encodedcommand|frombase64string)/.test(text);
      const score = (dl ? 1 : 0) + (hide ? 1 : 0) + (enc ? 1 : 0);
      if (score >= 2) {
        findings.push({ kind: 'heuristic', cat: 'trojan', sev: 3, fam: 'script-dropper', title: 'Heur.ScriptDropper', desc: 'Скрипт: загрузка из сети + скрытое выполнение' + (enc ? ' + base64-пейлоад' : '') });
      }
    }

    // 3) облачная репутация (только для исполняемых и при включённом облаке)
    if (this.cloud && findings.length === 0 && (EXEC_EXTS.includes(ext) || isPe(buf)) && st.size > 512) {
      let hash = null;
      try { hash = await sha256(file); } catch (_) {}
      if (hash && !this._seenHash.has(hash)) {
        this._seenHash.add(hash);
        try {
          const rep = await reputationForFile(hash, this.settings);
          if (rep.malicious) {
            findings.push({
              kind: 'cloud',
              cat: rep.signature && /miner|xmr/i.test(rep.signature || '') ? 'miner' : 'trojan',
              sev: 4,
              fam: rep.signature ? String(rep.signature).toLowerCase().replace(/[^a-z0-9-]/g, '-') : 'generic',
              title: (rep.signature || 'Cloud.Malicious') + '',
              desc: 'Подтверждено облачными базами: ' + [rep.services.malwarebazaar && rep.services.malwarebazaar.found ? 'MalwareBazaar' : null, rep.services.virustotal && rep.services.virustotal.found ? `VirusTotal ${rep.vtRatio}` : null].filter(Boolean).join(', '),
              cloud: rep,
            });
          }
        } catch (_) {}
      }
    }

    for (const f of findings) {
      this.stats.threats++;
      this.onEvent({
        type: 'threat',
        threat: {
          id: require('crypto').randomUUID(),
          scanId: this.scanId,
          source: 'file',
          kind: f.kind,
          cat: f.cat,
          sev: f.sev,
          fam: f.fam,
          title: f.title,
          desc: f.desc,
          path: f.inArchive ? file + '::' + f.inArchive : file,
          size: st.size,
          sha256: sha || (f.cloud ? f.cloud.sha256 : undefined),
          foundAt: new Date().toISOString(),
          status: 'new',
          cloud: f.cloud || null,
        },
      });
    }
  }
}

module.exports = { FileScanner, isTempPath, EXEC_EXTS, SCRIPT_EXTS };
