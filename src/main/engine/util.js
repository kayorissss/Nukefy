'use strict';
/**
 * Nukefy — утилиты движка: исполнение команд, декодирование вывода,
 * хэши, энтропия, мелочи для сканеров. Работает и на Windows, и на Linux
 * (Linux используется для разработки и автотестов).
 */
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const IS_WIN = process.platform === 'win32';

/**
 * Выполнить команду (без шелла), вернуть {ok, stdout, code}.
 * Вывод Windows-консолей декодируется из UTF-16LE (BOM) или CP866/CP1251/UTF-8.
 */
function execCapture(file, args, opts = {}) {
  const timeout = opts.timeout || 15000;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(file, args, {
        windowsHide: true,
        timeout,
        env: process.env,
        ...(opts.cwd ? { cwd: opts.cwd } : {}),
      });
    } catch (e) {
      resolve({ ok: false, stdout: '', code: -1, error: String(e && e.message) });
      return;
    }
    const chunks = [];
    let errText = '';
    let killed = false;
    const killer = setTimeout(() => { killed = true; try { child.kill('SIGKILL'); } catch (_) {} }, timeout);
    child.stdout.on('data', (d) => { if (chunks.reduce((s, c) => s + c.length, 0) < 96 * 1024 * 1024) chunks.push(d); });
    child.stderr.on('data', (d) => { if (errText.length < 8192) errText += d.toString('latin1'); });
    child.on('error', (e) => {
      clearTimeout(killer);
      resolve({ ok: false, stdout: '', code: -1, error: String(e && e.message) });
    });
    child.on('close', (code) => {
      clearTimeout(killer);
      const buf = Buffer.concat(chunks);
      resolve({ ok: code === 0 && !killed, stdout: decodeConsole(buf), code: code == null ? (killed ? -2 : -1) : code, stderr: errText });
    });
  });
}

/** Декодировать дампы консоли: UTF-16LE(BOM), UTF-8, иначе CP1251/CP866. */
function decodeConsole(buf) {
  if (!buf || !buf.length) return '';
  if (buf[0] === 0xff && buf[1] === 0xfe) return buf.toString('utf16le').replace(/^\uFEFF/, '');
  const utf8 = buf.toString('utf8');
  if (!/[\uFFFD]/.test(utf8)) return utf8;
  try {
    const iconv = require('iconv-lite');
    let cp = 'cp866';
    try { cp = iconv.encodingExists('cp1251') ? 'cp1251' : 'cp866'; } catch (_) {}
    // для powershell/reg характерен cp1251, для cmd — oem-кодировка; пробуем обе
    const a = iconv.decode(buf, 'cp1251');
    return a;
  } catch (_) {
    return utf8;
  }
}

async function sha256(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    const s = fs.createReadStream(file);
    s.on('data', (d) => h.update(d));
    s.on('end', () => resolve(h.digest('hex')));
    s.on('error', reject);
  });
}

/** Shannon entropy по буферу (быстрая, сэмплированная). */
function entropy(buf) {
  if (!buf || !buf.length) return 0;
  const step = Math.max(1, Math.floor(buf.length / 65536));
  const freq = new Array(256).fill(0);
  let n = 0;
  for (let i = 0; i < buf.length; i += step) { freq[buf[i]]++; n++; }
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / n;
    e -= p * Math.log2(p);
  }
  return e;
}

function fileStatsSafe(p) {
  try { return fs.statSync(p); } catch (_) { return null; }
}

async function readFileCapped(file, cap = 8 * 1024 * 1024) {
  const st = fileStatsSafe(file);
  if (!st || !st.isFile()) return null;
  if (st.size <= cap) {
    try { return await fsp.readFile(file); } catch (_) { return null; }
  }
  // большой файл: голова + хвост
  try {
    const fd = await fsp.open(file, 'r');
    try {
      const head = Buffer.alloc(Math.min(4 * 1024 * 1024, cap));
      await fd.read(head, 0, head.length, 0);
      const tailSize = Math.min(1024 * 1024, Math.max(0, st.size - head.length));
      let tail = Buffer.alloc(0);
      if (tailSize > 0) {
        tail = Buffer.alloc(tailSize);
        await fd.read(tail, 0, tailSize, st.size - tailSize);
      }
      return Buffer.concat([head, tail]);
    } finally { await fd.close(); }
  } catch (_) { return null; }
}

function walkFiles(dir, opts = {}) {
  // Возвращает Promise<[string]> — список файлов (рекурсивно, с лимитами).
  const { exts = null, maxSize = Infinity, maxFiles = 200000, maxDepth = 16, skipDirs } = opts;
  const skip = new Set((skipDirs || []).map((d) => d.toLowerCase()));
  skip.add('$recycle.bin');
  skip.add('system volume information');
  const out = [];
  const stack = [[dir, 0]];
  return (async () => {
    while (stack.length && out.length < maxFiles) {
      const [cur, depth] = stack.pop();
      let entries;
      try { entries = await fsp.readdir(cur, { withFileTypes: true }); } catch (_) { continue; }
      for (const ent of entries) {
        if (out.length >= maxFiles) break;
        let p;
        try { p = path.join(cur, ent.name); } catch (_) { continue; }
        const lname = ent.name.toLowerCase();
        if (ent.isDirectory()) {
          if (depth >= maxDepth) continue;
          if (skip.has(lname)) continue;
          stack.push([p, depth + 1]);
        } else if (ent.isFile()) {
          if (exts) {
            const e = path.extname(lname);
            if (!exts.includes(e)) continue;
          }
          if (maxSize < Infinity) {
            let st = null;
            try { st = await fsp.stat(p); } catch (_) { continue; }
            if (!st.isFile() || st.size > maxSize || st.size === 0) continue;
          }
          out.push(p);
        }
      }
    }
    return out;
  })();
}

/** Простой levenshtein для поиска опечаток в доменах. */
function lev(a, b, cap = 3) {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const m = a.length, n = b.length;
  let prev = new Array(n + 1);
  let curr = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    let rowMin = curr[0];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      if (curr[j] < rowMin) rowMin = curr[j];
    }
    if (rowMin > cap) return cap + 1;
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

const uuid = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();

function safeNameFromPath(p) {
  try { return path.basename(p); } catch (_) { return String(p || ''); }
}

/** Атомарная запись JSON. */
let _tmpSeq = 0;
async function writeJson(file, obj) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${++_tmpSeq}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(obj, null, 2));
  try { await fsp.rename(tmp, file); } catch (_) {
    try { await fsp.rm(file, { force: true }); await fsp.rename(tmp, file); } catch (e) { await fsp.rm(tmp, { force: true }); throw e; }
  }
}

async function readJson(file, fallback = null) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch (_) { return fallback; }
}

function isPe(buf) {
  if (!buf || buf.length < 0x40) return false;
  if (buf[0] !== 0x4d || buf[1] !== 0x5a) return false; // MZ
  const off = buf.readUInt32LE(0x3c);
  return off > 0 && off + 4 < buf.length && buf[off] === 0x50 && buf[off + 1] === 0x45 && buf[off + 2] === 0 && buf[off + 3] === 0;
}

module.exports = {
  IS_WIN, execCapture, decodeConsole, sha256, entropy, fileStatsSafe, readFileCapped,
  walkFiles, lev, uuid, nowIso, safeNameFromPath, writeJson, readJson, isPe,
};
