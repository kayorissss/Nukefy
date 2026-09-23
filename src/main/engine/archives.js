'use strict';
/**
 * Nukefy — рекурсивное сканирование ZIP-архивов (в т.ч. вложенных).
 * Чистый JS: центральный каталог + inflateRawSync. RAR/7z помечаются как
 * «не поддерживается» (информационно), без ложных тревог.
 */
const zlib = require('zlib');

const MAX_ENTRIES = 2000;
const MAX_UNPACK = 64 * 1024 * 1024;
const MAX_DEPTH = 3;

function isZip(buf) { return buf.length > 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07); }
function isRar(buf) { return buf.length > 7 && buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72; }
function is7z(buf) { return buf.length > 6 && buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf; }

function findEOCD(buf) {
  const start = Math.max(0, buf.length - 66000);
  for (let i = buf.length - 22; i >= start; i--) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x05 && buf[i + 3] === 0x06) return i;
  }
  return -1;
}

/** Вернуть список {name, buf} распакованных записей (с ограничением глубины/размера). */
function unzipEntries(buf, depth = 0) {
  const out = [];
  if (depth > MAX_DEPTH || !isZip(buf)) return out;
  const eocd = findEOCD(buf);
  if (eocd < 0) return out;
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count && i < MAX_ENTRIES && off + 46 <= buf.length; i++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const uncompSize = buf.readUInt32LE(off + 24);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.toString('utf8', off + 46, off + 46 + nameLen);
    off += 46 + nameLen + extraLen + commentLen;
    if (uncompSize > MAX_UNPACK || uncompSize === 0) continue;
    // local header → data offset
    if (localOff + 30 > buf.length || buf.readUInt32LE(localOff) !== 0x04034b50) continue;
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataOff = localOff + 30 + lNameLen + lExtraLen;
    if (dataOff + compSize > buf.length) continue;
    const raw = buf.subarray(dataOff, dataOff + compSize);
    let data = null;
    try {
      if (method === 0) data = Buffer.from(raw);
      else if (method === 8) data = zlib.inflateRawSync(raw, { maxOutputLength: MAX_UNPACK });
    } catch (_) { data = null; }
    if (!data) continue;
    out.push({ name, buf: data });
    if (/\.zip$/i.test(name) && depth < MAX_DEPTH) {
      for (const sub of unzipEntries(data, depth + 1)) out.push({ name: name + '::' + sub.name, buf: sub.buf });
    }
  }
  return out;
}

module.exports = { unzipEntries, isZip, isRar, is7z };
