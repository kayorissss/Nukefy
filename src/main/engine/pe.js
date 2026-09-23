'use strict';
/**
 * Nukefy — статический PE-анализ: секции, импорты, упаковщики, аномалии.
 * Консервативные эвристики: комбинации API учитываются только вместе с
 * дополнительным признаком (упаковка/энтропия/временная папка), чтобы не
 * помечать легитимные браузеры, античиты и системные компоненты.
 */
const { entropy } = require('./util');

const PACKER_SECTIONS = ['upx0', 'upx1', '.aspack', '.themida', '.enigma1', '.enigma2', '.vmp0', '.vmp1', '.packed', '.ncrypt', 'mpress1', 'mpress2', '.confu', 'pebundle', '.crink', '.nsp1'];
const KNOWN_GOOD_SECTIONS = ['.text', '.data', '.rdata', '.bss', '.edata', '.idata', '.rsrc', '.reloc', '.pdata', '.tls', '.gfids', '.00cfg', '.voltbl'];

const API_COMBOS = [
  { id: 'Heur.PE.Injection', cat: 'trojan', sev: 3, fam: 'generic', need: ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'], desc: 'Комбинация API инъекции кода в чужой процесс (process hollowing / DLL injection)' },
  { id: 'Heur.PE.DropperAPI', cat: 'trojan', sev: 3, fam: 'script-dropper', need2: [['URLDownloadToFileA', 'URLDownloadToFileW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'WinHttpOpen', 'HttpOpenRequestA'], ['WinExec', 'ShellExecuteA', 'ShellExecuteW', 'CreateProcessA', 'CreateProcessW', 'system']], desc: 'Комбинация «скачать из сети + выполнить» — классический загрузчик' },
  { id: 'Heur.PE.KeylogAPI', cat: 'trojan', sev: 3, fam: 'infostealer', need: ['SetWindowsHookExA', 'GetAsyncKeyState', 'GetKeyState'], need2: [['send', 'WSASend', 'InternetOpenA', 'HttpSendRequestA', 'URLDownloadToFileA']], desc: 'Перехват клавиатуры + отправка данных наружу' },
  { id: 'Heur.PE.RansomAPI', cat: 'virus', sev: 4, fam: 'ransomware', need2: [['CryptAcquireContextA', 'CryptAcquireContextW', 'CryptEncrypt', 'CryptGenKey'], ['FindFirstFileA', 'FindNextFileA', 'FindFirstFileW'], ['MoveFileExA', 'MoveFileExW', 'DeleteFileA', 'DeleteFileW']], desc: 'Шифрование + обход файлов + переименование/удаление — паттерн шифровальщика' },
];

function readSz(buf, off, max = 64) {
  let s = '';
  for (let i = 0; i < max && off + i < buf.length; i++) {
    const c = buf[off + i];
    if (!c) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function parsePE(buf) {
  if (!buf || buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return { ok: false };
  const eLfanew = buf.readUInt32LE(0x3c);
  if (eLfanew + 0x18 >= buf.length || buf.readUInt32LE(eLfanew) !== 0x00004550) return { ok: false };
  const coff = eLfanew + 4;
  const numSections = buf.readUInt16LE(coff + 2);
  const timestamp = buf.readUInt32LE(coff + 4);
  const sizeOpt = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  if (opt + sizeOpt > buf.length) return { ok: false };
  const magic = buf.readUInt16LE(opt);
  const is64 = magic === 0x20b;
  const checksum = buf.readUInt32LE(opt + (is64 ? 64 : 56) + (is64 ? 0 : 0) + (is64 ? 0 : 0)); // offset 64 both? PE32: 56? use standard: PE32 checksum at opt+64? actually both at opt+64
  const ddOff = opt + (is64 ? 112 : 96);
  const numDD = buf.readUInt32LE(opt + (is64 ? 108 : 92));
  const secOff = opt + sizeOpt;
  const sections = [];
  for (let i = 0; i < numSections && secOff + i * 40 + 40 <= buf.length; i++) {
    const o = secOff + i * 40;
    const name = buf.toString('latin1', o, o + 8).replace(/\0+$/, '');
    const vsize = buf.readUInt32LE(o + 8);
    const vaddr = buf.readUInt32LE(o + 12);
    const rawSize = buf.readUInt32LE(o + 16);
    const rawPtr = buf.readUInt32LE(o + 20);
    const chars = buf.readUInt32LE(o + 36);
    let ent = 0;
    if (rawSize > 0 && rawPtr + rawSize <= buf.length) ent = entropy(buf.subarray(rawPtr, rawPtr + rawSize));
    sections.push({ name, vsize, vaddr, rawSize, rawPtr, chars, entropy: ent });
  }
  // imports
  const imports = [];
  if (numDD >= 2) {
    const impRVA = buf.readUInt32LE(ddOff + 8);
    const impSize = buf.readUInt32LE(ddOff + 12);
    const rva2off = (rva) => {
      for (const s of sections) {
        if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawSize)) return s.rawPtr + (rva - s.vaddr);
      }
      return -1;
    };
    if (impRVA && impSize) {
      let off = rva2off(impRVA);
      for (let d = 0; d < 64 && off >= 0 && off + 20 <= buf.length; d++, off += 20) {
        const ilt = buf.readUInt32LE(off);
        const nameRva = buf.readUInt32LE(off + 12);
        if (!nameRva && !ilt) break;
        const noff = rva2off(nameRva);
        if (noff < 0) break;
        const dll = readSz(buf, noff, 128).toLowerCase();
        const funcs = [];
        let toff = rva2off(ilt || buf.readUInt32LE(off + 16));
        for (let f = 0; f < 200 && toff >= 0 && toff + (is64 ? 8 : 4) <= buf.length; f++, toff += (is64 ? 8 : 4)) {
          const t = is64 ? buf.readBigUInt64LE(toff) : BigInt(buf.readUInt32LE(toff));
          if (t === 0n) break;
          const isOrd = is64 ? (t & 0x8000000000000000n) !== 0n : (t & 0x80000000n) !== 0n;
          if (isOrd) continue;
          const nOff = rva2off(Number(t) & 0x7fffffff);
          if (nOff < 0 || nOff + 2 >= buf.length) continue;
          funcs.push(readSz(buf, nOff + 2, 96));
        }
        imports.push({ dll, funcs });
      }
    }
  }
  // overlay
  let overlay = { size: 0, entropy: 0 };
  const maxRaw = sections.reduce((m, s) => Math.max(m, s.rawPtr + s.rawSize), 0);
  if (maxRaw > 0 && buf.length > maxRaw + 512) {
    const ov = buf.subarray(maxRaw);
    overlay = { size: ov.length, entropy: entropy(ov) };
  }
  // cert directory present?
  let hasCert = false;
  if (numDD >= 5) {
    hasCert = buf.readUInt32LE(ddOff + 4 * 8) !== 0; // IMAGE_DIRECTORY_ENTRY_SECURITY = 4 → offset 4*8
  }
  return { ok: true, is64, timestamp, checksum, sections, imports, overlay, hasCert, ddCount: numDD };
}

function allImportedFuncs(pe) {
  const set = new Set();
  for (const imp of pe.imports) for (const f of imp.funcs) set.add(f);
  return set;
}

/** Эвристики PE → находки (пусто = чисто). extra: {path, entropyAll} */
function peHeuristics(buf, pe, extra = {}) {
  const out = [];
  if (!pe.ok) return out;
  const lowerPath = String(extra.path || '').toLowerCase();
  const tempish = /\\(temp|tmp)\\|\\appdata\\local\\temp|\/tmp\//.test(lowerPath);
  const highEnt = (extra.entropyAll || 0) > 6.6;
  const packedSection = pe.sections.some((s) => PACKER_SECTIONS.includes(s.name.toLowerCase()));
  const weirdSection = pe.sections.some((s) => s.name && !KNOWN_GOOD_SECTIONS.includes(s.name.toLowerCase()) && !PACKER_SECTIONS.includes(s.name.toLowerCase()) && s.rawSize > 0 && s.entropy > 7.4);
  const wx = pe.sections.some((s) => (s.chars & 0x80000000) && (s.chars & 0x20000000)); // writable+executable
  const funcs = allImportedFuncs(pe);
  const aggr = packedSection || weirdSection || highEnt || tempish;

  if (packedSection) out.push({ kind: 'heuristic', cat: 'risk', sev: 2, fam: 'packed', title: 'Heur.PE.Packer', desc: `Секции упаковщика: ${pe.sections.filter((s) => PACKER_SECTIONS.includes(s.name.toLowerCase())).map((s) => s.name).join(', ')}` });
  if (wx) out.push({ kind: 'heuristic', cat: 'risk', sev: 2, fam: 'packed', title: 'Heur.PE.WXSection', desc: 'Секция с правами на запись и выполнение (W+X) — признак распаковки кода в памяти' });

  for (const combo of API_COMBOS) {
    let hit = false;
    if (combo.need) hit = combo.need.every((f) => funcs.has(f));
    if (!hit && combo.need2) hit = combo.need2.every((group) => group.some((f) => funcs.has(f)));
    if (!hit) continue;
    // анти-ФП: комбинацию учитываем только при дополнительном признаке или высокой опасности
    const severe = combo.sev >= 4;
    if (!aggr && !severe) continue;
    out.push({ kind: 'heuristic', cat: combo.cat, sev: combo.sev, fam: combo.fam, title: combo.id, desc: combo.desc + (aggr ? '' : ' (без доп. признаков — понижено до наблюдения)') });
  }
  const now = Math.floor(Date.now() / 1000);
  if (pe.timestamp !== 0 && (pe.timestamp > now + 60 * 60 * 24 * 366 || pe.timestamp < 600000000)) {
    out.push({ kind: 'heuristic', cat: 'risk', sev: 1, fam: 'packed', title: 'Heur.PE.FakeTimestamp', desc: 'Аномальная метка времени компиляции PE — часто у упакованного/модифицированного кода' });
  }
  return out;
}

module.exports = { parsePE, peHeuristics, PACKER_SECTIONS, API_COMBOS };
