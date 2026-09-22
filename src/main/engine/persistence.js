'use strict';
/**
 * Nukefy — проверка точек автозапуска и файла hosts.
 * Windows: реестр Run/RunOnce (HKCU+HKLM), папки Startup, планировщик (schtasks), службы подозрительных путей.
 * Linux (dev): ~/.config/autostart, cron-каталоги, rc.local.
 * hosts: сравнение с эталоном, поиск перенаправлений.
 */
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const { execCapture, IS_WIN } = require('./util');

const RUN_KEYS = [
  ['HKCU', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
  ['HKCU-Once', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'],
  ['HKLM', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
  ['HKLM-Once', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'],
  ['HKLM-WOW', 'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'],
];

function startupFolders() {
  const env = process.env;
  const out = [];
  if (IS_WIN) {
    if (env.APPDATA) out.push(path.join(env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'));
    if (env.ProgramData) out.push(path.join(env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'));
  } else {
    out.push(path.join(os.homedir(), '.config', 'autostart'));
    out.push('/etc/xdg/autostart');
  }
  return out;
}

function hostsPath() {
  return IS_WIN
    ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts')
    : '/etc/hosts';
}

const DEFAULT_HOSTS = '# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n127.0.0.1       localhost\r\n::1             localhost\r\n';

/** Разбор вывода `reg query` на пары имя=значение. */
function parseRegQuery(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const ln of lines) {
    const m = ln.match(/^\s{2,}([^\t]+?)\s+(REG_[A-Z_]+)\s+(.*)$/);
    if (m) out.push({ name: m[1].trim(), type: m[2], value: m[3].trim() });
  }
  return out;
}

function looksLikeAutorunValue(value) {
  const v = String(value || '').toLowerCase();
  if (!v) return false;
  if (/^\s*"[a-z]:\\(windows|winnt)\\(explorer|system32|syswow64)\\[a-z0-9_.-]+\.(exe|com|bat|cmd|vbs|js|msi)"?/i.test(v)) return false;
  return true;
}

async function collectAutorun() {
  const items = [];
  if (IS_WIN) {
    for (const [hive, key] of RUN_KEYS) {
      const r = await execCapture('reg', ['query', key], { timeout: 8000 });
      if (!r.ok && !r.stdout) continue;
      for (const e of parseRegQuery(r.stdout)) {
        items.push({ source: `Реестр ${hive}`, key, name: e.name, command: e.value, kind: 'registry' });
      }
    }
    // Планировщик: задачи с исполняемыми файлами вне системных папок
    const sch = await execCapture('schtasks', ['/query', '/fo', 'csv', '/v', '/nh'], { timeout: 20000 });
    if (sch.stdout) {
      const lines = sch.stdout.split(/\r?\n/).slice(0, 4000);
      for (const ln of lines) {
        const cols = splitCsv(ln);
        if (cols.length < 10) continue;
        const taskName = cols[1] || cols[0];
        const taskToRun = cols[8] || '';
        if (!taskToRun || taskToRun === 'N/A' || taskToRun === '#') continue;
        const low = taskToRun.toLowerCase();
        if (!/\.(exe|bat|cmd|vbs|js|ps1|scr|com)/.test(low)) continue;
        const outside = !/(\\windows\\|\\system32\\|\\syswow64\\|\\microsoft\\)/.test(low);
        items.push({ source: 'Планировщик', key: taskName, name: path.basename(taskToRun.replace(/"/g, '')), command: taskToRun, kind: 'task', outside });
      }
    }
  } else {
    for (const dir of startupFolders()) {
      let ents = [];
      try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
      for (const ent of ents) {
        if (!ent.isFile()) continue;
        const p = path.join(dir, ent.name);
        let content = '';
        try { content = await fsp.readFile(p, 'utf8'); } catch (_) {}
        const exec = (content.match(/^Exec=(.+)$/m) || [])[1] || p;
        items.push({ source: `Autostart ${dir}`, key: p, name: ent.name, command: exec, kind: 'desktop' });
      }
    }
    for (const cron of ['/etc/cron.d', '/var/spool/cron/crontabs', path.join(os.homedir(), '.config', 'systemd', 'user')]) {
      let ents = [];
      try { ents = await fsp.readdir(cron, { withFileTypes: true }); } catch (_) { continue; }
      for (const ent of ents) {
        if (!ent.isFile()) continue;
        items.push({ source: `Cron ${cron}`, key: path.join(cron, ent.name), name: ent.name, command: ent.name, kind: 'cron' });
      }
    }
  }
  // папки автозагрузки (файлы/ярлыки)
  for (const dir of startupFolders()) {
    let ents = [];
    try { ents = await fsp.readdir(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const ent of ents) {
      if (!ent.isFile()) continue;
      const p = path.join(dir, ent.name);
      items.push({ source: 'Папка автозагрузки', key: p, name: ent.name, command: p, kind: 'startup-file' });
    }
  }
  return items;
}

function splitCsv(line) {
  const out = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { if (inQ && line[i + 1] === '"') { cur += '"'; i++; } else inQ = !inQ; }
    else if (ch === ',' && !inQ) { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/** Проверить autorun-записи на опасность: файл отсутствует / во временной папке / маска. */
function analyzeAutorun(items, db) {
  const threats = [];
  for (const it of items) {
    const cmd = String(it.command || '');
    const low = cmd.toLowerCase();
    const m = low.match(/([a-z]:\\[^"']+?\.(?:exe|dll|scr|bat|cmd|vbs|js|ps1|hta))|"([^"]+?\.(?:exe|dll|scr|bat|cmd|vbs|js|ps1|hta))/);
    const target = m ? (m[2] || m[1]) : null;
    let missing = false;
    if (target) {
      try { fs.accessSync(target.replace(/\//g, path.sep)); } catch (_) { missing = !/^(cmd|explorer|rundll32|msiexec|powershell|pwsh|wscript|cscript)\.exe/.test(path.basename(target.replace(/\\/g, '/')).toLowerCase()); }
    }
    const sigHits = target ? db.matchText(low, null).filter((s) => s.cat !== 'risk' || /miner|trojan|virus/.test(s.cat)) : [];
    const tempish = /\\(temp|tmp)\\|\\appdata\\local\\temp|\/tmp\//.test(low);
    const masked = /(^|[\\/])(svchost|csrss|lsass|winlogon|services|smss)\.exe$/.test(low) && !/\\(system32|syswow64|winnt|windows)\\/.test(low);
    if (masked) {
      threats.push({ ...it, reason: 'masquerade', fam: 'hidden-autorun', sev: 4, cat: 'trojan', title: 'Autorun.Masquerade', desc: 'Автозапуск под именем системного процесса вне системной папки' });
    } else if (tempish && target) {
      threats.push({ ...it, reason: 'temp', fam: 'hidden-autorun', sev: 3, cat: 'trojan', title: 'Autorun.TempTarget', desc: 'Автозапуск файла из временной папки' });
    } else if (missing && it.kind !== 'cron') {
      threats.push({ ...it, reason: 'orphan', fam: 'orphan-autorun', sev: 1, cat: 'risk', title: 'Autorun.Orphan', desc: 'Запись автозапуска указывает на несуществующий файл' });
    } else if (sigHits.length) {
      threats.push({ ...it, reason: 'sig', fam: sigHits[0].fam, sev: sigHits[0].sev, cat: sigHits[0].cat, title: sigHits[0].id, desc: 'Автозапуск: ' + sigHits[0].desc });
    }
  }
  return threats;
}

async function checkHosts() {
  const p = hostsPath();
  let text = '';
  try { text = await fsp.readFile(p, 'utf8'); } catch (_) { return { ok: true, issues: [] }; }
  const issues = [];
  const lines = text.split(/\r?\n/);
  for (const ln of lines) {
    const t = ln.trim();
    if (!t || t.startsWith('#')) continue;
    const parts = t.split(/\s+/);
    if (parts.length < 2) continue;
    const ip = parts[0], host = parts[1].toLowerCase();
    const blocked = /^(127\.|0\.0\.0\.0|::1)/.test(ip);
    const secSite = /(virus|kaspersky|drweb|dr\.web|microsoft|windowsupdate|update\.microsoft|malware|abuse\.ch|virustotal|eset|avast|avg|defender|safebrowsing|gnu\.org|license)/.test(host);
    if (blocked && secSite) {
      issues.push({ line: t, ip, host, reason: 'Блокировка сайта безопасности/обновлений через hosts' });
    } else if (!blocked && !/^(127\.|::1|0\.0\.0\.0)/.test(ip) && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && secSite) {
      issues.push({ line: t, ip, host, reason: `Перенаправление сайта безопасности на ${ip}` });
    }
  }
  return { ok: issues.length === 0, issues, path: p };
}

async function restoreHosts(backupDir) {
  const p = hostsPath();
  try {
    const cur = await fsp.readFile(p);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    await fsp.mkdir(backupDir, { recursive: true });
    await fsp.writeFile(path.join(backupDir, `hosts.backup-${stamp}.txt`), cur);
    await fsp.writeFile(p, IS_WIN ? DEFAULT_HOSTS : '127.0.0.1\tlocalhost\n::1\tlocalhost\n');
    return { ok: true, backup: path.join(backupDir, `hosts.backup-${stamp}.txt`) };
  } catch (e) {
    return { ok: false, error: String(e && e.message) };
  }
}

/** Удалить запись автозапуска (лечение). */
async function removeAutorunEntry(item) {
  try {
    if (item.kind === 'registry' && IS_WIN) {
      const r = await execCapture('reg', ['delete', item.key, '/v', item.name, '/f'], { timeout: 8000 });
      return { ok: r.ok, error: r.ok ? null : (r.stderr || r.error || 'reg delete failed') };
    }
    if (item.kind === 'task' && IS_WIN) {
      const r = await execCapture('schtasks', ['/delete', '/tn', item.key, '/f'], { timeout: 8000 });
      return { ok: r.ok, error: r.ok ? null : (r.stderr || r.error) };
    }
    if (item.kind === 'startup-file' || item.kind === 'desktop' || item.kind === 'cron') {
      await fsp.rm(item.key, { force: true });
      return { ok: true };
    }
    return { ok: false, error: 'unsupported' };
  } catch (e) { return { ok: false, error: String(e && e.message) }; }
}

module.exports = { collectAutorun, analyzeAutorun, checkHosts, restoreHosts, removeAutorunEntry, startupFolders, hostsPath, RUN_KEYS };
