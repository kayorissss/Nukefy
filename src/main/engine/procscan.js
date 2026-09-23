'use strict';
/**
 * Nukefy — анализ процессов и сетевых соединений.
 * Windows: tasklist + Get-CimInstance Win32_Process (командная строка), Get-NetTCPConnection.
 * Linux: /proc (dev-режим).
 */
const fs = require('fs');
const path = require('path');
const { execCapture, IS_WIN } = require('./util');
const { MINER_PORTS, isTrustedPath } = require('./constants');

const SYSTEM_NAMES = ['system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe', 'dwm.exe', 'explorer.exe', 'spoolsv.exe', 'searchindexer.exe', 'system interrupts', 'memory compression', 'secure system', 'fontdrvhost.exe', 'taskhostw.exe', 'runtimebroker.exe', 'sihost.exe', 'ctfmon.exe', 'conhost.exe', 'dllhost.exe', 'wudfhost.exe', 'searchapp.exe', 'startmenuexperiencehost.exe', 'textinputhost.exe', 'applicationframehost.exe', 'shellexperiencehost.exe', 'backgroundtaskhost.exe', 'compattelrunner.exe', 'msmpeng.exe', 'nissrv.exe', 'securityhealthservice.exe', 'smartscreen.exe', 'consent.exe', 'taskmgr.exe'];

/* Где legitimately живут системные процессы Windows */
const SYS_HOME = {
  'svchost.exe': ['\\windows\\system32\\', '\\windows\\syswow64\\'],
  'csrss.exe': ['\\windows\\system32\\'],
  'lsass.exe': ['\\windows\\system32\\'],
  'winlogon.exe': ['\\windows\\system32\\'],
  'wininit.exe': ['\\windows\\system32\\'],
  'services.exe': ['\\windows\\system32\\'],
  'smss.exe': ['\\windows\\system32\\'],
  'dwm.exe': ['\\windows\\system32\\'],
  'conhost.exe': ['\\windows\\system32\\'],
  'explorer.exe': ['\\windows\\', '\\windows\\system32\\'], // explorer лежит в корне Windows
  'taskhostw.exe': ['\\windows\\system32\\'],
  'runtimebroker.exe': ['\\windows\\system32\\', '\\windows\\immersive control panel\\'],
};
function masquerade(name, exePath) {
  const n = String(name || '').toLowerCase();
  const p = String(exePath || '').toLowerCase();
  const homes = SYS_HOME[n];
  if (!homes) return null;
  if (!p) return null; // путь недоступен (системный процесс без прав) — не считаем маскарадом
  if (homes.some((h) => p.includes(h))) return null;
  if (/\/(sbin|bin|usr\/bin|usr\/sbin)\//.test(p)) return null; // linux
  return `Процесс с именем системного «${n}» запущен из ${exePath}`;
}

async function listProcesses() {
  const procs = [];
  if (IS_WIN) {
    const r = await execCapture('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine,CreationDate,ParentProcessId | ConvertTo-Json -Compress -Depth 2'], { timeout: 20000 });
    if (r.stdout) {
      let arr = null;
      try { arr = JSON.parse(r.stdout.replace(/^\uFEFF/, '')); } catch (_) {}
      if (arr) {
        for (const p of Array.isArray(arr) ? arr : [arr]) {
          procs.push({ pid: p.ProcessId, name: p.Name || '', path: p.ExecutablePath || '', cmd: p.CommandLine || '', parent: p.ParentProcessId, started: p.CreationDate || null });
        }
        return procs;
      }
    }
    const t = await execCapture('tasklist', ['/fo', 'csv', '/nh'], { timeout: 15000 });
    for (const ln of t.stdout.split(/\r?\n/)) {
      const c = ln.split('","').map((s) => s.replace(/^"|"$/g, ''));
      if (c.length >= 2) procs.push({ pid: parseInt(c[1], 10), name: c[0], path: '', cmd: '' });
    }
    return procs;
  }
  let pids = [];
  try { pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d)); } catch (_) { return procs; }
  for (const pid of pids) {
    try {
      const cmd = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
      let exe = '';
      try { exe = fs.readlinkSync(`/proc/${pid}/exe`); } catch (_) {}
      const name = path.basename(exe || cmd.split(' ')[0] || pid);
      const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
      const ppid = parseInt(stat.split(')')[1].trim().split(' ')[1], 10);
      procs.push({ pid: parseInt(pid, 10), name, path: exe, cmd, parent: ppid });
    } catch (_) {}
  }
  return procs;
}

async function listConnections() {
  const conns = [];
  if (IS_WIN) {
    const r = await execCapture('powershell', ['-NoProfile', '-NonInteractive', '-Command',
      'Get-NetTCPConnection -State Established | Select-Object OwningProcess,RemoteAddress,RemotePort,LocalPort | ConvertTo-Json -Compress'], { timeout: 15000 });
    if (r.stdout) {
      let arr = null;
      try { arr = JSON.parse(r.stdout.replace(/^\uFEFF/, '')); } catch (_) {}
      if (arr) for (const c of Array.isArray(arr) ? arr : [arr]) {
        conns.push({ pid: c.OwningProcess, remote: `${c.RemoteAddress}:${c.RemotePort}`, remotePort: c.RemotePort });
      }
      return conns;
    }
    const n = await execCapture('netstat', ['-ano'], { timeout: 15000 });
    for (const ln of n.stdout.split(/\r?\n/)) {
      const m = ln.match(/^\s*TCP\s+(\S+)\s+(\S+)\s+ESTABLISHED\s+(\d+)/i);
      if (m) {
        const rp = m[2].split(':').pop();
        conns.push({ pid: parseInt(m[3], 10), remote: m[2], remotePort: parseInt(rp, 10) });
      }
    }
    return conns;
  }
  try {
    const tcp = fs.readFileSync('/proc/net/tcp', 'utf8').split('\n').slice(1);
    const tcp6 = (() => { try { return fs.readFileSync('/proc/net/tcp6', 'utf8').split('\n').slice(1); } catch (_) { return []; } })();
    for (const ln of [...tcp, ...tcp6]) {
      const c = ln.trim().split(/\s+/);
      if (c.length < 10 || c[3] !== '01') continue; // ESTABLISHED
      const rem = c[2];
      const [hexIp, hexPort] = rem.split(':');
      const port = parseInt(hexPort, 16);
      let ip = '';
      if (hexIp.length === 8) {
        const b = [3, 2, 1, 0].map((i) => parseInt(hexIp.substr(i * 2, 2), 16));
        ip = b.join('.');
      } else ip = hexIp;
      conns.push({ pid: parseInt(c[9], 10) || 0, remote: `${ip}:${port}`, remotePort: port, inode: c[9] });
    }
  } catch (_) {}
  return conns;
}


/* Свои собственные пути (Nukefy, в т.ч. portable из Temp) — не детектим себя */
function isSelf(p, selfPaths) {
  if (!p) return false;
  const lp = String(p).toLowerCase();
  return (selfPaths || []).some((s) => s && lp.startsWith(String(s).toLowerCase()));
}


/** PowerShell-дропер: скрытое окно + загрузка из сети в одной командной строке. */
function psDropper(cmd) {
  const c = String(cmd || '').toLowerCase();
  if (!/(powershell|pwsh)/.test(c)) return false;
  const hidden = /(-w\s+hidden|-windowstyle\s+hidden|-noninteractive[^|]*-enc\s|encodedcommand)/.test(c);
  const fetch = /(https?:\/\/|iwr\s|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|net\.webclient|start-bits)/.test(c);
  return hidden && fetch && c.length > 40;
}

/** Сопоставить процессы+соединения+сигнатуры → угрозы. */
function analyzeProcesses(procs, conns, db, opts = {}) {
  const threats = [];
  const selfPaths = opts.selfPaths || [];
  for (const p of procs) {
    const lowName = String(p.name || '').toLowerCase();
    const self = isSelf(p.path, selfPaths) || isSelf(p.cmd, selfPaths);
    const trusted = isTrustedPath(p.path) || isTrustedPath(p.cmd);
    const minerConn = conns.filter((c) => c.pid === p.pid && MINER_PORTS.includes(c.remotePort));
    // сигнатуры с корректной логикой; в контексте процессов не используем файловые эвристики-сигнатуры
    const sigHits = self ? [] : db.matchTextSmart(`${p.name} ${p.cmd}`, {
      cats: ['miner', 'trojan', 'virus'],
      excludeFams: ['script-dropper', 'webshell', 'packed', 'ransomware', 'remote-admin'],
    });
    const mask = (!self && !trusted) ? masquerade(p.name, p.path) : null;
    const tempRun = (!self && !trusted) && p.path && /\\(temp|tmp)\\|\\appdata\\local\\temp|\/tmp\/|\/var\/tmp\//.test(String(p.path).toLowerCase());
    const dropper = !self && psDropper(p.cmd);
    if (sigHits.length) {
      threats.push({ pid: p.pid, name: p.name, path: p.path, cmd: p.cmd, fam: sigHits[0].fam, cat: sigHits[0].cat, sev: sigHits[0].sev, title: sigHits[0].id, desc: 'Процесс: ' + sigHits[0].desc, reason: 'sig' });
    } else if (dropper) {
      threats.push({ pid: p.pid, name: p.name, path: p.path, cmd: p.cmd, fam: 'script-dropper', cat: 'trojan', sev: 3, title: 'Proc.ScriptDropper', desc: 'Командная строка: скрытое выполнение + загрузка полезной нагрузки из сети', reason: 'dropper' });
    } else if (mask) {
      threats.push({ pid: p.pid, name: p.name, path: p.path, cmd: p.cmd, fam: 'temp-exec', cat: 'trojan', sev: 4, title: 'Proc.Masquerade', desc: mask, reason: 'masquerade' });
    } else if (minerConn.length) {
      threats.push({ pid: p.pid, name: p.name, path: p.path, cmd: p.cmd, fam: 'network-pool', cat: 'miner', sev: 4, title: 'Proc.MinerPort', desc: `Процесс держит соединение с портом майнинг-пула ${minerConn[0].remotePort} (${minerConn[0].remote})`, reason: 'pool-port', conns: minerConn });
    } else if (tempRun && !SYSTEM_NAMES.includes(lowName) && /\.(exe|scr|com)$/i.test(lowName)) {
      threats.push({ pid: p.pid, name: p.name, path: p.path, cmd: p.cmd, fam: 'temp-exec', cat: 'risk', sev: 2, title: 'Proc.TempRun', desc: `Исполняемый файл процесса находится во временной папке: ${p.path}`, reason: 'temp' });
    }
  }
  return threats;
}

async function killProcess(pid) {
  if (IS_WIN) {
    const r = await execCapture('taskkill', ['/pid', String(pid), '/f', '/t'], { timeout: 8000 });
    return { ok: r.ok, error: r.ok ? null : (r.stderr || r.error) };
  }
  try { process.kill(pid, 'SIGKILL'); return { ok: true }; } catch (e) { return { ok: false, error: String(e && e.message) }; }
}

module.exports = { listProcesses, listConnections, analyzeProcesses, killProcess, SYSTEM_NAMES, masquerade };
