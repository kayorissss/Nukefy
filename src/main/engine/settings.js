'use strict';
/**
 * Nukefy — хранилище настроек (userData/settings.json).
 * Единая точка правды о путях, ключах API и режимах защиты.
 */
const path = require('path');
const os = require('os');
const fs = require('fs');
const { writeJson, readJson, IS_WIN } = require('./util');

let DATA_DIR = null;
function dataDir() {
  if (DATA_DIR) return DATA_DIR;
  try {
    const { app } = require('electron');
    DATA_DIR = app.getPath('userData');
  } catch (_) {
    DATA_DIR = process.env.NUKEFY_DATA || path.join(os.homedir(), '.nukefy');
  }
  return DATA_DIR;
}
function overrideDataDir(p) { DATA_DIR = p; }

function defaultScanRoots() {
  if (IS_WIN) {
    const home = os.homedir();
    const env = process.env;
    return unique([
      home,
      env.APPDATA,
      env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Temp') : null,
      env.ProgramData,
      env.PUBLIC,
      env.SystemRoot ? path.join(env.SystemRoot, 'System32') : null,
      env['ProgramFiles'],
      env['ProgramFiles(x86)'],
    ].filter(Boolean));
  }
  return unique([os.homedir(), '/tmp', '/etc', '/usr/local/bin', '/opt']);
}

function quickScanRoots() {
  if (IS_WIN) {
    const env = process.env;
    return unique([
      env.APPDATA ? path.join(env.APPDATA, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') : null,
      env.ProgramData ? path.join(env.ProgramData, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup') : null,
      env.TEMP,
      env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, 'Temp') : null,
      path.join(os.homedir(), 'Downloads'),
      env.ProgramData ? path.join(env.ProgramData, 'Temp') : null,
      env.PUBLIC ? path.join(env.PUBLIC, 'Desktop') : null,
    ].filter(Boolean));
  }
  return unique(['/tmp', '/var/tmp', path.join(os.homedir(), '.config', 'autostart'), path.join(os.homedir(), 'Downloads')]);
}

const unique = (arr) => [...new Set(arr)];

const DEFAULTS = () => ({
  version: 1,
  vtKey: '',
  cloud: { malwarebazaar: true, urlhaus: true, virustotal: 'auto' }, // auto: только при ключе
  checks: { processes: true, persistence: true, network: true, startupFiles: true, hashScan: true, modules: true, boot: true },
  schedule: { enabled: false, time: '03:00', mode: 'quick' },
  ui: { quiet: false },
  autoupdate: { enabled: true, intervalH: 4, lastCheck: null, lastVersion: null },
  scan: {
    fullRoots: defaultScanRoots(),
    quickRoots: quickScanRoots(),
    excludeDirs: ['node_modules', '.git', 'WinSxS', 'Nukefy'],
    maxFileMb: 128,
    maxFilesFull: 160000,
    maxFilesQuick: 40000,
  },
  protection: { enabled: true, intervalSec: 300 },
  actions: { onThreat: 'notify' }, // notify | quarantine
  whitelist: [], // [{hash, path, title, addedAt}]
  ignored: [], // ключи угроз, «игнорировать в этой сессии не нужно» — постоянный ignore
  urlHistory: [], // [{url, score, verdict, at}]
  autostart: false,
  firstRun: true,
});

class Settings {
  constructor() { this.file = path.join(dataDir(), 'settings.json'); this.data = DEFAULTS(); this._loaded = false; }
  async load() {
    const saved = await readJson(this.file, null);
    if (saved) this.data = mergeDefaults(DEFAULTS(), saved);
    this._loaded = true;
    return this.data;
  }
  get() { return this.data; }
  async set(patch) {
    const merged = mergeDefaults(this.data, patch);
    // whitelists: патч заменяет массивы целиком, если передан
    if (Array.isArray(patch.whitelist)) merged.whitelist = patch.whitelist;
    if (Array.isArray(patch.ignored)) merged.ignored = patch.ignored;
    if (Array.isArray(patch.urlHistory)) merged.urlHistory = patch.urlHistory;
    this.data = merged;
    try { await writeJson(this.file, merged); } catch (_) {}
    return merged;
  }
}

function mergeDefaults(def, src) {
  const out = Array.isArray(def) ? def : { ...def };
  for (const k of Object.keys(src || {})) {
    const sv = src[k], dv = def[k];
    if (sv && typeof sv === 'object' && !Array.isArray(sv) && dv && typeof dv === 'object' && !Array.isArray(dv)) {
      out[k] = mergeDefaults(dv, sv);
    } else if (sv !== undefined) {
      out[k] = sv;
    }
  }
  return out;
}

module.exports = { Settings, dataDir, overrideDataDir, defaultScanRoots, quickScanRoots };
