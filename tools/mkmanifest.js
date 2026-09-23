'use strict';
// Генерация nukefy-db/manifest.json для автообновления баз:
// версия + SHA-256 каждого файла. Запуск: node tools/mkmanifest.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const dbDir = path.join(__dirname, '..', 'nukefy-db');
const files = ['signatures.json', 'knowledge.json'];
const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(path.join(dbDir, f))).digest('hex');
const sig = JSON.parse(fs.readFileSync(path.join(dbDir, 'signatures.json'), 'utf8'));

const manifest = {
  product: 'Nukefy',
  version: sig.version,
  updated: new Date().toISOString(),
  sha256: Object.fromEntries(files.map((f) => [f, sha(f)])),
};
fs.writeFileSync(path.join(dbDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log('manifest.json →', manifest.version, JSON.stringify(manifest.sha256));
