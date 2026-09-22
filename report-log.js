'use strict';
/* CI: собрать payload.json с хвостом лога для commit comment (без backtick в shell). */
const fs = require('fs');
const fence = String.fromCharCode(96).repeat(3);
let log = '';
try { log = fs.readFileSync('ci-build-log.txt', 'utf8'); } catch (_) { log = '(лог недоступен)'; }
fs.writeFileSync('payload.json', JSON.stringify({ body: 'ELECTRON-BUILDER LOG:\n' + fence + '\n' + log + '\n' + fence + '\n' }));
console.log('payload.json готов, байт: ' + fs.statSync('payload.json').size);
