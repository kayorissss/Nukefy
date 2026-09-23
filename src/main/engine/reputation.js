'use strict';
/**
 * Nukefy — облачная репутация.
 *  • MalwareBazaar (abuse.ch)  — бесплатно, без ключа: хэш файла → сигнатура, дата попадания в базу.
 *  • URLhaus (abuse.ch)        — бесплатно, без ключа: URL/домен → активные вредоносные ссылки.
 *  • VirusTotal v3             — если пользователь ввёл бесплатный API-ключ: файл/URL-резюмэ, детекты.
 * Все запросы с деградацией: сервис недоступен — молча пропускаем, UI это покажет.
 */
const https = require('https');
const { URL } = require('url');

const UA = 'Nukefy/1.0 (+https://github.com/kayorissss/Nukefy)';

function httpRequest(opts, body) {
  return new Promise((resolve) => {
    try {
      const req = https.request(opts, (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (d) => { if (size < 4 * 1024 * 1024) { chunks.push(d); size += d.length; } });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', () => resolve({ status: 0, headers: {}, body: '' }));
      });
      req.setTimeout(opts.timeout || 12000, () => { try { req.destroy(new Error('timeout')); } catch (_) {} });
      req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', error: String(e && e.message || e) }));
      if (body) req.write(body);
      req.end();
    } catch (e) {
      resolve({ status: 0, headers: {}, body: '', error: String(e && e.message) });
    }
  });
}

function jsonRequest(method, urlStr, headers, body) {
  return new Promise((resolve) => {
    try {
      const u = new URL(urlStr);
      httpRequest({
        method, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search,
        headers: { 'User-Agent': UA, ...headers }, timeout: 12000,
      }, body).then((r) => {
        let json = null;
        try { json = JSON.parse(r.body); } catch (_) {}
        resolve({ status: r.status, json, raw: r.body, error: r.error });
      });
    } catch (e) { resolve({ status: 0, json: null, raw: '', error: String(e && e.message) }); }
  });
}

/* ---------------- MalwareBazaar ---------------- */
async function mbLookup(sha256) {
  const body = new URLSearchParams({ query: 'getinfo', hash: sha256 }).toString();
  const r = await jsonRequest('POST', 'https://mb-api.abuse.ch/api/v1/', {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(body),
  }, body);
  if (!r.json || r.json.query_status !== 'ok' || !Array.isArray(r.json.data) || !r.json.data.length) {
    return { found: false, status: r.status };
  }
  const d = r.json.data[0];
  return {
    found: true,
    status: r.status,
    signature: d.signature || null,
    firstSeen: d.first_seen_utc || null,
    lastSeen: d.last_seen_utc || null,
    tags: d.tags_list || [],
    fileTypes: d.file_type || null,
    reportsCount: d.delivery_method || null,
    source: 'MalwareBazaar',
    link: `https://bazaar.abuse.ch/sample/${sha256}/`,
  };
}

/* ---------------- URLhaus ---------------- */
async function urlhausUrl(urlStr) {
  const r = await jsonRequest('GET', 'https://urlhaus-api.abuse.ch/v1/url/?full=true&url=' + encodeURIComponent(urlStr), {});
  if (!r.json || !r.json.url || r.json.url_status === 'not_found') return { found: false, status: r.status };
  return {
    found: true, status: r.status,
    host: r.json.host, urlStatus: r.json.url_status,
    firstSeen: r.json.first_seen, lastSeen: r.json.last_seen,
    online: r.json.Urls_online_count, signatures: (r.json.payloads || []).map(p => p.signature).filter(Boolean),
    source: 'URLhaus', link: r.json.urlhaus_reference || 'https://urlhaus.abuse.ch/',
  };
}
async function urlhausHost(host) {
  const r = await jsonRequest('GET', 'https://urlhaus-api.abuse.ch/v1/host/?host=' + encodeURIComponent(host), {});
  if (!r.json || !r.json.host) return { found: false, status: r.status };
  return {
    found: true, status: r.status, host: r.json.host,
    urlCount: r.json.urls_count, onlineCount: r.json.urls_online,
    firstSeen: r.json.first_seen, lastSeen: r.json.last_seen,
    source: 'URLhaus', link: r.json.urlhaus_reference || 'https://urlhaus.abuse.ch/host/' + host + '/',
  };
}
async function urlhausPayload(sha256) {
  const r = await jsonRequest('GET', 'https://urlhaus-api.abuse.ch/v1/payload/?sha256=' + encodeURIComponent(sha256), {});
  if (!r.json || !r.json.sha256) return { found: false, status: r.status };
  return {
    found: true, status: r.status, signature: r.json.signature,
    firstSeen: r.json.first_seen, fileTypes: r.json.file_type,
    source: 'URLhaus-Payload', link: r.json.urlhaus_reference,
  };
}

/* ---------------- VirusTotal v3 ---------------- */
const VT = 'https://www.virustotal.com/api/v3';
function b64url(s) { return Buffer.from(s).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); }

async function vtFile(sha256, key) {
  if (!key) return { available: false, reason: 'no-key' };
  const r = await jsonRequest('GET', `${VT}/files/${sha256}`, { 'x-apikey': key });
  if (r.status === 404) return { available: true, found: false };
  if (!r.json || !r.json.data || !r.json.data.attributes) return { available: !!key, found: false, status: r.status, error: r.error };
  const a = r.json.data.attributes;
  const s = a.last_analysis_stats || {};
  return {
    available: true, found: true,
    malicious: s.malicious || 0, suspicious: s.suspicious || 0,
    total: (s.malicious || 0) + (s.suspicious || 0) + (s.undetected || 0) + (s.harmless || 0),
    score: a.reputation, popularity: a.popularity_indices ? null : null,
    names: (a.names || []).slice(0, 6),
    firstSubmission: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : null,
    lastSubmission: a.last_submission_date ? new Date(a.last_submission_date * 1000).toISOString().slice(0, 10) : null,
    types: a.type_tag ? [a.type_tag] : (a.tags || []),
    link: `https://www.virustotal.com/gui/file/${sha256}`,
    engineSample: pickEngines(a.last_analysis_results),
  };
}
function pickEngines(results) {
  if (!results) return [];
  const hits = [];
  for (const [engine, r] of Object.entries(results)) {
    if (r && r.category === 'malicious' && r.result) hits.push({ engine, result: r.result });
    if (hits.length >= 5) break;
  }
  return hits;
}
async function vtUrl(urlStr, key) {
  if (!key) return { available: false, reason: 'no-key' };
  const id = b64url(urlStr);
  const r = await jsonRequest('GET', `${VT}/urls/${id}/report`, { 'x-apikey': key });
  if (r.status === 404 || !r.json || !r.json.data) {
    return { available: true, found: false, urlId: id, link: 'https://www.virustotal.com/gui/url/' + id };
  }
  const a = r.json.data.attributes || {};
  const s = a.last_analysis_stats || {};
  return {
    available: true, found: true,
    malicious: s.malicious || 0, suspicious: s.suspicious || 0,
    total: (s.malicious || 0) + (s.suspicious || 0) + (s.undetected || 0) + (s.harmless || 0),
    firstSubmission: a.first_submission_date ? new Date(a.first_submission_date * 1000).toISOString().slice(0, 10) : null,
    result: a.last_analysis_results,
    link: 'https://www.virustotal.com/gui/url/' + id,
  };
}
async function vtTestKey(key) {
  const r = await jsonRequest('GET', `${VT}/users/me`, { 'x-apikey': key });
  if (r.status === 200) return { ok: true, name: r.json && r.json.data && r.json.data.attributes ? r.json.data.attributes.username : 'user' };
  if (r.status === 401) return { ok: false, error: 'Ключ отклонён (401). Проверьте, что это публичный API-ключ v3.' };
  return { ok: false, error: `Сервис ответил ${r.status || r.error || 'неизвестно'}.` };
}

/** Отправка образца в VirusTotal (нужен ключ; лимит бесплатного тарифа). */
async function vtSubmit(file, key) {
  const fs = require('fs');
  const path = require('path');
  let buf;
  try { buf = fs.readFileSync(file); } catch (e) { return { ok: false, error: String(e && e.message) }; }
  if (buf.length > 32 * 1024 * 1024) return { ok: false, error: 'файл больше 32 МБ — отправка недоступна в бесплатном тарифе' };
  const boundary = '----Nukefy' + Date.now().toString(16);
  const head = Buffer.from(
    '--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + path.basename(file).replace(/"/g, '') + '"\r\nContent-Type: application/octet-stream\r\n\r\n');
  const tail = Buffer.from('\r\n--' + boundary + '--\r\n');
  const body = Buffer.concat([head, buf, tail]);
  const r = await new Promise((resolve) => {
    const req = https.request({
      method: 'POST', hostname: 'www.virustotal.com', path: '/api/v3/files',
      headers: { 'x-apikey': key, 'Content-Type': 'multipart/form-data; boundary=' + boundary, 'Content-Length': body.length, 'User-Agent': UA },
      timeout: 60000,
    }, (res) => {
      let b = ''; res.on('data', (d) => { if (b.length < 64 * 1024) b += d; });
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    });
    req.on('error', (e) => resolve({ status: 0, body: '', error: String(e && e.message) }));
    req.on('timeout', () => { try { req.destroy(); } catch (_) {} });
    req.end(body);
  });
  if (r.status === 200) {
    try { return { ok: true, id: JSON.parse(r.body).data && JSON.parse(r.body).data.id }; } catch (_) { return { ok: true }; }
  }
  return { ok: false, error: 'VirusTotal ответил ' + (r.status || r.error || 'ошибкой') };
}

/* ---------------- Агрегатор ---------------- */
async function reputationForFile(sha256, settings) {
  const out = { sha256, services: {} };
  const cloud = settings.cloud || {};
  const jobs = [];
  if (cloud.malwarebazaar !== false) {
    jobs.push(mbLookup(sha256).then((r) => { out.services.malwarebazaar = r; }));
  }
  if (cloud.virustotal !== 'off' && settings.vtKey) {
    jobs.push(vtFile(sha256, settings.vtKey).then((r) => { out.services.virustotal = r; }));
  }
  await Promise.all(jobs);
  out.malicious = false;
  const mb = out.services.malwarebazaar;
  if (mb && mb.found) { out.malicious = true; out.signature = mb.signature; out.firstSeen = mb.firstSeen; }
  const vt = out.services.virustotal;
  if (vt && vt.found && vt.malicious > 0) { out.malicious = true; out.vtRatio = `${vt.malicious}/${vt.total}`; if (!out.firstSeen) out.firstSeen = vt.firstSubmission; }
  return out;
}

module.exports = {
  mbLookup, urlhausUrl, urlhausHost, urlhausPayload,
  vtFile, vtUrl, vtTestKey, vtSubmit, reputationForFile, httpRequest, jsonRequest,
};
