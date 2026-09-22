'use strict';
/**
 * Nukefy — анализ ссылки/страницы: вирусы и слежка.
 * Этапы: разбор URL → эвристики домена → RDAP (дата регистрации) → загрузка страницы
 * (цепочка редиректов, TLS-ошибки) → разбор HTML (скрипты, iframe, формы, трекеры,
 * майнер-код, обфускация, скрытые редиректы) → облако URLhaus / VirusTotal.
 * Итог: score 0..100, verdict, список находок с пояснениями.
 */
const https = require('https');
const http = require('http');
const zlib = require('zlib');
const { URL } = require('url');
const { lev } = require('./util');
const { urlhausUrl, urlhausHost, vtUrl } = require('./reputation');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 Nukefy/1.0';

const TRACKERS = [
  ['google-analytics.com', 'Google Analytics'], ['googletagmanager.com', 'Google Tag Manager'],
  ['doubleclick.net', 'Google DoubleClick'], ['analytics.google.com', 'Google Analytics 4'],
  ['connect.facebook.net', 'Meta Pixel'], ['facebook.com/tr', 'Meta Pixel'],
  ['mc.yandex.ru', 'Яндекс.Метрика'], ['metrika', 'Яндекс.Метрика'],
  ['hotjar.com', 'Hotjar (запись сессий)'], ['clarity.ms', 'Microsoft Clarity (запись сессий)'],
  ['tiktok.com/i18n/pixel', 'TikTok Pixel'], ['adsbygoogle', 'Google AdSense'],
  ['top.mail.ru', 'Рейтинг Mail.ru'], ['counter.', 'Счётчик-трекер'],
  ['segment.io', 'Segment'], ['mixpanel.com', 'Mixpanel'], ['amplitude.com', 'Amplitude'],
  ['fullstory.com', 'FullStory (запись сессий)'], ['mouseflow.com', 'Mouseflow'],
];
const TOP_DOMAINS = ['google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'gitlab.com', 'yahoo.com', 'yandex.ru', 'vk.com', 'mail.ru', 'gosuslugi.ru', 'sberbank.ru', 'alfabank.ru', 'tinkoff.ru', 'ozon.ru', 'wildberries.ru', 'aliexpress.com', 'avito.ru', 'hh.ru', 'ria.ru', 'lenta.ru', 'habr.com', 'pikabu.ru', 'steamcommunity.com', 'store.steampowered.com', 'playstation.com', 'epicgames.com', 'unity.com', 'nvidia.com', 'amd.com', 'intel.com', 'dell.com', 'hp.com', 'lenovo.com', 'asus.com', 'paypal.com', 'visa.com', 'mastercard.com', 'bitcoin.org', 'ethereum.org', 'binance.com', 'bybit.com', 'coinbase.com', 'kraken.com', 'virustotal.com', 'kaspersky.ru', 'kaspersky.com', 'drweb.com', 'drweb.ru', 'eset.com', 'avast.com', 'malwarebytes.com', 'windows.com', 'office.com', 'adobe.com', 'autodesk.com', 'figma.com', 'notion.so', 'trello.com', 'slack.com', 'discord.com', 'telegram.org', 'whatsapp.com', 'zoom.us', 'skype.com', 'teamviewer.com', 'anydesk.com', 'chrome.google.com', 'chromewebstore.google.com', 'mozilla.org', 'addons.mozilla.org', 'npmjs.com', 'pypi.org', 'docker.com', 'cloudflare.com', 'aws.amazon.com', 'azure.microsoft.com', 'heroku.com', 'vercel.com', 'netlify.com', 'godaddy.com', 'reg.ru', 'timeweb.com', 'beget.com', 'hostinger.com', 'ruvds.com', 'selectel.ru', 'wikipedia.org', 'britannica.com', 'nature.com', 'sciencedirect.com', 'springer.com', 'elsevier.com', 'arxiv.org', 'ieee.org', 'acm.org', 'reddit.com', 'quora.com', 'medium.com', 'vc.ru', 'cnews.ru', '3dnews.ru', 'ixbt.com', 'overclockers.ru', 'dns-shop.ru', 'citilink.ru', 'mvideo.ru', 'eldorado.ru', 'leroymerlin.ru', 'castorama.ru', 'ikea.com', 'lamoda.ru', 'sportmaster.ru', 'decathlon.ru', 'aeroflot.ru', 'rzd.ru', 'tutu.ru', 'aviasales.ru', 'booking.com', 'airbnb.com', 'tripadvisor.com', 'hotels.com', 'expedia.com', 'uber.com', 'citymobil.ru', 'yandex.ru/taxi', 'delivery-club.ru', 'eda.yandex', 'kfc.ru', 'mcdonalds.ru', 'burgerking.ru', 'pizza-sushi.ru', 'dodopizza.ru'];

const SUS_TLD = ['.zip', '.mov', '.lol', '.xyz', '.top', '.click', '.link', '.gq', '.cf', '.ml', '.tk', '.ga', '.buzz', '.rest', '.icu', '.monster', '.sbs', '.cyou', '.quest', '.cam', '.uno', '.work', '.date', '.download', '.stream', '.review', '.science', '.country', '.pw'];

function hostVariants(host) {
  const parts = host.split('.');
  return { host, parts, sld: parts.length >= 2 ? parts.slice(-2).join('.') : host };
}

function urlHeuristics(u) {
  const f = [];
  const host = u.hostname.toLowerCase();
  const { sld } = hostVariants(host);
  const label = sld.split('.')[0] || '';

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) f.push({ id: 'ip-host', sev: 3, w: 18, label: 'Адрес вместо домена', detail: `Сайт открыт по IP ${host} — так прячутся от репутационных баз и блокируют жалобу на домен.` });
  if (SUS_TLD.some((t) => host.endsWith(t))) f.push({ id: 'sus-tld', sev: 2, w: 12, label: 'Подозрительная доменная зона', detail: `Зона ${SUS_TLD.find((t) => host.endsWith(t))} массово регистрируется бесплатно/дёшево для фишинга и малвари.` });
  if ((host.match(/-/g) || []).length >= 3) f.push({ id: 'many-hyphens', sev: 2, w: 10, label: 'Много дефисов в домене', detail: 'Домены вида bank-login-verify-secure.top — типичный фишинговый шаблон.' });
  if (label.length > 24) f.push({ id: 'long-label', sev: 1, w: 8, label: 'Аномально длинный домен', detail: 'Длинные домены-«простыни» используют, чтобы бренд жертвы оказался поддоменом: paypal.com.evil.example.' });
  if (host.startsWith('xn--')) f.push({ id: 'punycode', sev: 2, w: 12, label: 'Punycode (гомоглифы)', detail: 'Домен содержит символы юникод-подделки (xn--...). Может выглядеть как известный бренд.' });
  // бренд + лишнее: подделка под известный домен
  for (const brand of ['paypal', 'google', 'apple', 'microsoft', 'sberbank', 'gosuslugi', 'binance', 'bybit', 'wildberries', 'ozon', 'avito', 'tinkoff', 'alfabank', 'steam', 'discord', 'telegram', 'whatsapp', 'instagram', 'facebook', 'amazon', 'netflix', 'github']) {
    if (label.includes(brand) && sld !== brand + '.com' && sld !== brand + '.ru' && !host.endsWith('.' + brand + '.com') && !host.endsWith('.' + brand + '.ru')) {
      f.push({ id: 'brand-spoof', sev: 3, w: 20, label: `Имитация бренда «${brand}»`, detail: `В домене есть имя бренда «${brand}», но домен ему не принадлежит (${host}). Классический фишинг.` });
      break;
    }
  }
  // опечаточные домены
  for (const top of TOP_DOMAINS) {
    const tld = top.split('.').pop();
    const tsl = top.split('.')[0];
    if (sld === top) break;
    if (label !== tsl && Math.abs(label.length - tsl.length) <= 2 && lev(label, tsl, 2) <= 1 && label.length > 4 && host.endsWith('.' + tld)) {
      f.push({ id: 'typosquat', sev: 3, w: 18, label: 'Похоже на опечатку известного домена', detail: `Домен ${sld} отличается от ${top} на одну букву — тайпосквоттинг.` });
      break;
    }
  }
  const pathQ = (u.pathname + u.search);
  if (/\.(exe|msi|scr|apk|jar|vbs|scr|bat|cmd|ps1|hta)(\?|$)/i.test(pathQ)) f.push({ id: 'exe-link', sev: 3, w: 22, label: 'Ссылка ведёт на исполняемый файл', detail: 'Прямая ссылка на .exe/.msi/.apk — частый способ доставки троянов.' });
  if (/redirect|url=|next=|goto=|return=|continue=/i.test(u.search) && /https?:/.test(decodeURIComponent(u.search))) f.push({ id: 'open-redirect', sev: 2, w: 8, label: 'Параметр-редирект с внешним адресом', detail: 'Открытый редирект позволяет увести пользователя на вредоносный сайт через «легальный» домен.' });
  if (u.protocol === 'http:') f.push({ id: 'no-tls', sev: 2, w: 14, label: 'Нет шифрования (HTTP)', detail: 'Трафик читается и подменяется по пути; пароли и карты передаются открыто.' });
  if (/@/.test(u.pathname) || u.username) f.push({ id: 'at-trick', sev: 3, w: 16, label: 'Трюк с «@» в адресе', detail: 'Часть до «@» — имя пользователя, настоящий хост дальше. Приём для обмана внимания.' });
  if (u.port && !['80', '443', ''].includes(u.port)) f.push({ id: 'odd-port', sev: 1, w: 6, label: 'Нестандартный порт', detail: `Порт ${u.port}: легальные сайты редко уходят с 80/443.` });
  if ((u.pathname.match(/\.(php|aspx?|jsp)\?/i) || []).length && /[?&](id|file|path|doc|url|page)=/i.test(u.search)) f.push({ id: 'lfi-ish', sev: 1, w: 5, label: 'Признаки уязвимого скрипта', detail: 'Параметры file/path/page — потенциальная точка LFI/RFI на сервере.' });
  return f;
}

function fetchPage(urlStr, maxRedirects = 6) {
  return new Promise((resolve) => {
    const chain = [];
    let current = urlStr;
    let tlsError = null;
    const step = (n) => {
      if (n > maxRedirects) return resolve({ ok: false, error: 'Слишком много редиректов', chain, tlsError });
      let u;
      try { u = new URL(current); } catch (e) { return resolve({ ok: false, error: 'Некорректный URL', chain, tlsError }); }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return resolve({ ok: false, error: 'Поддерживаются только http/https', chain, tlsError });
      const mod = u.protocol === 'http:' ? http : https;
      const req = mod.request({
        method: 'GET', hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        headers: {
          'User-Agent': UA,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'ru-RU,ru;q=0.9,en;q=0.8',
          'Accept-Encoding': 'gzip, deflate',
        },
        timeout: 15000,
      }, (res) => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          chain.push({ from: current, to: res.headers.location, code: res.statusCode });
          try { current = new URL(res.headers.location, current).toString(); } catch (_) { return resolve({ ok: false, error: 'Битый редирект', chain, tlsError }); }
          res.resume();
          return step(n + 1);
        }
        const chunks = [];
        let size = 0;
        let stream = res;
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        if (enc === 'gzip') stream = res.pipe(zlib.createGunzip());
        else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
        else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
        stream.on('data', (d) => { if (size < 6 * 1024 * 1024) { chunks.push(d); size += d.length; } });
        stream.on('end', () => resolve({ ok: res.statusCode < 400, status: res.statusCode, body: Buffer.concat(chunks).toString('utf8'), headers: res.headers, chain, finalUrl: current, tlsError }));
        stream.on('error', (e) => resolve({ ok: false, error: String(e && e.message), chain, tlsError, finalUrl: current }));
      });
      req.on('timeout', () => { try { req.destroy(new Error('timeout')); } catch (_) {} });
      req.on('error', (e) => {
        if (!tlsError && /certificate|TLS|SSL|handshake/i.test(String(e && e.message))) tlsError = String(e.message);
        resolve({ ok: false, error: String(e && e.message), chain, tlsError, finalUrl: current });
      });
      req.end();
    };
    step(0);
  });
}

function analyzeHtml(html, finalUrl) {
  const f = [];
  const low = html.toLowerCase();
  const trackers = [];
  for (const [sig, name] of TRACKERS) {
    if (low.includes(sig) && !trackers.includes(name)) trackers.push(name);
  }
  const scripts = [...html.matchAll(/<script[^>]*src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const inlineScripts = [...html.matchAll(/<script(?![^>]*src)[^>]*>([\s\S]{0,20000}?)<\/script>/gi)].map((m) => m[1]);
  const iframes = [...html.matchAll(/<iframe[^>]*src=["']([^"']*)["']([^>]*)>/gi)].map((m) => ({ src: m[1], attrs: m[2] }));
  const forms = [...html.matchAll(/<form[^>]*action=["']([^"']*)["'][^>]*>/gi)].map((m) => m[1]);
  const metas = [...html.matchAll(/<meta[^>]*http-equiv=["']refresh["'][^>]*content=["']([^"']*)["']/gi)].map((m) => m[1]);

  const externalHosts = new Set();
  let fu;
  try { fu = new URL(finalUrl); } catch (_) { fu = null; }
  const noteHost = (s) => {
    try {
      const h = new URL(s, finalUrl).hostname;
      if (h && fu && h !== fu.hostname) externalHosts.add(h);
    } catch (_) {}
  };
  scripts.forEach(noteHost); iframes.forEach((i) => noteHost(i.src)); forms.forEach(noteHost);

  // майнер-код
  if (/(coinhive|cryptoloot|coin-have|webxmr|miner\.start\(|stratum\+tcp)/i.test(html)) {
    f.push({ id: 'page-miner', sev: 4, w: 30, label: 'Браузерный майнер на странице', detail: 'В коде страницы найден скрипт скрытого майнинга (CoinHive-класс). Вкладка браузера будет грузить процессор.' });
  }
  // обфускация
  const obf = inlineScripts.filter((s) => /\\x[0-9a-f]{2}/i.test(s) && s.length > 2000)
    .concat(inlineScripts.filter((s) => /(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent)?\s*\(?["']/.test(s) && s.length > 500));
  if (obf.length) f.push({ id: 'obfuscation', sev: 3, w: 16, label: 'Обфусцированный JavaScript', detail: 'Inline-скрипты с eval/atob и длинными hex-строками — так прячут полезную нагрузку стилеров и редиректов.' });
  // скрытые iframe
  const hidden = iframes.filter((i) => /display\s*:\s*none|width\s*=\s*["']?[01]["']?|height\s*=\s*["']?[01]["']?|style\s*=\s*["'][^"']*visibility\s*:\s*hidden/i.test(i.attrs));
  if (hidden.length) f.push({ id: 'hidden-iframe', sev: 3, w: 14, label: 'Скрытые iframe', detail: 'Невидимые фреймы загружают сторонние страницы: драйв-бай загрузка, клик-фрод, счётчики слежки.' });
  // авто-редиректы
  const metaRedir = metas.filter((m) => /url\s*=\s*https?:/i.test(m));
  if (metaRedir.length || /(?:window\.)?location\.(?:href|replace)\s*=\s*["']https?:/i.test(low) && /setTimeout|onload|DOMContentLoaded/.test(low)) {
    f.push({ id: 'auto-redirect', sev: 2, w: 10, label: 'Автоматический редирект', detail: 'Страница сама уводит браузер на другой адрес (meta refresh / location).*' });
  }
  // формы наружу по http
  for (const act of forms) {
    try {
      const a = new URL(act, finalUrl);
      if (a.protocol === 'http:' && fu && a.hostname !== fu.hostname) {
        f.push({ id: 'form-plain', sev: 3, w: 16, label: 'Форма отправляется открытым текстом на сторонний сайт', detail: `action=${act} — введённые данные уйдут без шифрования на ${a.hostname}.` });
        break;
      }
    } catch (_) {}
  }
  // сборщики отпечатка
  if (/(canvas\.getContext|navigator\.webdriver|AudioContext\(|rtcpeerconnection)/i.test(html) && /fingerprint|fp2|clientinfo/i.test(html)) {
    f.push({ id: 'fingerprint', sev: 2, w: 8, label: 'Скрипт снятия отпечатка браузера', detail: 'Canvas/WebGL/Audio-фингерпринтинг для отслеживания между сайтами без cookies.' });
  }
  // кейлоггер-подобные хуки
  if (/addEventListener\s*\(\s*["'](keydown|keypress|input)["'][\s\S]{0,400}(fetch|XMLHttpRequest|sendBeacon)/i.test(html)) {
    f.push({ id: 'keylog-js', sev: 3, w: 18, label: 'Перехват ввода с отправкой наружу', detail: 'Скрипт слушает нажатия клавиш и отправляет их сетевым запросом — признак форм-стилера.' });
  }
  // внешние хосты
  const thirdParty = [...externalHosts];
  if (thirdParty.length > 12) f.push({ id: 'many-3p', sev: 1, w: 6, label: `Много сторонних доменов (${thirdParty.length})`, detail: 'Страница тянет ресурсы с десятков чужих доменов — широкая поверхность слежки.' });

  return { findings: f, trackers, scripts, thirdParty, iframes: iframes.length, forms: forms.length };
}

async function rdapDomain(host) {
  try {
    const sld = host.split('.').slice(-2).join('.');
    const r = await new Promise((resolve) => {
      const req = https.request({ method: 'GET', hostname: 'rdap.org', path: '/domain/' + encodeURIComponent(sld), headers: { 'User-Agent': UA, Accept: 'application/rdap+json' }, timeout: 8000 }, (res) => {
        let b = '';
        res.on('data', (d) => { if (b.length < 512 * 1024) b += d; });
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      });
      req.on('error', (e) => resolve({ status: 0, body: '' }));
      req.on('timeout', () => { try { req.destroy(); } catch (_) {} });
      req.end();
    });
    if (r.status !== 200) return null;
    const j = JSON.parse(r.body);
    const ev = (j.events || []).find((e) => e.eventAction === 'registration');
    return ev ? { registered: String(ev.eventDate || '').slice(0, 10), registrar: (j.entities || []).map((e) => (e.vcardArray && e.vcardArray[1] || []).map((v) => v[3]).join(' ')).filter(Boolean)[0] || null } : null;
  } catch (_) { return null; }
}

async function analyzeUrl(urlStr, settings, onEvent = () => {}) {
  const started = Date.now();
  let u;
  try { u = new URL(urlStr.includes('://') ? urlStr : 'https://' + urlStr); }
  catch (_) { return { ok: false, error: 'Не удалось разобрать адрес' }; }
  const res = { ok: true, url: u.toString(), host: u.hostname, steps: [], findings: [], score: 0, trackers: [], thirdParty: [], cloud: {}, ms: 0 };

  onEvent({ step: 'url', label: 'Эвристики адреса' });
  res.findings.push(...urlHeuristics(u));

  onEvent({ step: 'rdap', label: 'Возраст домена (RDAP)' });
  const rdap = await rdapDomain(u.hostname);
  res.rdap = rdap;
  if (rdap && rdap.registered) {
    const days = (Date.now() - Date.parse(rdap.registered)) / 86400000;
    if (days < 45) res.findings.push({ id: 'young-domain', sev: 3, w: 16, label: 'Домен зарегистрирован недавно', detail: `Регистрация ${rdap.registered} (${Math.max(1, Math.round(days))} дн. назад). Фишинговые домены живут считанные дни.` });
    else if (days < 120) res.findings.push({ id: 'youngish-domain', sev: 1, w: 6, label: 'Молодой домен', detail: `Регистрация ${rdap.registered}.` });
  }

  onEvent({ step: 'fetch', label: 'Загрузка страницы' });
  const page = await fetchPage(u.toString());
  res.redirects = page.chain || [];
  res.tlsError = page.tlsError || null;
  res.finalUrl = page.finalUrl || u.toString();
  res.status = page.status || null;
  if (res.redirects.length >= 3) res.findings.push({ id: 'redirect-chain', sev: 2, w: 10, label: `Длинная цепочка редиректов (${res.redirects.length})`, detail: res.redirects.map((r) => r.to).join(' → ').slice(0, 400) });
  if (page.tlsError) res.findings.push({ id: 'tls-error', sev: 3, w: 18, label: 'Проблема TLS-сертификата', detail: page.tlsError });
  if (page.ok && page.body) {
    onEvent({ step: 'html', label: 'Разбор HTML' });
    const ha = analyzeHtml(page.body, page.finalUrl || u.toString());
    res.findings.push(...ha.findings);
    res.trackers = ha.trackers;
    res.thirdParty = ha.thirdParty.slice(0, 40);
    res.pageStats = { scripts: ha.scripts.length, iframes: ha.iframes, forms: ha.forms, bytes: page.body.length };
    if (ha.trackers.length >= 4) res.findings.push({ id: 'trackers', sev: 2, w: 10, label: `Активная слежка: ${ha.trackers.length} трекеров`, detail: ha.trackers.join(', ') });
    else if (ha.trackers.length) res.findings.push({ id: 'trackers-few', sev: 1, w: 3, label: `Трекеры: ${ha.trackers.length}`, detail: ha.trackers.join(', ') });
  } else if (!page.ok) {
    res.fetchError = page.error || 'Страница недоступна';
  }

  onEvent({ step: 'cloud', label: 'Репутационные базы' });
  const cloud = settings.cloud || {};
  if (cloud.urlhaus !== false) {
    const [hu, hh] = await Promise.all([urlhausUrl(u.toString()), urlhausHost(u.hostname)]);
    res.cloud.urlhausUrl = hu; res.cloud.urlhausHost = hh;
    if (hu.found) res.findings.push({ id: 'urlhaus-url', sev: 4, w: 35, label: 'URL в базе URLhaus (abuse.ch)', detail: `Статус: ${hu.urlStatus}, впервые замечен: ${hu.firstSeen || 'н/д'}. База активных вредоносных ссылок.` });
    if (hh.found) res.findings.push({ id: 'urlhaus-host', sev: 4, w: 30, label: 'Домен раздавал вредоносные файлы', detail: `URLhaus: ${hh.urlCount || 0} вредоносных URL с этого хоста, последний: ${hh.lastSeen || 'н/д'}.` });
  }
  if (cloud.virustotal !== 'off' && settings.vtKey) {
    const vt = await vtUrl(u.toString(), settings.vtKey);
    res.cloud.virustotal = vt;
    if (vt.found && (vt.malicious > 0 || vt.suspicious > 0)) {
      res.findings.push({ id: 'vt-url', sev: 4, w: 32, label: `VirusTotal: ${vt.malicious} детектов`, detail: `Пометок: malicious ${vt.malicious}, suspicious ${vt.suspicious} из ${vt.total}.` });
    }
  }

  res.score = Math.min(100, res.findings.reduce((s, x) => s + x.w, 0));
  res.verdict = res.score >= 60 ? 'danger' : res.score >= 30 ? 'suspicious' : res.score >= 10 ? 'caution' : 'clean';
  res.ms = Date.now() - started;
  return res;
}

module.exports = { analyzeUrl, fetchPage, analyzeHtml, urlHeuristics, TRACKERS };
