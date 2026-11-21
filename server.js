'use strict';
/* Slimi Bookstore platform: zero-dependency Node server (node:sqlite). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(path.join(DATA_DIR, 'backups'), { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'slimi.db'));
db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, perms TEXT, salt TEXT NOT NULL, hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS media(id TEXT PRIMARY KEY, mime TEXT NOT NULL, data BLOB NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(id TEXT PRIMARY KEY, cat TEXT NOT NULL, type TEXT NOT NULL, name_ar TEXT NOT NULL, name_fr TEXT NOT NULL, price INTEGER NOT NULL DEFAULT 0, old INTEGER NOT NULL DEFAULT 0, avail INTEGER NOT NULL DEFAULT 1, img TEXT NOT NULL DEFAULT '', sort INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, number TEXT UNIQUE NOT NULL, created INTEGER NOT NULL, status TEXT NOT NULL, pay_status TEXT NOT NULL, pay_method TEXT NOT NULL, delivery TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL, wilaya TEXT, addr TEXT, note TEXT, staff_note TEXT, items TEXT NOT NULL, subtotal INTEGER NOT NULL, fee INTEGER NOT NULL, total INTEGER NOT NULL, onreq INTEGER NOT NULL DEFAULT 0, has_phys INTEGER NOT NULL DEFAULT 0, has_dig INTEGER NOT NULL DEFAULT 0, lang TEXT, proof_mime TEXT, proof BLOB, proof_ts INTEGER);
CREATE INDEX IF NOT EXISTS orders_created ON orders(created);
CREATE INDEX IF NOT EXISTS sessions_exp ON sessions(exp);
CREATE TABLE IF NOT EXISTS order_events(id INTEGER PRIMARY KEY, order_id INTEGER NOT NULL, ts INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT, actor TEXT);
CREATE TABLE IF NOT EXISTS subs(id INTEGER PRIMARY KEY, customer TEXT NOT NULL, phone TEXT, service TEXT NOT NULL, price INTEGER NOT NULL DEFAULT 0, start TEXT NOT NULL, end TEXT NOT NULL, note TEXT, order_number TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT);
`);

function addCol(t, c, d) { if (!db.prepare('PRAGMA table_info(' + t + ')').all().some(r => r.name === c)) db.exec('ALTER TABLE ' + t + ' ADD COLUMN ' + c + ' ' + d); }
addCol('orders', 'delivery_info', "TEXT DEFAULT ''"); addCol('orders', 'account_ref', "TEXT DEFAULT ''"); addCol('orders', 'pay_ref', "TEXT DEFAULT ''");
addCol('products', 'needs_ref', 'INTEGER NOT NULL DEFAULT 0'); addCol('products', 'pays', "TEXT DEFAULT ''");
addCol('products', 'desc_ar', "TEXT DEFAULT ''"); addCol('products', 'desc_fr', "TEXT DEFAULT ''");
addCol('orders', 'customer_id', 'INTEGER');
db.exec('CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY, phone TEXT UNIQUE NOT NULL, name TEXT NOT NULL, email TEXT DEFAULT "", salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS csessions(token TEXT PRIMARY KEY, cid INTEGER NOT NULL, exp INTEGER NOT NULL);');
db.exec('CREATE INDEX IF NOT EXISTS orders_customer_id ON orders(customer_id); CREATE INDEX IF NOT EXISTS csessions_exp ON csessions(exp);');
const GATEWAY_KEY = process.env.CHARGILY_SECRET_KEY || '';
const GATEWAY_BASE = process.env.GATEWAY_BASE_URL || ((process.env.CHARGILY_MODE === 'live') ? 'https://pay.chargily.net/api/v2' : 'https://pay.chargily.net/test/api/v2');
/* ---------- helpers ---------- */
const now = () => Date.now();
const ALL_PERMS = ['orders', 'products', 'subs', 'reports', 'settings', 'audit', 'staff'];
const ROLE_PERMS = { owner: ALL_PERMS, manager: ['orders', 'products', 'subs', 'reports'], staff: ['orders', 'products', 'subs', 'reports'] };
const STATUSES = ['new', 'confirmed', 'preparing', 'shipped', 'delivered', 'cancelled'];
const PAYS = ['unpaid', 'proof_sent', 'paid', 'refunded'];
const CATS = ['school', 'office', 'apps', 'games', 'services'];
const rows = (sql, ...a) => db.prepare(sql).all(...a).map(r => ({ ...r }));
const row = (sql, ...a) => { const r = db.prepare(sql).get(...a); return r ? { ...r } : null; };
const run = (sql, ...a) => db.prepare(sql).run(...a);
const getSetting = (k, d) => { const r = row('SELECT v FROM settings WHERE k=?', k); if (!r) return d; try { return JSON.parse(r.v); } catch { return d; } };
const TG_BASE = process.env.TELEGRAM_API_BASE || 'https://api.telegram.org';
const PAYN = { cod: 'عند الاستلام', transfer: 'تحويل CCP/بريدي موب', online: 'دفع إلكتروني' };
function tgCfg() {
  const g = k => { const r = row('SELECT v FROM settings WHERE k=?', k); try { return r ? JSON.parse(r.v) : ''; } catch { return ''; } };
  return { token: process.env.TELEGRAM_BOT_TOKEN || g('tgToken'), chat: process.env.TELEGRAM_CHAT_ID || g('tgChat') };
}
async function notify(text) {
  const c = tgCfg(); if (!c.token || !c.chat) return false;
  try {
    const ctl = new AbortController(), tm = setTimeout(() => ctl.abort(), 8000);
    const r = await fetch(TG_BASE + '/bot' + c.token + '/sendMessage', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chat_id: c.chat, text, disable_web_page_preview: true }), signal: ctl.signal });
    clearTimeout(tm); if (!r.ok) console.error('[notify] http', r.status); return r.ok;
  } catch (e) { console.error('[notify]', e.message); return false; }
}
const setSetting = (k, v) => run('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v', k, JSON.stringify(v));
const audit = (actor, action, detail) => run('INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)', now(), actor, action, detail ? String(detail).slice(0, 400) : '');
const hashPw = (pw, salt) => crypto.scryptSync(String(pw), salt, 64).toString('hex');
function userPerms(u) {
  if (!u) return [];
  if (u.role === 'owner') return ALL_PERMS;
  if (u.perms) { try { const p = JSON.parse(u.perms); if (Array.isArray(p)) return p.filter(x => ALL_PERMS.includes(x) && x !== 'staff'); } catch { } }
  return ROLE_PERMS[u.role] || [];
}
const publicUser = u => ({ id: u.id, username: u.username, name: u.name, role: u.role, perms: userPerms(u), active: !!u.active });
const ymd = ts => { const d = new Date(ts + 3600e3); return d.toISOString().slice(0, 10); }; /* Algeria is UTC+1 */

/* ---------- seed ---------- */
const SEED = []; // no sample products: the owner adds the real catalog from the dashboard
let firstRunPassword = null;
function seed() {
  if (!row('SELECT 1 x FROM products LIMIT 1') && !getSetting('seeded', false)) {
    SEED.forEach((p, i) => run('INSERT INTO products(id,cat,type,name_ar,name_fr,price,old,avail,img,sort) VALUES(?,?,?,?,?,?,?,1,\'\',?)', p[0], p[1], p[2], p[3], p[4], p[5], p[6], i));
    const defaults = { whatsapp: '213772827262', phone: '0772 82 72 62', email: 'toyschop@gmail.com', hours: '', ccp: '', feeLocal: 300, feeOther: 600, freeFrom: 5000, addrAr: 'شارع الاستقلال، عطبة (42008)، تيبازة', addrFr: "Rue de l'Indépendance, Attatba (42008), Tipaza", logo: '', facade: '', facade2: '', in1: '', pricesConfirmed: false };
    Object.keys(defaults).forEach(k => setSetting(k, defaults[k]));
    const f = path.join(__dirname, 'seed', 'facade.jpg');
    if (fs.existsSync(f)) { const id = crypto.randomBytes(9).toString('hex'); run('INSERT INTO media(id,mime,data,created) VALUES(?,?,?,?)', id, 'image/jpeg', fs.readFileSync(f), now()); setSetting('facade', '/media/' + id); }
    const lg = path.join(__dirname, 'seed', 'logo.png');
    if (fs.existsSync(lg)) { const id2 = crypto.randomBytes(9).toString('hex'); run('INSERT INTO media(id,mime,data,created) VALUES(?,?,?,?)', id2, 'image/png', fs.readFileSync(lg), now()); setSetting('logo', '/media/' + id2); }
    run("UPDATE products SET needs_ref=1 WHERE id='p16'");
    setSetting('seeded', true);
  }
  if (!row('SELECT 1 x FROM users LIMIT 1')) {
    const pw = process.env.OWNER_PASSWORD || crypto.randomBytes(6).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    run('INSERT INTO users(username,name,role,salt,hash,active,created) VALUES(?,?,?,?,?,1,?)', 'owner', 'صاحب المكتبة', 'owner', salt, hashPw(pw, salt), now());
    firstRunPassword = pw;
    console.log('[setup] owner account created. username=owner password=' + pw);
  }
}
seed();

/* ---------- http plumbing ---------- */
const PUB = path.join(__dirname, 'public');
function send(res, code, body, headers) {
  const h = Object.assign({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()' }, headers || {});
  res.writeHead(code, h); res.end(body);
}
const json = (res, code, obj) => send(res, code, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
const fail = (res, code, msg) => json(res, code, { error: msg });
function readBody(req, limit) {
  return new Promise((ok, no) => {
    let n = 0, settled = false; const c = [];
    req.on('data', d => {
      if (settled) return;
      n += d.length;
      if (n > limit) { settled = true; c.length = 0; no(Object.assign(new Error('too_large'), { code: 413 })); req.resume(); }
      else c.push(d);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      try { ok(c.length ? JSON.parse(Buffer.concat(c).toString('utf8')) : {}); }
      catch { no(Object.assign(new Error('bad_json'), { code: 400 })); }
    });
    req.on('error', e => { if (!settled) { settled = true; no(e); } });
  });
}
function readRaw(req, limit) {
  return new Promise((ok, no) => {
    let n = 0, settled = false; const c = [];
    req.on('data', d => {
      if (settled) return;
      n += d.length;
      if (n > limit) { settled = true; c.length = 0; no(Object.assign(new Error('too_large'), { code: 413 })); req.resume(); }
      else c.push(d);
    });
    req.on('end', () => { if (!settled) { settled = true; ok(Buffer.concat(c)); } });
    req.on('error', e => { if (!settled) { settled = true; no(e); } });
  });
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]).map(a => [a[0], decodeURIComponent(a.slice(1).join('='))]));
const isHttps = req => req.headers['x-forwarded-proto'] === 'https' || !!req.socket.encrypted;
function sessionUser(req) {
  const t = cookies(req).sid; if (!t) return null;
  const s = row('SELECT * FROM sessions WHERE token=?', t);
  if (!s || s.exp < now()) return null;
  const u = row('SELECT * FROM users WHERE id=? AND active=1', s.user_id);
  return u;
}
const normPhone = x => { let d = String(x || '').replace(/\D/g, ''); if (d.startsWith('213')) d = '0' + d.slice(3); if (d.length === 9) d = '0' + d; return d; };
function custUser(req) {
  const t = cookies(req).cid; if (!t) return null;
  const s = row('SELECT * FROM csessions WHERE token=?', t);
  if (!s || s.exp < now()) return null;
  return row('SELECT * FROM customers WHERE id=?', s.cid);
}
const publicCust = c => ({ id: c.id, name: c.name, phone: c.phone, email: c.email || '' });
function custLogin(req, res, c) {
  const tok = crypto.randomBytes(32).toString('base64url');
  run('INSERT INTO csessions(token,cid,exp) VALUES(?,?,?)', tok, c.id, now() + 30 * 86400e3);
  res.setHeader('Set-Cookie', 'cid=' + tok + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000' + (isHttps(req) ? '; Secure' : ''));
}
const attempts = new Map();
function pruneAttempts(t) {
  if (attempts.size <= 10000) return;
  for (const [k, a] of attempts) if (!a.length || t - a[a.length - 1] > 3600e3) attempts.delete(k);
  while (attempts.size > 10000) attempts.delete(attempts.keys().next().value);
}
function limited(key, max, win) {
  const t = now(), a = (attempts.get(key) || []).filter(x => t - x < win);
  attempts.set(key, a); pruneAttempts(t); return a.length >= max;
}
const hit = key => {
  const t = now(), a = (attempts.get(key) || []).filter(x => t - x < 3600e3);
  a.push(t); attempts.set(key, a); pruneAttempts(t);
};
const CSP = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
function page(res, file) {
  const f = path.join(PUB, file);
  if (!fs.existsSync(f)) return fail(res, 404, 'not_found');
  send(res, 200, fs.readFileSync(f), { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': CSP, 'Cache-Control': 'no-cache' });
}
const MIME_OK = ['image/jpeg', 'image/png', 'image/webp'];
function decodeFile(b, allowPdf, max) {
  if (!b || typeof b.data !== 'string') return null;
  const okm = allowPdf ? MIME_OK.concat(['application/pdf']) : MIME_OK;
  if (!okm.includes(b.mime)) return null;
  const buf = Buffer.from(b.data, 'base64');
  if (!buf.length || buf.length > max) return null;
  const sig = buf.subarray(0, 4).toString('hex');
  const good = (b.mime === 'image/jpeg' && sig.startsWith('ffd8ff')) || (b.mime === 'image/png' && sig === '89504e47') || (b.mime === 'image/webp' && buf.subarray(0, 4).toString() === 'RIFF' && buf.subarray(8, 12).toString() === 'WEBP') || (b.mime === 'application/pdf' && buf.subarray(0, 4).toString() === '%PDF');
  return good ? buf : null;
}

/* ---------- business logic ---------- */
const phoneOk = p => /^0[5-7]\d{8}$/.test(String(p || '').replace(/[\s.\-]/g, ''));
const cleanPhone = p => String(p || '').replace(/[\s.\-]/g, '');
const str = (v, n) => String(v == null ? '' : v).trim().slice(0, n);
const intv = (v, max) => Math.min(max || 1e9, Math.max(0, Math.round(Number(v) || 0)));
function eventAdd(orderId, kind, value, actor) { run('INSERT INTO order_events(order_id,ts,kind,value,actor) VALUES(?,?,?,?,?)', orderId, now(), kind, value || '', actor || 'customer'); }
function nextNumber() {
  const d = ymd(now()).replace(/-/g, '').slice(2);
  const start = new Date(); start.setUTCHours(0, 0, 0, 0);
  const n = row('SELECT COUNT(*) c FROM orders WHERE number LIKE ?', 'SLM-' + d + '-%').c + 1;
  return 'SLM-' + d + '-' + String(n).padStart(3, '0');
}
function createOrder(b, cu) {
  const items = Array.isArray(b.items) ? b.items.slice(0, 40) : [];
  const lines = []; let sub = 0, phys = 0, onreq = 0, hasP = 0, hasD = 0, needRef = 0, pm = null;
  for (const it of items) {
    const p = row('SELECT * FROM products WHERE id=? AND avail=1', str(it && it.id, 40)); const q = intv(it && it.q, 50);
    if (!p || q < 1) return { error: 'bad_items' };
    lines.push({ id: p.id, name_ar: p.name_ar, name_fr: p.name_fr, price: p.price, q, type: p.type, cat: p.cat });
    if (p.needs_ref) needRef = 1;
    if (p.pays) { const a = String(p.pays).split(',').filter(Boolean); pm = pm ? pm.filter(x => a.includes(x)) : a; }
    if (p.price > 0) { sub += p.price * q; if (p.type === 'physical') phys += p.price * q; } else onreq = 1;
    if (p.type === 'physical') hasP = 1; else hasD = 1;
  }
  if (!lines.length) return { error: 'empty' };
  const name = str(b.name, 80), phone = cleanPhone(b.phone);
  if (name.length < 3) return { error: 'name' };
  if (!phoneOk(phone)) return { error: 'phone' };
  let delivery = hasP ? (b.delivery === 'pickup' ? 'pickup' : 'home') : 'none';
  let wilaya = '', addr = '';
  if (delivery === 'home') { wilaya = str(b.wilaya, 2); addr = str(b.addr, 200); if (!/^\d{2}$/.test(wilaya) || +wilaya < 1 || +wilaya > 58) return { error: 'wilaya' }; if (addr.length < 5) return { error: 'addr' }; }
  const ref = str(b.accountRef, 40);
  if (needRef && ref.length < 4) return { error: 'ref' };
  const allowed = ['transfer'].concat(hasD ? [] : ['cod']);
  const canOnline = !!GATEWAY_KEY && !onreq;
  if (canOnline) allowed.push('online');
  const allowedF = pm ? allowed.filter(x => pm.includes(x)) : allowed;
  if (!allowedF.length) return { error: 'pay_mix' };
  const pay = allowedF.includes(b.pay) ? b.pay : allowedF[0];
  let fee = 0;
  if (delivery === 'home') { const fl = getSetting('freeFrom', 0); if (!(fl > 0 && phys >= fl)) fee = wilaya === '42' ? getSetting('feeLocal', 0) : getSetting('feeOther', 0); }
  const total = sub + fee;
  if (pay === 'online' && total < 50) return { error: 'min_online' };
  const number = nextNumber();
  const r = run('INSERT INTO orders(number,created,status,pay_status,pay_method,delivery,name,phone,wilaya,addr,note,items,subtotal,fee,total,onreq,has_phys,has_dig,lang,account_ref,customer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    number, now(), 'new', 'unpaid', pay, delivery, name, phone, wilaya, addr, str(b.note, 300), JSON.stringify(lines), sub, fee, total, onreq, hasP, hasD, b.lang === 'fr' ? 'fr' : 'ar', ref, cu ? cu.id : null);
  eventAdd(Number(r.lastInsertRowid), 'status', 'new', 'customer');
  notify('🛒 طلب جديد ' + number + '\n' + name + ' · ' + phone + '\nالمجموع: ' + total + ' دج' + (onreq ? ' + (سعر عند الطلب)' : '') + '\nالدفع: ' + (PAYN[pay] || pay) + '\n' + lines.map(l => l.name_ar + ' ×' + l.q).join('، ') + (ref ? '\nرقم الخط/العقد: ' + ref : ''));
  return { number, total, subtotal: sub, fee, onreq: !!onreq, pay_method: pay, delivery, status: 'new', lines };
}

function reports(days) {
  const t = now(), since = t - days * 86400e3;
  const os = rows('SELECT created,status,pay_status,total,items,has_phys,has_dig FROM orders WHERE created>=?', since);
  const today = ymd(t), month = today.slice(0, 7);
  const live = o => o.status !== 'cancelled';
  const R = { ordersToday: 0, revenueToday: 0, ordersMonth: 0, revenueMonth: 0, paidMonth: 0, byStatus: {}, daily: [], top: [], byType: { physical: 0, digital: 0 }, newCount: 0 };
  const dayMap = {};
  for (let i = days - 1; i >= 0; i--) { const k = ymd(t - i * 86400e3); dayMap[k] = { day: k, count: 0, revenue: 0 }; }
  const prod = {};
  for (const o of os) {
    const d = ymd(o.created); R.byStatus[o.status] = (R.byStatus[o.status] || 0) + 1;
    if (!live(o)) continue;
    if (dayMap[d]) { dayMap[d].count++; dayMap[d].revenue += o.total; }
    if (d === today) { R.ordersToday++; R.revenueToday += o.total; }
    if (d.slice(0, 7) === month) { R.ordersMonth++; R.revenueMonth += o.total; if (o.pay_status === 'paid') R.paidMonth += o.total; }
    try { JSON.parse(o.items).forEach(l => { const k = l.name_ar; prod[k] = prod[k] || { name: k, q: 0, revenue: 0 }; prod[k].q += l.q; prod[k].revenue += l.price * l.q; R.byType[l.type] = (R.byType[l.type] || 0) + l.price * l.q; }); } catch { }
  }
  R.daily = Object.values(dayMap);
  R.top = Object.values(prod).sort((a, b) => b.q - a.q).slice(0, 6);
  R.newCount = row("SELECT COUNT(*) c FROM orders WHERE status='new'").c;
  const td = today, in7 = ymd(t + 7 * 86400e3);
  R.subs = { active: row('SELECT COUNT(*) c FROM subs WHERE end>=?', td).c, expiring: row('SELECT COUNT(*) c FROM subs WHERE end>=? AND end<=?', td, in7).c, expired: row('SELECT COUNT(*) c FROM subs WHERE end<?', td).c, monthRevenue: row('SELECT COALESCE(SUM(price),0) s FROM subs WHERE start>=?', month + '-01').s };
  return R;
}

/* ---------- routes ---------- */
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'), p = url.pathname, m = req.method;
  if (m === 'GET' && p === '/logo.webp') return send(res, 200, fs.readFileSync(path.join(PUB, 'logo.webp')), { 'Content-Type': 'image/webp', 'Cache-Control': 'public, max-age=86400' });
  if (m === 'GET' && /^\/brand\/(logo|mark)\.png$/.test(p)) return send(res, 200, fs.readFileSync(path.join(PUB, p)), { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' });
  if (m === 'GET' && (p === '/' || p === '/index.html')) return page(res, 'store.html');
  if (m === 'GET' && (p === '/admin' || p === '/admin/')) return page(res, 'admin.html');
  if (m === 'GET' && p === '/health') return json(res, 200, { ok: true });
  if (m === 'GET' && p === '/favicon.ico') return send(res, 204, '');
  let mm;
  if (m === 'GET' && (mm = p.match(/^\/media\/([a-f0-9]{18})$/))) {
    const r = row('SELECT mime,data FROM media WHERE id=?', mm[1]); if (!r) return fail(res, 404, 'not_found');
    const buf = Buffer.from(r.data), hd = { 'Content-Type': r.mime, 'Cache-Control': 'public, max-age=31536000, immutable', 'Content-Security-Policy': 'sandbox', 'Accept-Ranges': 'bytes' };
    const rg = req.headers.range && r.mime.startsWith('video/') ? /^bytes=(\d*)-(\d*)$/.exec(req.headers.range) : null;
    if (rg && (rg[1] || rg[2])) {
      let a, z; if (rg[1] === '') { a = Math.max(0, buf.length - +rg[2]); z = buf.length - 1; } else { a = +rg[1]; z = rg[2] === '' ? buf.length - 1 : Math.min(+rg[2], buf.length - 1); }
      if (a > z || a >= buf.length) return send(res, 416, '', { 'Content-Range': 'bytes */' + buf.length });
      return send(res, 206, buf.subarray(a, z + 1), Object.assign(hd, { 'Content-Range': 'bytes ' + a + '-' + z + '/' + buf.length, 'Content-Length': z - a + 1 }));
    }
    return send(res, 200, buf, hd);
  }
  if (!p.startsWith('/api/')) return fail(res, 404, 'not_found');
  if (m === 'POST' && p === '/api/webhook/chargily') {
    if (!GATEWAY_KEY) return fail(res, 404, 'no_gateway');
    let raw; try { raw = await readRaw(req, 50000); } catch (e) { return fail(res, e && e.code === 413 ? 413 : 400, 'bad_webhook_body'); }
    const sig = String(req.headers['signature'] || ''), calc = crypto.createHmac('sha256', GATEWAY_KEY).update(raw).digest('hex');
    if (sig.length !== calc.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(calc))) { audit('gateway', 'webhook_rejected', 'bad signature'); return fail(res, 403, 'bad_signature'); }
    let ev; try { ev = JSON.parse(raw.toString('utf8')); } catch { return fail(res, 400, 'bad_json'); }
    const d = ev && ev.data || {}, num = d.metadata && d.metadata.order_number, o = num ? row('SELECT * FROM orders WHERE number=?', String(num)) : null;
    if (o && ev.type === 'checkout.paid' && o.pay_method === 'online' && o.pay_status !== 'paid' && Number(d.amount) >= o.total) {
      run("UPDATE orders SET pay_status='paid' WHERE id=?", o.id); eventAdd(o.id, 'pay', 'paid', 'gateway'); audit('gateway', 'payment_confirmed', o.number + ' ' + o.total); notify('✅ دفع إلكتروني مؤكد للطلب ' + o.number + ' (' + o.total + ' دج).');
    } else if (o && (ev.type === 'checkout.failed' || ev.type === 'checkout.expired')) { eventAdd(o.id, 'pay', ev.type === 'checkout.failed' ? 'gateway_failed' : 'gateway_expired', 'gateway'); }
    return json(res, 200, { ok: true });
  }
  if (m !== 'GET' && m !== 'HEAD') {
    const ctype = String(req.headers['content-type'] || '');
    if (!ctype.includes('application/json') && !(p === '/api/admin/video' && /^video\/(mp4|webm)\b/.test(ctype))) return fail(res, 415, 'json_only');
    const o = req.headers.origin; if (o) { try { if (new URL(o).host !== req.headers.host) return fail(res, 403, 'origin'); } catch { return fail(res, 403, 'origin'); } }
  }
  const forwarded = process.env.TRUST_PROXY === 'true' ? String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() : '';
  const ip = forwarded || String(req.socket.remoteAddress || 'unknown').trim();

  /* public */
  if (m === 'GET' && p === '/api/catalog') {
    const st = {}; rows('SELECT k,v FROM settings').forEach(r => { if (!['seeded', 'pricesConfirmed', 'tgToken', 'tgChat'].includes(r.k)) { try { st[r.k] = JSON.parse(r.v); } catch { } } });
    const products = rows('SELECT * FROM products WHERE avail=1 ORDER BY sort,id').map(r => ({ id: r.id, cat: r.cat, type: r.type, name: { ar: r.name_ar, fr: r.name_fr }, price: r.price, old: r.old, img: r.img, needsRef: !!r.needs_ref, pays: r.pays ? String(r.pays).split(',').filter(Boolean) : [], desc: { ar: r.desc_ar || '', fr: r.desc_fr || '' } }));
    st.gateway = !!GATEWAY_KEY;
    return json(res, 200, { settings: st, products });
  }
  if (m === 'POST' && p === '/api/orders') {
    if (limited('ord:' + ip, 12, 3600e3)) return fail(res, 429, 'slow_down');
    hit('ord:' + ip); const b = await readBody(req, 20000);
    const r = createOrder(b, custUser(req)); if (r.error) return fail(res, 422, r.error);
    return json(res, 201, r);
  }
  if (m === 'GET' && p === '/api/track') {
    if (limited('trk:' + ip, 30, 600e3)) return fail(res, 429, 'slow_down'); hit('trk:' + ip);
    const o = row('SELECT * FROM orders WHERE number=?', str(url.searchParams.get('number'), 30).toUpperCase());
    if (!o || o.phone !== cleanPhone(url.searchParams.get('phone'))) return fail(res, 404, 'not_found');
    const ev = rows("SELECT ts,value FROM order_events WHERE order_id=? AND kind='status' ORDER BY id", o.id);
    return json(res, 200, { number: o.number, created: o.created, status: o.status, pay_status: o.pay_status, pay_method: o.pay_method, total: o.total, onreq: !!o.onreq, has_proof: !!o.proof_ts, history: ev, ccp: getSetting('ccp', ''), delivery_info: o.delivery_info || '', account_ref: o.account_ref || '' });
  }
  if (m === 'POST' && p === '/api/proof') {
    if (limited('prf:' + ip, 10, 3600e3)) return fail(res, 429, 'slow_down');
    hit('prf:' + ip); const b = await readBody(req, 4e6);
    const o = row('SELECT * FROM orders WHERE number=?', str(b.number, 30).toUpperCase());
    if (!o || o.phone !== cleanPhone(b.phone)) return fail(res, 404, 'not_found');
    const buf = decodeFile(b, true, 2.5e6); if (!buf) return fail(res, 422, 'bad_file');
    run('UPDATE orders SET proof=?,proof_mime=?,proof_ts=?,pay_status=CASE WHEN pay_status=\'unpaid\' THEN \'proof_sent\' ELSE pay_status END WHERE id=?', buf, b.mime, now(), o.id);
    eventAdd(o.id, 'proof', 'uploaded', 'customer');
    notify('🧾 وصل إثبات دفع للطلب ' + o.number + ' (' + o.total + ' دج). راجعه في لوحة التحكم.');
    return json(res, 200, { ok: true });
  }
  if (m === 'POST' && p === '/api/pay') {
    if (!GATEWAY_KEY) return fail(res, 404, 'no_gateway');
    if (limited('pay:' + ip, 15, 3600e3)) return fail(res, 429, 'slow_down'); hit('pay:' + ip);
    const b = await readBody(req, 2000);
    const o = row('SELECT * FROM orders WHERE number=?', str(b.number, 30).toUpperCase());
    if (!o || o.phone !== cleanPhone(b.phone)) return fail(res, 404, 'not_found');
    if (o.pay_method !== 'online' || o.pay_status === 'paid' || o.status === 'cancelled' || o.onreq || o.total < 50) return fail(res, 409, 'not_payable');
    const proto = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http'), base = process.env.PUBLIC_URL || (proto + '://' + req.headers.host);
    try {
      const r = await fetch(GATEWAY_BASE + '/checkouts', { method: 'POST', headers: { Authorization: 'Bearer ' + GATEWAY_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ amount: o.total, currency: 'dzd', description: 'Slimi Bookstore ' + o.number, locale: o.lang === 'fr' ? 'fr' : 'ar', metadata: { order_number: o.number }, success_url: base + '/?paid=' + encodeURIComponent(o.number) + '#track', failure_url: base + '/?failed=' + encodeURIComponent(o.number) + '#track', webhook_endpoint: base + '/api/webhook/chargily' }) });
      const j = await r.json().catch(() => ({}));
      if (!r.ok || !j.checkout_url) { console.error('[gateway]', r.status, JSON.stringify(j).slice(0, 300)); return fail(res, 502, 'gateway_error'); }
      run('UPDATE orders SET pay_ref=? WHERE id=?', String(j.id || ''), o.id); eventAdd(o.id, 'pay', 'checkout_created', 'system');
      return json(res, 200, { url: j.checkout_url });
    } catch (e) { console.error('[gateway]', e.message); return fail(res, 502, 'gateway_error'); }
  }
  if (m === 'POST' && p === '/api/login') {
    const b = await readBody(req, 2000), uname = str(b.username, 40).toLowerCase(), key = 'login:' + ip + ':' + uname;
    if (limited(key, 6, 600e3)) return fail(res, 429, 'slow_down');
    const u = row('SELECT * FROM users WHERE username=? AND active=1', uname);
    const ok = u && crypto.timingSafeEqual(Buffer.from(hashPw(b.password || '', u.salt), 'hex'), Buffer.from(u.hash, 'hex'));
    if (!ok) { hit(key); audit(uname || '?', 'login_failed', ip); return fail(res, 401, 'bad_credentials'); }
    const tok = crypto.randomBytes(32).toString('base64url');
    run('INSERT INTO sessions(token,user_id,exp) VALUES(?,?,?)', tok, u.id, now() + 12 * 3600e3);
    audit(u.username, 'login', ip);
    res.setHeader('Set-Cookie', 'sid=' + tok + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200' + (isHttps(req) ? '; Secure' : ''));
    return json(res, 200, publicUser(u));
  }

  /* customer accounts */
  if (p === '/api/c/me' && m === 'GET') { const c = custUser(req); return c ? json(res, 200, publicCust(c)) : fail(res, 401, 'auth'); }
  if (p === '/api/c/logout' && m === 'POST') { const t = cookies(req).cid; if (t) run('DELETE FROM csessions WHERE token=?', t); res.setHeader('Set-Cookie', 'cid=; Path=/; HttpOnly; Max-Age=0'); return json(res, 200, { ok: true }); }
  if (p === '/api/c/register' && m === 'POST') {
    if (limited('reg:' + ip, 8, 3600e3)) return fail(res, 429, 'slow_down'); hit('reg:' + ip);
    const b = await readBody(req, 2000), name = str(b.name, 80), phone = normPhone(b.phone), pw = String(b.password || ''), email = str(b.email, 120);
    if (name.length < 3) return fail(res, 422, 'name'); if (!/^0[567]\d{8}$/.test(phone)) return fail(res, 422, 'phone'); if (pw.length < 6 || pw.length > 100) return fail(res, 422, 'password');
    if (row('SELECT 1 x FROM customers WHERE phone=?', phone)) return fail(res, 409, 'exists');
    const salt = crypto.randomBytes(16).toString('hex');
    const r = run('INSERT INTO customers(phone,name,email,salt,hash,created) VALUES(?,?,?,?,?,?)', phone, name, email, salt, hashPw(pw, salt), now());
    const c = row('SELECT * FROM customers WHERE id=?', Number(r.lastInsertRowid)); custLogin(req, res, c); return json(res, 201, publicCust(c));
  }
  if (p === '/api/c/login' && m === 'POST') {
    const b = await readBody(req, 1000), phone = normPhone(b.phone), key = 'clogin:' + ip + ':' + phone;
    if (limited(key, 6, 600e3)) return fail(res, 429, 'slow_down');
    const c = row('SELECT * FROM customers WHERE phone=?', phone);
    const ok = c && crypto.timingSafeEqual(Buffer.from(hashPw(b.password || '', c.salt), 'hex'), Buffer.from(c.hash, 'hex'));
    if (!ok) { hit(key); return fail(res, 401, 'bad_credentials'); }
    custLogin(req, res, c); return json(res, 200, publicCust(c));
  }
  if (p === '/api/c/orders' && m === 'GET') {
    const c = custUser(req); if (!c) return fail(res, 401, 'auth');
    const list = rows('SELECT number,created,status,pay_status,pay_method,total,items,delivery_info,phone,customer_id FROM orders WHERE customer_id=? ORDER BY id DESC LIMIT 100', c.id);
    return json(res, 200, list.map(o => ({ number: o.number, created: o.created, status: o.status, pay_status: o.pay_status, pay_method: o.pay_method, total: o.total, items: JSON.parse(o.items).map(l => ({ name_ar: l.name_ar, name_fr: l.name_fr, q: l.q })), delivery_info: o.delivery_info || '' })));
  }

  /* authenticated */
  const user = sessionUser(req);
  if (p === '/api/logout' && m === 'POST') {
    const t = cookies(req).sid; if (t) run('DELETE FROM sessions WHERE token=?', t);
    res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; Max-Age=0'); return json(res, 200, { ok: true });
  }
  if (!user) return fail(res, 401, 'auth');
  const perms = userPerms(user), need = k => perms.includes(k);
  const actor = user.username;
  if (p === '/api/me' && m === 'GET') return json(res, 200, publicUser(user));
  if (p === '/api/me/password' && m === 'POST') {
    const b = await readBody(req, 2000);
    if (hashPw(b.old || '', user.salt) !== user.hash) return fail(res, 403, 'bad_password');
    if (String(b.new || '').length < 8) return fail(res, 422, 'short');
    const salt = crypto.randomBytes(16).toString('hex');
    run('UPDATE users SET salt=?,hash=? WHERE id=?', salt, hashPw(b.new, salt), user.id);
    audit(actor, 'password_changed'); return json(res, 200, { ok: true });
  }
  if (!p.startsWith('/api/admin/')) return fail(res, 404, 'not_found');
  const sub = p.slice(11);

  /* notifications poll */
  if (m === 'GET' && sub === 'poll') {
    if (!need('orders')) return json(res, 200, {});
    const last = row('SELECT id,number,name,total,created FROM orders ORDER BY id DESC LIMIT 1');
    const proofs = row('SELECT COALESCE(MAX(proof_ts),0) t FROM orders').t;
    return json(res, 200, { lastId: last ? last.id : 0, last, newCount: row("SELECT COUNT(*) c FROM orders WHERE status='new'").c, proofTs: proofs });
  }
  /* orders */
  if (sub.startsWith('orders')) {
    if (!need('orders')) return fail(res, 403, 'forbidden');
    if (m === 'GET' && sub === 'orders') {
      const st = url.searchParams.get('status') || '', q = str(url.searchParams.get('q'), 40), pay = url.searchParams.get('pay') || '';
      let sql = 'SELECT id,number,created,status,pay_status,pay_method,delivery,name,phone,wilaya,total,onreq,has_phys,has_dig,(proof_ts IS NOT NULL) has_proof FROM orders WHERE 1=1', a = [];
      if (STATUSES.includes(st)) { sql += ' AND status=?'; a.push(st); }
      if (PAYS.includes(pay)) { sql += ' AND pay_status=?'; a.push(pay); }
      if (q) { sql += ' AND (number LIKE ? OR name LIKE ? OR phone LIKE ?)'; a.push('%' + q + '%', '%' + q + '%', '%' + q + '%'); }
      sql += ' ORDER BY id DESC LIMIT 300';
      return json(res, 200, rows(sql, ...a));
    }
    if ((mm = sub.match(/^orders\/(\d+)$/))) {
      const o = row('SELECT id,number,created,status,pay_status,pay_method,delivery,name,phone,wilaya,addr,note,staff_note,delivery_info,account_ref,items,subtotal,fee,total,onreq,has_phys,has_dig,lang,proof_mime,proof_ts FROM orders WHERE id=?', +mm[1]);
      if (!o) return fail(res, 404, 'not_found');
      if (m === 'GET') { o.items = JSON.parse(o.items); o.events = rows('SELECT ts,kind,value,actor FROM order_events WHERE order_id=? ORDER BY id', o.id); return json(res, 200, o); }
      if (m === 'PATCH') {
        const b = await readBody(req, 4000), ch = [];
        if (b.status !== undefined) { if (!STATUSES.includes(b.status)) return fail(res, 422, 'status'); if (b.status !== o.status) { run('UPDATE orders SET status=? WHERE id=?', b.status, o.id); eventAdd(o.id, 'status', b.status, actor); ch.push('status=' + b.status); } }
        if (b.pay_status !== undefined) { if (!PAYS.includes(b.pay_status)) return fail(res, 422, 'pay'); if (b.pay_status !== o.pay_status) { run('UPDATE orders SET pay_status=? WHERE id=?', b.pay_status, o.id); eventAdd(o.id, 'pay', b.pay_status, actor); ch.push('pay=' + b.pay_status); } }
        if (b.delivery_info !== undefined) { run('UPDATE orders SET delivery_info=? WHERE id=?', str(b.delivery_info, 600), o.id); eventAdd(o.id, 'delivery', 'updated', actor); ch.push('delivery_info'); }
        if (b.staff_note !== undefined) { run('UPDATE orders SET staff_note=? WHERE id=?', str(b.staff_note, 500), o.id); eventAdd(o.id, 'note', str(b.staff_note, 500), actor); ch.push('note'); }
        if (ch.length) audit(actor, 'order_update', o.number + ' ' + ch.join(' '));
        return json(res, 200, { ok: true });
      }
    }
    if (m === 'GET' && (mm = sub.match(/^orders\/(\d+)\/proof$/))) {
      const o = row('SELECT proof,proof_mime,number FROM orders WHERE id=?', +mm[1]); if (!o || !o.proof) return fail(res, 404, 'not_found');
      audit(actor, 'proof_view', o.number);
      return send(res, 200, Buffer.from(o.proof), { 'Content-Type': o.proof_mime, 'Cache-Control': 'private, no-store', 'Content-Security-Policy': 'sandbox' });
    }
    return fail(res, 404, 'not_found');
  }
  /* products */
  if (sub.startsWith('products')) {
    if (!need('products')) return fail(res, 403, 'forbidden');
    const toRow = r => ({ id: r.id, cat: r.cat, type: r.type, name: { ar: r.name_ar, fr: r.name_fr }, price: r.price, old: r.old, avail: !!r.avail, img: r.img, needsRef: !!r.needs_ref, pays: r.pays ? String(r.pays).split(',').filter(Boolean) : [], desc: { ar: r.desc_ar || '', fr: r.desc_fr || '' } });
    if (m === 'GET' && sub === 'products') return json(res, 200, rows('SELECT * FROM products ORDER BY sort,id').map(toRow));
    const clean = b => { const ar = str(b.name && b.name.ar, 120); if (!ar || !CATS.includes(b.cat) || !['physical', 'digital'].includes(b.type)) return null; return { cat: b.cat, type: b.type, ar, fr: str(b.name && b.name.fr, 120) || ar, price: intv(b.price, 1e7), old: intv(b.old, 1e7), avail: b.avail ? 1 : 0, dar: str(b.desc && b.desc.ar, 600), dfr: str(b.desc && b.desc.fr, 600), ref: b.needsRef ? 1 : 0, pays: (Array.isArray(b.pays) ? ['cod', 'transfer', 'online'].filter(x => b.pays.includes(x) && !(x === 'cod' && b.type === 'digital')) : []).join(','), img: /^\/media\/[a-f0-9]{18}$/.test(b.img || '') ? b.img : '' }; };
    if (m === 'POST' && sub === 'products') {
      const c = clean(await readBody(req, 4000)); if (!c) return fail(res, 422, 'invalid');
      const id = 'p' + crypto.randomBytes(4).toString('hex'), mx = row('SELECT COALESCE(MAX(sort),0)+1 s FROM products').s;
      run('INSERT INTO products(id,cat,type,name_ar,name_fr,price,old,avail,img,sort,needs_ref,desc_ar,desc_fr,pays) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', id, c.cat, c.type, c.ar, c.fr, c.price, c.old, c.avail, c.img, mx, c.ref, c.dar, c.dfr, c.pays);
      audit(actor, 'product_add', c.ar); return json(res, 201, { id });
    }
    if ((mm = sub.match(/^products\/([\w-]+)$/))) {
      if (m === 'PUT') { const c = clean(await readBody(req, 4000)); if (!c) return fail(res, 422, 'invalid'); run('UPDATE products SET cat=?,type=?,name_ar=?,name_fr=?,price=?,old=?,avail=?,img=?,needs_ref=?,desc_ar=?,desc_fr=?,pays=? WHERE id=?', c.cat, c.type, c.ar, c.fr, c.price, c.old, c.avail, c.img, c.ref, c.dar, c.dfr, c.pays, mm[1]); audit(actor, 'product_edit', c.ar + ' ' + c.price); return json(res, 200, { ok: true }); }
      if (m === 'DELETE') { run('DELETE FROM products WHERE id=?', mm[1]); audit(actor, 'product_delete', mm[1]); return json(res, 200, { ok: true }); }
    }
    return fail(res, 404, 'not_found');
  }
  if (m === 'POST' && sub === 'media') {
    if (!need('products') && !need('settings')) return fail(res, 403, 'forbidden');
    const b = await readBody(req, 4e6), buf = decodeFile(b, false, 2.5e6); if (!buf) return fail(res, 422, 'bad_file');
    const id = crypto.randomBytes(9).toString('hex'); run('INSERT INTO media(id,mime,data,created) VALUES(?,?,?,?)', id, b.mime, buf, now());
    return json(res, 201, { url: '/media/' + id });
  }
  /* subscriptions */
  if (sub.startsWith('subs')) {
    if (!need('subs')) return fail(res, 403, 'forbidden');
    const dateOk = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !isNaN(Date.parse(s));
    const clean = b => { const c = str(b.customer, 80), s = str(b.service, 80); if (!c || !s || !dateOk(b.start) || !dateOk(b.end) || b.end < b.start) return null; return { c, s, phone: cleanPhone(b.phone).slice(0, 15), price: intv(b.price, 1e7), start: b.start, end: b.end, note: str(b.note, 300), on: str(b.order_number, 30) }; };
    if (m === 'GET' && sub === 'subs') return json(res, 200, rows('SELECT * FROM subs ORDER BY end'));
    if (m === 'POST' && sub === 'subs') { const c = clean(await readBody(req, 3000)); if (!c) return fail(res, 422, 'invalid'); const r = run('INSERT INTO subs(customer,phone,service,price,start,end,note,order_number,created) VALUES(?,?,?,?,?,?,?,?,?)', c.c, c.phone, c.s, c.price, c.start, c.end, c.note, c.on, now()); audit(actor, 'sub_add', c.c + ' ' + c.s); return json(res, 201, { id: Number(r.lastInsertRowid) }); }
    if ((mm = sub.match(/^subs\/(\d+)$/))) {
      if (m === 'PUT') { const c = clean(await readBody(req, 3000)); if (!c) return fail(res, 422, 'invalid'); run('UPDATE subs SET customer=?,phone=?,service=?,price=?,start=?,end=?,note=?,order_number=? WHERE id=?', c.c, c.phone, c.s, c.price, c.start, c.end, c.note, c.on, +mm[1]); audit(actor, 'sub_edit', c.c + ' ' + c.s + ' -> ' + c.end); return json(res, 200, { ok: true }); }
      if (m === 'DELETE') { run('DELETE FROM subs WHERE id=?', +mm[1]); audit(actor, 'sub_delete', mm[1]); return json(res, 200, { ok: true }); }
    }
    return fail(res, 404, 'not_found');
  }
  if (m === 'GET' && sub === 'reports') { if (!need('reports')) return fail(res, 403, 'forbidden'); return json(res, 200, reports(Math.min(90, Math.max(7, +url.searchParams.get('days') || 30)))); }
  if (m === 'GET' && sub === 'audit') { if (!need('audit')) return fail(res, 403, 'forbidden'); return json(res, 200, rows('SELECT ts,actor,action,detail FROM audit ORDER BY id DESC LIMIT 300')); }
  if (m === 'POST' && sub === 'notify-test') { if (!need('settings')) return fail(res, 403, 'forbidden'); const ok = await notify('✅ رسالة تجربة من متجر مكتبة سليمي. الإشعارات تعمل.'); return json(res, ok ? 200 : 502, { ok }); }
  if (m === 'POST' && sub === 'video') {
    if (!need('settings')) return fail(res, 403, 'forbidden');
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim();
    let buf; try { buf = await readRaw(req, 12e6); } catch (e) { return fail(res, e.code || 400, 'too_large'); }
    const okv = buf.length > 12 && ((ct === 'video/mp4' && buf.subarray(4, 8).toString() === 'ftyp') || (ct === 'video/webm' && buf.subarray(0, 4).toString('hex') === '1a45dfa3'));
    if (!okv) return fail(res, 422, 'bad_file');
    const id = crypto.randomBytes(9).toString('hex'); run('INSERT INTO media(id,mime,data,created) VALUES(?,?,?,?)', id, ct, buf, now()); audit(actor, 'video_upload', id);
    return json(res, 201, { url: '/media/' + id });
  }
  /* settings */
  if (sub === 'settings') {
    if (!need('settings')) return fail(res, 403, 'forbidden');
    if (m === 'GET') { const st = {}; rows('SELECT k,v FROM settings').forEach(r => { if (r.k !== 'seeded') { try { st[r.k] = JSON.parse(r.v); } catch { } } }); const tg = tgCfg(); st.tgToken = tg.token ? '••••' + String(tg.token).slice(-4) : ''; st.tgChat = tg.chat || ''; st.tgEnv = !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID); st.gatewayEnabled = !!GATEWAY_KEY; st.gatewayMode = process.env.CHARGILY_MODE === 'live' ? 'live' : 'test'; return json(res, 200, st); }
    if (m === 'PUT') {
      const b = await readBody(req, 8000);
      const text = ['phone', 'email', 'hours', 'ccp', 'addrAr', 'addrFr'], nums = ['feeLocal', 'feeOther', 'freeFrom'], imgs = ['logo', 'facade', 'facade2', 'in1', 'svc_subs', 'svc_games', 'svc_bills', 'svc_shop', 'vid'];
      text.forEach(k => { if (b[k] !== undefined) setSetting(k, str(b[k], 160)); });
      nums.forEach(k => { if (b[k] !== undefined) setSetting(k, intv(b[k], 1e6)); });
      imgs.forEach(k => { if (b[k] !== undefined) setSetting(k, /^\/media\/[a-f0-9]{18}$/.test(b[k]) ? b[k] : ''); });
      if (Array.isArray(b.gallery)) setSetting('gallery', b.gallery.filter(x => typeof x === 'string' && /^\/media\/[a-f0-9]{18}$/.test(x)).slice(0, 8));
      if (b.tgChat !== undefined) setSetting('tgChat', String(b.tgChat).replace(/[^\d-]/g, '').slice(0, 20));
      if (b.tgToken !== undefined && !String(b.tgToken).startsWith('•')) { const tk = String(b.tgToken).trim(); setSetting('tgToken', /^\d{6,12}:[\w-]{30,50}$/.test(tk) ? tk : ''); }
      if (b.whatsapp !== undefined) setSetting('whatsapp', String(b.whatsapp).replace(/\D/g, '').slice(0, 15));
      if (b.pricesConfirmed !== undefined) setSetting('pricesConfirmed', !!b.pricesConfirmed);
      audit(actor, 'settings_update', Object.keys(b).join(',')); return json(res, 200, { ok: true });
    }
  }
  /* staff */
  if (sub.startsWith('users')) {
    if (!need('staff')) return fail(res, 403, 'forbidden');
    if (m === 'GET' && sub === 'users') return json(res, 200, rows('SELECT * FROM users ORDER BY id').map(publicUser));
    const cleanPerms = b => Array.isArray(b.perms) ? JSON.stringify(b.perms.filter(x => ALL_PERMS.includes(x) && x !== 'staff')) : null;
    if (m === 'POST' && sub === 'users') {
      const b = await readBody(req, 2000), un = str(b.username, 30).toLowerCase();
      if (!/^[a-z0-9._-]{3,30}$/.test(un) || str(b.name, 60).length < 2 || !['manager', 'staff'].includes(b.role) || String(b.password || '').length < 8) return fail(res, 422, 'invalid');
      if (row('SELECT 1 x FROM users WHERE username=?', un)) return fail(res, 409, 'exists');
      const salt = crypto.randomBytes(16).toString('hex');
      run('INSERT INTO users(username,name,role,perms,salt,hash,active,created) VALUES(?,?,?,?,?,?,1,?)', un, str(b.name, 60), b.role, cleanPerms(b), salt, hashPw(b.password, salt), now());
      audit(actor, 'staff_add', un + ' ' + b.role); return json(res, 201, { ok: true });
    }
    if ((mm = sub.match(/^users\/(\d+)$/)) && m === 'PUT') {
      const t = row('SELECT * FROM users WHERE id=?', +mm[1]); if (!t) return fail(res, 404, 'not_found');
      if (t.role === 'owner') return fail(res, 403, 'owner_locked');
      const b = await readBody(req, 2000);
      if (b.role && !['manager', 'staff'].includes(b.role)) return fail(res, 422, 'invalid');
      run('UPDATE users SET name=?,role=?,perms=?,active=? WHERE id=?', str(b.name, 60) || t.name, b.role || t.role, b.perms !== undefined ? cleanPerms(b) : t.perms, b.active === undefined ? t.active : (b.active ? 1 : 0), t.id);
      if (b.password) { if (String(b.password).length < 8) return fail(res, 422, 'short'); const salt = crypto.randomBytes(16).toString('hex'); run('UPDATE users SET salt=?,hash=? WHERE id=?', salt, hashPw(b.password, salt), t.id); }
      if (b.active === false) run('DELETE FROM sessions WHERE user_id=?', t.id);
      audit(actor, 'staff_update', t.username); return json(res, 200, { ok: true });
    }
    return fail(res, 404, 'not_found');
  }
  /* backup (owner) */
  if (m === 'GET' && sub === 'backup.db') {
    if (user.role !== 'owner') return fail(res, 403, 'forbidden');
    const tmp = path.join(DATA_DIR, 'export-' + crypto.randomBytes(4).toString('hex') + '.db');
    db.exec("VACUUM INTO '" + tmp.replace(/'/g, "''") + "'");
    const buf = fs.readFileSync(tmp); fs.unlinkSync(tmp); audit(actor, 'backup_download');
    return send(res, 200, buf, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': 'attachment; filename="slimi-' + ymd(now()) + '.db"', 'Cache-Control': 'no-store' });
  }
  return fail(res, 404, 'not_found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => { if (!res.headersSent) fail(res, e && e.code === 413 ? 413 : e && e.code === 400 ? 400 : 500, e && e.code ? e.message : 'server_error'); if (!e || !e.code) console.error(e); });
});
server.listen(PORT, '0.0.0.0', () => console.log('[slimi] listening on ' + PORT));

/* maintenance: expire sessions and keep 7 daily backups */
function maintain() {
  try {
    run('DELETE FROM sessions WHERE exp<?', now());
    run('DELETE FROM csessions WHERE exp<?', now());
    const f = path.join(DATA_DIR, 'backups', 'slimi-' + ymd(now()) + '.db');
    if (!fs.existsSync(f)) { db.exec("VACUUM INTO '" + f.replace(/'/g, "''") + "'"); }
    fs.readdirSync(path.join(DATA_DIR, 'backups')).filter(x => x.endsWith('.db')).sort().reverse().slice(7).forEach(x => fs.unlinkSync(path.join(DATA_DIR, 'backups', x)));
  } catch (e) { console.error('[maintain]', e.message); }
}
setTimeout(maintain, 5000); setInterval(maintain, 6 * 3600e3);
