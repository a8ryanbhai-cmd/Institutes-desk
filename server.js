// Institute Desk - one owner, many institutes (cc / schl), each with its own WhatsApp number.
// Needs Node 22+. No npm install required.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
try { process.loadEnvFile(path.join(__dirname, '.env')); } catch {}
const PORT = process.env.PORT || 3000, PASS = process.env.OWNER_PASSWORD || 'change-me';
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const UP = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'); fs.mkdirSync(UP, { recursive: true });
const db = new DatabaseSync(process.env.DB || path.join(__dirname, 'data.db'));
db.exec(`
create table if not exists inst(id integer primary key,name text,type text,wa_id text default '',wa_token text default '',cfg text default '{}');
create table if not exists sec(id integer primary key,inst integer,name text);
create table if not exists stu(id integer primary key,inst integer,sec integer,name text,roll text,phone text);
create table if not exists att(stu integer,day text,status text,primary key(stu,day));
create table if not exists fee(stu integer,month text,status text,cleared text,primary key(stu,month));
create table if not exists log(id integer primary key,ts text,inst integer,phone text,kind text,status text,info text);
create table if not exists sent(key text primary key);`);
const Q = (s, ...a) => db.prepare(s).all(...a), G = (s, ...a) => db.prepare(s).get(...a), R = (s, ...a) => db.prepare(s).run(...a);
const DEF = { color: '#c8553d', feeDay: 15, lang: 'en', tpl: { absent: 'absent_alert', paid: 'fee_received', due: 'fee_due', ann: 'announcement', annImg: 'announcement_image', annDoc: 'announcement_document' } };
const cfgOf = i => { const c = JSON.parse(i.cfg || '{}'); return { ...DEF, ...c, tpl: { ...DEF.tpl, ...(c.tpl || {}) } }; };
const norm = p => { const d = String(p).replace(/\D/g, ''); return d.length === 10 ? '91' + d : d; };
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- WhatsApp: every institute sends from ITS OWN number/token. Missing token or DRY_RUN=1 -> only logged. ----
async function wa(inst, phone, kind, tpl, params, header) {
  const to = norm(phone); let status = 'dry-run', info = '';
  if (inst.wa_id && inst.wa_token && !process.env.DRY_RUN) {
    const comps = []; if (header) comps.push({ type: 'header', parameters: [header] });
    comps.push({ type: 'body', parameters: params.map(t => ({ type: 'text', text: String(t).replace(/\s+/g, ' ').trim().slice(0, 900) })) });
    try {
      const r = await fetch(`https://graph.facebook.com/v21.0/${inst.wa_id}/messages`, { method: 'POST',
        headers: { Authorization: 'Bearer ' + inst.wa_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'template', template: { name: tpl, language: { code: cfgOf(inst).lang }, components: comps } }) });
      const j = await r.json(); status = r.ok ? 'sent' : 'failed'; info = r.ok ? '' : (j.error?.message || r.status);
    } catch (e) { status = 'failed'; info = e.message; }
    await sleep(80);
  }
  R('insert into log(ts,inst,phone,kind,status,info) values(?,?,?,?,?,?)', new Date().toISOString(), inst.id, to, kind, status, info);
}
const once = (key) => !G('select 1 x from sent where key=?', key);
const mark = key => R('insert or ignore into sent(key) values(?)', key);
const fmt = d => new Date(d + 'T00:00:00').toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });

async function dueReminders(inst, month, force) {
  const c = cfgOf(inst); if (!force && new Date(today()).getUTCDate() <= c.feeDay) return 0;
  const rows = Q(`select s.* from stu s where s.inst=? and not exists(select 1 from fee f where f.stu=s.id and f.month=? and f.status='cleared')`, inst.id, month);
  let n = 0;
  for (const s of rows) { const k = `due:${s.id}:${month}`; if (!force && !once(k)) continue; mark(k); n++; await wa(inst, s.phone, 'fee-due', c.tpl.due, [s.name, month, inst.name]); }
  return n;
}
setInterval(() => Q('select * from inst').forEach(i => dueReminders(i, today().slice(0, 7)).catch(console.error)), 3600e3);

// ---- API ----
const sessions = new Set();
const pub = i => ({ id: i.id, name: i.name, type: i.type, wa_id: i.wa_id, has_token: !!i.wa_token, cfg: cfgOf(i) });
const inst = id => G('select * from inst where id=?', id) || (() => { throw new Error('Institute not found'); })();
const routes = [
  ['POST', /^\/api\/login$/, (_, b) => { if (b.password !== PASS) throw new Error('Wrong password'); const t = crypto.randomBytes(24).toString('hex'); sessions.add(t); return { token: t }; }, true],
  ['GET', /^\/api\/inst$/, () => Q('select * from inst order by id').map(pub)],
  ['POST', /^\/api\/inst$/, (_, b) => { if (!b.name) throw new Error('Name needed'); return { id: R('insert into inst(name,type) values(?,?)', b.name, b.type === 'schl' ? 'schl' : 'cc').lastInsertRowid }; }],
  ['PUT', /^\/api\/inst\/(\d+)$/, (m, b) => { const i = inst(m[1]); R('update inst set name=?,type=?,wa_id=?,wa_token=?,cfg=? where id=?', b.name || i.name, b.type || i.type, b.wa_id ?? i.wa_id, b.wa_token || i.wa_token, JSON.stringify(b.cfg || {}), i.id); return { ok: 1 }; }],
  ['DELETE', /^\/api\/inst\/(\d+)$/, m => { for (const t of ['sec', 'stu', 'log']) R(`delete from ${t} where inst=?`, m[1]); R('delete from inst where id=?', m[1]); return { ok: 1 }; }],
  ['GET', /^\/api\/sec$/, (_, __, q) => Q('select s.*,(select count(*) from stu where sec=s.id) n from sec s where inst=?', q.inst)],
  ['POST', /^\/api\/sec$/, (_, b) => ({ id: R('insert into sec(inst,name) values(?,?)', b.inst, b.name).lastInsertRowid })],
  ['DELETE', /^\/api\/sec\/(\d+)$/, m => { R('delete from stu where sec=?', m[1]); R('delete from sec where id=?', m[1]); return { ok: 1 }; }],
  ['GET', /^\/api\/stu$/, (_, __, q) => Q('select * from stu where sec=? order by cast(roll as integer),name', q.sec)],
  ['POST', /^\/api\/stu\/bulk$/, (_, b) => { // lines: Name, ParentPhone, Roll(optional)
    const s = G('select * from sec where id=?', b.sec); let n = 0;
    for (const line of String(b.text).split('\n')) { const [name, phone, roll] = line.split(/[,\t]/).map(x => x.trim()); if (name && norm(phone || '').length >= 10) { R('insert into stu(inst,sec,name,roll,phone) values(?,?,?,?,?)', s.inst, s.id, name, roll || '', norm(phone)); n++; } }
    return { added: n }; }],
  ['DELETE', /^\/api\/stu\/(\d+)$/, m => { R('delete from stu where id=?', m[1]); return { ok: 1 }; }],
  ['GET', /^\/api\/att$/, (_, __, q) => Q(`select s.id,s.name,s.roll,coalesce(a.status,'P') status,a.status saved from stu s left join att a on a.stu=s.id and a.day=? where s.sec=? order by cast(s.roll as integer),s.name`, q.day, q.sec)],
  ['POST', /^\/api\/att$/, async (_, b) => {
    const sec = G('select * from sec where id=?', b.sec), i = inst(sec.inst), c = cfgOf(i), ab = new Set(b.absent), out = [];
    for (const s of Q('select * from stu where sec=?', sec.id)) {
      R('insert or replace into att(stu,day,status) values(?,?,?)', s.id, b.day, ab.has(s.id) ? 'A' : 'P');
      if (ab.has(s.id) && once(`abs:${s.id}:${b.day}`)) { mark(`abs:${s.id}:${b.day}`); out.push(s); }
    }
    (async () => { for (const s of out) await wa(i, s.phone, 'absent', c.tpl.absent, [s.name, fmt(b.day), i.name]); })();
    return { saved: 1, alerts: out.length }; }],
  ['GET', /^\/api\/fee$/, (_, __, q) => Q(`select s.id,s.name,s.roll,coalesce(f.status,'pending') status,f.cleared from stu s left join fee f on f.stu=s.id and f.month=? where s.sec=? order by cast(s.roll as integer),s.name`, q.month, q.sec)],
  ['POST', /^\/api\/fee\/clear$/, async (_, b) => { const s = G('select * from stu where id=?', b.stu), i = inst(s.inst);
    R('insert or replace into fee(stu,month,status,cleared) values(?,?,?,?)', s.id, b.month, 'cleared', today());
    if (once(`paid:${s.id}:${b.month}`)) { mark(`paid:${s.id}:${b.month}`); await wa(i, s.phone, 'fee-paid', cfgOf(i).tpl.paid, [s.name, b.month, i.name]); }
    return { ok: 1 }; }],
  ['POST', /^\/api\/fee\/remind$/, async (_, b) => ({ sent: await dueReminders(inst(b.inst), b.month, true) })],
  ['POST', /^\/api\/announce$/, async (_, b) => {
    const i = inst(b.inst), c = cfgOf(i); let tpl = c.tpl.ann, header = null;
    if (b.file) { const ext = path.extname(b.file.name).toLowerCase(), fn = crypto.randomBytes(6).toString('hex') + ext.replace(/[^.\w]/g, '');
      fs.writeFileSync(path.join(UP, fn), Buffer.from(b.file.data, 'base64')); const link = `${BASE}/files/${fn}`;
      if (ext === '.pdf') { tpl = c.tpl.annDoc; header = { type: 'document', document: { link, filename: b.file.name } }; }
      else { tpl = c.tpl.annImg; header = { type: 'image', image: { link } }; } }
    const phones = [...new Set(Q(b.sec ? 'select phone from stu where sec=?' : 'select phone from stu where inst=?', b.sec || i.id).map(r => r.phone))];
    (async () => { for (const p of phones) await wa(i, p, 'announce', tpl, [b.text], header); })();
    return { queued: phones.length }; }],
  ['GET', /^\/api\/log$/, (_, __, q) => Q('select * from log where inst=? order by id desc limit 200', q.inst)],
  ['GET', /^\/api\/export$/, (_, __, q) => { // CSV in the same columns your n8n chatbot Google Sheet uses
    const rows = q.kind === 'attendance' ? Q('select a.day Date,a.stu Student_ID,a.status Status from att a join stu s on s.id=a.stu where s.inst=?', q.inst)
      : Q('select id Student_ID,name Name,roll Roll_No,phone Parent_Phone_1 from stu where inst=?', q.inst);
    return { csv: rows.length ? [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).map(v => `"${v}"`).join(','))].join('\n') : '' }; }],
];

http.createServer(async (req, res) => {
  const u = new URL(req.url, BASE), send = (c, d, t = 'application/json') => { res.writeHead(c, { 'Content-Type': t }); res.end(t === 'application/json' ? JSON.stringify(d) : d); };
  try {
    if (u.pathname === '/' ) return send(200, fs.readFileSync(['index.html', 'public/index.html'].map(f => path.join(__dirname, f)).find(f => fs.existsSync(f))), 'text/html; charset=utf-8');
    if (u.pathname.startsWith('/files/')) { const f = path.join(UP, path.basename(u.pathname)); return fs.existsSync(f) ? (res.writeHead(200), res.end(fs.readFileSync(f))) : send(404, {}); }
    for (const [method, re, fn, open] of routes) {
      const m = u.pathname.match(re); if (method !== req.method || !m) continue;
      if (!open && !sessions.has((req.headers.authorization || '').slice(7))) return send(401, { error: 'Login again' });
      let body = ''; for await (const ch of req) body += ch; const b = body ? JSON.parse(body) : {};
      return send(200, await fn(m, b, Object.fromEntries(u.searchParams)));
    }
    send(404, { error: 'Not found' });
  } catch (e) { send(400, { error: e.message }); }
}).listen(PORT, () => console.log(`Institute Desk running on ${BASE}` + (PASS === 'change-me' ? '  (set OWNER_PASSWORD in .env!)' : '')));
