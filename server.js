// Institute Desk v2
// Roles: super (you, via OWNER_PASSWORD) > head (principal/director, one per institute) > staff (class/batch teacher, ONE class).
// Needs Node 22+. No npm install required.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
try { process.loadEnvFile(path.join(__dirname, '.env')); } catch {}
const PORT = process.env.PORT || 3000, BOOT_RANDOM = !process.env.OWNER_PASSWORD, ADMIN_PASS = process.env.OWNER_PASSWORD || crypto.randomBytes(9).toString('hex');
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const UP = process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'); fs.mkdirSync(UP, { recursive: true });
const db = new DatabaseSync(process.env.DB || path.join(__dirname, 'data.db'));
db.exec(`
create table if not exists inst(id integer primary key,name text,type text,wa_id text default '',wa_token text default '',cfg text default '{}',active integer default 1);
create table if not exists sec(id integer primary key,inst integer,name text);
create table if not exists stu(id integer primary key,inst integer,sec integer,name text,roll text,phone text);
create table if not exists att(stu integer,day text,status text,primary key(stu,day));
create table if not exists fee(stu integer,month text,status text,cleared text,primary key(stu,month));
create table if not exists log(id integer primary key,ts text,inst integer,phone text,kind text,status text,info text);
create table if not exists sent(key text primary key);
create table if not exists users(id integer primary key,username text unique,name text,role text,inst integer,sec integer,salt text,hash text,active integer default 1,last_login text);
create table if not exists activity(id integer primary key,ts text,uname text,role text,inst integer,action text,detail text);`);
try { db.exec('alter table inst add column active integer default 1'); } catch {}
db.exec(`create table if not exists admin(id integer primary key check(id=1),username text,salt text,hash text,updated text);
create table if not exists col(id integer primary key,inst integer,name text,type text,opts text default '');`);
try { db.exec("alter table stu add column extra text default '{}'"); } catch {}
const Q = (s, ...a) => db.prepare(s).all(...a), G = (s, ...a) => db.prepare(s).get(...a), R = (s, ...a) => db.prepare(s).run(...a);
const E = (m, status = 400) => Object.assign(new Error(m), { status });
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const DEF = { color: '#0f8b8d', feeDay: 15, lang: 'en', tpl: { absent: 'absent_alert', paid: 'fee_received', due: 'fee_due', ann: 'announcement', annImg: 'announcement_image', annDoc: 'announcement_document' } };
const cfgOf = i => { let c = {}; try { c = JSON.parse(i.cfg || '{}'); } catch {} return { ...DEF, ...c, tpl: { ...DEF.tpl, ...(c.tpl || {}) } }; };
const norm = p => { const d = String(p).replace(/\D/g, ''); return d.length === 10 ? '91' + d : d; };
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isDay = s => /^\d{4}-\d{2}-\d{2}$/.test(s || ''), isMonth = s => /^\d{4}-\d{2}$/.test(s || '');
process.on('uncaughtException', e => console.error('uncaught', e)); process.on('unhandledRejection', e => console.error('unhandled', e));

// ---------- passwords, sessions, login throttle ----------
const hashPw = (p, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(p, salt, 32).toString('hex') });
const okPw = (p, u) => { const a = Buffer.from(crypto.scryptSync(p, u.salt, 32).toString('hex')), b = Buffer.from(u.hash); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
const sessions = new Map(), tries = new Map(), TTL = 30 * 60e3;
setInterval(() => { const n = Date.now(); for (const [k, v] of sessions) if (v.exp < n) sessions.delete(k); for (const [k, v] of tries) if (v.until < n) tries.delete(k); }, 600e3);
const authUser = tok => {
  const s = sessions.get(tok); if (!s || s.exp < Date.now()) return null; s.exp = Date.now() + TTL;
  if (s.role === 'super') return { role: 'super', name: 'Administrator', username: 'admin' };
  const r = G('select * from users where id=?', s.uid); if (!r || !r.active) return null;
  const i = G('select active from inst where id=?', r.inst); if (!i || i.active === 0) return null;
  return { id: r.id, role: r.role, name: r.name || r.username, username: r.username, inst: r.inst, sec: r.sec };
};
const act = (u, action, detail = '', inst = null) => R('insert into activity(ts,uname,role,inst,action,detail) values(?,?,?,?,?,?)', new Date().toISOString(), u.username, u.role, inst ?? u.inst ?? null, action, str(detail, 300));

// ---------- permission helpers ----------
const needAdm = u => { if (u.role === 'staff') throw E('Not allowed for class teachers', 403); };
const needSuper = u => { if (u.role !== 'super') throw E('Administrator only', 403); };
const instFor = (u, id) => { id = +id; if (u.role !== 'super' && u.inst !== id) throw E('Not allowed', 403); const i = G('select * from inst where id=?', id); if (!i) throw E('Institute not found', 404); return i; };
const secFor = (u, id) => { const s = G('select * from sec where id=?', +id); if (!s) throw E('Class not found', 404); instFor(u, s.inst); if (u.role === 'staff' && u.sec !== s.id) throw E('This class belongs to another teacher', 403); return s; };
const stuFor = (u, id) => { const s = G('select * from stu where id=?', +id); if (!s) throw E('Student not found', 404); secFor(u, s.sec); return s; };
const pub = i => ({ id: i.id, name: i.name, type: i.type, active: i.active !== 0, wa_id: i.wa_id, has_token: !!i.wa_token, cfg: cfgOf(i) });
const validUser = (un, pw) => { if (!/^[a-z0-9._-]{3,30}$/.test(un) || un === 'admin') throw E('Username: 3-30 letters/numbers/._- (and not "admin")'); if (String(pw).length < 6) throw E('Password must be at least 6 characters'); if (G('select 1 x from users where username=?', un)) throw E('That username is already taken'); };

// ---------- WhatsApp (each institute sends from its OWN number). No token or DRY_RUN=1 -> only logged. ----------
async function wa(inst, phone, kind, tpl, params, header) {
  const to = norm(phone); let status = 'dry-run', info = '';
  if (inst.wa_id && inst.wa_token && !process.env.DRY_RUN) {
    const comps = []; if (header) comps.push({ type: 'header', parameters: [header] });
    comps.push({ type: 'body', parameters: params.map(t => ({ type: 'text', text: String(t).replace(/\s+/g, ' ').trim().slice(0, 900) })) });
    try {
      const r = await fetch(`https://graph.facebook.com/v21.0/${encodeURIComponent(inst.wa_id)}/messages`, { method: 'POST', headers: { Authorization: 'Bearer ' + inst.wa_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ messaging_product: 'whatsapp', to, type: 'template', template: { name: tpl, language: { code: cfgOf(inst).lang }, components: comps } }) });
      const j = await r.json(); status = r.ok ? 'sent' : 'failed'; info = r.ok ? '' : (j.error?.message || r.status);
    } catch (e) { status = 'failed'; info = e.message; }
    await sleep(80);
  }
  R('insert into log(ts,inst,phone,kind,status,info) values(?,?,?,?,?,?)', new Date().toISOString(), inst.id, to, kind, status, String(info).slice(0, 200));
}
const once = k => !G('select 1 x from sent where key=?', k), mark = k => R('insert or ignore into sent(key) values(?)', k);
const fmt = d => new Date(d + 'T00:00:00').toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
async function dueReminders(inst, month, force) {
  const c = cfgOf(inst); if (!force && Number(today().slice(8)) <= c.feeDay) return 0;
  const rows = Q(`select s.* from stu s where s.inst=? and not exists(select 1 from fee f where f.stu=s.id and f.month=? and f.status='cleared')`, inst.id, month); let n = 0;
  for (const s of rows) { const k = `due:${s.id}:${month}`; if (!force && !once(k)) continue; mark(k); n++; await wa(inst, s.phone, 'fee-due', c.tpl.due, [s.name, month, inst.name]); }
  return n;
}
setInterval(() => { Q('select * from inst where active!=0').forEach(i => dueReminders(i, today().slice(0, 7)).catch(console.error));
  R('delete from activity where id < (select coalesce(max(id),0)-5000 from activity)'); R('delete from log where id < (select coalesce(max(id),0)-20000 from log)'); }, 3600e3);
const queue = fn => { fn().catch(e => console.error('queue', e)); };

// ---------- student columns ----------
const colsOf = inst => Q('select * from col where inst=? order by id', inst);
const colFor = (u, id) => { const c = G('select * from col where id=?', +id); if (!c) throw E('Column not found', 404); instFor(u, c.inst); return c; };
const optsOf = v => [...new Set((Array.isArray(v) ? v : String(v || '').split(/[\n,]/)).map(x => str(x, 40).replace(/\|/g, '')).filter(Boolean))].slice(0, 20).join('|');
const cleanBase = b => { const name = str(b.name, 80), phone = norm(b.phone || ''), roll = str(b.roll, 10); if (!name) throw E('Name is required'); if (phone.length < 10 || phone.length > 15) throw E(`Enter a valid parent number for ${name}`); return { name, phone, roll }; };
const cleanExtra = (inst, ex) => { const out = {}; for (const c of colsOf(inst)) { const v = str((ex || {})[c.id], 200); if (v === '') continue;
  if (c.type === 'number' && !/^-?\d+(\.\d+)?$/.test(v)) throw E(`${c.name} must be a number`); if (c.type === 'date' && !isDay(v)) throw E(`${c.name} must be a date`);
  if (c.type === 'dropdown' && !c.opts.split('|').includes(v)) throw E(`${c.name}: choose one of the listed options`); out[c.id] = v; } return JSON.stringify(out); };
const killOtherAdmin = req => { const keep = (req.headers.authorization || '').slice(7); for (const [k, v] of sessions) if (v.role === 'super' && k !== keep) sessions.delete(k); };

// ---------- routes: [method, regex, handler(m, body, query, user, req), isPublic] ----------
const ipOf = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const routes = [
  ['POST', /^\/api\/login$/, (_, b, __, ___, req) => {
    const ip = ipOf(req), t = tries.get(ip); if (t && t.n >= 8 && t.until > Date.now()) throw E('Too many attempts. Try again in a few minutes.', 429);
    const un = str(b.username, 40).toLowerCase(), pw = String(b.password || '').slice(0, 200); let ses = null, msg = 'Wrong username or password';
    if (!un || un === 'admin') { /* the administrator signs in at /admin only */ }
    else { const r = G('select * from users where username=?', un);
      if (r && r.active && okPw(pw, r)) { const i = G('select active from inst where id=?', r.inst); if (i && i.active !== 0) { ses = { role: r.role, uid: r.id }; R('update users set last_login=? where id=?', new Date().toISOString(), r.id); } else msg = 'This institute account is suspended. Contact the administrator.'; } }
    if (!ses) { tries.set(ip, { n: (t && t.until > Date.now() ? t.n : 0) + 1, until: Date.now() + 600e3 }); throw E(msg, 401); }
    tries.delete(ip); const token = crypto.randomBytes(24).toString('hex'); sessions.set(token, { ...ses, exp: Date.now() + TTL });
    act(ses.role === 'super' ? { username: 'admin', role: 'super' } : authUser(token), 'login', ''); return { token }; }, true],
  ['POST', /^\/api\/admin\/login$/, (_, b, __, ___, req) => {
    const ip = 'adm:' + ipOf(req), t = tries.get(ip); if (t && t.n >= 6 && t.until > Date.now()) throw E('Too many attempts. Try again in a few minutes.', 429);
    const un = str(b.username, 40).toLowerCase(), pw = String(b.password || '').slice(0, 200), row = G('select * from admin where id=1'), eq = (x, y) => crypto.timingSafeEqual(sha(x), sha(y));
    // custom login saved in the panel; blank username + server OWNER_PASSWORD is the recovery route
    const ok = row ? ((un && un === row.username && okPw(pw, row)) || (!un && eq(pw, ADMIN_PASS))) : (eq(pw, ADMIN_PASS) && (!un || un === 'admin'));
    if (!ok) { tries.set(ip, { n: (t && t.until > Date.now() ? t.n : 0) + 1, until: Date.now() + 600e3 }); throw E('Wrong username or password', 401); }
    tries.delete(ip); const token = crypto.randomBytes(24).toString('hex'); sessions.set(token, { role: 'super', exp: Date.now() + TTL });
    act({ username: row?.username || 'admin', role: 'super' }, 'admin login', ''); return { token }; }, true],
  ['GET', /^\/api\/admin\/account$/, (_, __, ___, u) => { needSuper(u); const r = G('select username,updated from admin where id=1'); return { custom: !!r, username: r?.username || null, updated: r?.updated || null }; }],
  ['POST', /^\/api\/admin\/account$/, (_, b, __, u, req) => { needSuper(u); const un = str(b.username, 30).toLowerCase();
    if (!/^[a-z0-9._-]{3,30}$/.test(un)) throw E('Username: 3-30 letters, numbers or ._-'); if (String(b.password || '').length < 8) throw E('Password must be at least 8 characters'); if (b.password !== b.confirm) throw E('The two passwords do not match');
    const h = hashPw(String(b.password)); R('insert or replace into admin(id,username,salt,hash,updated) values(1,?,?,?,?)', un, h.salt, h.hash, new Date().toISOString()); killOtherAdmin(req); act(u, 'changed admin login'); return { ok: 1 }; }],
  ['DELETE', /^\/api\/admin\/account$/, (_, __, ___, u, req) => { needSuper(u); R('delete from admin where id=1'); killOtherAdmin(req); act(u, 'reset admin login to the server password'); return { ok: 1 }; }],
  ['GET', /^\/api\/me$/, (_, __, ___, u) => ({ role: u.role, name: u.name, username: u.username, inst: u.inst ?? null, sec: u.sec ?? null })],
  ['POST', /^\/api\/logout$/, (_, __, ___, u, req) => { sessions.delete((req.headers.authorization || '').slice(7)); return { ok: 1 }; }],
  ['POST', /^\/api\/password$/, () => { throw E('Passwords are managed by your administrator', 403); }],

  // institutes
  ['GET', /^\/api\/inst$/, (_, __, ___, u) => (u.role === 'super' ? Q('select * from inst order by id') : Q('select * from inst where id=?', u.inst)).map(pub)],
  ['GET', /^\/api\/overview$/, (_, __, ___, u) => { needSuper(u); const d = today(), c = (s, ...a) => G(s, ...a).c;
    return { totals: { institutes: c('select count(*) c from inst'), accounts: c('select count(*) c from users'), students: c('select count(*) c from stu'), activityToday: c('select count(*) c from activity where ts>=?', d), messagesToday: c('select count(*) c from log where ts>=?', d) },
      list: Q(`select i.*,(select count(*) from stu where inst=i.id) students,(select count(*) from sec where inst=i.id) sections,(select count(*) from users where inst=i.id) accounts,(select max(ts) from activity where inst=i.id) last from inst i order by id`)
        .map(i => ({ ...pub(i), students: i.students, sections: i.sections, accounts: i.accounts, last: i.last })) }; }],
  ['POST', /^\/api\/inst$/, (_, b, __, u) => { needSuper(u); const name = str(b.name, 80), un = str(b.username, 30).toLowerCase(); if (!name) throw E('Institute name is required'); validUser(un, b.password);
    const id = Number(R('insert into inst(name,type) values(?,?)', name, b.type === 'schl' ? 'schl' : 'cc').lastInsertRowid), h = hashPw(String(b.password));
    R('insert into users(username,name,role,inst,salt,hash) values(?,?,?,?,?,?)', un, str(b.head_name, 60) || (b.type === 'schl' ? 'Principal' : 'Director'), 'head', id, h.salt, h.hash);
    act(u, 'created institute', `${name} (login: ${un})`, id); return { id }; }],
  ['PUT', /^\/api\/inst\/(\d+)$/, (m, b, __, u) => { needAdm(u); const i = instFor(u, m[1]), c = b.cfg || {}, old = cfgOf(i), cfg = { color: /^#[0-9a-f]{6}$/i.test(c.color) ? c.color : old.color, feeDay: Math.min(28, Math.max(1, +c.feeDay || old.feeDay)), lang: str(c.lang, 10) || old.lang, tpl: { ...old.tpl } };
    for (const k of Object.keys(DEF.tpl)) if (c.tpl?.[k]) cfg.tpl[k] = str(c.tpl[k], 60);
    const name = u.role === 'super' ? str(b.name, 80) || i.name : i.name, type = u.role === 'super' ? (b.type === 'schl' ? 'schl' : 'cc') : i.type;
    R('update inst set name=?,type=?,wa_id=?,wa_token=?,cfg=? where id=?', name, type, str(b.wa_id ?? i.wa_id, 40), str(b.wa_token, 400) || i.wa_token, JSON.stringify(cfg), i.id); act(u, 'updated settings', '', i.id); return { ok: 1 }; }],
  ['POST', /^\/api\/inst\/(\d+)\/active$/, (m, b, __, u) => { needSuper(u); const i = instFor(u, m[1]); R('update inst set active=? where id=?', b.active ? 1 : 0, i.id); act(u, b.active ? 'activated institute' : 'suspended institute', i.name, i.id); return { ok: 1 }; }],
  ['DELETE', /^\/api\/inst\/(\d+)$/, (m, _, __, u) => { needSuper(u); const i = instFor(u, m[1]);
    R('delete from att where stu in (select id from stu where inst=?)', i.id); R('delete from fee where stu in (select id from stu where inst=?)', i.id);
    for (const t of ['stu', 'sec', 'users', 'log']) R(`delete from ${t} where inst=?`, i.id); R('delete from inst where id=?', i.id); act(u, 'deleted institute', i.name, null); return { ok: 1 }; }],

  // accounts (principal manages class teachers; admin manages everything)
  ['GET', /^\/api\/users$/, (_, __, q, u) => { needAdm(u); const i = instFor(u, q.inst); return Q(`select u.id,u.username,u.name,u.role,u.sec,u.active,u.last_login,(select name from sec where id=u.sec) sec_name from users u where u.inst=? order by u.role,u.id`, i.id); }],
  ['POST', /^\/api\/users$/, (_, b, __, u) => { needAdm(u); const i = instFor(u, b.inst), un = str(b.username, 30).toLowerCase(); validUser(un, b.password);
    const role = u.role === 'super' && b.role === 'head' ? 'head' : 'staff'; let sec = null;
    if (role === 'staff') { const s = G('select * from sec where id=? and inst=?', +b.sec, i.id); if (!s) throw E('Choose a class for this teacher'); sec = s.id; }
    const h = hashPw(String(b.password)); R('insert into users(username,name,role,inst,sec,salt,hash) values(?,?,?,?,?,?,?)', un, str(b.name, 60) || un, role, i.id, sec, h.salt, h.hash);
    act(u, 'created account', `${un} (${role})`, i.id); return { ok: 1 }; }],
  ['PUT', /^\/api\/users\/(\d+)$/, (m, b, __, u) => { needAdm(u); const t = G('select * from users where id=?', +m[1]); if (!t) throw E('Account not found', 404); instFor(u, t.inst); if (u.role !== 'super' && t.role !== 'staff') throw E('Not allowed', 403);
    if (b.password) { if (String(b.password).length < 6) throw E('Password must be at least 6 characters'); const h = hashPw(String(b.password)); R('update users set salt=?,hash=? where id=?', h.salt, h.hash, t.id); }
    if (b.active !== undefined) R('update users set active=? where id=?', b.active ? 1 : 0, t.id);
    if (b.sec && t.role === 'staff') { const s = G('select * from sec where id=? and inst=?', +b.sec, t.inst); if (!s) throw E('Class not found'); R('update users set sec=? where id=?', s.id, t.id); }
    act(u, 'updated account', t.username, t.inst); return { ok: 1 }; }],
  ['DELETE', /^\/api\/users\/(\d+)$/, (m, _, __, u) => { needAdm(u); const t = G('select * from users where id=?', +m[1]); if (!t) throw E('Account not found', 404); instFor(u, t.inst); if (u.role !== 'super' && t.role !== 'staff') throw E('Not allowed', 403);
    R('delete from users where id=?', t.id); act(u, 'deleted account', t.username, t.inst); return { ok: 1 }; }],
  ['GET', /^\/api\/activity$/, (_, __, q, u) => { const lim = Math.min(300, +q.limit || 100);
    if (u.role === 'super' && !q.inst) return Q('select a.*,(select name from inst where id=a.inst) inst_name from activity a order by id desc limit ?', lim);
    needAdm(u); const i = instFor(u, q.inst || u.inst); return Q('select a.*,(select name from inst where id=a.inst) inst_name from activity a where inst=? order by id desc limit ?', i.id, lim); }],

  // classes / batches: every role can SEE the list, only the assigned teacher (or head/admin) can open one
  ['GET', /^\/api\/sec$/, (_, __, q, u) => { const i = instFor(u, q.inst);
    return Q(`select s.id,s.name,(select count(*) from stu where sec=s.id) n,(select name from users where sec=s.id and role='staff' and active=1 limit 1) teacher from sec s where inst=? order by name`, i.id).map(s => ({ ...s, locked: u.role === 'staff' && u.sec !== s.id })); }],
  ['POST', /^\/api\/sec$/, (_, b, __, u) => { needAdm(u); const i = instFor(u, b.inst), name = str(b.name, 60); if (!name) throw E('Name is required'); const id = Number(R('insert into sec(inst,name) values(?,?)', i.id, name).lastInsertRowid); act(u, 'created class', name, i.id); return { id }; }],
  ['DELETE', /^\/api\/sec\/(\d+)$/, (m, _, __, u) => { needAdm(u); const s = secFor(u, m[1]);
    R('delete from att where stu in (select id from stu where sec=?)', s.id); R('delete from fee where stu in (select id from stu where sec=?)', s.id); R('delete from stu where sec=?', s.id); R('update users set sec=null where sec=?', s.id); R('delete from sec where id=?', s.id); act(u, 'deleted class', s.name, s.inst); return { ok: 1 }; }],

  // students
  ['GET', /^\/api\/stu$/, (_, __, q, u) => Q('select * from stu where sec=? order by cast(roll as integer),name', secFor(u, q.sec).id).map(r => ({ ...r, extra: JSON.parse(r.extra || '{}') }))],
  ['GET', /^\/api\/cols$/, (_, __, q, u) => colsOf(instFor(u, q.inst).id).map(c => ({ ...c, opts: c.opts ? c.opts.split('|') : [] }))],
  ['POST', /^\/api\/cols$/, (_, b, __, u) => { const i = instFor(u, b.inst), name = str(b.name, 40), type = ['text', 'date', 'number', 'dropdown'].includes(b.type) ? b.type : 'text', all = colsOf(i.id);
    if (!name) throw E('Column name is required'); if (all.length >= 30) throw E('Maximum 30 extra columns'); if (all.some(c => c.name.toLowerCase() === name.toLowerCase())) throw E('That column already exists');
    const opts = type === 'dropdown' ? optsOf(b.opts) : ''; if (type === 'dropdown' && !opts) throw E('Add at least one option');
    const id = Number(R('insert into col(inst,name,type,opts) values(?,?,?,?)', i.id, name, type, opts).lastInsertRowid); act(u, 'added column', name, i.id); return { id }; }],
  ['PUT', /^\/api\/cols\/(\d+)$/, (m, b, __, u) => { const c = colFor(u, m[1]), name = str(b.name, 40) || c.name, opts = c.type === 'dropdown' ? (optsOf(b.opts) || c.opts) : '';
    R('update col set name=?,opts=? where id=?', name, opts, c.id); act(u, 'edited column', name, c.inst); return { ok: 1 }; }],
  ['DELETE', /^\/api\/cols\/(\d+)$/, (m, _, __, u) => { needAdm(u); const c = colFor(u, m[1]); R('delete from col where id=?', c.id); act(u, 'deleted column', c.name, c.inst); return { ok: 1 }; }],
  ['POST', /^\/api\/stu$/, (_, b, __, u) => { const s = secFor(u, b.sec), x = cleanBase(b), ex = cleanExtra(s.inst, b.extra);
    const id = Number(R('insert into stu(inst,sec,name,roll,phone,extra) values(?,?,?,?,?,?)', s.inst, s.id, x.name, x.roll, x.phone, ex).lastInsertRowid); act(u, 'added student', `${x.name} to ${s.name}`, s.inst); return { id }; }],
  ['PUT', /^\/api\/stu\/(\d+)$/, (m, b, __, u) => { const s = stuFor(u, m[1]), x = cleanBase(b), ex = cleanExtra(s.inst, b.extra);
    R('update stu set name=?,roll=?,phone=?,extra=? where id=?', x.name, x.roll, x.phone, ex, s.id); act(u, 'edited student', x.name, s.inst); return { ok: 1 }; }],
  ['POST', /^\/api\/stu\/bulk$/, (_, b, __, u) => { const s = secFor(u, b.sec), cols = colsOf(s.inst); let n = 0, skip = 0; // columns: Name, Number, Roll, then your extra columns (tab-separated from Excel/Sheets, or comma-separated)
    for (const line of String(b.text).split('\n').slice(0, 500)) { if (!line.trim()) continue; const p = (line.includes('\t') ? line.split('\t') : line.split(',')).map(x => x.trim());
      try { const x = cleanBase({ name: p[0], phone: p[1], roll: p[2] }), ex = {}; cols.forEach((c, k) => { if (p[3 + k]) ex[c.id] = p[3 + k]; });
        R('insert into stu(inst,sec,name,roll,phone,extra) values(?,?,?,?,?,?)', s.inst, s.id, x.name, x.roll, x.phone, cleanExtra(s.inst, ex)); n++; } catch { skip++; } }
    act(u, 'imported students', `${n} to ${s.name}`, s.inst); return { added: n, skipped: skip }; }],
  ['DELETE', /^\/api\/stu\/(\d+)$/, (m, _, __, u) => { const s = stuFor(u, m[1]); R('delete from att where stu=?', s.id); R('delete from fee where stu=?', s.id); R('delete from stu where id=?', s.id); act(u, 'removed student', s.name, s.inst); return { ok: 1 }; }],

  // attendance
  ['GET', /^\/api\/att$/, (_, __, q, u) => { if (!isDay(q.day)) throw E('Invalid date'); return Q(`select s.id,s.name,s.roll,coalesce(a.status,'P') status,a.status saved from stu s left join att a on a.stu=s.id and a.day=? where s.sec=? order by cast(s.roll as integer),s.name`, q.day, secFor(u, q.sec).id); }],
  ['POST', /^\/api\/att$/, (_, b, __, u) => { const sec = secFor(u, b.sec), i = instFor(u, sec.inst), c = cfgOf(i); if (!isDay(b.day) || b.day > today()) throw E('Choose today or an earlier date');
    const ab = new Set((Array.isArray(b.absent) ? b.absent : []).map(Number)), out = [];
    for (const s of Q('select * from stu where sec=?', sec.id)) { R('insert or replace into att(stu,day,status) values(?,?,?)', s.id, b.day, ab.has(s.id) ? 'A' : 'P');
      if (ab.has(s.id) && once(`abs:${s.id}:${b.day}`)) { mark(`abs:${s.id}:${b.day}`); out.push(s); } }
    queue(async () => { for (const s of out) await wa(i, s.phone, 'absent', c.tpl.absent, [s.name, fmt(b.day), i.name]); });
    act(u, 'saved attendance', `${sec.name} ${b.day}: ${ab.size} absent`, sec.inst); return { saved: 1, alerts: out.length }; }],

  // fees (teachers can view their class, only head/admin can approve)
  ['GET', /^\/api\/fee$/, (_, __, q, u) => { if (!isMonth(q.month)) throw E('Invalid month'); return Q(`select s.id,s.name,s.roll,coalesce(f.status,'pending') status,f.cleared from stu s left join fee f on f.stu=s.id and f.month=? where s.sec=? order by cast(s.roll as integer),s.name`, q.month, secFor(u, q.sec).id); }],
  ['POST', /^\/api\/fee\/clear$/, (_, b, __, u) => { needAdm(u); if (!isMonth(b.month)) throw E('Invalid month'); const s = stuFor(u, b.stu), i = instFor(u, s.inst);
    R('insert or replace into fee(stu,month,status,cleared) values(?,?,?,?)', s.id, b.month, 'cleared', today());
    if (once(`paid:${s.id}:${b.month}`)) { mark(`paid:${s.id}:${b.month}`); queue(() => wa(i, s.phone, 'fee-paid', cfgOf(i).tpl.paid, [s.name, b.month, i.name])); }
    act(u, 'approved fees', `${s.name} ${b.month}`, s.inst); return { ok: 1 }; }],
  ['POST', /^\/api\/fee\/remind$/, async (_, b, __, u) => { needAdm(u); if (!isMonth(b.month)) throw E('Invalid month'); const i = instFor(u, b.inst); const n = await dueReminders(i, b.month, true); act(u, 'sent fee reminders', `${n} parents`, i.id); return { sent: n }; }],

  // notices: head/admin -> everyone or one class; teacher -> own class only
  ['POST', /^\/api\/announce$/, (_, b, __, u) => { const text = str(b.text, 900); if (!text) throw E('Write a message first');
    let i, secId = null; if (u.role === 'staff') { secId = secFor(u, u.sec).id; i = instFor(u, u.inst); } else { i = instFor(u, b.inst); if (b.sec) secId = secFor(u, b.sec).id; }
    const c = cfgOf(i); let tpl = c.tpl.ann, header = null;
    if (b.file) { const ext = path.extname(String(b.file.name || '')).toLowerCase(); if (!['.pdf', '.jpg', '.jpeg', '.png'].includes(ext)) throw E('Only PDF, JPG or PNG files are allowed');
      const buf = Buffer.from(String(b.file.data || ''), 'base64'); if (!buf.length || buf.length > 8e6) throw E('File must be under 8 MB');
      const fn = crypto.randomBytes(8).toString('hex') + ext; fs.writeFileSync(path.join(UP, fn), buf); const link = `${BASE}/files/${fn}`;
      if (ext === '.pdf') { tpl = c.tpl.annDoc; header = { type: 'document', document: { link, filename: str(b.file.name, 80) || 'notice.pdf' } }; } else { tpl = c.tpl.annImg; header = { type: 'image', image: { link } }; } }
    const phones = [...new Set(Q(secId ? 'select phone from stu where sec=?' : 'select phone from stu where inst=?', secId || i.id).map(r => r.phone))];
    queue(async () => { for (const p of phones) await wa(i, p, 'announce', tpl, [text], header); });
    act(u, 'sent notice', `${phones.length} parents${b.file ? ' + file' : ''}`, i.id); return { queued: phones.length }; }],

  // dashboard numbers (teachers see only their own class)
  ['GET', /^\/api\/stats$/, (_, __, q, u) => { const i = instFor(u, q.inst), d = today(), mo = d.slice(0, 7), c = (s, ...a) => G(s, ...a).c, sf = u.role === 'staff' ? ` and s.sec=${+u.sec || 0}` : '';
    const n = c(`select count(*) c from stu s where s.inst=?${sf}`, i.id), ab = st => c(`select count(*) c from att a join stu s on s.id=a.stu where s.inst=? and a.day=? and a.status=?${sf}`, i.id, d, st);
    const paid = c(`select count(*) c from fee f join stu s on s.id=f.stu where s.inst=? and f.month=? and f.status='cleared'${sf}`, i.id, mo);
    return { students: n, present: ab('P'), absent: ab('A'), paid, pending: n - paid, sections: c('select count(*) c from sec where inst=?', i.id), msgs: u.role === 'staff' ? null : c('select count(*) c from log where inst=? and ts>=?', i.id, d) }; }],
  ['GET', /^\/api\/log$/, (_, __, q, u) => { needAdm(u); return Q('select * from log where inst=? order by id desc limit 200', instFor(u, q.inst).id); }],
  ['GET', /^\/api\/export$/, (_, __, q, u) => { needAdm(u); const i = instFor(u, q.inst); // same columns as the n8n chatbot sheet
    const rows = q.kind === 'attendance' ? Q('select a.day Date,a.stu Student_ID,a.status Status from att a join stu s on s.id=a.stu where s.inst=?', i.id) : Q('select id Student_ID,name Name,roll Roll_No,phone Parent_Phone_1 from stu where inst=?', i.id);
    return { csv: rows.length ? [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))].join('\n') : '' }; }],
];

const MIME = { '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png' };
const readBody = req => new Promise((res, rej) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 12e6) { rej(E('Request too large', 413)); req.destroy(); } else c.push(d); });
  req.on('end', () => { try { res(c.length ? JSON.parse(Buffer.concat(c).toString()) : {}); } catch { rej(E('Invalid request')); } }); req.on('error', rej); });
http.createServer(async (req, res) => {
  const u = new URL(req.url, BASE), H = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ...(req.headers['x-forwarded-proto'] === 'https' ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}) };
  const send = (c, d, t = 'application/json') => { res.writeHead(c, { ...H, 'Content-Type': t, 'Cache-Control': 'no-store' }); res.end(t === 'application/json' ? JSON.stringify(d) : d); };
  try {
    if (u.pathname === '/' || u.pathname === '/admin') return send(200, fs.readFileSync(['index.html', 'public/index.html'].map(f => path.join(__dirname, f)).find(f => fs.existsSync(f))), 'text/html; charset=utf-8');
    if (u.pathname.startsWith('/files/')) { const f = path.join(UP, path.basename(u.pathname)); if (!fs.existsSync(f)) return send(404, {});
      res.writeHead(200, { ...H, 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream' }); return res.end(fs.readFileSync(f)); }
    for (const [method, re, fn, open] of routes) {
      const m = u.pathname.match(re); if (method !== req.method || !m) continue;
      let user = null; if (!open) { user = authUser((req.headers.authorization || '').slice(7)); if (!user) return send(401, { error: 'Please sign in again' }); }
      const b = req.method === 'GET' || req.method === 'DELETE' ? {} : await readBody(req);
      return send(200, await fn(m, b, Object.fromEntries(u.searchParams), user, req));
    }
    send(404, { error: 'Not found' });
  } catch (e) { if (!e.status) console.error(e); send(e.status || 400, { error: e.status ? e.message : (e.message || 'Something went wrong') }); }
}).listen(PORT, () => console.log(`Institute Desk running on ${BASE}` + (BOOT_RANDOM ? `\nOWNER_PASSWORD is not set. Temporary admin password for /admin: ${ADMIN_PASS}` : '')));
