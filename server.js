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
// Phase 2: per-institute display name, banner image file and contact profile. Each lives on that institute's own row.
for (const c of ["display_name text default ''", "banner text default ''", "profile text default '{}'"]) try { db.exec('alter table inst add column ' + c); } catch {}
db.exec(`create table if not exists admin(id integer primary key check(id=1),username text,salt text,hash text,updated text);
create table if not exists col(id integer primary key,inst integer,name text,type text,opts text default '');`);
try { db.exec("alter table stu add column extra text default '{}'"); } catch {}
const Q = (s, ...a) => db.prepare(s).all(...a), G = (s, ...a) => db.prepare(s).get(...a), R = (s, ...a) => db.prepare(s).run(...a);

// Phase 3: a class record (sec) = class name (required) + section (optional); students link to it by id, so attendance, fees and teacher
// assignments keep working. All changes are additive: existing rows are kept and only get new, empty columns.
try { db.exec("alter table sec add column section text default ''"); } catch {}
for (const c of ["adm_no text default ''", "parent text default ''", "relation text default ''", "gender text default ''", "dob text default ''", "adm_date text default ''", "address text default ''", "phone2 text default ''"]) try { db.exec('alter table stu add column ' + c); } catch {}
const genAdm = (inst, id) => { const base = 'ADM-' + String(id).padStart(5, '0'); let a = base, n = 1; while (G('select 1 x from stu where inst=? and lower(adm_no)=lower(?)', inst, a)) a = `${base}-${++n}`; return a; };
for (const r of Q("select id,inst from stu where coalesce(adm_no,'')=''")) R('update stu set adm_no=? where id=?', genAdm(r.inst, r.id), r.id); // older students get an admission number so they can be searched by it
for (const x of ['create index if not exists sec_inst on sec(inst)', 'create index if not exists stu_sec on stu(sec)', 'create index if not exists stu_inst_name on stu(inst, lower(name))',
  "create unique index if not exists stu_adm_uq on stu(inst, lower(adm_no)) where adm_no<>''"]) try { db.exec(x); } catch (e) { console.error('index', e.message); }
const secLabel = c => (c.section ? `${c.name} - ${c.section}` : c.name);
const natCmp = new Intl.Collator('en', { numeric: true, sensitivity: 'base' });
const bySec = (a, b) => natCmp.compare(a.name, b.name) || natCmp.compare(a.section || '', b.section || '');
const secTaken = (inst, name, section, except = 0) => G("select 1 x from sec where inst=? and lower(name)=lower(?) and lower(coalesce(section,''))=lower(?) and id<>?", inst, name, section, except);
const E = (m, status = 400) => Object.assign(new Error(m), { status });
const str = (v, n) => String(v ?? '').trim().slice(0, n);
const DEF = { color: '#356AE6', feeDay: 15, lang: 'en', tpl: { absent: 'absent_alert', paid: 'fee_received', due: 'fee_due', ann: 'announcement', annImg: 'announcement_image', annDoc: 'announcement_document' } };
const cfgOf = i => { let c = {}; try { c = JSON.parse(i.cfg || '{}'); } catch {} return { ...DEF, ...c, tpl: { ...DEF.tpl, ...(c.tpl || {}) } }; };
const norm = p => { const d = String(p).replace(/\D/g, ''); return d.length === 10 ? '91' + d : d; };
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
const isDay = s => /^\d{4}-\d{2}-\d{2}$/.test(s || ''), isMonth = s => /^\d{4}-\d{2}$/.test(s || '');
process.on('uncaughtException', e => console.error('uncaught', e)); process.on('unhandledRejection', e => console.error('unhandled', e));

// ---------- passwords, sessions, login throttle ----------
const hashPw = (p, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(p, salt, 32).toString('hex') });
const okPwRaw = (p, u) => { const a = Buffer.from(crypto.scryptSync(p, u.salt, 32).toString('hex')), b = Buffer.from(u.hash); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const okPw = (p, u) => okPwRaw(p, u) || okPwRaw(p.trim(), u);
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
const bannerUrl = i => (i.banner ? '/files/' + i.banner : '');
const pub = i => ({ id: i.id, name: i.name, type: i.type, active: i.active !== 0, wa_id: i.wa_id, has_token: !!i.wa_token, cfg: cfgOf(i), display_name: i.display_name || '', banner: bannerUrl(i) });
// contact profile + internal notes: only ever returned by administrator routes (never by pub())
const PROF = { contact: 80, phone: 20, email: 80, address: 300, notes: 600 };
const profOf = i => { let p = {}; try { p = JSON.parse(i.profile || '{}'); } catch {} return Object.fromEntries(Object.entries(PROF).map(([k, n]) => [k, str(p[k], n)])); };
const cleanProfile = (b, old = {}) => { const out = { ...old }; for (const [k, n] of Object.entries(PROF)) if (b && b[k] !== undefined) out[k] = str(b[k], n);
  if (out.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(out.email)) throw E('Enter a valid email address'); if (out.phone && !/^[\d\s+()-]{7,20}$/.test(out.phone)) throw E('Enter a valid phone number'); return out; };
const okColor = c => /^#[0-9a-f]{6}$/i.test(String(c || ''));
const ADM_SQL = `select i.*,(select count(*) from stu where inst=i.id) students,(select count(*) from sec where inst=i.id) sections,(select count(*) from users where inst=i.id) accounts,(select count(*) from users where inst=i.id and active=1) accounts_on,(select max(ts) from activity where inst=i.id) last from inst i`;
const admRow = i => ({ ...pub(i), profile: profOf(i), students: i.students, sections: i.sections, accounts: i.accounts, accounts_on: i.accounts_on, last: i.last });
// banner images: content is sniffed (not trusted by file name) and each file is named after its own institute
const sniff = b => b.length < 16 ? null : (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) ? '.jpg' : b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) ? '.png' : (b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP') ? '.webp' : null;
const dropBanner = i => { if (i.banner && i.banner.startsWith(`banner-${i.id}-`)) try { fs.unlinkSync(path.join(UP, path.basename(i.banner))); } catch {} };
const validUser = (un, pw) => { if (!/^[a-z0-9._-]{3,30}$/.test(un) || un === 'admin') throw E('Username: 3-30 letters/numbers/._- (and not "admin")'); if (String(pw).length < 6) throw E('Password must be at least 6 characters'); if (G('select 1 x from users where username=?', un)) throw E('That username is already taken'); };

// ---------- WhatsApp (each institute sends from its OWN number). No token or DRY_RUN=1 -> only logged. ----------
async function wa(inst, phone, kind, tpl, params, header) {
  const to = norm(phone); let status = 'dry-run', info = '';
  if (inst.wa_id && inst.wa_token && !process.env.DRY_RUN) {
    const comps = []; if (header) comps.push({ type: 'header', parameters: [header] });
    if (tpl !== 'hello_world') comps.push({ type: 'body', parameters: params.map(t => ({ type: 'text', text: String(t).replace(/\s+/g, ' ').trim().slice(0, 900) })) }); // 'hello_world' is Meta's built-in test template (no variables)
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
const ADM_RE = /^[A-Za-z0-9][A-Za-z0-9\-\/._ ]{0,29}$/, phoneOk = p => p.length >= 10 && p.length <= 15;
const cleanStu = b => {
  const name = str(b.name, 80); if (!name) throw E('Student name is required');
  const parent = str(b.parent, 80); if (!parent) throw E(`Parent or guardian name is required for ${name}`);
  const phone = norm(b.phone || ''); if (!phoneOk(phone)) throw E(`Enter a valid parent contact number for ${name}`);
  const p2 = String(b.phone2 || '').trim(), phone2 = p2 ? norm(p2) : ''; if (phone2 && !phoneOk(phone2)) throw E(`Enter a valid alternate number for ${name}`);
  const gender = str(b.gender, 10); if (!['', 'Male', 'Female', 'Other'].includes(gender)) throw E('Choose a valid gender');
  const dob = str(b.dob, 10), adm_date = str(b.adm_date, 10);
  if (dob && (!isDay(dob) || dob > today())) throw E('Date of birth must be a valid date in the past');
  if (adm_date && !isDay(adm_date)) throw E('Admission date must be a valid date');
  const adm_no = str(b.adm_no, 30); if (adm_no && !ADM_RE.test(adm_no)) throw E('Admission number can use letters, numbers and - / . _ only');
  return { name, parent, phone, phone2, gender, dob, adm_date, adm_no, relation: str(b.relation, 20), roll: str(b.roll, 10), address: str(b.address, 300) };
};
const admTaken = (inst, adm, except = 0) => adm && G('select 1 x from stu where inst=? and lower(adm_no)=lower(?) and id<>?', inst, adm, except);
const insertStu = (s, x, ex) => {
  const id = Number(R('insert into stu(inst,sec,name,roll,phone,extra,adm_no,parent,relation,gender,dob,adm_date,address,phone2) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', s.inst, s.id, x.name, x.roll, x.phone, ex, x.adm_no, x.parent, x.relation, x.gender, x.dob, x.adm_date, x.address, x.phone2).lastInsertRowid);
  if (!x.adm_no) R('update stu set adm_no=? where id=?', genAdm(s.inst, id), id); return id;
};
const STU_SQL = 'select s.id,s.sec,s.adm_no,s.name,s.roll,s.parent,s.relation,s.phone,s.phone2,s.gender,s.dob,s.adm_date,s.address,s.extra,c.name cls,coalesce(c.section,\'\') section';
const stuOut = r => { let extra = {}; try { extra = JSON.parse(r.extra || '{}'); } catch {} return { ...r, extra, label: secLabel({ name: r.cls, section: r.section }) }; };
const LESC = " escape '\\'";
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
    const un = str(b.username, 40).toLowerCase(), pw = String(b.password || '').slice(0, 200), row = G('select * from admin where id=1'), eq = (x, y) => crypto.timingSafeEqual(sha(x), sha(y)) || crypto.timingSafeEqual(sha(x.trim()), sha(y));
    // custom login saved in the panel; blank username + server OWNER_PASSWORD is the recovery route
    const ok = row ? ((un && un === row.username && okPw(pw, row)) || (!un && eq(pw, ADMIN_PASS))) : (eq(pw, ADMIN_PASS) && (!un || un === 'admin'));
    if (!ok) { tries.set(ip, { n: (t && t.until > Date.now() ? t.n : 0) + 1, until: Date.now() + 600e3 }); throw E('Wrong username or password', 401); }
    tries.delete(ip); const token = crypto.randomBytes(24).toString('hex'); sessions.set(token, { role: 'super', exp: Date.now() + TTL });
    act({ username: row?.username || 'admin', role: 'super' }, 'admin login', ''); return { token }; }, true],
  ['GET', /^\/api\/admin\/account$/, (_, __, ___, u) => { needSuper(u); const r = G('select username,updated from admin where id=1'); return { custom: !!r, username: r?.username || null, updated: r?.updated || null }; }],
  ['POST', /^\/api\/admin\/account$/, (_, b, __, u, req) => { needSuper(u); const un = str(b.username, 30).toLowerCase();
    if (!/^[a-z0-9._-]{3,30}$/.test(un)) throw E('Username: 3-30 letters, numbers or ._-'); if (String(b.password || '').length < 8) throw E('Password must be at least 8 characters'); if (b.password !== b.confirm) throw E('The two passwords do not match');
    const h = hashPw(String(b.password).trim()); R('insert or replace into admin(id,username,salt,hash,updated) values(1,?,?,?,?)', un, h.salt, h.hash, new Date().toISOString()); killOtherAdmin(req); act(u, 'changed admin login'); return { ok: 1 }; }],
  ['DELETE', /^\/api\/admin\/account$/, (_, __, ___, u, req) => { needSuper(u); R('delete from admin where id=1'); killOtherAdmin(req); act(u, 'reset admin login to the server password'); return { ok: 1 }; }],
  ['GET', /^\/api\/me$/, (_, __, ___, u) => ({ role: u.role, name: u.name, username: u.username, inst: u.inst ?? null, sec: u.sec ?? null })],
  ['POST', /^\/api\/logout$/, (_, __, ___, u, req) => { sessions.delete((req.headers.authorization || '').slice(7)); return { ok: 1 }; }],
  ['POST', /^\/api\/password$/, () => { throw E('Passwords are managed by your administrator', 403); }],

  // institutes
  ['GET', /^\/api\/inst$/, (_, __, ___, u) => (u.role === 'super' ? Q('select * from inst order by id') : Q('select * from inst where id=?', u.inst)).map(pub)],
  ['GET', /^\/api\/overview$/, (_, __, ___, u) => { needSuper(u); const d = today(), c = (s, ...a) => G(s, ...a).c;
    return { totals: { institutes: c('select count(*) c from inst'), accounts: c('select count(*) c from users'), students: c('select count(*) c from stu'), activityToday: c('select count(*) c from activity where ts>=?', d), messagesToday: c('select count(*) c from log where ts>=?', d) },
      list: Q(ADM_SQL + ' order by i.id').map(admRow) }; }],
  ['POST', /^\/api\/inst$/, (_, b, __, u) => { needSuper(u); const name = str(b.name, 80), un = str(b.username, 30).toLowerCase(); if (!name) throw E('Institute name is required'); validUser(un, b.password);
    const prof = JSON.stringify(cleanProfile(b.profile)), disp = str(b.display_name, 80), cfg = JSON.stringify(okColor(b.color) ? { color: b.color } : {}), h = hashPw(String(b.password).trim()); let id;
    db.exec('begin'); try { id = Number(R('insert into inst(name,type,display_name,profile,cfg) values(?,?,?,?,?)', name, b.type === 'schl' ? 'schl' : 'cc', disp, prof, cfg).lastInsertRowid);
      R('insert into users(username,name,role,inst,salt,hash) values(?,?,?,?,?,?)', un, str(b.head_name, 60) || (b.type === 'schl' ? 'Principal' : 'Director'), 'head', id, h.salt, h.hash); db.exec('commit'); } catch (e) { db.exec('rollback'); throw e; }
    act(u, 'created institute', `${name} (login: ${un})`, id); return { id }; }],
  // administrator-only: one institute's full record, editable details, branding (custom name, colour, banner image)
  ['GET', /^\/api\/admin\/inst\/(\d+)$/, (m, _, __, u) => { needSuper(u); instFor(u, m[1]); return admRow(G(ADM_SQL + ' where i.id=?', +m[1])); }],
  ['PUT', /^\/api\/admin\/inst\/(\d+)$/, (m, b, __, u) => { needSuper(u); const i = instFor(u, m[1]), f = {};
    if (b.name !== undefined) { const n = str(b.name, 80); if (!n) throw E('Institute name is required'); f.name = n; }
    if (b.type !== undefined) f.type = b.type === 'schl' ? 'schl' : 'cc';
    if (b.display_name !== undefined) f.display_name = str(b.display_name, 80);
    if (b.profile !== undefined) f.profile = JSON.stringify(cleanProfile(b.profile, profOf(i)));
    if (b.color !== undefined) { if (!okColor(b.color)) throw E('Choose a valid colour'); let raw = {}; try { raw = JSON.parse(i.cfg || '{}'); } catch {} raw.color = b.color; f.cfg = JSON.stringify(raw); }
    const ks = Object.keys(f); if (!ks.length) throw E('Nothing to update');
    R(`update inst set ${ks.map(k => k + '=?').join(',')} where id=?`, ...ks.map(k => f[k]), i.id); act(u, 'updated institute', ks.join(', '), i.id); return admRow(G(ADM_SQL + ' where i.id=?', i.id)); }],
  ['POST', /^\/api\/admin\/inst\/(\d+)\/banner$/, (m, b, __, u) => { needSuper(u); const i = instFor(u, m[1]), buf = Buffer.from(String(b.data || '').replace(/^data:[^,]*,/, ''), 'base64');
    if (!buf.length) throw E('Choose an image first'); if (buf.length > 4e6) throw E('Image must be under 4 MB'); const ext = sniff(buf); if (!ext) throw E('Only JPG, PNG or WebP images are allowed');
    const fn = `banner-${i.id}-${crypto.randomBytes(8).toString('hex')}${ext}`; fs.writeFileSync(path.join(UP, fn), buf); R('update inst set banner=? where id=?', fn, i.id); dropBanner(i);
    act(u, 'changed banner', '', i.id); return { banner: '/files/' + fn }; }],
  ['DELETE', /^\/api\/admin\/inst\/(\d+)\/banner$/, (m, _, __, u) => { needSuper(u); const i = instFor(u, m[1]); R("update inst set banner='' where id=?", i.id); dropBanner(i); act(u, 'removed banner', '', i.id); return { ok: 1 }; }],
  ['PUT', /^\/api\/inst\/(\d+)$/, (m, b, __, u) => { needAdm(u); const i = instFor(u, m[1]), c = b.cfg || {}, old = cfgOf(i), cfg = { color: /^#[0-9a-f]{6}$/i.test(c.color) ? c.color : old.color, feeDay: Math.min(28, Math.max(1, +c.feeDay || old.feeDay)), lang: str(c.lang, 10) || old.lang, tpl: { ...old.tpl } };
    for (const k of Object.keys(DEF.tpl)) if (c.tpl?.[k]) cfg.tpl[k] = str(c.tpl[k], 60);
    const name = u.role === 'super' ? str(b.name, 80) || i.name : i.name, type = u.role === 'super' ? (b.type === 'schl' ? 'schl' : 'cc') : i.type;
    R('update inst set name=?,type=?,wa_id=?,wa_token=?,cfg=? where id=?', name, type, str(b.wa_id ?? i.wa_id, 40), str(b.wa_token, 400) || i.wa_token, JSON.stringify(cfg), i.id); act(u, 'updated settings', '', i.id); return { ok: 1 }; }],
  ['POST', /^\/api\/inst\/(\d+)\/active$/, (m, b, __, u) => { needSuper(u); const i = instFor(u, m[1]); R('update inst set active=? where id=?', b.active ? 1 : 0, i.id); act(u, b.active ? 'activated institute' : 'suspended institute', i.name, i.id); return { ok: 1 }; }],
  ['DELETE', /^\/api\/inst\/(\d+)$/, (m, _, __, u) => { needSuper(u); const i = instFor(u, m[1]);
    R('delete from att where stu in (select id from stu where inst=?)', i.id); R('delete from fee where stu in (select id from stu where inst=?)', i.id);
    for (const t of ['stu', 'sec', 'users', 'log', 'col']) R(`delete from ${t} where inst=?`, i.id); R('delete from inst where id=?', i.id); dropBanner(i); act(u, 'deleted institute', i.name, null); return { ok: 1 }; }],

  // accounts (principal manages class teachers; admin manages everything)
  ['GET', /^\/api\/users$/, (_, __, q, u) => { needAdm(u); const i = instFor(u, q.inst); return Q(`select u.id,u.username,u.name,u.role,u.sec,u.active,u.last_login,(select name||case when coalesce(section,'')<>'' then ' - '||section else '' end from sec where id=u.sec) sec_name from users u where u.inst=? order by u.role,u.id`, i.id); }],
  ['POST', /^\/api\/users$/, (_, b, __, u) => { needAdm(u); const i = instFor(u, b.inst), un = str(b.username, 30).toLowerCase(); validUser(un, b.password);
    const role = u.role === 'super' && b.role === 'head' ? 'head' : 'staff'; let sec = null;
    if (role === 'staff') { const s = G('select * from sec where id=? and inst=?', +b.sec, i.id); if (!s) throw E('Choose a class for this teacher'); sec = s.id; }
    const h = hashPw(String(b.password).trim()); R('insert into users(username,name,role,inst,sec,salt,hash) values(?,?,?,?,?,?,?)', un, str(b.name, 60) || un, role, i.id, sec, h.salt, h.hash);
    act(u, 'created account', `${un} (${role})`, i.id); return { ok: 1 }; }],
  ['PUT', /^\/api\/users\/(\d+)$/, (m, b, __, u) => { needAdm(u); const t = G('select * from users where id=?', +m[1]); if (!t) throw E('Account not found', 404); instFor(u, t.inst); if (u.role !== 'super' && t.role !== 'staff') throw E('Not allowed', 403);
    if (b.password) { if (String(b.password).length < 6) throw E('Password must be at least 6 characters'); const h = hashPw(String(b.password).trim()); R('update users set salt=?,hash=? where id=?', h.salt, h.hash, t.id); }
    if (b.active !== undefined) R('update users set active=? where id=?', b.active ? 1 : 0, t.id);
    if (b.sec && t.role === 'staff') { const s = G('select * from sec where id=? and inst=?', +b.sec, t.inst); if (!s) throw E('Class not found'); R('update users set sec=? where id=?', s.id, t.id); }
    act(u, 'updated account', t.username, t.inst); return { ok: 1 }; }],
  ['DELETE', /^\/api\/users\/(\d+)$/, (m, _, __, u) => { needAdm(u); const t = G('select * from users where id=?', +m[1]); if (!t) throw E('Account not found', 404); instFor(u, t.inst); if (u.role !== 'super' && t.role !== 'staff') throw E('Not allowed', 403);
    R('delete from users where id=?', t.id); act(u, 'deleted account', t.username, t.inst); return { ok: 1 }; }],
  ['GET', /^\/api\/activity$/, (_, __, q, u) => { const lim = Math.min(300, +q.limit || 100);
    if (u.role === 'super' && !q.inst) return Q('select a.*,(select name from inst where id=a.inst) inst_name from activity a order by id desc limit ?', lim);
    needAdm(u); const i = instFor(u, q.inst || u.inst); return Q('select a.*,(select name from inst where id=a.inst) inst_name from activity a where inst=? order by id desc limit ?', i.id, lim); }],

  // classes / batches: a class = name (required) + section (optional). Every role can SEE the list, only the assigned teacher (or head/admin) can open one
  ['GET', /^\/api\/sec$/, (_, __, q, u) => { const i = instFor(u, q.inst);
    return Q(`select s.id,s.name,coalesce(s.section,'') section,(select count(*) from stu where sec=s.id) n,(select name from users where sec=s.id and role='staff' and active=1 limit 1) teacher from sec s where inst=?`, i.id)
      .map(s => ({ ...s, label: secLabel(s), locked: u.role === 'staff' && u.sec !== s.id })).sort(bySec); }],
  ['POST', /^\/api\/sec$/, (_, b, __, u) => { needAdm(u); const i = instFor(u, b.inst), name = str(b.name, 60); if (!name) throw E('Class name is required');
    let secs = [...new Set((Array.isArray(b.sections) ? b.sections : [b.section]).map(x => str(x, 20)).filter(Boolean))]; if (!secs.length) secs = [''];
    for (const x of secs) if (secTaken(i.id, name, x)) throw E(`${secLabel({ name, section: x })} already exists`);
    const ids = []; db.exec('begin'); try { for (const x of secs) ids.push(Number(R('insert into sec(inst,name,section) values(?,?,?)', i.id, name, x).lastInsertRowid)); db.exec('commit'); } catch (e) { db.exec('rollback'); throw e; }
    act(u, 'created class', secs.map(x => secLabel({ name, section: x })).join(', '), i.id); return { id: ids[0], ids }; }],
  ['PUT', /^\/api\/sec\/(\d+)$/, (m, b, __, u) => { needAdm(u); const s = secFor(u, m[1]); if (b.name !== undefined && !str(b.name, 60)) throw E('Class name is required');
    const name = b.name === undefined ? s.name : str(b.name, 60), section = b.section === undefined ? (s.section || '') : str(b.section, 20);
    if (secTaken(s.inst, name, section, s.id)) throw E(`${secLabel({ name, section })} already exists`);
    R('update sec set name=?,section=? where id=?', name, section, s.id); act(u, 'edited class', `${secLabel(s)} to ${secLabel({ name, section })}`, s.inst); return { ok: 1 }; }],
  ['DELETE', /^\/api\/sec\/(\d+)$/, (m, _, __, u) => { needAdm(u); const s = secFor(u, m[1]);
    R('delete from att where stu in (select id from stu where sec=?)', s.id); R('delete from fee where stu in (select id from stu where sec=?)', s.id); R('delete from stu where sec=?', s.id); R('update users set sec=null where sec=?', s.id); R('delete from sec where id=?', s.id); act(u, 'deleted class', secLabel(s), s.inst); return { ok: 1 }; }],

  // students. Scope is enforced here on the server: teachers are pinned to their own class + section, heads to their institute, the administrator to the institute asked for.
  ['GET', /^\/api\/students$/, (_, __, q, u) => { const staff = u.role === 'staff', i = instFor(u, staff ? u.inst : (q.inst || u.inst));
    const mine = staff ? G('select * from sec where id=? and inst=?', +u.sec || 0, i.id) : null, counts = Object.fromEntries(Q('select sec,count(*) c from stu where inst=? group by sec', i.id).map(r => [r.sec, r.c]));
    const groups = (staff ? (mine ? [mine] : []) : Q('select * from sec where inst=?', i.id)).map(s => ({ id: s.id, name: s.name, section: s.section || '', label: secLabel(s), n: counts[s.id] || 0 })).sort(bySec);
    const limit = [25, 50, 100].includes(+q.limit) ? +q.limit : 50, none = { rows: [], total: 0, page: 1, pages: 1, limit, groups };
    if (staff && !mine) return none;
    const w = ['s.inst=?'], a = [i.id], search = str(q.q, 100); let rank = '', ra = [];
    if (staff) { w.push('s.sec=?'); a.push(mine.id); }
    if (search) { // search covers the whole visible scope: name, admission no., parent/guardian name, parent phone (and the alternate phone)
      const lk = t => '%' + t.replace(/[\\%_]/g, m => '\\' + m) + '%';
      if (/^[\d\s+()-]+$/.test(search) && search.replace(/\D/g, '').length >= 3) { let d = search.replace(/\D/g, ''); if (d.length === 11 && d[0] === '0') d = d.slice(1);
        w.push(`(s.phone like ?${LESC} or s.phone2 like ?${LESC} or s.adm_no like ?${LESC})`); a.push(lk(d), lk(d), lk(search)); }
      else for (const t of search.split(/\s+/).slice(0, 6)) { const d = t.replace(/\D/g, ''), p = [`s.name like ?${LESC}`, `s.adm_no like ?${LESC}`, `s.parent like ?${LESC}`], v = [lk(t), lk(t), lk(t)];
        if (d.length >= 3) { p.push(`s.phone like ?${LESC}`, `s.phone2 like ?${LESC}`); v.push(lk(d), lk(d)); } w.push('(' + p.join(' or ') + ')'); a.push(...v); }
      rank = `(lower(s.adm_no)=lower(?)) desc,(lower(s.name)=lower(?)) desc,(s.name like ?${LESC}) desc,lower(s.name),`; ra = [search, search, lk(search).slice(1)];
    } else if (q.sec) { const s = secFor(u, q.sec); if (s.inst !== i.id) throw E('Class not found', 404); w.push('s.sec=?'); a.push(s.id); }
    else if (q.class) { w.push('lower(c.name)=lower(?)'); a.push(str(q.class, 60)); }
    const from = 'from stu s join sec c on c.id=s.sec where ' + w.join(' and '), total = G(`select count(*) c ${from}`, ...a).c, pages = Math.max(1, Math.ceil(total / limit)), page = Math.min(pages, Math.max(1, +q.page || 1));
    if (!total) return { ...none, page: 1 };
    const ord = groups.length ? `case s.sec ${groups.map((g, k) => `when ${g.id} then ${k}`).join(' ')} else 1000000 end` : '0';
    const dup = `(select count(*) from stu d where d.inst=s.inst and lower(d.name)=lower(s.name)${staff ? ' and d.sec=s.sec' : ''}) dup`; // students sharing this exact name, counted only inside the caller's own scope
    const rows = Q(`${STU_SQL},${dup} ${from} order by ${rank}${ord},cast(s.roll as integer),s.name collate nocase limit ? offset ?`, ...a, ...ra, limit, (page - 1) * limit);
    return { rows: rows.map(stuOut), total, page, pages, limit, groups }; }],
  ['GET', /^\/api\/stu$/, (_, __, q, u) => Q('select * from stu where sec=? order by cast(roll as integer),name', secFor(u, q.sec).id).map(r => ({ ...r, extra: JSON.parse(r.extra || '{}') }))],
  ['GET', /^\/api\/cols$/, (_, __, q, u) => colsOf(instFor(u, q.inst).id).map(c => ({ ...c, opts: c.opts ? c.opts.split('|') : [] }))],
  ['POST', /^\/api\/cols$/, (_, b, __, u) => { needAdm(u); const i = instFor(u, b.inst), name = str(b.name, 40), type = ['text', 'date', 'number', 'dropdown'].includes(b.type) ? b.type : 'text', all = colsOf(i.id);
    if (!name) throw E('Column name is required'); if (all.length >= 30) throw E('Maximum 30 extra columns'); if (all.some(c => c.name.toLowerCase() === name.toLowerCase())) throw E('That column already exists');
    const opts = type === 'dropdown' ? optsOf(b.opts) : ''; if (type === 'dropdown' && !opts) throw E('Add at least one option');
    const id = Number(R('insert into col(inst,name,type,opts) values(?,?,?,?)', i.id, name, type, opts).lastInsertRowid); act(u, 'added column', name, i.id); return { id }; }],
  ['PUT', /^\/api\/cols\/(\d+)$/, (m, b, __, u) => { needAdm(u); const c = colFor(u, m[1]), name = str(b.name, 40) || c.name, opts = c.type === 'dropdown' ? (optsOf(b.opts) || c.opts) : '';
    R('update col set name=?,opts=? where id=?', name, opts, c.id); act(u, 'edited column', name, c.inst); return { ok: 1 }; }],
  ['DELETE', /^\/api\/cols\/(\d+)$/, (m, _, __, u) => { needAdm(u); const c = colFor(u, m[1]); R('delete from col where id=?', c.id); act(u, 'deleted column', c.name, c.inst); return { ok: 1 }; }],
  ['POST', /^\/api\/stu$/, (_, b, __, u) => { const s = secFor(u, b.sec), x = cleanStu(b), ex = cleanExtra(s.inst, b.extra); if (admTaken(s.inst, x.adm_no)) throw E('That admission number is already in use');
    const id = insertStu(s, x, ex); act(u, 'added student', `${x.name} to ${secLabel(s)}`, s.inst); return { id, adm_no: G('select adm_no from stu where id=?', id).adm_no }; }],
  ['PUT', /^\/api\/stu\/(\d+)$/, (m, b, __, u) => { const s = stuFor(u, m[1]), x = cleanStu(b), ex = cleanExtra(s.inst, b.extra); let to = G('select * from sec where id=?', s.sec);
    if (b.sec && +b.sec !== s.sec) { needAdm(u); to = secFor(u, b.sec); if (to.inst !== s.inst) throw E('Class not found', 404); } // only head/admin can move a student to another class or section
    if (x.adm_no && admTaken(s.inst, x.adm_no, s.id)) throw E('That admission number is already in use'); const adm = x.adm_no || s.adm_no || genAdm(s.inst, s.id);
    R('update stu set sec=?,name=?,roll=?,phone=?,extra=?,adm_no=?,parent=?,relation=?,gender=?,dob=?,adm_date=?,address=?,phone2=? where id=?', to.id, x.name, x.roll, x.phone, ex, adm, x.parent, x.relation, x.gender, x.dob, x.adm_date, x.address, x.phone2, s.id);
    act(u, 'edited student', to.id !== s.sec ? `${x.name} moved to ${secLabel(to)}` : x.name, s.inst); return { ok: 1 }; }],
  // bulk columns: Name, Parent contact, Roll no, Admission no, Parent/guardian, Gender, Date of birth, Address, then your extra columns (tab-separated from Excel/Sheets, or comma-separated)
  ['POST', /^\/api\/stu\/bulk$/, (_, b, __, u) => { const s = secFor(u, b.sec), cols = colsOf(s.inst), errors = [], failed = []; let n = 0, skip = 0, first = true;
    const iso = v => { v = String(v || '').trim(); const m = v.match(/^(\d{1,2})[\/.-](\d{1,2})[\/.-](\d{4})$/); return m ? `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}` : v; };
    const gen = v => { v = String(v || '').trim().toLowerCase(); return !v ? '' : v[0] === 'm' ? 'Male' : v[0] === 'f' ? 'Female' : 'Other'; };
    const lines = String(b.text || '').split('\n'); db.exec('begin');
    try { for (let k = 0; k < lines.length && k < 500; k++) { const line = lines[k]; if (!line.trim()) continue; const p = (line.includes('\t') ? line.split('\t') : line.split(',')).map(x => x.trim());
        if (first) { first = false; if (!/\d{5,}/.test(p[1] || '')) continue; } // a heading row is skipped
        try { const x = cleanStu({ name: p[0], phone: p[1], roll: p[2], adm_no: p[3], parent: p[4], gender: gen(p[5]), dob: iso(p[6]), address: p[7] }), ex = {}; cols.forEach((c, j) => { if (p[8 + j]) ex[c.id] = p[8 + j]; });
          const exj = cleanExtra(s.inst, ex); if (admTaken(s.inst, x.adm_no)) throw E('Admission number is already in use'); insertStu(s, x, exj); n++; }
        catch (e) { skip++; failed.push(k + 1); if (errors.length < 10) errors.push({ line: k + 1, name: p[0] || '', msg: e.message }); } }
      db.exec('commit'); } catch (e) { db.exec('rollback'); throw e; }
    act(u, 'imported students', `${n} to ${secLabel(s)}`, s.inst); return { added: n, skipped: skip, errors, failed }; }],
  ['DELETE', /^\/api\/stu\/(\d+)$/, (m, _, __, u) => { needAdm(u); const s = stuFor(u, m[1]); R('delete from att where stu=?', s.id); R('delete from fee where stu=?', s.id); R('delete from stu where id=?', s.id); act(u, 'removed student', s.name, s.inst); return { ok: 1 }; }],

  // attendance
  ['GET', /^\/api\/att$/, (_, __, q, u) => { if (!isDay(q.day)) throw E('Invalid date'); return Q(`select s.id,s.name,s.roll,coalesce(a.status,'P') status,a.status saved from stu s left join att a on a.stu=s.id and a.day=? where s.sec=? order by cast(s.roll as integer),s.name`, q.day, secFor(u, q.sec).id); }],
  ['POST', /^\/api\/att$/, (_, b, __, u) => { const sec = secFor(u, b.sec), i = instFor(u, sec.inst), c = cfgOf(i); if (!isDay(b.day) || b.day > today()) throw E('Choose today or an earlier date');
    const ab = new Set((Array.isArray(b.absent) ? b.absent : []).map(Number)), out = [];
    for (const s of Q('select * from stu where sec=?', sec.id)) { R('insert or replace into att(stu,day,status) values(?,?,?)', s.id, b.day, ab.has(s.id) ? 'A' : 'P');
      if (ab.has(s.id) && once(`abs:${s.id}:${b.day}`)) { mark(`abs:${s.id}:${b.day}`); out.push(s); } }
    queue(async () => { for (const s of out) await wa(i, s.phone, 'absent', c.tpl.absent, [s.name, fmt(b.day), i.name]); });
    act(u, 'saved attendance', `${secLabel(sec)} ${b.day}: ${ab.size} absent`, sec.inst); return { saved: 1, alerts: out.length }; }],

  // fees (teachers can view their class, only head/admin can approve)
  ['GET', /^\/api\/fee$/, (_, __, q, u) => { if (!isMonth(q.month)) throw E('Invalid month'); return Q(`select s.id,s.name,s.roll,coalesce(f.status,'pending') status,f.cleared from stu s left join fee f on f.stu=s.id and f.month=? where s.sec=? order by cast(s.roll as integer),s.name`, q.month, secFor(u, q.sec).id); }],
  ['POST', /^\/api\/fee\/clear$/, (_, b, __, u) => { if (!isMonth(b.month)) throw E('Invalid month'); const s = stuFor(u, b.stu), i = instFor(u, s.inst);
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
    const only = u.role === 'staff' ? ` and s.id=${+u.sec || 0}` : '';
    const classes = Q(`select s.id,s.name,coalesce(s.section,'') section,(select name from users where sec=s.id and role='staff' and active=1 limit 1) teacher,(select count(*) from stu where sec=s.id) n,(select count(*) from att a join stu t on t.id=a.stu where t.sec=s.id and a.day=? and a.status='A') absent,(select count(*) from att a join stu t on t.id=a.stu where t.sec=s.id and a.day=?) marked from sec s where s.inst=?${only} order by s.name`, d, d, i.id).map(c => ({ ...c, label: secLabel(c) })).sort(bySec);
    return { classes, students: n, present: ab('P'), absent: ab('A'), paid, pending: n - paid, sections: c('select count(*) c from sec where inst=?', i.id), msgs: u.role === 'staff' ? null : c('select count(*) c from log where inst=? and ts>=?', i.id, d) }; }],
  ['GET', /^\/api\/trend$/, (_, __, q, u) => { const i = instFor(u, q.inst), sf = u.role === 'staff' ? ` and s.sec=${+u.sec || 0}` : ''; // read-only: last 14 days with attendance, for dashboard charts
    return Q(`select a.day day,sum(a.status='P') present,sum(a.status='A') absent from att a join stu s on s.id=a.stu where s.inst=?${sf} group by a.day order by a.day desc limit 14`, i.id).reverse(); }],
  ['GET', /^\/api\/log$/, (_, __, q, u) => { needAdm(u); return Q('select * from log where inst=? order by id desc limit 200', instFor(u, q.inst).id); }],
  ['GET', /^\/api\/export$/, (_, __, q, u) => { needAdm(u); const i = instFor(u, q.inst); // same columns as the n8n chatbot sheet
    const rows = q.kind === 'attendance' ? Q('select a.day Date,a.stu Student_ID,a.status Status from att a join stu s on s.id=a.stu where s.inst=?', i.id) : Q('select id Student_ID,name Name,roll Roll_No,phone Parent_Phone_1 from stu where inst=?', i.id);
    return { csv: rows.length ? [Object.keys(rows[0]).join(','), ...rows.map(r => Object.values(r).map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))].join('\n') : '' }; }],
];

const MIME = { '.pdf': 'application/pdf', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp' };
const readBody = req => new Promise((res, rej) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > 12e6) { rej(E('Request too large', 413)); req.destroy(); } else c.push(d); });
  req.on('end', () => { try { res(c.length ? JSON.parse(Buffer.concat(c).toString()) : {}); } catch { rej(E('Invalid request')); } }); req.on('error', rej); });
http.createServer(async (req, res) => {
  const u = new URL(req.url, BASE), H = { 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ...(req.headers['x-forwarded-proto'] === 'https' ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}) };
  const send = (c, d, t = 'application/json') => { res.writeHead(c, { ...H, 'Content-Type': t, 'Cache-Control': 'no-store' }); res.end(t === 'application/json' ? JSON.stringify(d) : d); };
  try {
    if (u.pathname === '/' || u.pathname === '/admin') { const html = fs.readFileSync(['index.html', 'public/index.html'].map(f => path.join(__dirname, f)).find(f => fs.existsSync(f)), 'utf8').replaceAll('%BASE%', BASE); // %BASE% = BASE_URL, used for canonical + social preview links
      res.writeHead(200, { ...H, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...(u.pathname === '/admin' ? { 'X-Robots-Tag': 'noindex, nofollow' } : {}) }); return res.end(html); }
    if (u.pathname.startsWith('/files/')) { const f = path.join(UP, path.basename(u.pathname)); if (!fs.existsSync(f)) return send(404, {});
      res.writeHead(200, { ...H, 'Content-Type': MIME[path.extname(f).toLowerCase()] || 'application/octet-stream', ...(path.basename(f).startsWith('banner-') ? { 'Cache-Control': 'public, max-age=31536000, immutable' } : {}) }); return res.end(fs.readFileSync(f)); }
    for (const [method, re, fn, open] of routes) {
      const m = u.pathname.match(re); if (method !== req.method || !m) continue;
      let user = null; if (!open) { user = authUser((req.headers.authorization || '').slice(7)); if (!user) return send(401, { error: 'Please sign in again' }); }
      const b = req.method === 'GET' || req.method === 'DELETE' ? {} : await readBody(req);
      return send(200, await fn(m, b, Object.fromEntries(u.searchParams), user, req));
    }
    send(404, { error: 'Not found' });
  } catch (e) { if (!e.status) console.error(e); send(e.status || 400, { error: e.status ? e.message : (e.message || 'Something went wrong') }); }
}).listen(PORT, () => console.log(`Institute Desk running on ${BASE}` + (BOOT_RANDOM ? `\nOWNER_PASSWORD is not set. Temporary admin password for /admin: ${ADMIN_PASS}` : '')));
