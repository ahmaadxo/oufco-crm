// OUFCO CRM: the server part, running as a Netlify Function at /api.
// Accounts, sign-ins and records are kept in this project's Netlify Blobs store "oufco-crm".
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

// The setup key is asked for once, when the first admin account is created. Only a slow, salted
// fingerprint of it is kept here, so this file can be read by anyone without revealing the key.
const SETUP_KEY_HASH = '++McVB9J71D6QrHcCLWN1qjkiTebW6qO75WOsqtOBaE=';
const SETUP_KEY_SALT = 'XvXTtfMW0t9TyKJMK4g1Sg==';
const APP_VERSION = '1.0';
const COLLECTIONS = ['people', 'companies', 'deals', 'activities', 'tasks'];
const ROLES = ['admin', 'member', 'viewer'];
const SESSION_DAYS = 30;
const DAY = 86400000;
const MAX_DOC_BYTES = 262144;
const PAGE_BYTES = 4 * 1024 * 1024;          // keep each reply well under Netlify's 6 MB limit
const TOMBSTONE_DAYS = 60;
const COOKIE = 'oufco_crm';
const USERS = 'users';
const ID_RE = /^[A-Za-z0-9_\-.~:@+]{1,64}$/;
const UNCHANGED = Symbol('unchanged');

let blobs = null;                            // the store, opened for each request

class Refusal extends Error {
  constructor(code, message, http = 400) { super(message); this.code = code; this.http = http; }
}
const fail = (code, message, http = 400) => { throw new Refusal(code, message, http); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
const nowIso = () => new Date().toISOString();
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const str = (o, k, max = 200) => (typeof o[k] === 'string' ? o[k].trim().slice(0, max) : '');
const validId = id => typeof id === 'string' && ID_RE.test(id) && id !== '.' && id !== '..';
const validEmail = e => e.length <= 200 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

/* ---------------- passwords ---------------- */
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const scrypt = (pass, salt, len) => new Promise((res, rej) => crypto.scrypt(pass, salt, len, SCRYPT, (e, k) => (e ? rej(e) : res(k))));
async function hashPassword(pass) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(pass), salt, 64);
  return `s1$${salt.toString('base64')}$${key.toString('base64')}`;
}
async function verifyPassword(pass, stored) {
  const [v, s, k] = String(stored || '').split('$');
  if (v !== 's1' || !s || !k) return false;
  const want = Buffer.from(k, 'base64');
  const got = await scrypt(String(pass), Buffer.from(s, 'base64'), want.length);
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function checkPassword(p) {
  if (typeof p !== 'string' || p.length < 8) fail('invalid', 'Use a password of at least 8 characters.');
  if (p.length > 200) fail('invalid', 'That password is too long.');
}

/* ---------------- storage ---------------- */
const readJSON = key => blobs.get(key, { type: 'json' });
// Always write through set() with a JSON string: its "only if unchanged" options work on every
// package version (setJSON ignored them in @netlify/blobs 10.x).
const writeJSON = (key, value, opts = {}) => blobs.set(key, JSON.stringify(value), opts);

/* Read-change-write that never loses someone else's change: the write only lands if the
   entry is still the version we read, otherwise read again and redo the change. */
async function mutate(key, initial, change) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const cur = await blobs.getWithMetadata(key, { type: 'json' });
    const state = cur && cur.data ? cur.data : initial();
    const result = await change(state);
    if (result === UNCHANGED) return { state, result: undefined };
    const opts = cur ? { onlyIfMatch: cur.etag } : { onlyIfNew: true };
    if (typeof state.maxSeq === 'number') opts.metadata = { maxSeq: state.maxSeq };
    const res = await writeJSON(key, state, opts);
    if (res && res.modified) return { state, result };
    await sleep(15 + Math.random() * 60 * (attempt + 1));
  }
  fail('busy', 'The CRM is busy. Try again in a moment.', 503);
}

/* ---------------- accounts and sign-in ---------------- */
const emptyUsers = () => ({ nextId: 1, list: [] });
const loadUsers = async () => (await readJSON(USERS)) || emptyUsers();
const userOut = (u, full = true) => (full
  ? { id: String(u.id), name: u.name, role: u.role, email: u.email, active: !!u.active, lastLogin: u.lastLogin || null }
  : { id: String(u.id), name: u.name, role: u.role });

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
const cookieHeader = (R, value, maxAge) => `${COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${R.secure ? '; Secure' : ''}`;
function sessionRef(R) {
  const m = /^(\d{1,9})\.([a-f0-9]{64})$/.exec(parseCookies(R.req)[COOKIE] || '');
  return m ? { uid: Number(m[1]), token: m[2], key: `sess/${m[1]}/${sha(m[2])}` } : null;
}
async function startSession(R, uid) {
  const token = crypto.randomBytes(32).toString('hex');
  const exp = Date.now() + SESSION_DAYS * DAY;
  await writeJSON(`sess/${uid}/${sha(token)}`, { exp, at: nowIso(), agent: (R.req.headers.get('user-agent') || '').slice(0, 200) }, { metadata: { exp } });
  R.cookies.push(cookieHeader(R, `${uid}.${token}`, SESSION_DAYS * 86400));
}
async function currentUser(R, usersPromise) {
  if (R.user !== undefined) return R.user;
  R.user = null;
  const ref = sessionRef(R);
  if (!ref) return null;
  const [sess, users] = await Promise.all([readJSON(ref.key), usersPromise || loadUsers()]);
  if (!sess || !(sess.exp > Date.now())) return null;
  const u = users.list.find(x => x.id === ref.uid && x.active);
  if (!u) return null;
  if (sess.exp - Date.now() < (SESSION_DAYS - 1) * DAY) {            // keep active people signed in
    const exp = Date.now() + SESSION_DAYS * DAY;
    await writeJSON(ref.key, { ...sess, exp }, { metadata: { exp } });
    R.cookies.push(cookieHeader(R, `${ref.uid}.${ref.token}`, SESSION_DAYS * 86400));
  }
  return (R.user = u);
}
async function requireUser(R, usersPromise) {
  const u = await currentUser(R, usersPromise);
  if (!u) fail('auth', 'Sign in to continue.', 401);
  return u;
}
async function requireRole(R, roles) {
  const u = await requireUser(R);
  if (!roles.includes(u.role)) fail('forbidden', u.role === 'viewer' ? 'Your account is view only.' : 'Only an admin can do that.', 403);
  return u;
}
async function deleteSessions(uid, keepKey = '') {
  const { blobs: list } = await blobs.list({ prefix: `sess/${uid}/` });
  await Promise.all(list.filter(b => b.key !== keepKey).map(b => blobs.delete(b.key)));
}
async function dropExpiredSessions(uid) {
  const { blobs: list } = await blobs.list({ prefix: `sess/${uid}/` });
  await Promise.all(list.map(async b => {
    const m = await blobs.getMetadata(b.key);
    if (!m || !(Number(m.metadata && m.metadata.exp) > Date.now())) await blobs.delete(b.key);
  }));
}

/* Failed sign-ins in the last 15 minutes. An office shares one internet address, so the
   tight limit is per person per address; looser limits catch guessing from many places. */
const WINDOW = 15 * 60 * 1000;
const failKeys = (email, ip) => ({ pair: `fail/pair/${sha(email)}/${sha(ip)}`, email: `fail/email/${sha(email)}`, ip: `fail/ip/${sha(ip)}` });
async function recentFailures(key) {
  const v = await readJSON(key);
  return (v && Array.isArray(v.t) ? v.t : []).filter(t => t > Date.now() - WINDOW);
}
async function throttled(email, ip) {
  const k = failKeys(email, ip);
  const [a, b, c] = await Promise.all([recentFailures(k.pair), recentFailures(k.email), recentFailures(k.ip)]);
  return a.length >= 8 || b.length >= 25 || c.length >= 60;
}
async function noteFailure(email, ip) {
  await Promise.all(Object.values(failKeys(email, ip)).map(async key => {
    const t = await recentFailures(key);
    t.push(Date.now());
    await writeJSON(key, { t: t.slice(-100) });
  }));
}
const clearFailures = (email, ip) => blobs.delete(failKeys(email, ip).pair);
async function clearAllFailures(email) {
  const { blobs: list } = await blobs.list({ prefix: `fail/pair/${sha(email)}/` });
  await Promise.all([...list.map(b => blobs.delete(b.key)), blobs.delete(`fail/email/${sha(email)}`)]);
}

/* Forgotten admin password: an ADMIN_RESET_PASSWORD environment variable sets it, once per value. */
function envValue(name) {
  try {
    if (globalThis.Netlify && Netlify.env && typeof Netlify.env.get === 'function') {
      const v = Netlify.env.get(name);
      if (v) return String(v);
    }
  } catch (e) { /* fall back to process.env */ }
  return String(process.env[name] || '');
}
async function applyAdminReset() {
  const p = envValue('ADMIN_RESET_PASSWORD');
  if (p.length < 8) return;
  const h = sha('reset:' + p);
  const done = await readJSON('meta/reset');
  if (done && done.h === h) return;
  const passHash = await hashPassword(p);
  const { result: admin } = await mutate(USERS, emptyUsers, users => {
    const a = users.list.filter(x => x.role === 'admin').sort((x, y) => x.id - y.id)[0];
    if (!a) return UNCHANGED;
    a.pass = passHash; a.active = true;
    return { id: a.id, email: a.email };
  });
  if (!admin) return;
  await Promise.all([deleteSessions(admin.id), clearAllFailures(admin.email)]);
  await writeJSON('meta/reset', { h, at: nowIso() });
}

/* ---------------- records ---------------- */
const colKey = c => `col/${c}`;
const emptyCol = () => ({ maxSeq: 0, docs: {} });
const docOut = (col, id, d) => ({ col, id, seq: d.seq, deleted: !!d.deleted, data: d.deleted ? null : d.data });
function applyWrite(state, w, uid) {
  const op = w.op, id = w.id;
  if (!validId(id)) fail('invalid', 'Bad record id.');
  const cur = state.docs[id];
  const exists = !!cur && !cur.deleted;
  if (op === 'delete') {
    if (!cur) return null;
    state.docs[id] = { seq: ++state.maxSeq, deleted: true, at: Date.now() };
    return id;
  }
  if (!isPlainObject(w.data)) fail('invalid', 'Record data must be an object.');
  let data = { ...w.data };
  delete data.id;
  if (op === 'update') {
    if (!exists) fail('missing', 'That record was deleted by someone else.', 409);
    data = { ...cur.data, ...data };
  } else if (op === 'set') {
    if (!exists && data.by === undefined) data.by = String(uid);
  } else {
    fail('invalid', 'Unknown change type.');
  }
  if (Buffer.byteLength(JSON.stringify(data)) > MAX_DOC_BYTES) fail('invalid', 'That record is too large to save.');
  state.docs[id] = { seq: ++state.maxSeq, data, at: Date.now() };
  return id;
}
function purgeTombstones(state) {
  const cutoff = Date.now() - TOMBSTONE_DAYS * DAY;
  for (const [id, d] of Object.entries(state.docs)) if (d.deleted && (d.at || 0) < cutoff) delete state.docs[id];
}
async function writeCollection(col, writes, uid) {
  if (!COLLECTIONS.includes(col)) fail('invalid', 'Unknown record type.');
  const { state, result } = await mutate(colKey(col), emptyCol, st => {
    const touched = [];
    for (const w of writes) { const id = applyWrite(st, w, uid); if (id) touched.push(id); }
    if (!touched.length) return UNCHANGED;
    purgeTombstones(st);
    return touched;
  });
  return [...new Set(result || [])].filter(id => state.docs[id]).map(id => docOut(col, id, state.docs[id]));
}
async function importDocs(src, uid) {
  const map = { people: 'people', companies: 'companies', deals: 'deals', activities: 'activities', followups: 'tasks', tasks: 'tasks' };
  const byCol = {};
  for (const [k, col] of Object.entries(map)) {
    if (!Array.isArray(src[k])) continue;
    for (const doc of src[k]) {
      if (!isPlainObject(doc) || !validId(doc.id)) continue;
      const { id, ...data } = doc;
      (byCol[col] = byCol[col] || []).push({ op: 'set', id, data });
    }
  }
  const counts = {};
  for (const [col, writes] of Object.entries(byCol)) {
    for (let i = 0; i < writes.length; i += 500) await writeCollection(col, writes.slice(i, i + 500), uid);
    counts[col] = writes.length;
  }
  return counts;
}

/* Sync cursor: the last change number seen in each record type, e.g. "12.7.3.40.18". */
function parseCursor(since) {
  const s = String(since == null ? '0' : since);
  const zero = Object.fromEntries(COLLECTIONS.map(c => [c, 0]));
  if (s === '0' || s === '') return { full: true, cur: zero };
  const parts = s.split('.').map(n => Math.max(0, parseInt(n, 10) || 0));
  return { full: false, cur: Object.fromEntries(COLLECTIONS.map((c, i) => [c, parts[i] || 0])) };
}
const cursorString = cur => COLLECTIONS.map(c => cur[c] || 0).join('.');
async function syncDocs(R, since) {
  const { full, cur } = parseCursor(since);
  const [, metas] = await Promise.all([requireUser(R), Promise.all(COLLECTIONS.map(c => blobs.getMetadata(colKey(c))))]);
  const latest = {};
  COLLECTIONS.forEach((c, i) => {
    const m = metas[i];
    latest[c] = !m ? 0 : (m.metadata && m.metadata.maxSeq != null ? Number(m.metadata.maxSeq) : Infinity);
  });
  const need = COLLECTIONS.filter(c => latest[c] > cur[c]);
  const states = await Promise.all(need.map(c => readJSON(colKey(c))));
  const docs = [], next = { ...cur };
  let bytes = 0, more = false;
  for (let i = 0; i < need.length && !more; i++) {
    const c = need[i], st = states[i] || emptyCol();
    const changed = Object.entries(st.docs)
      .filter(([, d]) => d.seq > cur[c] && !(full && d.deleted))
      .sort((a, b) => a[1].seq - b[1].seq);
    let last = cur[c];
    for (const [id, d] of changed) {
      const out = docOut(c, id, d);
      const size = Buffer.byteLength(JSON.stringify(out));
      if (bytes + size > PAGE_BYTES && docs.length) { more = true; break; }
      docs.push(out); bytes += size; last = d.seq;
    }
    next[c] = more ? last : Math.max(st.maxSeq || 0, last);
  }
  return { docs, seq: cursorString(next), more };
}

/* ---------------- starting records ---------------- */
function seedData() {
  const now = nowIso(), today = now.slice(0, 10);
  return {
    companies: [{ id: 'tsurumi', name: 'Tsurumi Pump', type: 'Supplier', sector: '', status: 'In talks', city: '', phone: '', email: '',
      website: 'tsurumipump.ae', address: '',
      notes: "Working toward becoming Tsurumi's authorized distributor in Egypt. Formally requested the distributorship by email to Tomohiro Inoue and Pranay Shah; they invited OUFCO to their booth at the Egypt Mining Forum in Cairo to discuss their current setup in Egypt and a future partnership. Keep Ms. Hara in copy on emails.",
      lastContactAt: '2026-09-29T08:00:00.000Z', createdAt: now, updatedAt: now }],
    people: [
      { id: 'hara', name: 'Ms. Hara', role: 'Sales Engineer', companyId: 'tsurumi', phone: '', phone2: '', email: '', tags: ['Keep in copy'],
        notes: 'First contact at Tsurumi. Referred OUFCO to Tomohiro Inoue and Pranay Shah and asked to be kept in copy.', createdAt: now, updatedAt: now },
      { id: 'inoue', name: 'Tomohiro Inoue', role: 'Managing Director', companyId: 'tsurumi', phone: '', phone2: '', email: '', tags: [], notes: '', createdAt: now, updatedAt: now },
      { id: 'shah', name: 'Pranay Shah', role: 'Division Manager', companyId: 'tsurumi', phone: '', phone2: '', email: '', tags: [], notes: '', createdAt: now, updatedAt: now },
    ],
    activities: [{ id: 'tsurumi-forum-meeting', kind: 'meeting', at: '2026-09-29T08:00:00.000Z',
      summary: "Meeting at Tsurumi's booth, Egypt Mining Forum, Cairo, to discuss their current setup in Egypt and a future partnership.",
      personId: '', companyId: 'tsurumi', dealId: '', createdAt: now, updatedAt: now }],
    tasks: [
      { id: 'tsurumi-followup', title: 'Follow up with Tsurumi on the distributorship after the Mining Forum meeting', due: today,
        done: false, doneAt: null, personId: '', companyId: 'tsurumi', dealId: '', createdAt: now, updatedAt: now },
      { id: 'seal-suppliers', title: 'Find mechanical seal suppliers in China for Flygt pumps', due: '',
        done: false, doneAt: null, personId: '', companyId: '', dealId: '', createdAt: now, updatedAt: now },
    ],
  };
}

/* ---------------- requests ---------------- */
async function handle(R, method, action, b, url) {
  switch (`${method} ${action}`) {
    case 'GET me': {
      await applyAdminReset();
      const users = await loadUsers();
      const setup = users.list.length === 0;
      const u = setup ? null : await currentUser(R, Promise.resolve(users));
      const out = { user: u ? userOut(u) : null, setup, version: APP_VERSION };
      if (u && u.role === 'admin') out.storage = 'this Netlify project’s storage (Netlify Blobs)';
      return out;
    }
    case 'POST setup': {
      if ((await loadUsers()).list.length) fail('setup', 'The CRM is already set up. Sign in instead.', 409);
      if (await throttled('setup', R.ip)) fail('throttled', 'Too many attempts. Wait 15 minutes, then try again.', 429);
      const norm = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
      const typed = await scrypt(norm(str(b, 'key', 100)), Buffer.from(SETUP_KEY_SALT, 'base64'), 32);
      if (!crypto.timingSafeEqual(typed, Buffer.from(SETUP_KEY_HASH, 'base64'))) {
        await noteFailure('setup', R.ip);
        fail('invalid', 'That setup key isn’t right. It’s in the install instructions.', 403);
      }
      const name = str(b, 'name', 120), email = str(b, 'email', 200).toLowerCase();
      if (!name) fail('invalid', 'Add your name.');
      if (!validEmail(email)) fail('invalid', 'Add a valid email address.');
      checkPassword(b.password);
      const admin = { id: 1, name, email, pass: await hashPassword(b.password), role: 'admin', active: true, createdAt: nowIso(), lastLogin: nowIso() };
      const res = await writeJSON(USERS, { nextId: 2, list: [admin] }, { onlyIfNew: true });
      if (!res || !res.modified) fail('setup', 'The CRM is already set up. Sign in instead.', 409);
      if (b.seed) await importDocs(seedData(), 1);
      await startSession(R, 1);
      return { user: userOut(admin) };
    }
    case 'POST login': {
      const email = str(b, 'email', 200).toLowerCase();
      const pass = typeof b.password === 'string' ? b.password : '';
      if (await throttled(email, R.ip)) fail('throttled', 'Too many attempts. Wait 15 minutes, then try again.', 429);
      const users = await loadUsers();
      const u = users.list.find(x => x.email === email);
      const ok = u ? await verifyPassword(pass, u.pass) : (await hashPassword(pass), false);   // same effort either way
      if (!u || !u.active || !ok) {
        await noteFailure(email, R.ip);
        fail('invalid', 'Email or password is wrong, or the account is switched off.', 401);
      }
      await Promise.all([
        clearFailures(email, R.ip),
        dropExpiredSessions(u.id),
        mutate(USERS, emptyUsers, us => { const x = us.list.find(y => y.id === u.id); if (!x) return UNCHANGED; x.lastLogin = nowIso(); return true; }),
      ]);
      await startSession(R, u.id);
      return { user: userOut(u) };
    }
    case 'POST logout': {
      const ref = sessionRef(R);
      if (ref) await blobs.delete(ref.key);
      R.cookies.push(cookieHeader(R, '', 0));
      return { ok: true };
    }
    case 'POST password': {
      const u = await requireUser(R);
      if (!(await verifyPassword(b.current, u.pass))) fail('invalid', 'Your current password isn’t right.', 403);
      checkPassword(b.password);
      const h = await hashPassword(b.password);
      await mutate(USERS, emptyUsers, us => {
        const x = us.list.find(y => y.id === u.id);
        if (!x) fail('auth', 'Sign in to continue.', 401);
        x.pass = h;
        return true;
      });
      await deleteSessions(u.id, sessionRef(R).key);                 // sign out other devices
      return { ok: true };
    }
    case 'GET sync':
      return syncDocs(R, url.searchParams.get('since'));
    case 'POST write': {
      const u = await requireRole(R, ['admin', 'member']);
      const writes = b.writes;
      if (!Array.isArray(writes) || !writes.length || writes.length > 100) fail('invalid', 'Nothing to save.');
      const byCol = new Map();
      for (const w of writes) {
        if (!isPlainObject(w)) fail('invalid', 'Bad change.');
        const col = String(w.col || '');
        if (!COLLECTIONS.includes(col)) fail('invalid', 'Unknown record type.');
        if (!byCol.has(col)) byCol.set(col, []);
        byCol.get(col).push({ op: String(w.op || ''), id: String(w.id || ''), data: w.data });
      }
      const docs = [];
      for (const [col, ws] of byCol) docs.push(...(await writeCollection(col, ws, u.id)));
      return { ok: true, docs };
    }
    case 'GET users': {
      const users = await loadUsers();
      const u = await requireUser(R, Promise.resolve(users));
      const admin = u.role === 'admin';
      const list = users.list.slice().sort((a, b2) => (Number(b2.active) - Number(a.active)) || a.name.localeCompare(b2.name, undefined, { sensitivity: 'base' }));
      return { users: list.map(x => userOut(x, admin)) };
    }
    case 'POST user': {
      const me = await requireRole(R, ['admin']);
      const id = Number(b.id || 0);
      const role = ROLES.includes(b.role) ? b.role : null;
      const pass = typeof b.password === 'string' ? b.password : '';
      if (pass || !id) checkPassword(pass);
      const passHash = pass ? await hashPassword(pass) : null;
      let effect = {};
      const { result } = await mutate(USERS, emptyUsers, users => {
        if (!id) {
          const name = str(b, 'name', 120), email = str(b, 'email', 200).toLowerCase();
          if (!name) fail('invalid', 'Add their name.');
          if (!validEmail(email)) fail('invalid', 'Add a valid email address.');
          if (users.list.some(x => x.email === email)) fail('invalid', 'Someone with that email already has an account.');
          const nu = { id: users.nextId++, name, email, pass: passHash, role: role || 'member', active: true, createdAt: nowIso(), lastLogin: null };
          users.list.push(nu);
          effect = {};
          return nu;
        }
        const x = users.list.find(y => y.id === id);
        if (!x) fail('invalid', 'That account doesn’t exist.', 404);
        const active = 'active' in b ? !!b.active : x.active;
        const newRole = role || x.role;
        if (id === me.id && (!active || newRole !== 'admin')) fail('invalid', 'You can’t switch off or demote your own account.');
        if (x.role === 'admin' && x.active && (newRole !== 'admin' || !active)
            && users.list.filter(y => y.role === 'admin' && y.active).length <= 1) fail('invalid', 'Keep at least one active admin.');
        x.name = str(b, 'name', 120) || x.name; x.role = newRole; x.active = active;
        if (passHash) x.pass = passHash;
        effect = { kill: !!passHash || !active, clear: !!passHash, email: x.email };
        return x;
      });
      if (effect.kill) await deleteSessions(result.id);
      if (effect.clear) await clearAllFailures(effect.email);
      return { user: userOut(result) };
    }
    case 'POST import': {
      const u = await requireRole(R, ['admin']);
      return { ok: true, counts: await importDocs(b, u.id) };
    }
    default:
      fail('not_found', 'Unknown request.', 404);
  }
}

export default async (req, context) => {
  blobs = getStore({ name: 'oufco-crm', consistency: 'strong' });
  const url = new URL(req.url);
  const R = {
    req, cookies: [], user: undefined, secure: url.protocol === 'https:',
    ip: (context && context.ip) || req.headers.get('x-nf-client-connection-ip') || (req.headers.get('x-forwarded-for') || '').split(',')[0].trim(),
  };
  const reply = (data, status = 200) => {
    const h = new Headers({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
    for (const c of R.cookies) h.append('Set-Cookie', c);
    return new Response(JSON.stringify(data), { status, headers: h });
  };
  try {
    const method = req.method;
    if (method === 'POST' && req.headers.get('x-oufco-crm') !== '1') fail('forbidden', 'Request refused.', 403);
    let body = {};
    if (method === 'POST') { try { body = await req.json(); } catch (e) { body = {}; } }
    return reply(await handle(R, method, url.searchParams.get('action') || '', isPlainObject(body) ? body : {}, url));
  } catch (e) {
    if (e instanceof Refusal) return reply({ error: e.code, message: e.message }, e.http);
    console.error('OUFCO CRM error:', e);
    return reply({ error: 'server', message: 'Something went wrong on the server. Try again.' }, 500);
  }
};

export const config = { path: '/api' };
