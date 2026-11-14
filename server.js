'use strict';
/**
 * ISS-DS Document Repository — Express backend
 * ---------------------------------------------------------------------------
 * Layout:
 *   views/    HTML pages (served only through authenticated routes)
 *   public/   css/, js/, nobglogo.png (safe static assets)
 *   repository/  uploaded files (served only to signed-in users)
 *   backups/  weekly backup ZIPs
 */
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const archiver = require('archiver');
const cron = require('node-cron');
const { Pool } = require('pg');

/* ==========================================================================
   CONFIG
   ========================================================================== */
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const ROOT = __dirname;
const VIEWS_DIR = path.join(ROOT, 'views');
const PUBLIC_DIR = path.join(ROOT, 'public');
const REPO_DIR = path.join(ROOT, 'repository');
const BACKUP_DIR = path.join(ROOT, 'backups');

const ROLES = ['Officer', 'Secretary', 'Treasurer', 'President', 'Administrator'];
const ADMIN_ROLES = ['Administrator', 'President'];
const FINANCE_ROLES = ['President', 'Treasurer', 'Secretary']; // who may see/use the Finance type
const APPROVER_ROLES = ['President'];                          // who may approve documents
const MAX_UPLOAD_MB = 25;
const ALLOWED_EXT = new Set(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv', '.png', '.jpg', '.jpeg']);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

if (!process.env.DATABASE_URL) {
  console.error('✖ DATABASE_URL is missing. Copy .env.example to .env and fill it in.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.warn('⚠ SESSION_SECRET is not set — using a random one. Sessions reset on every restart.');
}
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false }, // Supabase needs SSL
  max: 10,
  idleTimeoutMillis: 30000,
});
pool.on('error', (err) => console.error('Idle PostgreSQL client error:', err.message));

/* ==========================================================================
   SMALL HELPERS
   ========================================================================== */
const httpError = (status, message) => Object.assign(new Error(message), { status });
const isAdminish = (role) => ADMIN_ROLES.includes(role);
const safeSegment = (s) => String(s).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60);
const escapeLike = (s) => s.replace(/[\\%_]/g, (m) => '\\' + m);
const str = (v) => (typeof v === 'string' ? v.trim() : '');
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', 10);

/** Run fn inside a transaction. fn receives the client. */
async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** Write one audit-trail row. Pass a client to include it in a transaction. */
const logActivity = (userId, action, docId, result, db = pool) =>
  db.query(
    'INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)',
    [userId, action, docId || null, result]
  );

/** Only FINANCE_ROLES may touch the Finance category. */
const canFinance = (role) => FINANCE_ROLES.includes(role);
const isFinance = (category) => String(category).toLowerCase() === 'finance';
function assertCategoryAccess(role, category) {
  if (isFinance(category) && !canFinance(role)) {
    throw httpError(403, 'Access denied: Finance documents are limited to the President, Treasurer and Secretary.');
  }
}
/** SQL fragment (alias "d") that hides Finance documents from everyone else. */
const visibility = (role) => (canFinance(role) ? '' : " AND lower(d.category) <> 'finance'");
async function assertFolderAccess(role, id) {
  const r = await pool.query('SELECT category FROM EventFolder WHERE id = $1', [id]);
  if (r.rows[0]) assertCategoryAccess(role, r.rows[0].category);
}

/** Final file name: Category_Title_Date_vN.ext */
const buildFileName = (category, title, date, version, ext) =>
  `${safeSegment(category)}_${String(title).replace(/[^a-zA-Z0-9]/g, '_')}_${date}_v${version}${ext}`;

/** Locate a stored file on disk from the DB row (works even if the DB path came from another machine). */
function storedFile(v) {
  const parts = String(v.file_path || '').split(/[\\/]/).filter(Boolean);
  const dir = parts.length > 1 ? parts[parts.length - 2] : '';
  return path.join(REPO_DIR, dir, v.standardized_file_name);
}
function fileUrl(row) {
  const parts = String(row.file_path || '').split(/[\\/]/).filter(Boolean);
  const dir = parts.length > 1 ? parts[parts.length - 2] : safeSegment(row.category);
  return `/repository/${encodeURIComponent(dir)}/${encodeURIComponent(row.standardized_file_name)}`;
}
const toDoc = ({ file_path, ...rest }) => ({ ...rest, file_url: fileUrl({ file_path, ...rest }) });

/** Latest version of every document (LATERAL is faster than a MAX() sub-select). */
const DOC_SELECT = `
  SELECT d.id, d.title, d.category, d.subfolder,
         to_char(d.document_date, 'YYYY-MM-DD') AS document_date,
         d.approval_status, d.approver, d.approval_date,
         COALESCE(d.view_count, 0) AS view_count,
         dv.version_number, dv.standardized_file_name, dv.file_path
  FROM Document d
  JOIN LATERAL (
    SELECT version_number, standardized_file_name, file_path
    FROM DocumentVersion WHERE document_id = d.id
    ORDER BY version_number DESC LIMIT 1
  ) dv ON TRUE`;

/* ==========================================================================
   SCHEMA BOOTSTRAP (document types + event folders now live in the database,
   not in each browser's localStorage)
   ========================================================================== */
async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS DocumentType (
      id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
    CREATE TABLE IF NOT EXISTS EventFolder (
      id SERIAL PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL,
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE, deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now(), UNIQUE (category, name));
    ALTER TABLE DocumentType ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE DocumentType ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
    ALTER TABLE EventFolder ADD COLUMN IF NOT EXISTS deleted_with_type BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE Document ADD COLUMN IF NOT EXISTS deleted_with_type BOOLEAN NOT NULL DEFAULT FALSE;`);

  // Seed types only the first time, so a type deleted later is not brought back on restart
  const typeCount = await pool.query('SELECT COUNT(*)::int AS n FROM DocumentType');
  if (typeCount.rows[0].n === 0) {
    await pool.query(`INSERT INTO DocumentType (name) VALUES ('Reports'),('Memos'),('Records'),('Finance') ON CONFLICT DO NOTHING`);
    await pool.query(`INSERT INTO DocumentType (name) SELECT DISTINCT category FROM Document WHERE category IS NOT NULL ON CONFLICT DO NOTHING`);
  }

  const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM EventFolder');
  if (rows[0].n === 0) {
    await pool.query(`INSERT INTO EventFolder (category, name) VALUES
      ('Memos','General Assembly'),('Memos','Year-End Evaluation'),
      ('Records','Resolution'),('Records','Minutes of the meeting'),
      ('Reports','Activity design'),('Reports','Utilization'),
      ('Finance','Budget Allocation') ON CONFLICT DO NOTHING`);
  }
  // Pick up any event folders that documents already reference
  await pool.query(`INSERT INTO EventFolder (category, name)
    SELECT DISTINCT category, subfolder FROM Document
    WHERE subfolder IS NOT NULL AND subfolder <> 'General' ON CONFLICT DO NOTHING`);
}

/* ==========================================================================
   MIDDLEWARE
   ========================================================================== */
const app = express();
if (IS_PROD) app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'same-origin',
  });
  next();
});
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(session({
  name: 'issds.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: 1000 * 60 * 60 * 8 },
}));

// Static assets: only css/js/images — never the HTML views.
app.use(express.static(PUBLIC_DIR, {
  index: false, dotfiles: 'ignore',
  setHeaders: (res, file) => { if (/\.(js|css)$/.test(file)) res.set('Cache-Control', IS_PROD ? 'public, max-age=3600' : 'no-cache'); }, // pages add ?v= to bust caches
}));

const wantsJson = (req) => req.originalUrl.startsWith('/api/') || req.accepts(['html', 'json']) === 'json';

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (wantsJson(req)) return res.status(401).json({ success: false, error: 'Please sign in again.' });
  res.redirect('/login');
}
const requireRole = (...roles) => (req, res, next) => {
  if (roles.includes(req.session.role)) return next();
  res.status(403).json({ success: false, error: `Access denied: ${roles.join(' or ')} only.` });
};
const notOfficer = (req, res, next) =>
  req.session.role === 'Officer'
    ? res.status(403).json({ success: false, error: 'Access denied: Officers cannot do this.' })
    : next();

// Every :id in a route must be a positive integer
app.param('id', (req, res, next, val) =>
  /^\d{1,9}$/.test(val) ? next() : res.status(400).json({ success: false, error: 'Invalid id.' }));

/* ==========================================================================
   PAGES
   ========================================================================== */
const sendView = (name) => (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.sendFile(path.join(VIEWS_DIR, `${name}.html`));
};
const guard = (allowed, denyCode) => (req, res, next) =>
  allowed(req.session.role) ? next() : res.redirect(`/dashboard?error=${denyCode}`);

app.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login'));
app.get('/login', (req, res, next) => (req.session.userId ? res.redirect('/dashboard') : sendView('login')(req, res, next)));
app.get('/logout', (req, res) => req.session.destroy(() => { res.clearCookie('issds.sid'); res.redirect('/login'); }));

app.get('/dashboard', requireAuth, sendView('dashboard'));
app.get('/upload', requireAuth, sendView('upload'));
app.get('/documents', requireAuth, sendView('documents'));
app.get('/activity-log', requireAuth, guard(isAdminish, 'activity_denied'), sendView('activity-log'));
app.get('/admin', requireAuth, guard(isAdminish, 'admin_denied'), sendView('admin'));
app.get('/recycle-bin', requireAuth, guard((r) => r !== 'Officer', 'bin_denied'), sendView('recycle-bin'));

/* ==========================================================================
   AUTH
   ========================================================================== */
const attempts = new Map(); // ip -> { n, reset }  (simple brute-force throttle)
function throttled(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || rec.reset < now) { attempts.set(ip, { n: 1, reset: now + 15 * 60 * 1000 }); return false; }
  rec.n += 1;
  return rec.n > 10;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of attempts) if (v.reset < now) attempts.delete(k); }, 60 * 1000).unref();

app.post('/api/login', async (req, res) => {
  const username = str(req.body.username);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!username || !password) throw httpError(400, 'Enter your username and password.');
  if (throttled(req.ip)) throw httpError(429, 'Too many attempts. Try again in 15 minutes.');

  const { rows } = await pool.query('SELECT * FROM UserAccount WHERE username = $1', [username]);
  const user = rows[0];

  let valid = false;
  if (user) {
    if (String(user.password_hash).startsWith('$2')) {
      valid = await bcrypt.compare(password, user.password_hash);
    } else {
      // Legacy plaintext seed password: accept once, then upgrade to a bcrypt hash.
      const a = Buffer.from(String(user.password_hash)), b = Buffer.from(password);
      valid = a.length === b.length && crypto.timingSafeEqual(a, b);
      if (valid) await pool.query('UPDATE UserAccount SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(password, 10), user.id]);
    }
  } else {
    await bcrypt.compare(password, DUMMY_HASH); // equalise timing so usernames can't be probed
  }

  if (!valid) throw httpError(401, 'Invalid username or password.');
  if (String(user.status || 'active').toLowerCase() === 'inactive') throw httpError(403, 'This account is deactivated. Contact an administrator.');

  attempts.delete(req.ip);
  await new Promise((resolve, reject) => req.session.regenerate((e) => (e ? reject(e) : resolve()))); // prevent session fixation
  Object.assign(req.session, { userId: user.id, role: user.access_level, username: user.username, fullName: user.full_name });
  await logActivity(user.id, 'Login', null, 'Success');
  res.json({ success: true, redirect: '/dashboard' });
});

const me = (req, res) => res.json({
  userId: req.session.userId, role: req.session.role,
  username: req.session.username, fullName: req.session.fullName,
});
app.get('/api/me', requireAuth, me);
app.get('/api/current-user', requireAuth, me); // backward-compatible alias

/* ==========================================================================
   USER MANAGEMENT (Administrator & President)
   ========================================================================== */
const userAdmin = [requireAuth, requireRole(...ADMIN_ROLES)];

/** Presidents may not create, edit or promote Administrators. */
function assertCanManage(actorRole, targetRole) {
  if (actorRole !== 'Administrator' && targetRole === 'Administrator') throw httpError(403, 'Only an Administrator can manage Administrator accounts.');
}
async function loadTarget(id) {
  const { rows } = await pool.query('SELECT id, username, access_level, status FROM UserAccount WHERE id = $1', [id]);
  if (!rows[0]) throw httpError(404, 'User not found.');
  return rows[0];
}

app.get('/api/users', ...userAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, full_name, username, access_level, status, date_created FROM UserAccount ORDER BY date_created DESC');
  res.json(rows);
});

app.post('/api/users', ...userAdmin, async (req, res) => {
  const full_name = str(req.body.full_name), username = str(req.body.username);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const access_level = str(req.body.access_level);

  if (!full_name || !username || !password || !access_level) throw httpError(400, 'Fill in every field.');
  if (!/^[a-zA-Z0-9._-]{3,32}$/.test(username)) throw httpError(400, 'Username: 3–32 letters, numbers, dot, dash or underscore.');
  if (password.length < 8) throw httpError(400, 'Password must be at least 8 characters.');
  if (!ROLES.includes(access_level)) throw httpError(400, 'Unknown access level.');
  assertCanManage(req.session.role, access_level);

  const hashed = await bcrypt.hash(password, 10);
  await tx(async (c) => {
    const dup = await c.query('SELECT 1 FROM UserAccount WHERE lower(username) = lower($1)', [username]);
    if (dup.rowCount) throw httpError(409, 'That username is already taken.');
    await c.query('INSERT INTO UserAccount (full_name, username, password_hash, access_level) VALUES ($1,$2,$3,$4)', [full_name, username, hashed, access_level]);
    await logActivity(req.session.userId, 'Create Account', null, `Created ${access_level} account: ${username}`, c);
  });
  res.status(201).json({ success: true });
});

app.put('/api/users/:id/role', ...userAdmin, async (req, res) => {
  const newRole = str(req.body.newRole);
  if (!ROLES.includes(newRole)) throw httpError(400, 'Unknown access level.');
  const target = await loadTarget(req.params.id);
  assertCanManage(req.session.role, newRole);
  assertCanManage(req.session.role, target.access_level);
  if (target.id === req.session.userId) throw httpError(400, 'You cannot change your own access level.');
  await pool.query('UPDATE UserAccount SET access_level = $1 WHERE id = $2', [newRole, target.id]);
  await logActivity(req.session.userId, 'Change Role', null, `${target.username}: ${target.access_level} → ${newRole}`);
  res.json({ success: true });
});

const setStatus = (status) => async (req, res) => {
  const target = await loadTarget(req.params.id);
  assertCanManage(req.session.role, target.access_level);
  if (target.id === req.session.userId) throw httpError(400, 'You cannot deactivate your own account.');
  await pool.query('UPDATE UserAccount SET status = $1 WHERE id = $2', [status, target.id]);
  await logActivity(req.session.userId, status === 'inactive' ? 'Deactivate Account' : 'Activate Account', null, target.username);
  res.json({ success: true });
};
app.put('/api/users/:id/deactivate', ...userAdmin, setStatus('inactive'));
app.put('/api/users/:id/activate', ...userAdmin, setStatus('active'));

app.put('/api/users/:id/reset-password', ...userAdmin, async (req, res) => {
  const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  if (newPassword.length < 8) throw httpError(400, 'Password must be at least 8 characters.');
  const target = await loadTarget(req.params.id);
  assertCanManage(req.session.role, target.access_level);
  await pool.query('UPDATE UserAccount SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(newPassword, 10), target.id]);
  await logActivity(req.session.userId, 'Reset Password', null, target.username);
  res.json({ success: true });
});

/** Remove one document + versions from the DB (inside a transaction); file paths are collected for deletion after commit. */
async function purgeDocument(c, id, files) {
  const vs = await c.query('SELECT standardized_file_name, file_path FROM DocumentVersion WHERE document_id = $1', [id]);
  vs.rows.forEach((v) => files.push(storedFile(v)));
  await c.query('UPDATE ActivityLogEntry SET document_id = NULL WHERE document_id = $1', [id]); // keep the audit trail, drop the dead reference
  await c.query('DELETE FROM DocumentVersion WHERE document_id = $1', [id]);
  await c.query('DELETE FROM Document WHERE id = $1', [id]);
}

/* ==========================================================================
   DOCUMENT TYPES & EVENT FOLDERS
   ========================================================================== */
app.get('/api/folders', requireAuth, async (req, res) => {
  const allowFinance = canFinance(req.session.role);
  const [types, events] = await Promise.all([
    pool.query('SELECT name FROM DocumentType WHERE is_deleted = FALSE ORDER BY id'),
    pool.query('SELECT id, category, name FROM EventFolder WHERE is_deleted = FALSE ORDER BY name'),
  ]);
  const hide = (c) => !allowFinance && isFinance(c);
  const map = {};
  events.rows.filter((e) => !hide(e.category)).forEach((e) => (map[e.category] ||= []).push({ id: e.id, name: e.name }));
  res.json({ types: types.rows.map((t) => t.name).filter((n) => !hide(n)), events: map });
});

app.post('/api/types', requireAuth, notOfficer, async (req, res) => {
  const name = str(req.body.name);
  if (!/^[\w][\w &.-]{1,39}$/.test(name)) throw httpError(400, 'Use 2–40 letters, numbers or spaces.');
  const r = await pool.query('INSERT INTO DocumentType (name) VALUES ($1) ON CONFLICT DO NOTHING RETURNING id', [name]);
  if (!r.rowCount) {
    const bin = await pool.query('SELECT 1 FROM DocumentType WHERE name = $1 AND is_deleted', [name]);
    throw httpError(409, bin.rowCount ? 'That type is in the Recycle Bin. Restore it from there.' : 'That document type already exists.');
  }
  await logActivity(req.session.userId, 'Create Document Type', null, `Created type "${name}"`);
  res.status(201).json({ success: true });
});

/* ---- Delete a type = move it, its events and its documents to the Recycle Bin ---- */
app.delete('/api/types/:name', requireAuth, requireRole('Administrator'), async (req, res) => {
  const name = req.params.name;
  assertCategoryAccess(req.session.role, name);
  const count = await tx(async (c) => {
    const t = await c.query('UPDATE DocumentType SET is_deleted = TRUE, deleted_at = now() WHERE name = $1 AND is_deleted = FALSE RETURNING id', [name]);
    if (!t.rowCount) throw httpError(404, 'Document type not found.');
    const d = await c.query('UPDATE Document SET is_deleted = TRUE, deleted_with_type = TRUE WHERE category = $1 AND is_deleted = FALSE RETURNING id', [name]);
    await c.query('UPDATE EventFolder SET is_deleted = TRUE, deleted_at = now(), deleted_with_type = TRUE WHERE category = $1 AND is_deleted = FALSE', [name]);
    await logActivity(req.session.userId, 'Delete Document Type', null, `Moved type "${name}" and ${d.rowCount} document(s) to Recycle Bin`, c);
    return d.rowCount;
  });
  res.json({ success: true, documents: count });
});

app.get('/api/types/deleted', requireAuth, notOfficer, async (req, res) => {
  const { rows } = await pool.query(`SELECT t.name, t.deleted_at, (SELECT COUNT(*)::int FROM Document d WHERE d.category = t.name) AS doc_count
                                     FROM DocumentType t WHERE t.is_deleted ORDER BY t.deleted_at DESC`);
  res.json({ types: rows.filter((t) => !isFinance(t.name) || canFinance(req.session.role)) });
});

app.post('/api/types/restore/:name', requireAuth, notOfficer, async (req, res) => {
  const name = req.params.name;
  assertCategoryAccess(req.session.role, name);
  await tx(async (c) => {
    const t = await c.query('UPDATE DocumentType SET is_deleted = FALSE, deleted_at = NULL WHERE name = $1 AND is_deleted RETURNING id', [name]);
    if (!t.rowCount) throw httpError(404, 'Document type not found in the Recycle Bin.');
    await c.query('UPDATE Document SET is_deleted = FALSE, deleted_with_type = FALSE WHERE category = $1 AND deleted_with_type', [name]);
    await c.query('UPDATE EventFolder SET is_deleted = FALSE, deleted_at = NULL, deleted_with_type = FALSE WHERE category = $1 AND deleted_with_type', [name]);
    await logActivity(req.session.userId, 'Restore Document Type', null, `Restored type "${name}" with its events and documents`, c);
  });
  res.json({ success: true });
});

app.delete('/api/types/permanent/:name', requireAuth, requireRole('Administrator'), async (req, res) => {
  const name = req.params.name;
  assertCategoryAccess(req.session.role, name);
  const files = [];
  await tx(async (c) => {
    const t = await c.query('SELECT id FROM DocumentType WHERE name = $1 AND is_deleted FOR UPDATE', [name]);
    if (!t.rowCount) throw httpError(404, 'Document type not found in the Recycle Bin.');
    const docs = await c.query('SELECT id FROM Document WHERE category = $1', [name]);
    for (const d of docs.rows) await purgeDocument(c, d.id, files);
    await c.query('DELETE FROM EventFolder WHERE category = $1', [name]);
    await c.query('DELETE FROM DocumentType WHERE name = $1', [name]);
    await logActivity(req.session.userId, 'Permanent Delete', null, `Permanently deleted type "${name}" and ${docs.rowCount} document(s)`, c);
  });
  await Promise.all(files.map((f) => fsp.unlink(f).catch(() => {})));
  res.json({ success: true });
});

app.post('/api/folders', requireAuth, async (req, res) => {
  const category = str(req.body.category), name = str(req.body.name);
  if (!category || name.length < 2 || name.length > 80) throw httpError(400, 'Event name must be 2–80 characters.');
  if (name.toLowerCase() === 'general') throw httpError(400, '“General” is reserved.');
  assertCategoryAccess(req.session.role, category);
  const t = await pool.query('SELECT 1 FROM DocumentType WHERE name = $1 AND is_deleted = FALSE', [category]);
  if (!t.rowCount) throw httpError(400, 'Unknown document type.');
  const r = await pool.query(
    `INSERT INTO EventFolder (category, name) VALUES ($1,$2)
     ON CONFLICT (category, name) DO UPDATE SET is_deleted = FALSE, deleted_at = NULL WHERE EventFolder.is_deleted
     RETURNING id`, [category, name]);
  if (!r.rowCount) throw httpError(409, 'That event already exists in this document type.');
  await logActivity(req.session.userId, 'Create Event', null, `Created event "${name}" under ${category}`);
  res.status(201).json({ success: true, id: r.rows[0].id });
});

app.put('/api/folders/:id', requireAuth, notOfficer, async (req, res) => {
  await assertFolderAccess(req.session.role, req.params.id);
  const name = str(req.body.name);
  if (name.length < 2 || name.length > 80) throw httpError(400, 'Event name must be 2–80 characters.');
  if (name.toLowerCase() === 'general') throw httpError(400, '“General” is reserved.');
  await tx(async (c) => {
    const cur = await c.query('SELECT category, name FROM EventFolder WHERE id = $1 AND is_deleted = FALSE FOR UPDATE', [req.params.id]);
    if (!cur.rowCount) throw httpError(404, 'Event not found.');
    const { category, name: old } = cur.rows[0];
    const dup = await c.query('SELECT 1 FROM EventFolder WHERE category = $1 AND name = $2 AND id <> $3', [category, name, req.params.id]);
    if (dup.rowCount) throw httpError(409, 'An event with that name already exists.');
    await c.query('UPDATE EventFolder SET name = $1 WHERE id = $2', [name, req.params.id]);
    await c.query('UPDATE Document SET subfolder = $1 WHERE category = $2 AND subfolder = $3', [name, category, old]); // keep documents attached
    await logActivity(req.session.userId, 'Rename Event', null, `"${old}" → "${name}" under ${category}`, c);
  });
  res.json({ success: true });
});

app.delete('/api/folders/:id', requireAuth, notOfficer, async (req, res) => {
  await assertFolderAccess(req.session.role, req.params.id);
  const r = await pool.query('UPDATE EventFolder SET is_deleted = TRUE, deleted_at = now() WHERE id = $1 AND is_deleted = FALSE RETURNING category, name', [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Event not found.');
  await logActivity(req.session.userId, 'Delete Event', null, `Moved event "${r.rows[0].name}" to Recycle Bin`);
  res.json({ success: true });
});

app.get('/api/folders/deleted', requireAuth, notOfficer, async (req, res) => {
  const { rows } = await pool.query('SELECT id, category, name, deleted_at FROM EventFolder WHERE is_deleted = TRUE ORDER BY deleted_at DESC');
  res.json({ folders: rows.filter((f) => !isFinance(f.category) || canFinance(req.session.role)) });
});

app.post('/api/folders/restore/:id', requireAuth, notOfficer, async (req, res) => {
  await assertFolderAccess(req.session.role, req.params.id);
  const r = await pool.query('UPDATE EventFolder SET is_deleted = FALSE, deleted_at = NULL WHERE id = $1 AND is_deleted RETURNING name', [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Event not found in the Recycle Bin.');
  await logActivity(req.session.userId, 'Restore Event', null, `Restored event "${r.rows[0].name}"`);
  res.json({ success: true });
});

app.delete('/api/folders/permanent/:id', requireAuth, requireRole('Administrator'), async (req, res) => {
  await assertFolderAccess(req.session.role, req.params.id);
  const r = await pool.query('DELETE FROM EventFolder WHERE id = $1 AND is_deleted RETURNING name', [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Event not found in the Recycle Bin.');
  await logActivity(req.session.userId, 'Permanent Delete', null, `Permanently deleted event "${r.rows[0].name}"`);
  res.json({ success: true });
});

/* ==========================================================================
   DOCUMENTS
   ========================================================================== */
app.get('/api/documents', requireAuth, async (req, res) => {
  const role = req.session.role;
  const keyword = str(req.query.keyword), category = str(req.query.category);
  const params = [];
  let sql = `${DOC_SELECT} WHERE d.is_deleted = FALSE${visibility(role)}`;
  if (keyword) {
    params.push(`%${escapeLike(keyword)}%`);
    const p = `$${params.length}`;
    sql += ` AND (d.title ILIKE ${p} OR d.category ILIKE ${p} OR d.subfolder ILIKE ${p} OR dv.standardized_file_name ILIKE ${p})`;
  }
  if (category) { params.push(category); sql += ` AND d.category = $${params.length}`; }
  sql += ' ORDER BY d.document_date DESC, d.id DESC';
  const { rows } = await pool.query(sql, params);
  res.json({ userRole: role, documents: rows.map(toDoc) });
});

app.get('/api/documents/frequent', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`${DOC_SELECT} WHERE d.is_deleted = FALSE${visibility(req.session.role)} ORDER BY COALESCE(d.view_count,0) DESC, d.id DESC LIMIT 4`);
  res.json({ documents: rows.map(toDoc) });
});

app.get('/api/documents/deleted', requireAuth, notOfficer, async (req, res) => {
  const { rows } = await pool.query(`${DOC_SELECT} WHERE d.is_deleted = TRUE${visibility(req.session.role)} ORDER BY d.id DESC`);
  res.json({ userRole: req.session.role, documents: rows.map(toDoc) });
});

/* ---- Upload ---- */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) =>
    ALLOWED_EXT.has(path.extname(file.originalname).toLowerCase())
      ? cb(null, true)
      : cb(httpError(400, `Unsupported file type. Allowed: ${[...ALLOWED_EXT].join(' ')}`)),
});

app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  const title = str(req.body.title), category = str(req.body.category), date = str(req.body.date);
  const sub = str(req.body.subfolder) || 'General';
  const file = req.file;
  const { userId, role } = req.session;

  if (!file || !title || !category || !date) throw httpError(400, 'Title, type, date and file are all required.');
  if (title.length > 150) throw httpError(400, 'Title is too long (150 characters max).');
  if (!DATE_RE.test(date)) throw httpError(400, 'Invalid date.');
  assertCategoryAccess(role, category);

  const type = await pool.query('SELECT 1 FROM DocumentType WHERE name = $1 AND is_deleted = FALSE', [category]);
  if (!type.rowCount) throw httpError(400, 'Unknown document type.');
  if (sub !== 'General') {
    const ev = await pool.query('SELECT 1 FROM EventFolder WHERE category = $1 AND name = $2 AND is_deleted = FALSE', [category, sub]);
    if (!ev.rowCount) throw httpError(400, 'That event folder does not exist.');
  }

  const ext = path.extname(file.originalname).toLowerCase();
  const dir = path.join(REPO_DIR, safeSegment(category));
  await fsp.mkdir(dir, { recursive: true });

  let writtenPath = null;
  try {
    const out = await tx(async (c) => {
      // Serialise concurrent uploads of the same title so two people can't both become "v2"
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`${category}|${sub}|${title.toLowerCase()}`]);
      const found = await c.query('SELECT id, is_deleted FROM Document WHERE title = $1 AND category = $2 AND subfolder = $3', [title, category, sub]);

      let documentId, version = 1;
      if (found.rowCount) {
        if (found.rows[0].is_deleted) throw httpError(409, 'A document with this title is in the Recycle Bin. Restore it or pick another title.');
        documentId = found.rows[0].id;
        const v = await c.query('SELECT COALESCE(MAX(version_number),0) AS m FROM DocumentVersion WHERE document_id = $1', [documentId]);
        version = v.rows[0].m + 1;
      } else {
        const d = await c.query('INSERT INTO Document (title, category, subfolder, document_date) VALUES ($1,$2,$3,$4) RETURNING id', [title, category, sub, date]);
        documentId = d.rows[0].id;
      }

      const name = buildFileName(category, title, date, version, ext);
      const finalPath = path.join(dir, name);
      await fsp.writeFile(finalPath, file.buffer, { flag: 'wx' });
      writtenPath = finalPath;

      await c.query('INSERT INTO DocumentVersion (document_id, version_number, standardized_file_name, file_path, uploaded_by) VALUES ($1,$2,$3,$4,$5)', [documentId, version, name, finalPath, userId]);
      await logActivity(userId, 'Upload Document', documentId, `Version ${version} uploaded to ${sub}`, c);
      return { documentId, version, name };
    });
    res.status(201).json({ success: true, ...out });
  } catch (err) {
    if (writtenPath) await fsp.unlink(writtenPath).catch(() => {}); // don't leave orphan files behind
    throw err;
  }
});

/* ---- Edit metadata (also re-standardises file names and moves files) ---- */
app.put('/api/documents/:id', requireAuth, async (req, res) => {
  const title = str(req.body.title), category = str(req.body.category), date = str(req.body.date);
  const { userId, role } = req.session;
  if (!title || !category || !date) throw httpError(400, 'Title, type and date are required.');
  if (title.length > 150) throw httpError(400, 'Title is too long (150 characters max).');
  if (!DATE_RE.test(date)) throw httpError(400, 'Invalid date.');
  assertCategoryAccess(role, category);

  const moves = [];
  try {
    await tx(async (c) => {
      const cur = await c.query('SELECT id, category FROM Document WHERE id = $1 FOR UPDATE', [req.params.id]);
      if (!cur.rowCount) throw httpError(404, 'Document not found.');
      assertCategoryAccess(role, cur.rows[0].category);
      const type = await c.query('SELECT 1 FROM DocumentType WHERE name = $1 AND is_deleted = FALSE', [category]);
      if (!type.rowCount) throw httpError(400, 'Unknown document type.');

      const versions = await c.query('SELECT id, version_number, standardized_file_name, file_path FROM DocumentVersion WHERE document_id = $1', [req.params.id]);
      const newDir = path.join(REPO_DIR, safeSegment(category));
      await fsp.mkdir(newDir, { recursive: true });

      for (const v of versions.rows) {
        const newName = buildFileName(category, title, date, v.version_number, path.extname(v.standardized_file_name));
        const from = storedFile(v), to = path.join(newDir, newName);
        if (from !== to) {
          try { await fsp.rename(from, to); moves.push({ from, to }); }
          catch (e) { if (e.code !== 'ENOENT') throw e; } // file already missing: still fix the DB name
        }
        await c.query('UPDATE DocumentVersion SET standardized_file_name = $1, file_path = $2 WHERE id = $3', [newName, to, v.id]);
      }

      const moved = cur.rows[0].category !== category;
      await c.query(`UPDATE Document SET title = $1, category = $2, document_date = $3${moved ? ", subfolder = 'General'" : ''} WHERE id = $4`, [title, category, date, req.params.id]);
      await logActivity(userId, 'Edit Document', req.params.id, `Updated metadata (type: ${category})`, c);
    });
  } catch (err) {
    for (const m of moves.reverse()) await fsp.rename(m.to, m.from).catch(() => {}); // undo file moves if the DB failed
    throw err;
  }
  res.json({ success: true });
});

/* ---- Approval ---- */
const approve = [requireAuth, requireRole(...APPROVER_ROLES), async (req, res) => {
  const r = await pool.query(
    `UPDATE Document SET approval_status = 'Approved', approver = $1, approval_date = CURRENT_TIMESTAMP
     WHERE id = $2 AND is_deleted = FALSE AND approval_status IS DISTINCT FROM 'Approved' RETURNING id`,
    [req.session.username, req.params.id]);
  if (!r.rowCount) throw httpError(409, 'Document is already approved or no longer exists.');
  await logActivity(req.session.userId, 'Approve Document', req.params.id, 'Document marked as Approved');
  res.json({ success: true });
}];
app.post('/api/documents/approve/:id', ...approve);
app.post('/api/approve/:id', ...approve); // backward-compatible alias

/* ---- Recycle bin ---- */
app.post('/api/documents/soft-delete/:id', requireAuth, notOfficer, async (req, res) => {
  const r = await pool.query(`UPDATE Document d SET is_deleted = TRUE WHERE d.id = $1 AND d.is_deleted = FALSE${visibility(req.session.role)} RETURNING d.id`, [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Document not found.');
  await logActivity(req.session.userId, 'Move to Recycle Bin', req.params.id, 'Document moved to recycle bin');
  res.json({ success: true });
});

app.post('/api/documents/restore/:id', requireAuth, notOfficer, async (req, res) => {
  const gone = await pool.query('SELECT t.name FROM Document d JOIN DocumentType t ON t.name = d.category WHERE d.id = $1 AND t.is_deleted', [req.params.id]);
  if (gone.rowCount) throw httpError(409, `Restore the document type “${gone.rows[0].name}” first.`);
  const r = await pool.query(`UPDATE Document d SET is_deleted = FALSE WHERE d.id = $1 AND d.is_deleted${visibility(req.session.role)} RETURNING d.id`, [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Document not found in the Recycle Bin.');
  await logActivity(req.session.userId, 'Restore Document', req.params.id, 'Document restored from recycle bin');
  res.json({ success: true });
});

app.delete('/api/documents/permanent-delete/:id', requireAuth, requireRole('Administrator'), async (req, res) => {
  const files = [];
  await tx(async (c) => {
    const d = await c.query(`SELECT d.title FROM Document d WHERE d.id = $1 AND d.is_deleted${visibility(req.session.role)} FOR UPDATE OF d`, [req.params.id]);
    if (!d.rowCount) throw httpError(404, 'Document not found in the Recycle Bin.');
    await purgeDocument(c, req.params.id, files);
    await logActivity(req.session.userId, 'Permanent Delete', null, `Permanently deleted "${d.rows[0].title}" (ID ${req.params.id})`, c);
  });
  await Promise.all(files.map((f) => fsp.unlink(f).catch(() => {}))); // remove files only after the DB commit succeeded
  res.json({ success: true });
});

/* ---- Views counter ---- */
app.post('/api/activity/log-view/:id', requireAuth, async (req, res) => {
  const r = await pool.query(`UPDATE Document d SET view_count = COALESCE(view_count,0) + 1 WHERE d.id = $1 AND d.is_deleted = FALSE${visibility(req.session.role)} RETURNING d.id`, [req.params.id]);
  if (!r.rowCount) throw httpError(404, 'Document not found.');
  await logActivity(req.session.userId, 'View Document', req.params.id, 'Document previewed or accessed');
  res.json({ success: true });
});

/* ==========================================================================
   FILE DELIVERY  (uploads are private — sign-in required)
   ========================================================================== */
app.use('/repository', requireAuth, (req, res, next) => {
  let folder = '';
  try { folder = decodeURIComponent(req.path).split('/')[1] || ''; } catch { return res.sendStatus(400); }
  if (isFinance(folder) && !canFinance(req.session.role)) return res.sendStatus(403);
  next();
}, express.static(REPO_DIR, { dotfiles: 'deny', index: false, fallthrough: false }));

// Short-lived signed links so Google's Office viewer can fetch a private file for preview.
const sign = (id, exp) => crypto.createHmac('sha256', SESSION_SECRET).update(`${id}.${exp}`).digest('hex');

app.get('/api/documents/:id/preview-link', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`${DOC_SELECT} WHERE d.id = $1 AND d.is_deleted = FALSE${visibility(req.session.role)}`, [req.params.id]);
  if (!rows[0]) throw httpError(404, 'Document not found.');
  const exp = Date.now() + 5 * 60 * 1000;
  res.json({ url: `/signed/${req.params.id}/${exp}/${sign(req.params.id, exp)}/${encodeURIComponent(rows[0].standardized_file_name)}` });
});

app.get('/signed/:id/:exp/:sig/:name', async (req, res) => {
  const { id, exp, sig } = req.params;
  const good = sign(id, exp);
  const ok = sig.length === good.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good));
  if (!ok || Number(exp) < Date.now()) return res.sendStatus(403);
  const { rows } = await pool.query(`${DOC_SELECT} WHERE d.id = $1 AND d.is_deleted = FALSE`, [id]);
  if (!rows[0]) return res.sendStatus(404);
  res.sendFile(storedFile(rows[0]), (err) => { if (err && !res.headersSent) res.sendStatus(404); });
});

/* ==========================================================================
   ACTIVITY LOG & BACKUP
   ========================================================================== */
app.get('/api/activity', requireAuth, requireRole(...ADMIN_ROLES), async (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 300, 1), 1000);
  const { rows } = await pool.query(
    `SELECT a.id, a.action_date, COALESCE(u.username, 'deleted-user') AS username, a.action_type,
            a.document_id, d.title AS document_title, a.result
     FROM ActivityLogEntry a
     LEFT JOIN UserAccount u ON a.user_id = u.id
     LEFT JOIN Document d ON a.document_id = d.id
     ORDER BY a.action_date DESC, a.id DESC LIMIT $1`, [limit]);
  res.json(rows);
});

async function getDatabaseExport() {
  const [users, docs, versions, activity, types, events] = await Promise.all([
    pool.query('SELECT id, full_name, username, access_level, status, date_created FROM UserAccount'), // never export password hashes
    pool.query('SELECT * FROM Document'),
    pool.query('SELECT * FROM DocumentVersion'),
    pool.query('SELECT * FROM ActivityLogEntry'),
    pool.query('SELECT * FROM DocumentType'),
    pool.query('SELECT * FROM EventFolder'),
  ]);
  return {
    export_date: new Date().toISOString(),
    UserAccount: users.rows, Document: docs.rows, DocumentVersion: versions.rows,
    ActivityLogEntry: activity.rows, DocumentType: types.rows, EventFolder: events.rows,
  };
}

function buildBackup(archive, dbBackup) {
  archive.append(JSON.stringify(dbBackup, null, 2), { name: 'database_export.json' });
  if (fs.existsSync(REPO_DIR)) archive.directory(REPO_DIR, 'repository_files');
}

app.get('/api/backup', requireAuth, requireRole('Administrator'), async (req, res) => {
  const dbBackup = await getDatabaseExport();
  res.attachment(`ISS_DS_Backup_${new Date().toISOString().split('T')[0]}.zip`);
  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', (err) => { console.error('Backup stream error:', err); res.destroy(err); });
  archive.pipe(res);
  buildBackup(archive, dbBackup);
  await archive.finalize();
  logActivity(req.session.userId, 'System Backup', null, 'Generated manual system backup ZIP').catch(console.error);
});

// Automated weekly backup (NFR-005): Sundays at 00:00, keeps the 8 newest
cron.schedule('0 0 * * 0', async () => {
  console.log('Running scheduled weekly backup…');
  try {
    await fsp.mkdir(BACKUP_DIR, { recursive: true });
    const dbBackup = await getDatabaseExport();
    const target = path.join(BACKUP_DIR, `Weekly_Backup_${new Date().toISOString().split('T')[0]}.zip`);
    const output = fs.createWriteStream(target);
    const archive = archiver('zip', { zlib: { level: 6 } });
    const closed = new Promise((resolve, reject) => { output.on('close', resolve); output.on('error', reject); archive.on('error', reject); });
    archive.pipe(output);
    buildBackup(archive, dbBackup);
    await archive.finalize();
    await closed;
    const old = (await fsp.readdir(BACKUP_DIR)).filter((f) => f.startsWith('Weekly_Backup_')).sort().reverse().slice(8);
    await Promise.all(old.map((f) => fsp.unlink(path.join(BACKUP_DIR, f)).catch(() => {})));
    console.log('Weekly backup saved to /backups.');
  } catch (err) {
    console.error('Automated backup failed:', err);
  }
});

/* ==========================================================================
   ERRORS & STARTUP
   ========================================================================== */
app.use((req, res) => {
  if (wantsJson(req)) return res.status(404).json({ success: false, error: 'Not found.' });
  res.status(404).type('text').send('404 — Page not found');
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  let status = err.status || 500;
  let message = err.message;
  if (err instanceof multer.MulterError) {
    status = 400;
    message = err.code === 'LIMIT_FILE_SIZE' ? `File is too large (max ${MAX_UPLOAD_MB} MB).` : err.message;
  } else if (err.code === 'ENOENT' && req.originalUrl.startsWith('/repository')) {
    status = 404; message = 'File not found.';
  } else if (status >= 500) {
    console.error(`${req.method} ${req.originalUrl}:`, err);
    message = IS_PROD ? 'Something went wrong on the server.' : err.message;
  }
  if (res.headersSent) return;
  res.status(status).json({ success: false, error: message });
});

let server;
(async () => {
  try { await ensureSchema(); } catch (err) { console.error('Schema bootstrap failed (continuing):', err.message); }
  server = app.listen(PORT, () => console.log(`ISS-DS running on http://localhost:${PORT}`));
})();

const shutdown = () => { console.log('Shutting down…'); (server ? server.close.bind(server) : (cb) => cb())(() => pool.end().then(() => process.exit(0))); };
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);