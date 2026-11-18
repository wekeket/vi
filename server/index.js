require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const { PORT = 3000, DB_HOST = 'localhost', DB_PORT = 3306, DB_USER = 'root', DB_PASSWORD = '', DB_NAME = 'vms', JWT_SECRET } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 16) {
  console.error('JWT_SECRET is missing or too short. Copy .env.example to .env and set it.');
  process.exit(1);
}
if (!/^[A-Za-z0-9_]+$/.test(DB_NAME)) {
  console.error('DB_NAME may only contain letters, numbers and underscores.');
  process.exit(1);
}

let pool;
const badge = (id) => `V-${String(id).padStart(3, '0')}`;
const ms = (d) => (d ? new Date(d).getTime() : null);
const visitOut = (r) => ({
  id: r.id, badge: badge(r.id), name: r.name, contact: r.contact, purpose: r.purpose, host: r.host,
  tin: ms(r.time_in), tout: ms(r.time_out), arch: !!r.archived,
});
const userOut = (r) => ({ id: r.id, name: r.name, username: r.username, role: r.role, active: !!r.active });

async function initDb() {
  const boot = await mysql.createConnection({ host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASSWORD, multipleStatements: true });
  await boot.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await boot.changeUser({ database: DB_NAME });
  // Run schema.sql minus its CREATE DATABASE / USE lines (the DB name comes from .env).
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8')
    .split('\n').filter((l) => !/^\s*(CREATE DATABASE|USE)\b/i.test(l)).join('\n');
  await boot.query(sql);
  await boot.end();
  pool = mysql.createPool({
    host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASSWORD, database: DB_NAME,
    timezone: 'Z', connectionLimit: 10, dateStrings: false,
  });
  await pool.query("SET time_zone = '+00:00'").catch(() => {});
}

const log = (userId, username, action) =>
  pool.query('INSERT INTO activity_logs (user_id, username, action) VALUES (?,?,?)', [userId || null, username || 'system', action]).catch(() => {});

// ---- tiny in-memory login throttle (per IP + username) ----
const fails = new Map();
const throttled = (k) => { const f = fails.get(k); return f && f.n >= 5 && Date.now() - f.t < 5 * 60 * 1000; };
const fail = (k) => { const f = fails.get(k); fails.set(k, { n: (f && Date.now() - f.t < 5 * 60 * 1000 ? f.n : 0) + 1, t: Date.now() }); };

const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error.' }); });
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function auth(req, res, next) {
  const h = req.headers.authorization || '';
  try {
    const p = jwt.verify(h.replace(/^Bearer\s+/i, ''), JWT_SECRET);
    const [[u]] = await pool.query('SELECT * FROM users WHERE id = ?', [p.id]);
    if (!u || !u.active) return res.status(401).json({ error: 'Session is no longer valid.' });
    req.user = u;
    next();
  } catch (e) { res.status(401).json({ error: 'Please sign in.' }); }
}
const adminOnly = (req, res, next) => (req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Administrators only.' }));
const sign = (u) => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '8h' });

const app = express();
app.use(cors());
app.use(express.json({ limit: '50kb' }));

// ---------- setup & auth ----------
app.get('/api/setup-status', wrap(async (req, res) => {
  const [[r]] = await pool.query('SELECT COUNT(*) AS n FROM users');
  res.json({ needsSetup: r.n === 0 });
}));

app.post('/api/setup', wrap(async (req, res) => {
  const [[r]] = await pool.query('SELECT COUNT(*) AS n FROM users');
  if (r.n > 0) return res.status(403).json({ error: 'Setup is already complete.' });
  const name = str(req.body.name, 120), username = str(req.body.username, 50).toLowerCase(), password = req.body.password;
  if (!name || !username || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Enter a name, a username, and a password of 8+ characters.' });
  const [ins] = await pool.query('INSERT INTO users (name, username, password_hash, role) VALUES (?,?,?,?)', [name, username, await bcrypt.hash(password, 10), 'admin']);
  await log(ins.insertId, username, 'Created first administrator account');
  const [[u]] = await pool.query('SELECT * FROM users WHERE id = ?', [ins.insertId]);
  res.json({ token: sign(u), user: userOut(u) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const username = str(req.body.username, 50).toLowerCase(), password = typeof req.body.password === 'string' ? req.body.password : '';
  const key = `${req.ip}|${username}`;
  if (throttled(key)) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  const [[u]] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
  if (!u || !u.active || !(await bcrypt.compare(password, u.password_hash))) {
    fail(key);
    return res.status(401).json({ error: 'Wrong username or password, or the account is disabled.' });
  }
  fails.delete(key);
  await log(u.id, u.username, 'Signed in');
  res.json({ token: sign(u), user: userOut(u) });
}));

app.get('/api/me', auth, (req, res) => res.json({ user: userOut(req.user) }));
app.post('/api/logout', auth, wrap(async (req, res) => { await log(req.user.id, req.user.username, req.body && req.body.reason === 'idle' ? 'Signed out (inactivity)' : 'Signed out'); res.json({ ok: true }); }));

// ---------- visits ----------
app.get('/api/visits', auth, wrap(async (req, res) => {
  const withArch = req.user.role === 'admin';
  const [rows] = await pool.query(`SELECT * FROM visits ${withArch ? '' : 'WHERE archived = 0'} ORDER BY time_in DESC, id DESC`);
  res.json({ visits: rows.map(visitOut) });
}));

app.post('/api/visits', auth, wrap(async (req, res) => {
  const f = { name: str(req.body.name, 120), contact: str(req.body.contact, 40), purpose: str(req.body.purpose, 255), host: str(req.body.host, 160) };
  if (Object.values(f).some((x) => !x)) return res.status(400).json({ error: 'Fill in every field.' });
  const [ins] = await pool.query('INSERT INTO visits (name, contact, purpose, host, created_by) VALUES (?,?,?,?,?)', [f.name, f.contact, f.purpose, f.host, req.user.id]);
  const [[v]] = await pool.query('SELECT * FROM visits WHERE id = ?', [ins.insertId]);
  await log(req.user.id, req.user.username, `Registered ${v.name} (${badge(v.id)})`);
  res.status(201).json({ visit: visitOut(v) });
}));

app.post('/api/visits/:id/timeout', auth, wrap(async (req, res) => {
  const [[v]] = await pool.query('SELECT * FROM visits WHERE id = ?', [req.params.id]);
  if (!v) return res.status(404).json({ error: 'Visit not found.' });
  if (v.time_out) return res.status(409).json({ error: 'Already checked out.' });
  await pool.query('UPDATE visits SET time_out = NOW(3) WHERE id = ?', [v.id]);
  await log(req.user.id, req.user.username, `Time-out recorded for ${v.name} (${badge(v.id)})`);
  const [[n]] = await pool.query('SELECT * FROM visits WHERE id = ?', [v.id]);
  res.json({ visit: visitOut(n) });
}));

app.patch('/api/visits/:id', auth, adminOnly, wrap(async (req, res) => {
  const f = { name: str(req.body.name, 120), contact: str(req.body.contact, 40), purpose: str(req.body.purpose, 255), host: str(req.body.host, 160) };
  if (Object.values(f).some((x) => !x)) return res.status(400).json({ error: 'Fill in every field.' });
  const [r] = await pool.query('UPDATE visits SET name=?, contact=?, purpose=?, host=? WHERE id=?', [f.name, f.contact, f.purpose, f.host, req.params.id]);
  if (!r.affectedRows) return res.status(404).json({ error: 'Visit not found.' });
  await log(req.user.id, req.user.username, `Edited record ${badge(Number(req.params.id))}`);
  const [[v]] = await pool.query('SELECT * FROM visits WHERE id = ?', [req.params.id]);
  res.json({ visit: visitOut(v) });
}));

app.post('/api/visits/:id/archive', auth, adminOnly, wrap(async (req, res) => {
  const [[v]] = await pool.query('SELECT * FROM visits WHERE id = ?', [req.params.id]);
  if (!v) return res.status(404).json({ error: 'Visit not found.' });
  await pool.query('UPDATE visits SET archived = ? WHERE id = ?', [v.archived ? 0 : 1, v.id]);
  await log(req.user.id, req.user.username, `${v.archived ? 'Restored' : 'Archived'} ${badge(v.id)}`);
  const [[n]] = await pool.query('SELECT * FROM visits WHERE id = ?', [v.id]);
  res.json({ visit: visitOut(n) });
}));

// ---------- staff ----------
app.get('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM users ORDER BY id');
  res.json({ users: rows.map(userOut) });
}));

app.post('/api/users', auth, adminOnly, wrap(async (req, res) => {
  const name = str(req.body.name, 120), username = str(req.body.username, 50).toLowerCase(), password = req.body.password;
  const role = req.body.role === 'admin' ? 'admin' : 'staff';
  if (!name || !username || typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Enter a name, a username, and a password of 8+ characters.' });
  const [[dup]] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
  if (dup) return res.status(409).json({ error: 'That username is taken.' });
  const [ins] = await pool.query('INSERT INTO users (name, username, password_hash, role) VALUES (?,?,?,?)', [name, username, await bcrypt.hash(password, 10), role]);
  await log(req.user.id, req.user.username, `Created account ${username}`);
  const [[u]] = await pool.query('SELECT * FROM users WHERE id = ?', [ins.insertId]);
  res.status(201).json({ user: userOut(u) });
}));

app.post('/api/users/:id/toggle', auth, adminOnly, wrap(async (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: "You can't disable your own account." });
  const [[u]] = await pool.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!u) return res.status(404).json({ error: 'Account not found.' });
  await pool.query('UPDATE users SET active = ? WHERE id = ?', [u.active ? 0 : 1, u.id]);
  await log(req.user.id, req.user.username, `${u.active ? 'Disabled' : 'Enabled'} ${u.username}`);
  const [[n]] = await pool.query('SELECT * FROM users WHERE id = ?', [u.id]);
  res.json({ user: userOut(n) });
}));

// ---------- activity ----------
app.get('/api/logs', auth, adminOnly, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT username, action, created_at FROM activity_logs ORDER BY created_at DESC, id DESC LIMIT 300');
  res.json({ logs: rows.map((r) => ({ t: ms(r.created_at), u: r.username, a: r.action })) });
}));

initDb()
  .then(() => app.listen(PORT, () => console.log(`VMS API running on http://localhost:${PORT} (database: ${DB_NAME})`)))
  .catch((e) => { console.error('Could not start. Is MySQL running and are the .env credentials right?\n', e.message); process.exit(1); });
