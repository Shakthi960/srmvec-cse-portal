// server.js
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');
const https = require('https');
const bcrypt = require('bcrypt');

const { TableClient } = require('@azure/data-tables');

const app = express();
const PORT = process.env.PORT || 8080;

// config from env
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change';
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
const TABLE_NAME = process.env.TABLE_NAME || 'StaffNotes';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cse@admin2k25';

// If provided, init table client
let tableClient = null;
if (AZURE_STORAGE_CONNECTION_STRING) {
  tableClient = new TableClient(AZURE_STORAGE_CONNECTION_STRING, TABLE_NAME);
}

// middlewares
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// helper: local staff.json fallback for display if needed
const STAFF_JSON = path.join(__dirname, 'staff.json');
function loadStaffList() {
  if (!fs.existsSync(STAFF_JSON)) return [];
  try { return JSON.parse(fs.readFileSync(STAFF_JSON, 'utf8')); }
  catch (e) { console.error('load staff.json error', e); return []; }
}

// ---------- TABLE helpers ----------

// get user entity by username (rowKey)
async function getUser(username) {
  if (!tableClient) return null;
  try {
    const entity = await tableClient.getEntity('staff', username);
    return entity;
  } catch (err) {
    return null;
  }
}

// upsert user (must include partitionKey='staff', rowKey=username)
async function upsertUserEntity(userEntity) {
  if (!tableClient) throw new Error('Table storage not configured');
  await tableClient.upsertEntity(userEntity, 'Merge');
}

// notes helpers: partitionKey = username, rowKey = 'notes'
async function getNotesForUser(username) {
  if (!tableClient) return '';
  try {
    const e = await tableClient.getEntity(username, 'notes');
    return e.notes || '';
  } catch (err) {
    return '';
  }
}
async function upsertNotesForUser(username, notes) {
  if (!tableClient) throw new Error('Table storage not configured');
  const entity = {
    partitionKey: username,
    rowKey: 'notes',
    notes: notes || ''
  };
  await tableClient.upsertEntity(entity, 'Merge');
}

// ---------- auth middleware ----------
function requireAuth(req, res, next) {
  const auth = req.signedCookies && req.signedCookies.auth;
  if (!auth) return res.status(401).json({ message: 'Unauthorized' });
  req.username = auth; // username stored in cookie on login
  next();
}
function requireAdmin(req, res, next) {
  const adminAuth = req.signedCookies && req.signedCookies.adminAuth;
  if (adminAuth === 'true') return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// ---------- API: staff login (username + password) ----------
app.post('/api/staff/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ success: false, message: 'Missing' });

    const user = await getUser(username);
    if (!user || !user.passwordHash) return res.status(401).json({ success: false });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ success: false });

    // set signed httpOnly cookie with username
    res.cookie('auth', username, {
      httpOnly: true,
      signed: true,
      sameSite: 'lax',
      secure: !!process.env.WEBSITE_SITE_NAME
    });

    return res.json({ success: true });
  } catch (err) {
    console.error('staff login error', err);
    return res.status(500).json({ success: false });
  }
});

// staff logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth');
  res.json({ success: true });
});

// get current user profile
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const user = await getUser(req.username);
    if (!user) return res.status(404).json({ message: 'Not found' });
    res.json({
      username: user.rowKey,
      name: user.name || user.rowKey,
      phone: user.phone || '',
      designation: user.designation || ''
    });
  } catch (err) {
    console.error('GET /api/me error', err);
    res.status(500).json({});
  }
});

// GET notes
app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const notes = await getNotesForUser(req.username);
    res.json({ notes });
  } catch (err) {
    console.error('GET notes error', err);
    res.status(500).json({ notes: '' });
  }
});

// POST notes
app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    const { notes } = req.body || {};
    await upsertNotesForUser(req.username, notes || '');
    res.json({ success: true });
  } catch (err) {
    console.error('POST notes error', err);
    res.status(500).json({ success: false });
  }
});

// ---------- Admin password-only login ----------
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ success: false });
  if (password === ADMIN_PASSWORD) {
    res.cookie('adminAuth', 'true', {
      httpOnly: true,
      signed: true,
      sameSite: 'lax',
      secure: !!process.env.WEBSITE_SITE_NAME
    });
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false });
});
app.post('/api/admin/logout', requireAdmin, (req, res) => {
  res.clearCookie('adminAuth');
  res.json({ success: true });
});

// Admin: create or update staff user (admin-only).
// body: { username, name, phone, password }
app.post('/api/admin/create-user', requireAdmin, async (req, res) => {
  try {
    const { username, name, phone, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ success: false, message: 'Missing' });

    const passwordHash = await bcrypt.hash(password, 10);
    const userEntity = {
      partitionKey: 'staff',
      rowKey: username,
      name: name || username,
      phone: phone || '',
      passwordHash
    };
    await upsertUserEntity(userEntity);
    res.json({ success: true });
  } catch (err) {
    console.error('create-user error', err);
    res.status(500).json({ success: false });
  }
});

// ---------- secure form proxy (admin only)
// If you want to hide the raw Google Form URL from client-side HTML, set
// GFORM_PLACEMENT / GFORM_ACHIEVEMENTS / GFORM_CODERIZZ env vars to the real URLs.
// This route will redirect to the configured URL (or you can change to stream).
app.get('/secure-form/:type', requireAdmin, (req, res) => {
  const map = {
    placement: process.env.GFORM_PLACEMENT || '',
    achievements: process.env.GFORM_ACHIEVEMENTS || '',
    coderizz: process.env.GFORM_CODERIZZ || ''
  };
  const url = map[req.params.type];
  if (!url) return res.status(404).send('Form not configured');
  // redirect; if you want to fully hide Google URL you'd stream & rewrite resources (more complex)
  res.redirect(url);
});

// fallback: serve index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// start
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
