// server.js
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');
const https = require('https');

const { TableClient } = require("@azure/data-tables");

const app = express();
const PORT = process.env.PORT || 8080;

// ----- CONFIG (set as app settings in Azure) -----
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-change-in-prod';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cse@admin2k25';
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
const TABLE_NAME = process.env.TABLE_NAME || 'StaffNotes';

// ----- staff.json path (server-only) -----
const STAFF_JSON = path.join(__dirname, 'staff.json');

// ----- init table client if connection string provided -----
let tableClient = null;
if (AZURE_STORAGE_CONNECTION_STRING) {
  tableClient = new TableClient(AZURE_STORAGE_CONNECTION_STRING, TABLE_NAME);
}

// ----- middlewares -----
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public'))); // public site files

// ----- helpers: staff list -----
function loadStaffList() {
  if (!fs.existsSync(STAFF_JSON)) return [];
  try {
    const raw = fs.readFileSync(STAFF_JSON, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('Failed to load staff.json', e);
    return [];
  }
}
function findStaffByEmailAndPhone(email, phone) {
  const list = loadStaffList();
  return list.find(s => s.email === email && (s.phone === phone || s.phone === (`+91${phone}`) || s.phone.replace(/\D/g,'') === phone.replace(/\D/g,'')));
}

// ----- Azure Table helpers (notes) -----
async function getNotesFromTable(email) {
  if (!tableClient) return '';
  try {
    const entity = await tableClient.getEntity(email, 'notes');
    return entity.notes || '';
  } catch (err) {
    // not found or error -> return empty
    return '';
  }
}

async function upsertNotesToTable(email, notes) {
  if (!tableClient) throw new Error('Table storage not configured');
  const entity = {
    partitionKey: email,
    rowKey: 'notes',
    notes: notes || ''
  };
  await tableClient.upsertEntity(entity, "Merge");
}

// ----- auth middleware -----
function requireAuth(req, res, next) {
  const { auth } = req.signedCookies;
  if (!auth) return res.status(401).json({ message: 'Unauthorized' });
  // auth value is staff email stored during login
  const staff = loadStaffList().find(s => s.email === auth);
  if (!staff) return res.status(401).json({ message: 'Unauthorized' });
  req.staff = staff;
  next();
}

function requireAdmin(req, res, next) {
  const { adminAuth } = req.signedCookies;
  if (!adminAuth || adminAuth !== 'true') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ----- API: staff login -----
app.post('/api/login', (req, res) => {
  const { email, phone } = req.body || {};
  if (!email || !phone) return res.status(400).json({ success: false, message: 'Missing' });

  const staff = findStaffByEmailAndPhone(email.trim(), phone.trim());
  if (!staff) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  // set signed httpOnly cookie with email as value
  res.cookie('auth', staff.email, {
    httpOnly: true,
    signed: true,
    sameSite: 'lax',
    secure: !!process.env.WEBSITE_SITE_NAME // secure only on https hosting
  });

  return res.json({ success: true });
});

// GET current staff profile
app.get('/api/me', requireAuth, (req, res) => {
  const { staff } = req;
  // return only safe fields
  res.json({
    name: staff.name,
    email: staff.email,
    phone: staff.phone,
    designation: staff.designation || ''
  });
});

// Staff notes routes (Azure Table)
app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const email = req.staff.email;
    const notes = tableClient ? await getNotesFromTable(email) : '';
    res.json({ notes });
  } catch (err) {
    console.error('GET notes failed', err);
    res.status(500).json({ notes: '' });
  }
});

app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    if (!tableClient) return res.status(500).json({ success: false, message: 'Storage not configured' });
    const { notes } = req.body || {};
    const email = req.staff.email;
    await upsertNotesToTable(email, notes || '');
    res.json({ success: true });
  } catch (err) {
    console.error('SAVE notes failed', err);
    res.status(500).json({ success: false });
  }
});

// staff logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth');
  res.json({ success: true });
});

// ----- ADMIN login (password only) -----
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

// Admin logout
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('adminAuth');
  res.json({ success: true });
});

// ----- Admin-only secure form proxy (hides GForm URLs from client) -----
app.get('/secure-form/:type', requireAdmin, (req, res) => {
  // Map type -> actual Google Form URL (server-side, not public)
  const forms = {
    placement: process.env.GFORM_PLACEMENT || '',
    achievements: process.env.GFORM_ACHIEVEMENTS || '',
    coderizz: process.env.GFORM_CODERIZZ || ''
  };

  const url = forms[req.params.type];
  if (!url) return res.status(404).send('Form not configured');

  // Basic proxy fetch and stream back to client (this hides the real GForm URL)
  https.get(url, proxyRes => {
    // forward content-type and status
    res.status(proxyRes.statusCode || 200);
    const contentType = proxyRes.headers['content-type'];
    if (contentType) res.setHeader('Content-Type', contentType);
    // pipe content
    proxyRes.pipe(res);
  }).on('error', (err) => {
    console.error('proxy error', err);
    res.status(502).send('Failed to load form');
  });
});

// fallback to index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// listen
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
