// server.js (diagnostic-ready)
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');
const https = require('https');

let TableClient;
try {
  ({ TableClient } = require('@azure/data-tables'));
} catch (e) {
  // will log later if storage is required but package missing
  TableClient = null;
}

const app = express();
const PORT = process.env.PORT || 8080;

// config
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-change-in-prod';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cse@admin2k25';
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING || '';
const TABLE_NAME = process.env.TABLE_NAME || 'StaffNotes';
const STAFF_JSON = path.join(__dirname, 'staff.json');

console.log('=== STARTUP ===');
console.log('PORT=', PORT);
console.log('TABLE_NAME=', TABLE_NAME);
console.log('AZURE_STORAGE_CONNECTION_STRING set?', !!AZURE_STORAGE_CONNECTION_STRING);
console.log('Table SDK loaded?', !!TableClient);

// middlewares
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// table client init (if configured)
let tableClient = null;
if (AZURE_STORAGE_CONNECTION_STRING) {
  if (!TableClient) {
    console.error('ERROR: @azure/data-tables not installed but AZURE_STORAGE_CONNECTION_STRING provided.');
  } else {
    try {
      tableClient = new TableClient(AZURE_STORAGE_CONNECTION_STRING, TABLE_NAME);
      console.log('TableClient initialized for table', TABLE_NAME);
    } catch (err) {
      console.error('Failed to init TableClient:', err && err.message);
      tableClient = null;
    }
  }
}

// helpers
function loadStaffList() {
  if (!fs.existsSync(STAFF_JSON)) return [];
  try {
    return JSON.parse(fs.readFileSync(STAFF_JSON, 'utf8'));
  } catch (e) {
    console.error('Failed to load staff.json', e);
    return [];
  }
}
function findStaffByEmailAndPhone(email, phone) {
  const list = loadStaffList();
  return list.find(s => s.email === email && (s.phone === phone || s.phone === (`+91${phone}`) || s.phone.replace(/\D/g,'') === phone.replace(/\D/g,'')));
}

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
  const entity = { partitionKey: email, rowKey: 'notes', notes: notes || '' };
  await tableClient.upsertEntity(entity, "Merge");
}

// auth middlewares
function requireAuth(req, res, next) {
  try {
    const { auth } = req.signedCookies;
    if (!auth) return res.status(401).json({ message: 'Unauthorized' });
    const staff = loadStaffList().find(s => s.email === auth);
    if (!staff) return res.status(401).json({ message: 'Unauthorized' });
    req.staff = staff;
    next();
  } catch (err) {
    console.error('requireAuth error', err);
    return res.status(500).json({ message: 'Server error' });
  }
}
function requireAdmin(req, res, next) {
  const { adminAuth } = req.signedCookies;
  if (!adminAuth || adminAuth !== 'true') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// routes (login, me, notes)
app.post('/api/login', (req, res) => {
  try {
    const { email, phone } = req.body || {};
    if (!email || !phone) return res.status(400).json({ success: false, message: 'Missing' });
    const staff = findStaffByEmailAndPhone(email.trim(), phone.trim());
    if (!staff) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    res.cookie('auth', staff.email, { httpOnly: true, signed: true, sameSite: 'lax', secure: !!process.env.WEBSITE_SITE_NAME });
    return res.json({ success: true });
  } catch (err) {
    console.error('/api/login error', err);
    return res.status(500).json({ success: false });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  const s = req.staff;
  res.json({ name: s.name, email: s.email, phone: s.phone, designation: s.designation || '' });
});

app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const notes = tableClient ? await getNotesFromTable(req.staff.email) : '';
    res.json({ notes });
  } catch (err) {
    console.error('GET /api/notes error', err);
    res.status(500).json({ notes: '' });
  }
});

app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    if (!tableClient) return res.status(500).json({ success: false, message: 'Storage not configured' });
    await upsertNotesToTable(req.staff.email, req.body.notes || '');
    res.json({ success: true });
  } catch (err) {
    console.error('POST /api/notes error', err);
    res.status(500).json({ success: false });
  }
});

app.post('/api/logout', (req, res) => { res.clearCookie('auth'); res.json({ success: true }); });

app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ success: false });
  if (password === ADMIN_PASSWORD) {
    res.cookie('adminAuth', 'true', { httpOnly: true, signed: true, sameSite: 'lax', secure: !!process.env.WEBSITE_SITE_NAME });
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false });
});

app.post('/api/admin/logout', (req, res) => { res.clearCookie('adminAuth'); res.json({ success: true }); });

app.get('/secure-form/:type', requireAdmin, (req, res) => {
  const forms = {
    placement: process.env.GFORM_PLACEMENT || '',
    achievements: process.env.GFORM_ACHIEVEMENTS || '',
    coderizz: process.env.GFORM_CODERIZZ || ''
  };
  const url = forms[req.params.type];
  if (!url) return res.status(404).send('Form not configured');
  https.get(url, proxyRes => {
    if (proxyRes.headers['content-type']) res.setHeader('Content-Type', proxyRes.headers['content-type']);
    proxyRes.pipe(res);
  }).on('error', (err) => {
    console.error('proxy error', err);
    res.status(502).send('Failed to load form');
  });
});

// fallback
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// global error handlers
process.on('unhandledRejection', (reason) => { console.error('UNHANDLED REJECTION', reason); });
process.on('uncaughtException', (err) => { console.error('UNCAUGHT EXCEPTION', err); });

// start
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
