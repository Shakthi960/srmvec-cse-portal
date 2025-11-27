// server.js
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const https = require('https');
const { TableClient } = require('@azure/data-tables');

const app = express();
const PORT = process.env.PORT || 8080;

// ===== ENV CONFIG =====
const STAFF_EMAIL = process.env.STAFF_EMAIL;
const STAFF_PHONE = process.env.STAFF_PHONE;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change';
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING;

if (!STAFF_EMAIL || !STAFF_PHONE) {
  console.warn('⚠️ STAFF_EMAIL / STAFF_PHONE not set in environment variables!');
}
if (!ADMIN_PASSWORD) {
  console.warn('⚠️ ADMIN_PASSWORD not set in environment variables!');
}
if (!AZURE_STORAGE_CONNECTION_STRING) {
  console.warn('⚠️ AZURE_STORAGE_CONNECTION_STRING not set in environment variables!');
}

// ===== MIDDLEWARE =====
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// ===== AZURE TABLE CLIENT =====
let tableClient = null;
if (AZURE_STORAGE_CONNECTION_STRING) {
  tableClient = TableClient.fromConnectionString(
    AZURE_STORAGE_CONNECTION_STRING,
    'StaffNotes'
  );
}

// ===== AUTH HELPERS =====
function requireAuth(req, res, next) {
  const { auth } = req.signedCookies;
  if (!auth || auth !== STAFF_EMAIL) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
}

function requireAdmin(req, res, next) {
  const { adminAuth } = req.signedCookies;
  if (!adminAuth || adminAuth !== 'true') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

// ===== STAFF LOGIN / PROFILE =====

// POST /api/login  { email, phone }
app.post('/api/login', (req, res) => {
  const { email, phone } = req.body || {};
  if (email === STAFF_EMAIL && phone === STAFF_PHONE) {
    res.cookie('auth', email, {
      httpOnly: true,
      signed: true,
      sameSite: 'lax'
    });
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false, message: 'Invalid credentials' });
});

// GET /api/me – returns staff details if logged in
app.get('/api/me', requireAuth, (req, res) => {
  const staff = {
    name: 'CSE Staff',
    email: STAFF_EMAIL,
    phone: STAFF_PHONE,
    designation: 'Assistant Professor'
  };
  res.json(staff);
});

// POST /api/logout – clear auth cookie
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth');
  return res.json({ success: true });
});

// ===== NOTES (AZURE TABLE STORAGE) =====

// GET /api/notes – get notes for logged-in staff
app.get('/api/notes', requireAuth, async (req, res) => {
  if (!tableClient) {
    console.error('Table client not configured');
    return res.json({ notes: '' });
  }
  try {
    const email = STAFF_EMAIL;
    const entity = await tableClient.getEntity(email, 'notes');
    res.json({ notes: entity.notes || '' });
  } catch (err) {
    // not found or other error → just return empty notes
    console.error('Error reading notes:', err.message || err);
    res.json({ notes: '' });
  }
});

// POST /api/notes – save notes
app.post('/api/notes', requireAuth, async (req, res) => {
  if (!tableClient) {
    console.error('Table client not configured');
    return res.status(500).json({ success: false });
  }
  try {
    const { notes } = req.body || {};
    const email = STAFF_EMAIL;

    const entity = {
      partitionKey: email,
      rowKey: 'notes',
      notes: notes || ''
    };

    await tableClient.upsertEntity(entity);
    res.json({ success: true });
  } catch (err) {
    console.error('Error saving notes:', err.message || err);
    res.status(500).json({ success: false });
  }
});

// ===== ADMIN LOGIN (PASSWORD ONLY) =====
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};

  if (password === ADMIN_PASSWORD) {
    res.cookie('adminAuth', 'true', {
      httpOnly: true,
      signed: true,
      sameSite: 'lax'
    });
    return res.json({ success: true });
  }

  res.status(401).json({ success: false });
});

// ===== SECURE GOOGLE FORM PROXY =====
app.get('/secure-form/:type', requireAdmin, (req, res) => {
  let formUrl = '';

  if (req.params.type === 'placement') {
    formUrl = 'https://docs.google.com/forms/d/PLACEMENT_FORM_ID/viewform';
  } else if (req.params.type === 'achievements') {
    formUrl = 'https://docs.google.com/forms/d/ACHIEVEMENTS_FORM_ID/viewform';
  } else if (req.params.type === 'coderizz') {
    formUrl = 'https://docs.google.com/forms/d/CODERIZZ_FORM_ID/viewform';
  }

  if (!formUrl) return res.status(404).end();

  https.get(formUrl, proxyRes => {
    res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'text/html');
    proxyRes.pipe(res);
  }).on('error', (err) => {
    console.error('Error proxying form:', err.message || err);
    res.status(500).send('Error loading form');
  });
});

// ===== ROOT ROUTE =====
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log('Server running on port', PORT);
});
