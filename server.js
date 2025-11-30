// server.js
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const https = require('https');
const { TableClient } = require('@azure/data-tables');

const app = express();
const PORT = process.env.PORT || 8080;

// ===== STAFF & ADMIN CREDENTIALS (use env vars in Azure) =====
const STAFF_EMAIL = process.env.STAFF_EMAIL || 'cse@srmvalliammai.ac.in';
const STAFF_PHONE = process.env.STAFF_PHONE || '6383149466';

// for real security REMOVE the default and set only in Azure
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'cse@admin2k25';

const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-me';

// ===== AZURE TABLES – StaffNotes table =====
const AZURE_STORAGE_CONNECTION_STRING = process.env.AZURE_STORAGE_CONNECTION_STRING;

let tableClient = null;
if (AZURE_STORAGE_CONNECTION_STRING) {
  try {
    tableClient = TableClient.fromConnectionString(
      AZURE_STORAGE_CONNECTION_STRING,
      'StaffNotes'
    );
    console.log('✅ TableClient initialised');
  } catch (err) {
    console.error('❌ Failed to create TableClient', err);
  }
} else {
  console.warn('⚠️ AZURE_STORAGE_CONNECTION_STRING not set – notes will not be persisted.');
}

// ===== MIDDLEWARE =====
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// ===== AUTH MIDDLEWARE =====
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

// ===== STAFF LOGIN / LOGOUT & PROFILE =====

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

// ===== NOTES USING AZURE TABLE STORAGE =====

// GET /api/notes – get notes for logged-in staff
app.get('/api/notes', requireAuth, async (req, res) => {
  if (!tableClient) {
    // no table configured – just return empty
    return res.json({ notes: '' });
  }

  try {
    const email = STAFF_EMAIL;
    const entity = await tableClient.getEntity(email, 'notes');
    res.json({ notes: entity.notes || '' });
  } catch (err) {
    // 404 when entity not found – just return empty string
    if (err.statusCode === 404) {
      return res.json({ notes: '' });
    }
    console.error('Error reading notes from table:', err);
    res.status(500).json({ notes: '' });
  }
});

// POST /api/notes – save notes
app.post('/api/notes', requireAuth, async (req, res) => {
  if (!tableClient) {
    // no table configured – pretend success but nothing is stored
    return res.json({ success: true });
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
    console.error('Error saving notes to table:', err);
    res.status(500).json({ success: false });
  }
});

// ===== ADMIN LOGIN + SECURE GOOGLE FORMS PROXY =====

// ADMIN LOGIN
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
  return res.status(401).json({ success: false });
});

// Secure proxy route – hides real Google Form URLs
app.get('/secure-form/:type', requireAdmin, (req, res) => {
  let formUrl = '';

  if (req.params.type === 'placement') {
    formUrl = 'https://docs.google.com/forms/d/e/1FAIpQLSc_WFKnWCs_VscOkD3uMvScdRAkaNVyl1FgDwumtDs7kEwG-A/viewform';
  } else if (req.params.type === 'achievements') {
    formUrl = 'https://docs.google.com/forms/d/e/1FAIpQLSemMq0OZq6uiRL_Kzx4CfqkkoB6-87dtBlCVrtgiaYmcKCz7g/viewform';
  } else if (req.params.type === 'coderizz') {
    formUrl = 'https://docs.google.com/forms/u/0/d/e/1FAIpQLSdEsYQRtS12wMuKnrImujNyRso5JgpvgHG1SpBUfiWK3xiKUA/formResponse';
  }

  if (!formUrl) return res.status(404).end();

  https.get(formUrl, proxyRes => {
    res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'text/html');
    proxyRes.pipe(res);
  }).on('error', err => {
    console.error('Error proxying form:', err);
    res.status(500).end('Error loading form');
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