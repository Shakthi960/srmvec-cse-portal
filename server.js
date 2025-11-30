// server.js (updated - robust + fallback)
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

// init table client safely
let tableClient = null;
try {
  if (AZURE_STORAGE_CONNECTION_STRING) {
    tableClient = new TableClient(AZURE_STORAGE_CONNECTION_STRING, TABLE_NAME);
    console.log('TableClient initialized for table:', TABLE_NAME);
  } else {
    console.warn('AZURE_STORAGE_CONNECTION_STRING not provided — running without table storage');
  }
} catch (e) {
  console.error('Failed to initialize TableClient:', e);
  tableClient = null;
}

// middlewares
app.use(bodyParser.json());
app.use(cookieParser(COOKIE_SECRET));
app.use(express.static(path.join(__dirname, 'public')));

// health check
app.get('/api/health', (req, res) => res.json({ ok: true, now: new Date().toISOString() }));

// staff.json fallback (read-only display)
const STAFF_JSON = path.join(__dirname, 'staff.json');
function loadStaffList() {
  try {
    if (!fs.existsSync(STAFF_JSON)) return [];
    return JSON.parse(fs.readFileSync(STAFF_JSON, 'utf8'));
  } catch (e) {
    console.error('loadStaffList error', e);
    return [];
  }
}

// ---------- Table helpers ----------

// get user from table (partitionKey = 'staff', rowKey = username)
async function getUserFromTable(username) {
  if (!tableClient) return null;
  try {
    const ent = await tableClient.getEntity('staff', username);
    return ent;
  } catch (err) {
    // not found -> null
    return null;
  }
}

async function upsertUserEntityToTable(entity) {
  if (!tableClient) throw new Error('Table storage not configured');
  await tableClient.upsertEntity(entity, 'Merge');
}

// notes are stored with partitionKey=username rowKey='notes'
async function getNotesFromTable(username) {
  if (!tableClient) return '';
  try {
    const e = await tableClient.getEntity(username, 'notes');
    return e.notes || '';
  } catch (err) {
    return '';
  }
}

async function upsertNotesToTable(username, notes) {
  if (!tableClient) throw new Error('Table storage not configured');
  const ent = { partitionKey: username, rowKey: 'notes', notes: notes || '' };
  await tableClient.upsertEntity(ent, 'Merge');
}

// ---------- auth middleware ----------
function requireAuth(req, res, next) {
  const auth = req.signedCookies && req.signedCookies.auth;
  if (!auth) return res.status(401).json({ message: 'Unauthorized' });
  req.username = auth;
  next();
}
function requireAdmin(req, res, next) {
  const adminAuth = req.signedCookies && req.signedCookies.adminAuth;
  if (adminAuth === 'true') return next();
  return res.status(403).json({ error: 'Forbidden' });
}

// ---------- API: staff login (username+password) ----------
app.post('/api/staff/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ success: false, message: 'Missing' });

    // prefer table storage
    let user = await getUserFromTable(username);

    // fallback to staff.json (read-only, no password)
    if (!user) {
      const list = loadStaffList();
      const found = list.find(s => s.username === username || s.email === username);
      if (found && !found.passwordHash) {
        // no passwords in staff.json -> forbid login
        return res.status(401).json({ success: false, message: 'No password for this user (admin must create in table)' });
      }
    }

    if (!user || !user.passwordHash) return res.status(401).json({ success: false });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ success: false });

    // set signed cookie (httpOnly)
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

// get current staff profile
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const username = req.username;
    let user = await getUserFromTable(username);
    if (!user) {
      // fallback: look up staff.json by email or username
      const list = loadStaffList();
      const found = list.find(s => s.username === username || s.email === username);
      if (found) {
        return res.json({
          username: found.username || found.email,
          name: found.name || found.username || found.email,
          phone: found.phone || '',
          designation: found.designation || ''
        });
      }
      return res.status(404).json({ message: 'Not found' });
    }

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

// GET notes (for current user)
app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const notes = tableClient ? await getNotesFromTable(req.username) : '';
    res.json({ notes });
  } catch (err) {
    console.error('GET notes error', err);
    res.status(500).json({ notes: '' });
  }
});

// POST notes
app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    if (!tableClient) return res.status(500).json({ success: false, message: 'Storage not configured' });
    const { notes } = req.body || {};
    await upsertNotesToTable(req.username, notes || '');
    res.json({ success: true });
  } catch (err) {
    console.error('POST notes error', err);
    res.status(500).json({ success: false });
  }
});

// ---------- Admin endpoints ----------
// admin login (password-only)
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

// admin logout
app.post('/api/admin/logout', requireAdmin, (req, res) => {
  res.clearCookie('adminAuth');
  res.json({ success: true });
});

// admin: create or update staff user (username, name, phone, password)
app.post('/api/admin/create-user', requireAdmin, async (req, res) => {
  try {
    if (!tableClient) return res.status(500).json({ success: false, message: 'Storage not configured' });

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
    await upsertUserEntityToTable(userEntity);
    res.json({ success: true });
  } catch (err) {
    console.error('create-user error', err);
    res.status(500).json({ success: false });
  }
});

// secure form proxy (admin only) - simple redirect to configured env vars
app.get('/secure-form/:type', requireAdmin, (req, res) => {
  const map = {
    placement: process.env.GFORM_PLACEMENT || '',
    achievements: process.env.GFORM_ACHIEVEMENTS || '',
    coderizz: process.env.GFORM_CODERIZZ || ''
  };

  const target = map[req.params.type];
  if (!target) return res.status(404).send("Form not configured");

  // PROXY GOOGLE FORM WITHOUT REVEALING URL
  https.get(target, (gRes) => {
    res.status(gRes.statusCode);
    res.setHeader("Content-Type", gRes.headers["content-type"] || "text/html");
    gRes.pipe(res);
  }).on("error", (err) => {
    console.error(err);
    res.status(500).send("Unable to load form");
  });
});

// fallback: serve index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// start server
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT} (NODE_ENV=${process.env.NODE_ENV || 'development'})`);
});
