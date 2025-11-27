// server.js
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 8080;

const STAFF_EMAIL = process.env.STAFF_EMAIL;
const STAFF_PHONE = process.env.STAFF_PHONE;

if (!STAFF_EMAIL || !STAFF_PHONE) {
  console.warn('⚠️ STAFF_EMAIL / STAFF_PHONE not set in environment variables!');
}


// simple JSON file for notes (per email)
const NOTES_FILE = path.join(__dirname, 'notes.json');

// middlewares
app.use(bodyParser.json());
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change';
app.use(cookieParser(COOKIE_SECRET));


// serve static files
app.use(express.static(path.join(__dirname, 'public')));

// helper: load/save notes
function loadNotes() {
  if (!fs.existsSync(NOTES_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(NOTES_FILE, 'utf-8'));
  } catch (e) {
    return {};
  }
}

function saveNotes(data) {
  fs.writeFileSync(NOTES_FILE, JSON.stringify(data, null, 2));
}

// auth middleware
function requireAuth(req, res, next) {
  const { auth } = req.signedCookies;
  if (!auth || auth !== STAFF_EMAIL) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  next();
}

// ===== ROUTES =====

// POST /api/login  { email, phone }
app.post('/api/login', (req, res) => {
  const { email, phone } = req.body || {};
  if (email === STAFF_EMAIL && phone === STAFF_PHONE) {
    // set signed cookie
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
  // Example static staff info – you can load from staff.json later
  const staff = {
    name: 'CSE Staff',
    email: STAFF_EMAIL,
    phone: STAFF_PHONE,
    designation: 'Assistant Professor'
  };
  res.json(staff);
});

// GET /api/notes – get notes for logged-in staff
app.get('/api/notes', requireAuth, (req, res) => {
  const data = loadNotes();
  const email = STAFF_EMAIL;
  res.json({ notes: data[email] || '' });
});

// POST /api/notes – save notes
app.post('/api/notes', requireAuth, (req, res) => {
  const { notes } = req.body || {};
  const data = loadNotes();
  const email = STAFF_EMAIL;
  data[email] = notes || '';
  saveNotes(data);
  res.json({ success: true });
});

// fallback: always serve index.html for root (optional)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('Server running on port', PORT);
});

// POST /api/logout – clear auth cookie
app.post('/api/logout', (req, res) => {
  res.clearCookie('auth');
  return res.json({ success: true });
});

