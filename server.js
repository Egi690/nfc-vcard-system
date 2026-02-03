require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const Database = require('better-sqlite3');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── DATABASE ────────────────────────────────────
const db = new Database(process.env.DB_PATH || './database.db');
db.pragma('journal_mode = WAL');

// Create base tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS vcards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    title TEXT,
    phone TEXT,
    email TEXT NOT NULL,
    website TEXT,
    company TEXT,
    address TEXT,
    linkedin TEXT,
    twitter TEXT,
    instagram TEXT,
    is_active BOOLEAN DEFAULT 1,
    scan_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (card_id) REFERENCES vcards(card_id)
  );
`);

// Safe one-time migration: add extra_fields column if it doesn't exist yet
(function migrateExtraFields() {
  const cols = db.prepare("PRAGMA table_info(vcards)").all();
  const has  = cols.some(function(c){ return c.name === 'extra_fields'; });
  if (!has) {
    db.exec("ALTER TABLE vcards ADD COLUMN extra_fields TEXT DEFAULT '{}';");
    console.log('✓ Migration: added extra_fields column');
  }
})();

// ─── ADMIN SYNC ──────────────────────────────────
(function syncAdminUser() {
  const adminEmail    = process.env.ADMIN_EMAIL;
  const adminPassword = process.env.ADMIN_PASSWORD || 'changeme123';
  const hashed        = bcrypt.hashSync(adminPassword, 10);
  const existing      = db.prepare('SELECT * FROM users WHERE id = 1').get();

  if (!existing) {
    db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(adminEmail, hashed);
    console.log('✓ Admin user created: ' + adminEmail);
  } else {
    db.prepare('UPDATE users SET email = ?, password = ? WHERE id = 1').run(adminEmail, hashed);
    console.log('✓ Admin user synced: ' + adminEmail);
  }
})();

// ─── MIDDLEWARE ──────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(express.json());
app.use(express.static('public'));

// ─── AUTH MIDDLEWARE ─────────────────────────────
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// ─── helper: serialize a vcard row for the API response ──
// Merges the legacy linkedin/twitter/instagram columns INTO extra_fields
// so the frontend only has to deal with one object.
function serializeCard(row) {
  var obj = Object.assign({}, row);

  // parse extra_fields JSON safely
  var extra = {};
  try { extra = JSON.parse(row.extra_fields || '{}'); } catch(e) {}

  // back-fill legacy columns into extra if they exist and aren't already there
  if (row.linkedin  && !extra.linkedin)  extra.linkedin  = row.linkedin;
  if (row.twitter   && !extra.twitter)   extra.twitter   = row.twitter;
  if (row.instagram && !extra.instagram) extra.instagram = row.instagram;

  obj.extra_fields = extra;   // return as parsed object
  return obj;
}

// ─── AUTH ROUTES ─────────────────────────────────

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email } });
});

app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword)
    return res.status(400).json({ error: 'Current and new password required' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password))
    return res.status(401).json({ error: 'Current password is incorrect' });

  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res.json({ message: 'Password changed successfully' });
});

// ─── VCARD ROUTES ────────────────────────────────

// GET all cards
app.get('/api/vcards', authenticateToken, (req, res) => {
  const rows = db.prepare('SELECT * FROM vcards WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json(rows.map(serializeCard));
});

// GET single card (public – NFC scan)
app.get('/api/vcard/:cardId', (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE card_id = ? AND is_active = 1').get(req.params.cardId);
  if (!vcard) return res.status(404).json({ error: 'Card not found' });

  db.prepare('INSERT INTO scan_logs (card_id, ip_address, user_agent) VALUES (?, ?, ?)').run(req.params.cardId, req.ip, req.get('user-agent'));
  db.prepare('UPDATE vcards SET scan_count = scan_count + 1 WHERE card_id = ?').run(req.params.cardId);

  res.json(serializeCard(vcard));
});

// POST create card
app.post('/api/vcards', authenticateToken, (req, res) => {
  const { card_id, name, title, phone, email, website, company, address, extra_fields } = req.body;

  if (!card_id || !name || !email)
    return res.status(400).json({ error: 'card_id, name, and email are required' });

  if (db.prepare('SELECT id FROM vcards WHERE card_id = ?').get(card_id))
    return res.status(400).json({ error: 'Card ID already exists' });

  // pull legacy columns out of extra_fields if present (keeps backward compat)
  var ef = extra_fields || {};
  var linkedin  = ef.linkedin  || '';
  var twitter   = ef.twitter   || '';
  var instagram = ef.instagram || '';

  try {
    const result = db.prepare(`
      INSERT INTO vcards (user_id, card_id, name, title, phone, email, website, company, address,
                          linkedin, twitter, instagram, extra_fields)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, card_id, name, title || '', phone || '', email,
      website || '', company || '', address || '',
      linkedin, twitter, instagram,
      JSON.stringify(ef)
    );

    res.status(201).json(serializeCard(db.prepare('SELECT * FROM vcards WHERE id = ?').get(result.lastInsertRowid)));
  } catch (err) {
    console.error('CREATE vcard error:', err);
    res.status(500).json({ error: 'Failed to create vcard' });
  }
});

// PUT update card
app.put('/api/vcards/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const vcard  = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?').get(id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Card not found or unauthorized' });

  const { name, title, phone, email, website, company, address, extra_fields, is_active } = req.body;

  var ef = extra_fields || {};
  var linkedin  = ef.linkedin  || '';
  var twitter   = ef.twitter   || '';
  var instagram = ef.instagram || '';

  try {
    db.prepare(`
      UPDATE vcards
      SET name = ?, title = ?, phone = ?, email = ?, website = ?, company = ?,
          address = ?, linkedin = ?, twitter = ?, instagram = ?, extra_fields = ?,
          is_active = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `).run(
      name || vcard.name,
      title !== undefined ? title : vcard.title,
      phone !== undefined ? phone : vcard.phone,
      email || vcard.email,
      website !== undefined ? website : vcard.website,
      company !== undefined ? company : vcard.company,
      address !== undefined ? address : vcard.address,
      linkedin, twitter, instagram,
      JSON.stringify(ef),
      is_active !== undefined ? is_active : vcard.is_active,
      id, req.user.id
    );

    res.json(serializeCard(db.prepare('SELECT * FROM vcards WHERE id = ?').get(id)));
  } catch (err) {
    console.error('UPDATE vcard error:', err);
    res.status(500).json({ error: 'Failed to update vcard' });
  }
});

// DELETE card
app.delete('/api/vcards/:id', authenticateToken, (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Card not found or unauthorized' });

  db.prepare('DELETE FROM vcards WHERE id = ?').run(req.params.id);
  res.json({ message: 'Card deleted successfully' });
});

// ─── STATS ROUTE (with ?from / ?to support) ─────
app.get('/api/vcards/:id/stats', authenticateToken, (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Card not found or unauthorized' });

  // date range: accept ?from=YYYY-MM-DD&to=YYYY-MM-DD
  // defaults: from = 30 days ago, to = today
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10);

  const from = req.query.from || thirtyDaysAgo;
  const to   = req.query.to   || today;

  // daily scan counts within the chosen range
  const dailyScans = db.prepare(`
    SELECT DATE(scanned_at) as date, COUNT(*) as count
    FROM scan_logs
    WHERE card_id = ? AND DATE(scanned_at) >= ? AND DATE(scanned_at) <= ?
    GROUP BY DATE(scanned_at)
    ORDER BY date DESC
  `).all(vcard.card_id, from, to);

  // recent log entries within the same range (max 100)
  const recentLogs = db.prepare(`
    SELECT * FROM scan_logs
    WHERE card_id = ? AND DATE(scanned_at) >= ? AND DATE(scanned_at) <= ?
    ORDER BY scanned_at DESC
    LIMIT 100
  `).all(vcard.card_id, from, to);

  // total across selected range
  const totalInRange = db.prepare(`
    SELECT COUNT(*) as cnt FROM scan_logs
    WHERE card_id = ? AND DATE(scanned_at) >= ? AND DATE(scanned_at) <= ?
  `).get(vcard.card_id, from, to);

  res.json({
    total_scans      : vcard.scan_count,          // lifetime total (unchanged)
    total_in_range   : totalInRange.cnt,          // total within selected range
    recent_logs      : recentLogs,
    daily_scans      : dailyScans,
    range            : { from: from, to: to }     // echo back so frontend can confirm
  });
});

// ─── PUBLIC CARD PAGE ────────────────────────────
app.get('/card/:cardId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'card.html'));
});

// ─── HEALTH ──────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── ROOT ────────────────────────────────────────
app.get('/', (req, res) => { res.redirect('/admin.html'); });

// ─── START ───────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════╗
║   NFC vCard Backend Server Running        ║
╠═══════════════════════════════════════════╣
║   Port: ${PORT}                              ║
║   Environment: ${process.env.NODE_ENV || 'development'}           ║
║   Database: ${process.env.DB_PATH || './database.db'}         ║
╚═══════════════════════════════════════════╝

📝 API: http://localhost:${PORT}/api/health
🔐 Admin: ${process.env.ADMIN_EMAIL}
  `);
});

process.on('SIGINT', () => { db.close(); process.exit(0); });
