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
    deleted_at DATETIME,
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

  CREATE TABLE IF NOT EXISTS card_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id TEXT NOT NULL,
    card_name TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
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

// Safe one-time migration: add deleted_at column if it doesn't exist yet
(function migrateDeletedAt() {
  const cols = db.prepare("PRAGMA table_info(vcards)").all();
  const has  = cols.some(function(c){ return c.name === 'deleted_at'; });
  if (!has) {
    db.exec("ALTER TABLE vcards ADD COLUMN deleted_at DATETIME;");
    console.log('✓ Migration: added deleted_at column');
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
  const includeDeleted = req.query.includeDeleted === 'true';
  const query = includeDeleted 
    ? 'SELECT * FROM vcards WHERE user_id = ? ORDER BY created_at DESC'
    : 'SELECT * FROM vcards WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC';
  
  const rows = db.prepare(query).all(req.user.id);
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

    // Log history
    db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
      req.user.id, card_id, name, 'created', `Created card: ${name}`
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

    // Log history
    const action = is_active !== undefined && is_active !== vcard.is_active 
      ? (is_active ? 'activated' : 'deactivated')
      : 'updated';
    db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
      req.user.id, vcard.card_id, name || vcard.name, action, `${action.charAt(0).toUpperCase() + action.slice(1)} card: ${name || vcard.name}`
    );

    res.json(serializeCard(db.prepare('SELECT * FROM vcards WHERE id = ?').get(id)));
  } catch (err) {
    console.error('UPDATE vcard error:', err);
    res.status(500).json({ error: 'Failed to update vcard' });
  }
});

// DELETE card (soft delete)
app.delete('/api/vcards/:id', authenticateToken, (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Card not found or unauthorized' });

  // Log history before soft deleting
  db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
    req.user.id, vcard.card_id, vcard.name, 'deleted', `Deleted card: ${vcard.name}`
  );

  // Soft delete: set deleted_at timestamp and deactivate
  db.prepare('UPDATE vcards SET deleted_at = CURRENT_TIMESTAMP, is_active = 0 WHERE id = ?').run(req.params.id);
  
  res.json({ message: 'Card deleted successfully' });
});

// RESTORE deleted card
app.post('/api/vcards/:id/restore', authenticateToken, (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL').get(req.params.id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Deleted card not found or unauthorized' });

  // Restore: clear deleted_at and reactivate
  db.prepare('UPDATE vcards SET deleted_at = NULL, is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.params.id);
  
  // Log history
  db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
    req.user.id, vcard.card_id, vcard.name, 'restored', `Restored card: ${vcard.name}`
  );

  res.json(serializeCard(db.prepare('SELECT * FROM vcards WHERE id = ?').get(req.params.id)));
});

// PERMANENTLY delete card
app.delete('/api/vcards/:id/permanent', authenticateToken, (req, res) => {
  const vcard = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL').get(req.params.id, req.user.id);
  if (!vcard) return res.status(404).json({ error: 'Deleted card not found or unauthorized' });

  // Log before permanent deletion
  db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
    req.user.id, vcard.card_id, vcard.name, 'permanently_deleted', `Permanently deleted card: ${vcard.name}`
  );

  // Hard delete from database
  db.prepare('DELETE FROM vcards WHERE id = ?').run(req.params.id);
  
  res.json({ message: 'Card permanently deleted' });
});

// ─── HISTORY & SUMMARY ──────────────────────────

// GET card history
app.get('/api/history', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const history = db.prepare(`
    SELECT * FROM card_history
    WHERE user_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(req.user.id, limit);
  
  res.json(history);
});

// GET summary statistics
app.get('/api/summary', authenticateToken, (req, res) => {
  // Accept optional date range
  const from = req.query.from || '2020-01-01';
  const to = req.query.to || new Date().toISOString().slice(0,10);
  
  const totalCards = db.prepare('SELECT COUNT(*) as count FROM vcards WHERE user_id = ? AND deleted_at IS NULL').get(req.user.id).count;
  const activeCards = db.prepare('SELECT COUNT(*) as count FROM vcards WHERE user_id = ? AND is_active = 1 AND deleted_at IS NULL').get(req.user.id).count;
  const deletedCards = db.prepare('SELECT COUNT(*) as count FROM vcards WHERE user_id = ? AND deleted_at IS NOT NULL').get(req.user.id).count;
  const totalScans = db.prepare('SELECT SUM(scan_count) as total FROM vcards WHERE user_id = ? AND deleted_at IS NULL').get(req.user.id).total || 0;
  
  // Get scans in date range
  const scansInRange = db.prepare(`
    SELECT COUNT(*) as count FROM scan_logs sl
    JOIN vcards v ON sl.card_id = v.card_id
    WHERE v.user_id = ? AND DATE(sl.scanned_at) >= ? AND DATE(sl.scanned_at) <= ?
  `).get(req.user.id, from, to).count;
  
  // Get scans today
  const today = new Date().toISOString().slice(0,10);
  const scansToday = db.prepare(`
    SELECT COUNT(*) as count FROM scan_logs sl
    JOIN vcards v ON sl.card_id = v.card_id
    WHERE v.user_id = ? AND DATE(sl.scanned_at) = ?
  `).get(req.user.id, today).count;

  // Get scans this week
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString().slice(0,10);
  const scansThisWeek = db.prepare(`
    SELECT COUNT(*) as count FROM scan_logs sl
    JOIN vcards v ON sl.card_id = v.card_id
    WHERE v.user_id = ? AND DATE(sl.scanned_at) >= ?
  `).get(req.user.id, weekAgo).count;

  // Get scans this month
  const monthStart = new Date().toISOString().slice(0,7) + '-01';
  const scansThisMonth = db.prepare(`
    SELECT COUNT(*) as count FROM scan_logs sl
    JOIN vcards v ON sl.card_id = v.card_id
    WHERE v.user_id = ? AND DATE(sl.scanned_at) >= ?
  `).get(req.user.id, monthStart).count;

  // Most scanned card
  const topCard = db.prepare(`
    SELECT card_id, name, scan_count FROM vcards
    WHERE user_id = ? AND deleted_at IS NULL
    ORDER BY scan_count DESC
    LIMIT 1
  `).get(req.user.id);

  // Recent activity counts
  const recentCreated = db.prepare(`
    SELECT COUNT(*) as count FROM card_history
    WHERE user_id = ? AND action = 'created' AND created_at >= datetime('now', '-7 days')
  `).get(req.user.id).count;

  const recentDeleted = db.prepare(`
    SELECT COUNT(*) as count FROM card_history
    WHERE user_id = ? AND action = 'deleted' AND created_at >= datetime('now', '-7 days')
  `).get(req.user.id).count;

  res.json({
    totalCards,
    activeCards,
    inactiveCards: totalCards - activeCards,
    deletedCards,
    totalScans,
    scansInRange,
    scansToday,
    scansThisWeek,
    scansThisMonth,
    topCard: topCard || null,
    recentActivity: {
      created: recentCreated,
      deleted: recentDeleted
    },
    dateRange: { from, to }
  });
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

// ─── EXCEL EXPORT / IMPORT ──────────────────────

// Export cards to Excel (simple CSV format since xlsx is not in dependencies)
app.get('/api/vcards/export', authenticateToken, (req, res) => {
  const includeDeleted = req.query.includeDeleted === 'true';
  const query = includeDeleted
    ? 'SELECT * FROM vcards WHERE user_id = ? ORDER BY created_at DESC'
    : 'SELECT * FROM vcards WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC';
  
  const cards = db.prepare(query).all(req.user.id);
  
  // Generate CSV
  const headers = ['card_id', 'name', 'title', 'phone', 'email', 'website', 'company', 'address', 'is_active'];
  const rows = cards.map(c => {
    const ef = JSON.parse(c.extra_fields || '{}');
    return [
      c.card_id,
      c.name,
      c.title || '',
      c.phone || '',
      c.email,
      c.website || '',
      c.company || '',
      c.address || '',
      c.is_active ? 'Yes' : 'No',
      ef.linkedin || '',
      ef.twitter || '',
      ef.instagram || '',
      ef.facebook || '',
      ef.github || '',
      ef.tiktok || '',
      ef.youtube || '',
      ef.portfolio || ''
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
  });
  
  const csv = [
    [...headers, 'linkedin', 'twitter', 'instagram', 'facebook', 'github', 'tiktok', 'youtube', 'portfolio'].join(','),
    ...rows
  ].join('\n');
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="vcards_export.csv"');
  res.send(csv);
});

// Download Excel template
app.get('/api/vcards/template', (req, res) => {
  const headers = ['card_id', 'name', 'title', 'phone', 'email', 'website', 'company', 'address', 'is_active', 'linkedin', 'twitter', 'instagram', 'facebook', 'github', 'tiktok', 'youtube', 'portfolio'];
  const example = ['john-smith', 'John Smith', 'Software Engineer', '+1 555 123 4567', 'john@example.com', 'https://johnsmith.com', 'Tech Corp', '123 Main St, City, Country', 'Yes', 'https://linkedin.com/in/johnsmith', '', 'https://instagram.com/johnsmith', '', '', '', '', ''];
  
  const csv = [
    headers.join(','),
    example.map(v => `"${v}"`).join(',')
  ].join('\n');
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="vcard_import_template.csv"');
  res.send(csv);
});

// Import cards from CSV
app.post('/api/vcards/import', authenticateToken, (req, res) => {
  const { rows } = req.body;
  
  if (!rows || !Array.isArray(rows)) {
    return res.status(400).json({ error: 'Invalid import data' });
  }
  
  const results = { success: 0, failed: 0, errors: [] };
  
  rows.forEach((row, idx) => {
    try {
      const [card_id, name, title, phone, email, website, company, address, is_active, linkedin, twitter, instagram, facebook, github, tiktok, youtube, portfolio] = row;
      
      if (!card_id || !name || !email) {
        results.failed++;
        results.errors.push(`Row ${idx + 1}: Missing required fields (card_id, name, email)`);
        return;
      }
      
      // Check if card_id already exists
      const existing = db.prepare('SELECT id FROM vcards WHERE card_id = ?').get(card_id);
      if (existing) {
        results.failed++;
        results.errors.push(`Row ${idx + 1}: Card ID "${card_id}" already exists`);
        return;
      }
      
      // Build extra_fields from social columns
      const extra_fields = {};
      if (linkedin) extra_fields.linkedin = linkedin;
      if (twitter) extra_fields.twitter = twitter;
      if (instagram) extra_fields.instagram = instagram;
      if (facebook) extra_fields.facebook = facebook;
      if (github) extra_fields.github = github;
      if (tiktok) extra_fields.tiktok = tiktok;
      if (youtube) extra_fields.youtube = youtube;
      if (portfolio) extra_fields.portfolio = portfolio;
      
      const active = is_active && (is_active.toLowerCase() === 'yes' || is_active === '1') ? 1 : 0;
      
      db.prepare(`
        INSERT INTO vcards (user_id, card_id, name, title, phone, email, website, company, address,
                            linkedin, twitter, instagram, is_active, extra_fields)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id, card_id, name, title || '', phone || '', email,
        website || '', company || '', address || '',
        linkedin || '', twitter || '', instagram || '',
        active, JSON.stringify(extra_fields)
      );
      
      // Log history
      db.prepare('INSERT INTO card_history (user_id, card_id, card_name, action, details) VALUES (?, ?, ?, ?, ?)').run(
        req.user.id, card_id, name, 'created', `Imported card: ${name}`
      );
      
      results.success++;
    } catch (err) {
      results.failed++;
      results.errors.push(`Row ${idx + 1}: ${err.message}`);
    }
  });
  
  res.json(results);
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
