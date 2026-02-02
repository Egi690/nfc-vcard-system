require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Database
const db = new Database(process.env.DB_PATH || './database.db');

// Create tables
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

// Create default admin user if not exists
const createDefaultAdmin = () => {
  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const existingUser = stmt.get(process.env.ADMIN_EMAIL);
  
  if (!existingUser) {
    const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'changeme123', 10);
    const insert = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)');
    insert.run(process.env.ADMIN_EMAIL, hashedPassword);
    console.log('✓ Default admin user created');
  }
};

createDefaultAdmin();

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============================================
// AUTH ROUTES
// ============================================

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
  const user = stmt.get(email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email
    }
  });
});

// Change password
app.post('/api/auth/change-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
  const user = stmt.get(req.user.id);

  if (!bcrypt.compareSync(currentPassword, user.password)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  const update = db.prepare('UPDATE users SET password = ? WHERE id = ?');
  update.run(hashedPassword, req.user.id);

  res.json({ message: 'Password changed successfully' });
});

// ============================================
// VCARD ROUTES
// ============================================

// Get all vcards for logged-in user
app.get('/api/vcards', authenticateToken, (req, res) => {
  const stmt = db.prepare('SELECT * FROM vcards WHERE user_id = ? ORDER BY created_at DESC');
  const vcards = stmt.all(req.user.id);
  res.json(vcards);
});

// Get single vcard by card_id (public - for NFC scanning)
app.get('/api/vcard/:cardId', (req, res) => {
  const { cardId } = req.params;
  
  const stmt = db.prepare('SELECT * FROM vcards WHERE card_id = ? AND is_active = 1');
  const vcard = stmt.get(cardId);

  if (!vcard) {
    return res.status(404).json({ error: 'Card not found' });
  }

  // Log the scan
  const logStmt = db.prepare('INSERT INTO scan_logs (card_id, ip_address, user_agent) VALUES (?, ?, ?)');
  logStmt.run(cardId, req.ip, req.get('user-agent'));

  // Increment scan count
  const updateStmt = db.prepare('UPDATE vcards SET scan_count = scan_count + 1 WHERE card_id = ?');
  updateStmt.run(cardId);

  res.json(vcard);
});

// Create new vcard
app.post('/api/vcards', authenticateToken, (req, res) => {
  const { card_id, name, title, phone, email, website, company, address, linkedin, twitter, instagram } = req.body;

  if (!card_id || !name || !email) {
    return res.status(400).json({ error: 'card_id, name, and email are required' });
  }

  // Check if card_id already exists
  const checkStmt = db.prepare('SELECT * FROM vcards WHERE card_id = ?');
  if (checkStmt.get(card_id)) {
    return res.status(400).json({ error: 'Card ID already exists' });
  }

  try {
    const stmt = db.prepare(`
      INSERT INTO vcards (user_id, card_id, name, title, phone, email, website, company, address, linkedin, twitter, instagram)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    
    const result = stmt.run(req.user.id, card_id, name, title, phone, email, website, company, address, linkedin, twitter, instagram);
    
    const newCard = db.prepare('SELECT * FROM vcards WHERE id = ?').get(result.lastInsertRowid);
    
    res.status(201).json(newCard);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create vcard' });
  }
});

// Update vcard
app.put('/api/vcards/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { name, title, phone, email, website, company, address, linkedin, twitter, instagram, is_active } = req.body;

  // Verify ownership
  const checkStmt = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?');
  const vcard = checkStmt.get(id, req.user.id);

  if (!vcard) {
    return res.status(404).json({ error: 'Card not found or unauthorized' });
  }

  try {
    const stmt = db.prepare(`
      UPDATE vcards 
      SET name = ?, title = ?, phone = ?, email = ?, website = ?, company = ?, 
          address = ?, linkedin = ?, twitter = ?, instagram = ?, is_active = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `);
    
    stmt.run(name, title, phone, email, website, company, address, linkedin, twitter, instagram, 
             is_active !== undefined ? is_active : 1, id, req.user.id);
    
    const updated = db.prepare('SELECT * FROM vcards WHERE id = ?').get(id);
    
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update vcard' });
  }
});

// Delete vcard
app.delete('/api/vcards/:id', authenticateToken, (req, res) => {
  const { id } = req.params;

  const checkStmt = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?');
  const vcard = checkStmt.get(id, req.user.id);

  if (!vcard) {
    return res.status(404).json({ error: 'Card not found or unauthorized' });
  }

  const stmt = db.prepare('DELETE FROM vcards WHERE id = ?');
  stmt.run(id);

  res.json({ message: 'Card deleted successfully' });
});

// Get scan statistics for a card
app.get('/api/vcards/:id/stats', authenticateToken, (req, res) => {
  const { id } = req.params;

  // Verify ownership
  const checkStmt = db.prepare('SELECT * FROM vcards WHERE id = ? AND user_id = ?');
  const vcard = checkStmt.get(id, req.user.id);

  if (!vcard) {
    return res.status(404).json({ error: 'Card not found or unauthorized' });
  }

  // Get scan logs
  const logsStmt = db.prepare(`
    SELECT * FROM scan_logs 
    WHERE card_id = ? 
    ORDER BY scanned_at DESC 
    LIMIT 50
  `);
  const logs = logsStmt.all(vcard.card_id);

  // Get scan count by day (last 30 days)
  const dailyStmt = db.prepare(`
    SELECT DATE(scanned_at) as date, COUNT(*) as count
    FROM scan_logs
    WHERE card_id = ? AND scanned_at >= DATE('now', '-30 days')
    GROUP BY DATE(scanned_at)
    ORDER BY date DESC
  `);
  const dailyScans = dailyStmt.all(vcard.card_id);

  res.json({
    total_scans: vcard.scan_count,
    recent_logs: logs,
    daily_scans: dailyScans
  });
});

// ============================================
// PUBLIC CARD PAGE
// ============================================

// Serve the public vCard page
app.get('/card/:cardId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'card.html'));
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Root route
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════╗
║   NFC vCard Backend Server Running        ║
╠═══════════════════════════════════════════╣
║   Port: ${PORT}                              ║
║   Environment: ${process.env.NODE_ENV || 'development'}           ║
║   Database: ${process.env.DB_PATH || './database.db'}         ║
╚═══════════════════════════════════════════╝

📝 API Documentation: http://localhost:${PORT}/api/health
🔐 Admin Login: ${process.env.ADMIN_EMAIL}
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close();
  console.log('\n✓ Database connection closed');
  process.exit(0);
});
