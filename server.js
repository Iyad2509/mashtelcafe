const express = require('express');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bwipjs = require('bwip-js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================================
// LOAD CONFIG — This is the ONLY file that changes per business
// ============================================================
const CONFIG = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DB_PATH = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'loyalty.db')
  : path.join(__dirname, 'loyalty.db');

let db;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
// CONFIG API — Frontend reads business config from here
// ============================================================
app.get('/api/config', (req, res) => {
  // Send only safe, public config to the frontend (no passwords/secrets)
  res.json({
    business: CONFIG.business,
    card: CONFIG.card,
    branding: CONFIG.branding,
    phone_validation: CONFIG.phone_validation,
  });
});

// ============================================================
// DATABASE INITIALIZATION
// ============================================================
async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'staff',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT,
    total_points INTEGER DEFAULT 0,
    redeemed_points INTEGER DEFAULT 0,
    visit_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_visit DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT NOT NULL,
    service_type TEXT NOT NULL,
    points_earned INTEGER NOT NULL,
    scanned_by TEXT,
    sector TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (member_id) REFERENCES members(member_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS redemptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    member_id TEXT NOT NULL,
    reward_name TEXT NOT NULL,
    points_spent INTEGER NOT NULL,
    processed_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (member_id) REFERENCES members(member_id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS flags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    comment TEXT NOT NULL,
    page TEXT,
    raised_by TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    resolved_by TEXT,
    resolve_note TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME
  )`);

  // Create default admin from config
  const adminCheck = db.exec("SELECT COUNT(*) as c FROM staff WHERE role='admin'");
  if (adminCheck[0].values[0][0] === 0) {
    const hash = bcrypt.hashSync(CONFIG.admin.default_password, 10);
    db.run("INSERT INTO staff (username, password_hash, full_name, role) VALUES (?, ?, ?, ?)",
      [CONFIG.admin.default_username, hash, 'Administrator', 'admin']);
    console.log(`Default admin created: ${CONFIG.admin.default_username}`);
  }

  saveDB();
  console.log('Database initialized');
}

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

setInterval(() => { if (db) saveDB(); }, 30000);

// ============================================================
// AUTHENTICATION
// ============================================================
const COOKIE_NAME = CONFIG.card.prefix.toLowerCase() + '_token';

function authMiddleware(req, res, next) {
  const token = req.cookies[COOKIE_NAME] || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const result = db.exec("SELECT * FROM staff WHERE username = ?", [username]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const row = result[0].values[0];
  const cols = result[0].columns;
  const user = {};
  cols.forEach((col, i) => user[col] = row[i]);
  if (!bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
    JWT_SECRET, { expiresIn: '12h' }
  );
  res.cookie(COOKIE_NAME, token, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000 });
  res.json({ success: true, user: { username: user.username, full_name: user.full_name, role: user.role } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ============================================================
// STAFF MANAGEMENT
// ============================================================
app.post('/api/staff', authMiddleware, adminOnly, (req, res) => {
  const { username, password, full_name } = req.body;
  if (!username || !password || !full_name) return res.status(400).json({ error: 'All fields required' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO staff (username, password_hash, full_name, role) VALUES (?, ?, ?, 'staff')",
      [username, hash, full_name]);
    saveDB();
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.get('/api/staff', authMiddleware, adminOnly, (req, res) => {
  const result = db.exec("SELECT id, username, full_name, role, created_at FROM staff ORDER BY created_at DESC");
  if (result.length === 0) return res.json([]);
  res.json(result[0].values.map(row => {
    const obj = {};
    result[0].columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  }));
});

app.delete('/api/staff/:id', authMiddleware, adminOnly, (req, res) => {
  db.run("DELETE FROM staff WHERE id = ? AND role != 'admin'", [req.params.id]);
  saveDB();
  res.json({ success: true });
});

app.post('/api/staff/:id/reset-password', authMiddleware, adminOnly, (req, res) => {
  const { new_password } = req.body;
  if (!new_password || new_password.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  db.run("UPDATE staff SET password_hash = ? WHERE id = ?", [hash, req.params.id]);
  saveDB();
  res.json({ success: true });
});

// ============================================================
// MEMBER REGISTRATION
// ============================================================
function generateMemberId() {
  const year = new Date().getFullYear();
  const prefix = CONFIG.card.prefix;
  const result = db.exec("SELECT MAX(CAST(SUBSTR(member_id, -5) AS INTEGER)) FROM members");
  const maxNum = (result[0].values[0][0] || 0) + 1;
  return `${prefix}-${year}-${String(maxNum).padStart(5, '0')}`;
}

app.post('/api/members', authMiddleware, async (req, res) => {
  const { full_name, phone } = req.body;
  if (!full_name) return res.status(400).json({ error: 'Name is required' });
  if (!phone) return res.status(400).json({ error: 'Phone number is required' });

  const cleanPhone = phone.replace(/[\s\-]/g, '');
  const phoneRegex = new RegExp(CONFIG.phone_validation.pattern);
  if (!phoneRegex.test(cleanPhone)) {
    return res.status(400).json({ error: CONFIG.phone_validation.error_message });
  }

  const phoneCheck = db.exec("SELECT member_id, full_name FROM members WHERE REPLACE(REPLACE(phone, ' ', ''), '-', '') = ?", [cleanPhone]);
  if (phoneCheck.length > 0 && phoneCheck[0].values.length > 0) {
    const existing = phoneCheck[0].values[0];
    return res.status(400).json({ error: `This phone number is already registered to ${existing[1]} (${existing[0]})` });
  }

  const member_id = generateMemberId();
  try {
    db.run("INSERT INTO members (member_id, full_name, phone) VALUES (?, ?, ?)",
      [member_id, full_name, cleanPhone]);
    saveDB();
    res.json({ success: true, member_id, full_name });
  } catch (e) {
    res.status(500).json({ error: 'Failed to register member' });
  }
});

app.get('/api/members', authMiddleware, (req, res) => {
  const search = req.query.search;
  let result;
  if (search) {
    result = db.exec(
      "SELECT * FROM members WHERE full_name LIKE ? OR member_id LIKE ? OR phone LIKE ? ORDER BY created_at DESC",
      [`%${search}%`, `%${search}%`, `%${search}%`]
    );
  } else {
    result = db.exec("SELECT * FROM members ORDER BY created_at DESC");
  }
  if (result.length === 0) return res.json([]);
  res.json(result[0].values.map(row => {
    const obj = {};
    result[0].columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  }));
});

app.get('/api/members/:memberId', authMiddleware, (req, res) => {
  const result = db.exec("SELECT * FROM members WHERE member_id = ?", [req.params.memberId]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(404).json({ error: 'Member not found' });
  }
  const obj = {};
  result[0].columns.forEach((col, i) => obj[col] = result[0].values[0][i]);

  const scans = db.exec("SELECT * FROM scans WHERE member_id = ? ORDER BY created_at DESC LIMIT 20", [req.params.memberId]);
  obj.scans = [];
  if (scans.length > 0) {
    obj.scans = scans[0].values.map(row => {
      const s = {};
      scans[0].columns.forEach((col, i) => s[col] = row[i]);
      return s;
    });
  }

  const redemptions = db.exec("SELECT * FROM redemptions WHERE member_id = ? ORDER BY created_at DESC LIMIT 20", [req.params.memberId]);
  obj.redemptions = [];
  if (redemptions.length > 0) {
    obj.redemptions = redemptions[0].values.map(row => {
      const r = {};
      redemptions[0].columns.forEach((col, i) => r[col] = row[i]);
      return r;
    });
  }

  res.json(obj);
});

app.delete('/api/members/:memberId', authMiddleware, (req, res) => {
  const mid = req.params.memberId;
  const check = db.exec("SELECT member_id FROM members WHERE member_id = ?", [mid]);
  if (check.length === 0 || check[0].values.length === 0) {
    return res.status(404).json({ error: 'Member not found' });
  }
  db.run("DELETE FROM scans WHERE member_id = ?", [mid]);
  db.run("DELETE FROM redemptions WHERE member_id = ?", [mid]);
  db.run("DELETE FROM members WHERE member_id = ?", [mid]);
  saveDB();
  res.json({ success: true });
});

// ============================================================
// QR CODE
// ============================================================
app.get('/api/qrcode/:memberId', async (req, res) => {
  try {
    const png = await bwipjs.toBuffer({
      bcid: 'qrcode', text: req.params.memberId,
      scale: 5, width: 30, height: 30,
    });
    res.set('Content-Type', 'image/png');
    res.send(png);
  } catch (e) {
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

app.get('/api/print-card/:memberId', authMiddleware, async (req, res) => {
  const result = db.exec("SELECT * FROM members WHERE member_id = ?", [req.params.memberId]);
  if (result.length === 0 || result[0].values.length === 0) {
    return res.status(404).json({ error: 'Member not found' });
  }
  const obj = {};
  result[0].columns.forEach((col, i) => obj[col] = result[0].values[0][i]);

  const qrPng = await bwipjs.toBuffer({
    bcid: 'qrcode', text: obj.member_id, scale: 6, width: 30, height: 30,
  });

  res.json({
    member_id: obj.member_id,
    full_name: obj.full_name,
    qr_base64: qrPng.toString('base64'),
    created_at: obj.created_at,
    // Send config so frontend can render the card with correct branding
    config: {
      business: CONFIG.business,
      card: CONFIG.card,
      branding: CONFIG.branding,
    }
  });
});

// ============================================================
// SERVICES & SCANNING — from config
// ============================================================
app.get('/api/services', authMiddleware, (req, res) => {
  res.json(CONFIG.services);
});

app.post('/api/scan', authMiddleware, (req, res) => {
  const { member_id, service_type, sector } = req.body;
  if (!member_id || !service_type) {
    return res.status(400).json({ error: 'Member ID and service type required' });
  }

  const service = CONFIG.services[service_type];
  if (!service) return res.status(400).json({ error: 'Invalid service type' });

  const memberCheck = db.exec("SELECT * FROM members WHERE member_id = ?", [member_id]);
  if (memberCheck.length === 0 || memberCheck[0].values.length === 0) {
    return res.status(404).json({ error: 'Member not found. Check the card and try again.' });
  }

  const memberObj = {};
  memberCheck[0].columns.forEach((col, i) => memberObj[col] = memberCheck[0].values[0][i]);

  db.run("INSERT INTO scans (member_id, service_type, points_earned, scanned_by, sector) VALUES (?, ?, ?, ?, ?)",
    [member_id, service_type, service.points, req.user.full_name, sector || null]);

  db.run("UPDATE members SET total_points = total_points + ?, visit_count = visit_count + 1, last_visit = CURRENT_TIMESTAMP WHERE member_id = ?",
    [service.points, member_id]);

  saveDB();

  const newPoints = memberObj.total_points + service.points;
  const availablePoints = newPoints - memberObj.redeemed_points;

  res.json({
    success: true,
    member_name: memberObj.full_name,
    service: service.name,
    points_earned: service.points,
    total_points: newPoints,
    available_points: availablePoints,
  });
});

// ============================================================
// REWARDS — from config
// ============================================================
app.get('/api/rewards', authMiddleware, (req, res) => {
  res.json(CONFIG.rewards);
});

app.post('/api/redeem', authMiddleware, (req, res) => {
  const { member_id, reward_key } = req.body;
  const reward = CONFIG.rewards[reward_key];
  if (!reward) return res.status(400).json({ error: 'Invalid reward' });

  const memberCheck = db.exec("SELECT * FROM members WHERE member_id = ?", [member_id]);
  if (memberCheck.length === 0 || memberCheck[0].values.length === 0) {
    return res.status(404).json({ error: 'Member not found' });
  }

  const memberObj = {};
  memberCheck[0].columns.forEach((col, i) => memberObj[col] = memberCheck[0].values[0][i]);

  const available = memberObj.total_points - memberObj.redeemed_points;
  if (available < reward.points) {
    return res.status(400).json({ error: `Not enough points. Has ${available}, needs ${reward.points}.` });
  }

  db.run("INSERT INTO redemptions (member_id, reward_name, points_spent, processed_by) VALUES (?, ?, ?, ?)",
    [member_id, reward.name, reward.points, req.user.full_name]);

  db.run("UPDATE members SET redeemed_points = redeemed_points + ? WHERE member_id = ?",
    [reward.points, member_id]);

  saveDB();

  res.json({
    success: true,
    reward: reward.name,
    points_spent: reward.points,
    remaining_points: available - reward.points,
  });
});

// ============================================================
// DASHBOARD STATS
// ============================================================
app.get('/api/stats', authMiddleware, (req, res) => {
  const totalMembers = db.exec("SELECT COUNT(*) FROM members")[0].values[0][0];
  const todayScans = db.exec("SELECT COUNT(*) FROM scans WHERE date(created_at) = date('now')")[0].values[0][0];
  const todayNewMembers = db.exec("SELECT COUNT(*) FROM members WHERE date(created_at) = date('now')")[0].values[0][0];
  const todayRedemptions = db.exec("SELECT COUNT(*) FROM redemptions WHERE date(created_at) = date('now')")[0].values[0][0];
  const totalPointsIssued = db.exec("SELECT COALESCE(SUM(total_points), 0) FROM members")[0].values[0][0];
  const totalRedeemed = db.exec("SELECT COALESCE(SUM(redeemed_points), 0) FROM members")[0].values[0][0];

  const recentScans = db.exec(
    `SELECT s.*, m.full_name as member_name FROM scans s
     JOIN members m ON s.member_id = m.member_id
     ORDER BY s.created_at DESC LIMIT 15`
  );
  let recent = [];
  if (recentScans.length > 0) {
    recent = recentScans[0].values.map(row => {
      const obj = {};
      recentScans[0].columns.forEach((col, i) => obj[col] = row[i]);
      return obj;
    });
  }

  const returningMembers = db.exec("SELECT COUNT(*) FROM members WHERE visit_count > 1")[0].values[0][0];
  const returnRate = totalMembers > 0 ? Math.round((returningMembers / totalMembers) * 100) : 0;

  res.json({
    total_members: totalMembers,
    today_scans: todayScans,
    today_new_members: todayNewMembers,
    today_redemptions: todayRedemptions,
    total_points_issued: totalPointsIssued,
    total_redeemed: totalRedeemed,
    return_rate: returnRate,
    recent_activity: recent,
  });
});

// ============================================================
// CHANGE PASSWORD
// ============================================================
app.post('/api/change-password', authMiddleware, (req, res) => {
  const { current_password, new_password } = req.body;
  const result = db.exec("SELECT password_hash FROM staff WHERE id = ?", [req.user.id]);
  if (result.length === 0) return res.status(400).json({ error: 'User not found' });
  if (!bcrypt.compareSync(current_password, result[0].values[0][0])) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  const newHash = bcrypt.hashSync(new_password, 10);
  db.run("UPDATE staff SET password_hash = ? WHERE id = ?", [newHash, req.user.id]);
  saveDB();
  res.json({ success: true });
});

// ============================================================
// FLAGS
// ============================================================
const FLAG_SECRET = process.env.FLAG_SECRET || CONFIG.monitoring.flag_secret;

app.post('/api/flags', authMiddleware, (req, res) => {
  const { category, comment, page } = req.body;
  if (!category) return res.status(400).json({ error: 'Select a category' });
  if (!comment || comment.trim().length === 0) return res.status(400).json({ error: 'Please describe the issue' });
  db.run("INSERT INTO flags (category, comment, page, raised_by) VALUES (?, ?, ?, ?)",
    [category, comment.trim(), page || null, req.user.full_name]);
  saveDB();
  res.json({ success: true });
});

app.get('/api/flags', authMiddleware, (req, res) => {
  let result;
  if (req.user.role === 'admin') {
    result = db.exec("SELECT * FROM flags ORDER BY CASE WHEN status='open' THEN 0 ELSE 1 END, created_at DESC");
  } else {
    result = db.exec("SELECT * FROM flags WHERE raised_by = ? ORDER BY created_at DESC", [req.user.full_name]);
  }
  if (result.length === 0) return res.json([]);
  res.json(result[0].values.map(row => {
    const obj = {};
    result[0].columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  }));
});

app.get('/api/flags/count', authMiddleware, (req, res) => {
  const result = db.exec("SELECT COUNT(*) FROM flags WHERE status = 'open'");
  res.json({ count: result[0].values[0][0] });
});

app.post('/api/flags/:id/resolve', authMiddleware, adminOnly, (req, res) => {
  const { note } = req.body;
  db.run("UPDATE flags SET status = 'resolved', resolved_by = ?, resolve_note = ?, resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
    [req.user.full_name, note || '', req.params.id]);
  saveDB();
  res.json({ success: true });
});

// External monitoring endpoint for Command Centre
app.get('/api/flags/external', (req, res) => {
  const key = req.query.key;
  if (key !== FLAG_SECRET) return res.status(403).json({ error: 'Invalid key' });
  const result = db.exec("SELECT * FROM flags WHERE status = 'open' ORDER BY created_at DESC");
  if (result.length === 0) return res.json({ project: CONFIG.monitoring.project_name, open_flags: 0, flags: [] });
  const rows = result[0].values.map(row => {
    const obj = {};
    result[0].columns.forEach((col, i) => obj[col] = row[i]);
    return obj;
  });
  res.json({ project: CONFIG.monitoring.project_name, open_flags: rows.length, flags: rows });
});

// External stats endpoint for Command Centre
app.get('/api/stats/external', (req, res) => {
  const key = req.query.key;
  if (key !== FLAG_SECRET) return res.status(403).json({ error: 'Invalid key' });
  const totalMembers = db.exec("SELECT COUNT(*) FROM members")[0].values[0][0];
  const totalScans = db.exec("SELECT COUNT(*) FROM scans")[0].values[0][0];
  const todayScans = db.exec("SELECT COUNT(*) FROM scans WHERE date(created_at) = date('now')")[0].values[0][0];
  res.json({
    project: CONFIG.monitoring.project_name,
    total_members: totalMembers,
    total_scans: totalScans,
    today_scans: todayScans,
  });
});

// ============================================================
// SERVE FRONTEND
// ============================================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req, res, next) => {
  if (!req.path.startsWith('/api/') && req.method === 'GET') {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    next();
  }
});

// ============================================================
// START
// ============================================================
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n===================================`);
    console.log(`  ${CONFIG.monitoring.project_name}`);
    console.log(`  Running on http://localhost:${PORT}`);
    console.log(`  Admin: ${CONFIG.admin.default_username}`);
    console.log(`===================================\n`);
  });
});

process.on('SIGINT', () => { if (db) saveDB(); process.exit(); });
process.on('SIGTERM', () => { if (db) saveDB(); process.exit(); });
