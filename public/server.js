// server.js
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Database setup ---
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));

db.serialize(() => {
  // Create tables if not exist
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS trains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    from_station TEXT NOT NULL,
    to_station TEXT NOT NULL,
    class_types TEXT NOT NULL
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pnr TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    train_id INTEGER NOT NULL,
    class_type TEXT NOT NULL,
    journey_date TEXT NOT NULL,
    from_station TEXT NOT NULL,
    to_station TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'CONFIRMED',
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(train_id) REFERENCES trains(id)
  );`);

  // Seed example trains if table is empty
  db.get('SELECT COUNT(*) as c FROM trains', (err, row) => {
    if (err) return console.error('Seed count error:', err.message);
    if (row.c === 0) {
      const trains = [
        ['12728', 'Godavari Superfast Express', 'HYB', 'VSKP', 'SL,3A,2A,1A'],
        ['12723', 'Telangana Express', 'HYB', 'NDLS', 'SL,3A,2A,1A'],
        ['12862', 'Visakhapatnam Express', 'VSKP', 'HYB', 'SL,3A,2A'],
        ['12627', 'Karnataka Express', 'SBC', 'NDLS', 'SL,3A,2A,1A']
      ];
      const stmt = db.prepare('INSERT INTO trains (number, name, from_station, to_station, class_types) VALUES (?, ?, ?, ?, ?)');
      trains.forEach(t => stmt.run(t));
      stmt.finalize();
      console.log('✅ Seeded trains table.');
    }
  });
});

// --- Helper functions ---
function generatePNR() {
  return crypto.randomBytes(6).toString('base64').replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 10);
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Auth Routes ---
app.post('/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password are required' });
  const hash = bcrypt.hashSync(password, 10);
  const sql = 'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)';
  db.run(sql, [name, email, hash], function(err) {
    if (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
      return res.status(500).json({ error: 'DB error' });
    }
    res.status(201).json({ id: this.lastID, name, email });
  });
});

app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  });
});

// --- Train Routes ---
app.get('/trains', (req, res) => {
  const { from, to } = req.query;
  let sql = 'SELECT * FROM trains';
  const params = [];
  if (from && to) {
    sql += ' WHERE from_station = ? AND to_station = ?';
    params.push(from, to);
  }
  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.get('/trains/:number', (req, res) => {
  db.get('SELECT * FROM trains WHERE number = ?', [req.params.number], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Train not found' });
    res.json(row);
  });
});

// --- Reservation Routes ---
app.post('/reservations', auth, (req, res) => {
  const { trainNumber, classType, journeyDate, from, to } = req.body;
  if (!trainNumber || !classType || !journeyDate || !from || !to) {
    return res.status(400).json({ error: 'trainNumber, classType, journeyDate, from, to required' });
  }
  db.get('SELECT * FROM trains WHERE number = ?', [trainNumber], (err, train) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!train) return res.status(404).json({ error: 'Train not found' });

    const allowed = train.class_types.split(',').map(s => s.trim());
    if (!allowed.includes(classType)) return res.status(400).json({ error: 'Invalid class type for this train' });

    const insert = () => {
      const pnr = generatePNR();
      const now = new Date().toISOString();
      const sql = `INSERT INTO reservations (pnr, user_id, train_id, class_type, journey_date, from_station, to_station, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'CONFIRMED', ?)`;
      db.run(sql, [pnr, req.user.id, train.id, classType, journeyDate, from, to, now], function(e) {
        if (e) {
          if (e.message.includes('UNIQUE') && e.message.includes('pnr')) return insert();
          return res.status(500).json({ error: 'DB error' });
        }
        db.get('SELECT * FROM reservations WHERE id = ?', [this.lastID], (e2, r) => {
          if (e2) return res.status(500).json({ error: 'DB error' });
          res.status(201).json({
            ...r,
            train: { id: train.id, number: train.number, name: train.name }
          });
        });
      });
    };
    insert();
  });
});

app.get('/reservations/:pnr', (req, res) => {
  const pnr = req.params.pnr.toUpperCase();
  const sql = `SELECT r.*, t.number as train_number, t.name as train_name
               FROM reservations r JOIN trains t ON r.train_id = t.id
               WHERE r.pnr = ?`;
  db.get(sql, [pnr], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'PNR not found' });
    res.json(row);
  });
});

app.post('/reservations/:pnr/cancel', auth, (req, res) => {
  const pnr = req.params.pnr.toUpperCase();
  db.get('SELECT * FROM reservations WHERE pnr = ?', [pnr], (err, r) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!r) return res.status(404).json({ error: 'PNR not found' });
    if (r.user_id !== req.user.id) return res.status(403).json({ error: 'Not your reservation' });
    if (r.status === 'CANCELLED') return res.json({ ...r, message: 'Already cancelled' });

    db.run('UPDATE reservations SET status = ? WHERE pnr = ?', ['CANCELLED', pnr], function(e2) {
      if (e2) return res.status(500).json({ error: 'DB error' });
      db.get('SELECT * FROM reservations WHERE pnr = ?', [pnr], (e3, updated) => {
        if (e3) return res.status(500).json({ error: 'DB error' });
        res.json(updated);
      });
    });
  });
});

app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
