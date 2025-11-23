// index.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');              // built–in Node
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const app = express();
const port = parseInt(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME';

// middleware global
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// serve semua file di folder project (html, css, js)
app.use(express.static(path.join(__dirname))); 

// =====================
//  MySQL connection pool
// =====================
let pool;
async function initDb() {
  pool = await mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'apikey_db',
    waitForConnections: true,
    connectionLimit: 10,
  });

  // users table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      first_name VARCHAR(150) NOT NULL,
      last_name VARCHAR(150) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      api_key_id INT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // api_keys table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INT AUTO_INCREMENT PRIMARY KEY,
      api_key VARCHAR(255) NOT NULL UNIQUE,
      user_id INT DEFAULT NULL,
      status ENUM('active','inactive') DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // admins table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  console.log('✅ Database ready');
}

// =====================
//  JWT admin middleware
// =====================
function verifyAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || req.headers.Authorization;
    if (!header) return res.status(401).json({ message: 'No token provided' });

    const token = header.split(' ')[1] || header;
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// =====================
//  Serve HTML pages
// =====================
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

app.get('/admin.html', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
);

app.get('/register.html', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'register.html'))
);

app.get('/dashboard.html', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'))
);

app.get('/index.html', (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
);

// =====================
//  PUBLIC: create user + API key
//  dipakai oleh index.html & dashboard.html
// =====================
app.post('/user/create', async (req, res) => {
  const { first_name, last_name, email, apiKey } = req.body;
  if (!first_name || !last_name || !email) {
    return res
      .status(400)
      .json({ message: 'first_name, last_name, email required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // insert user
    const [userRes] = await conn.query(
      'INSERT INTO users (first_name, last_name, email) VALUES (?, ?, ?)',
      [first_name, last_name, email]
    );
    const userId = userRes.insertId;

    // pakai apiKey dari client jika dikirim & panjangnya cukup, kalau tidak generate sendiri
    const finalApiKey =
      apiKey && typeof apiKey === 'string' && apiKey.length > 10
        ? apiKey
        : crypto.randomBytes(32).toString('hex');

    // insert api_keys
    const [apiRes] = await conn.query(
      'INSERT INTO api_keys (api_key, user_id) VALUES (?, ?)',
      [finalApiKey, userId]
    );
    const apiKeyId = apiRes.insertId;

    // update users.api_key_id
    await conn.query(
      'UPDATE users SET api_key_id = ? WHERE id = ?',
      [apiKeyId, userId]
    );

    await conn.commit();

    res.json({
      message: 'User created and API key generated',
      user: { id: userId, first_name, last_name, email },
      apiKey: finalApiKey,
    });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Email already registered' });
    }
    res.status(500).json({ message: 'Server error' });
  } finally {
    conn.release();
  }
});

// =====================
//  PUBLIC: cek validitas API key
//  dipakai tombol "Check Validity" di index.html
// =====================
app.post('/cekapi', async (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) {
    return res.status(400).json({ valid: false, message: 'apiKey required' });
  }

  const [rows] = await pool.query(
    `SELECT a.*, u.first_name, u.last_name, u.email
     FROM api_keys a
     LEFT JOIN users u ON a.user_id = u.id
     WHERE a.api_key = ?`,
    [apiKey]
  );

  if (rows.length) {
    res.json({
      valid: true,
      message: 'API Key valid ✅',
      row: rows[0],
    });
  } else {
    res.json({
      valid: false,
      message: 'API Key tidak valid ❌',
    });
  }
});

// (opsional) list semua API key (buat debug)
app.get('/list', async (req, res) => {
  const [rows] = await pool.query(
    `SELECT a.id,
            a.api_key,
            a.user_id,
            a.status,
            a.created_at,
            CONCAT(u.first_name, ' ', u.last_name) AS user_name
     FROM api_keys a
     LEFT JOIN users u ON a.user_id = u.id
     ORDER BY a.created_at DESC`
  );
  res.json({ count: rows.length, apiKeys: rows });
});

// =====================
//  ADMIN: register & login
// =====================
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'email and password required' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO admins (email, password) VALUES (?, ?)', [
      email,
      hashed,
    ]);
    res.json({ message: 'Admin registered' });
  } catch (err) {
    console.error(err);
    if (err && err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Email already registered' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'email and password required' });

  try {
    const [rows] = await pool.query('SELECT * FROM admins WHERE email = ?', [
      email,
    ]);
    if (!rows.length)
      return res.status(401).json({ message: 'Invalid credentials' });

    const admin = rows[0];
    const ok = await bcrypt.compare(password, admin.password);
    if (!ok)
      return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: admin.id, email: admin.email },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ message: 'Login success', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// =====================
//  ADMIN: protected routes (dipakai dashboard.html)
// =====================

// list semua user + api_key + status
app.get('/admin/users', verifyAdmin, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT u.id,
            u.first_name,
            u.last_name,
            u.email,
            a.api_key,
            u.created_at,
            a.status
     FROM users u
     LEFT JOIN api_keys a ON u.api_key_id = a.id
     ORDER BY u.created_at DESC`
  );
  res.json({ users: rows });
});

// list semua api_key
app.get('/admin/apikeys', verifyAdmin, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT a.id,
            a.api_key,
            a.status,
            a.created_at,
            a.user_id,
            CONCAT(u.first_name, ' ', u.last_name) AS user_name
     FROM api_keys a
     LEFT JOIN users u ON a.user_id = u.id
     ORDER BY a.created_at DESC`
  );
  res.json({ apiKeys: rows });
});

// status ringkas di dashboard (jumlah user & API key)
app.get('/admin/status', verifyAdmin, async (req, res) => {
  const [[{ usersCount }]] = await pool.query(
    'SELECT COUNT(*) AS usersCount FROM users'
  );
  const [[{ apiCount }]] = await pool.query(
    'SELECT COUNT(*) AS apiCount FROM api_keys'
  );
  const [[{ activeCount }]] = await pool.query(
    "SELECT COUNT(*) AS activeCount FROM api_keys WHERE status = 'active'"
  );
  res.json({ usersCount, apiCount, activeCount });
});

// toggle aktif/nonaktif API key (button Activate/Deactivate)
app.post('/admin/apikeys/:id/toggle', verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const [rows] = await pool.query(
    'SELECT status FROM api_keys WHERE id = ?',
    [id]
  );
  if (!rows.length) return res.status(404).json({ message: 'Not found' });

  const current = rows[0].status;
  const newStatus = current === 'active' ? 'inactive' : 'active';
  await pool.query('UPDATE api_keys SET status = ? WHERE id = ?', [
    newStatus,
    id,
  ]);

  res.json({ message: 'status updated', status: newStatus });
});

// UPDATE user (dipanggil dari modal "Update" di dashboard)
app.put('/admin/users/:id', verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const { first_name, last_name, email } = req.body;
  if (!first_name || !last_name || !email) {
    return res
      .status(400)
      .json({ message: 'first_name, last_name, email required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query(
      'UPDATE users SET first_name = ?, last_name = ?, email = ? WHERE id = ?',
      [first_name, last_name, email, id]
    );
    await conn.commit();
    res.json({ message: 'User updated' });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  } finally {
    conn.release();
  }
});

// DELETE user (tombol Delete di list user)
app.delete('/admin/users/:id', verifyAdmin, async (req, res) => {
  const id = req.params.id;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // putuskan relasi user terhadap api_keys
    const [[userRow]] = await conn.query(
      'SELECT api_key_id FROM users WHERE id = ?',
      [id]
    );
    if (userRow && userRow.api_key_id) {
      await conn.query(
        'UPDATE api_keys SET user_id = NULL WHERE id = ?',
        [userRow.api_key_id]
      );
    }

    await conn.query('DELETE FROM users WHERE id = ?', [id]);

    await conn.commit();
    res.json({ message: 'User deleted' });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  } finally {
    conn.release();
  }
});

// DELETE API key (tombol Delete di list API key)
app.delete('/admin/apikeys/:id', verifyAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    // semua user yang pakai api_key ini di–null–kan
    await pool.query('UPDATE users SET api_key_id = NULL WHERE api_key_id = ?', [
      id,
    ]);
    await pool.query('DELETE FROM api_keys WHERE id = ?', [id]);
    res.json({ message: 'API key deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// =====================
//  Start server
// =====================
initDb()
  .then(() => {
    app.listen(port, () =>
      console.log(`🚀 Server berjalan di http://localhost:${port}`)
    );
  })
  .catch((err) => {
    console.error('Gagal inisialisasi DB', err);
    process.exit(1);
  });
