const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const express = require('express');
const bcrypt = require('bcryptjs');
const { DatabaseSync } = require('node:sqlite');

const app = express();
const port = Number(process.env.PORT) || 5000;
const dataDirectory = path.join(__dirname, 'data');
fs.mkdirSync(dataDirectory, { recursive: true });

const database = new DatabaseSync(path.join(dataDirectory, 'accounts.sqlite'));
database.exec('PRAGMA journal_mode = WAL');
database.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    phone TEXT NOT NULL,
    country TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

const sessions = new Map();
const createUser = database.prepare(`
  INSERT INTO users (username, email, phone, country, password_hash)
  VALUES (@username, @email, @phone, @country, @passwordHash)
`);
const findUser = database.prepare(`
  SELECT id, username, email, phone, country, password_hash AS passwordHash
  FROM users
  WHERE username = @identity OR email = @identity
`);

app.use(express.json({ limit: '32kb' }));
app.use(express.static(__dirname));

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    phone: user.phone,
    country: user.country
  };
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, userId);
  return token;
}

function getSessionUser(request) {
  const token = request.get('Authorization')?.replace(/^Bearer\s+/i, '');
  const userId = token ? sessions.get(token) : undefined;
  if (!userId) return null;
  return database.prepare('SELECT id, username, email, phone, country FROM users WHERE id = ?').get(userId);
}

app.post('/api/register', (request, response) => {
  const { name, email, phone, password, confirmPassword, country } = request.body || {};
  if (!name || !email || !phone || !password || !confirmPassword || !country) {
    return response.status(400).json({ success: false, message: 'All fields are required.' });
  }
  if (password !== confirmPassword || password.length < 8) {
    return response.status(400).json({ success: false, message: 'Passwords must match and contain at least 8 characters.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return response.status(400).json({ success: false, message: 'Enter a valid email address.' });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 12);
    const result = createUser.run({ username: name.trim(), email: email.trim(), phone: phone.trim(), country, passwordHash });
    const user = database.prepare('SELECT id, username, email, phone, country FROM users WHERE id = ?').get(Number(result.lastInsertRowid));
    const token = createSession(user.id);
    return response.status(201).json({ success: true, user: publicUser(user), token });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return response.status(409).json({ success: false, message: 'Username or email is already registered.' });
    }
    console.error('Registration failed:', error);
    return response.status(500).json({ success: false, message: 'Could not create the account.' });
  }
});

app.post('/api/login', (request, response) => {
  const { identity, password } = request.body || {};
  if (!identity || !password) {
    return response.status(400).json({ success: false, message: 'Username/email and password are required.' });
  }
  const user = findUser.get({ identity: identity.trim() });
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return response.status(401).json({ success: false, message: 'Invalid username/email or password.' });
  }
  const token = createSession(user.id);
  return response.json({ success: true, user: publicUser(user), token });
});

app.get('/api/me', (request, response) => {
  const user = getSessionUser(request);
  if (!user) return response.status(401).json({ success: false, message: 'Not authenticated.' });
  return response.json({ success: true, user: publicUser(user) });
});

app.post('/api/logout', (request, response) => {
  const token = request.get('Authorization')?.replace(/^Bearer\s+/i, '');
  if (token) sessions.delete(token);
  return response.json({ success: true });
});

app.listen(port, () => {
  console.log(`Minecraft dashboard running at http://localhost:${port}`);
});
