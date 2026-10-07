const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const db = new Database('joy.db');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 1. ИНИЦИАЛИЗАЦИЯ ТАБЛИЦ БАЗЫ ДАННЫХ
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE COLLATE NOCASE,
    password_hash TEXT,
    invite_code TEXT,
    hwid TEXT DEFAULT NULL,
    sub_until INTEGER DEFAULT 0,
    created_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    used INTEGER DEFAULT 0,
    used_by TEXT DEFAULT NULL
  );
`);

// Создаем тестовые инвайты, если таблица пустая
const inviteCount = db.prepare('SELECT count(*) as count FROM invites').get().count;
if (inviteCount === 0) {
  const insertInvite = db.prepare('INSERT INTO invites (code) VALUES (?)');
  insertInvite.run('JOY-DEV-KEY1');
  insertInvite.run('JOY-TEST-2026');
  insertInvite.run('JOY-ALPHA-777');
  console.log('[DB] Сгенерированы тестовые инвайты: JOY-DEV-KEY1, JOY-TEST-2026, JOY-ALPHA-777');
}

// 2. ANTI-DDOS / RATE-LIMITER ПО IP
const ipRequests = new Map();
const IP_LIMIT_WINDOW_MS = 10000; // Окно 10 секунд
const MAX_REQUESTS_PER_WINDOW = 12; // Максимум 12 запросов с одного IP
const BLOCK_TIME_MS = 60000; // Бан на 1 минуту при флуде

function antiDdosMiddleware(req, res, next) {
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();

  let record = ipRequests.get(clientIp);

  if (!record) {
    record = { count: 1, firstRequest: now, blockedUntil: 0 };
    ipRequests.set(clientIp, record);
  } else {
    // Проверка активного бана
    if (record.blockedUntil > now) {
      const waitSec = Math.ceil((record.blockedUntil - now) / 1000);
      return res.status(429).json({ message: `IP временно заблокирован защитой от DDoS. Ждите ${waitSec} сек.` });
    }

    // Сброс окна времени
    if (now - record.firstRequest > IP_LIMIT_WINDOW_MS) {
      record.count = 1;
      record.firstRequest = now;
    } else {
      record.count++;
      if (record.count > MAX_REQUESTS_PER_WINDOW) {
        record.blockedUntil = now + BLOCK_TIME_MS;
        console.warn(`[ANTI-DDOS] Временная блокировка IP: ${clientIp}`);
        return res.status(429).json({ message: 'Слишком много запросов. Ваш IP временно заблокирован.' });
      }
    }
  }

  req.clientIp = clientIp;
  next();
}

app.use('/api', antiDdosMiddleware);

// 3. API ЭНДПОИНТЫ

// Проверка соединения и IP при загрузке
app.get('/api/verify-ip', (req, res) => {
  res.json({ status: 'ok', ip: req.clientIp });
});

// Регистрация
app.post('/api/register', (req, res) => {
  const { invite_code, username, password } = req.body;

  if (!invite_code || !username || !password) {
    return res.status(400).json({ message: 'Заполните все поля' });
  }

  // Проверка инвайта
  const inv = db.prepare('SELECT * FROM invites WHERE code = ? AND used = 0').get(invite_code.trim());
  if (!inv) {
    return res.status(400).json({ message: 'Недействительный или использованный инвайт' });
  }

  // Проверка занятости никнейма
  const existingUser = db.prepare('SELECT id FROM users WHERE username = ?').get(username.trim());
  if (existingUser) {
    return res.status(400).json({ message: 'Логин уже занят' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const now = Date.now();

  // Транзакция: создаем юзера и гасим инвайт
  const registerTx = db.transaction(() => {
    db.prepare('INSERT INTO users (username, password_hash, invite_code, created_at) VALUES (?, ?, ?, ?)').run(
      username.trim(), hash, invite_code.trim(), now
    );
    db.prepare('UPDATE invites SET used = 1, used_by = ? WHERE code = ?').run(username.trim(), invite_code.trim());
  });

  try {
    registerTx();
    res.json({
      token: `joy_session_${username.trim()}`,
      user: { username: username.trim(), invite_code: invite_code.trim(), hwid: null, subscription_expires: null }
    });
  } catch (err) {
    res.status(500).json({ message: 'Ошибка базы данных' });
  }
});

// Вход
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ message: 'Неверный логин или пароль' });
  }

  res.json({
    token: `joy_session_${user.username}`,
    user: {
      username: user.username,
      invite_code: user.invite_code,
      hwid: user.hwid,
      subscription_expires: user.sub_until ? new Date(user.sub_until).toLocaleDateString() : null
    }
  });
});

// Получение профиля
app.get('/api/profile', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).json({ message: 'Сессия недействительна' });
  }

  const username = token.replace('joy_session_', '');
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) return res.status(404).json({ message: 'Пользователь не найден' });

  res.json({
    user: {
      username: user.username,
      invite_code: user.invite_code,
      hwid: user.hwid,
      subscription_expires: user.sub_until ? new Date(user.sub_until).toLocaleDateString() : null
    }
  });
});

// Сброс HWID
app.post('/api/hwid/reset', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Не авторизован' });

  const username = token.replace('joy_session_', '');
  db.prepare('UPDATE users SET hwid = NULL WHERE username = ?').run(username);

  res.json({ message: 'HWID успешно сброшен. Привязка очищена.' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`[JOY.CC] Сервер и база активны на http://localhost:${PORT}`);
});