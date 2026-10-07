const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');

// Инициализация базы данных в JSON-файле
function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: {},
      invites: {
        'JOY-DEV-KEY1': { used: false },
        'JOY-TEST-2026': { used: false },
        'JOY-ALPHA-777': { used: false }
      }
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch (e) {
    return { users: {}, invites: {} };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Защита от флуда по IP
const ipRequests = new Map();
app.use('/api', (req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();
  let record = ipRequests.get(ip);

  if (!record || now - record.firstRequest > 10000) {
    record = { count: 1, firstRequest: now };
    ipRequests.set(ip, record);
  } else {
    record.count++;
    if (record.count > 15) {
      return res.status(429).json({ message: 'Слишком частые запросы. Подождите.' });
    }
  }
  next();
});

// Проверка соединения
app.get('/api/verify-ip', (req, res) => {
  res.json({ status: 'ok' });
});

// Регистрация
app.post('/api/register', (req, res) => {
  const { invite_code, username, password } = req.body;

  if (!invite_code || !username || !password) {
    return res.status(400).json({ message: 'Заполните все поля' });
  }

  const db = loadDB();
  const inv = db.invites[invite_code.trim()];

  if (!inv || inv.used) {
    return res.status(400).json({ message: 'Недействительный или использованный инвайт' });
  }

  const userKey = username.trim().toLowerCase();
  if (db.users[userKey]) {
    return res.status(400).json({ message: 'Логин уже занят' });
  }

  // Создаем аккаунт и гасим инвайт
  db.invites[invite_code.trim()].used = true;
  db.invites[invite_code.trim()].used_by = username.trim();

  db.users[userKey] = {
    username: username.trim(),
    password: password, // В проде можно добавить хеширование
    invite_code: invite_code.trim(),
    hwid: null,
    sub_until: 0,
    created_at: Date.now()
  };

  saveDB(db);

  res.json({
    token: `joy_session_${userKey}`,
    user: {
      username: username.trim(),
      invite_code: invite_code.trim(),
      hwid: null,
      subscription_expires: null
    }
  });
});

// Вход
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];

  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Неверный логин или пароль' });
  }

  res.json({
    token: `joy_session_${user.username.toLowerCase()}`,
    user: {
      username: user.username,
      invite_code: user.invite_code,
      hwid: user.hwid,
      subscription_expires: user.sub_until ? new Date(user.sub_until).toLocaleDateString() : null
    }
  });
});

// Профиль
app.get('/api/profile', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).json({ message: 'Сессия истекла' });
  }

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

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

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  if (db.users[userKey]) {
    db.users[userKey].hwid = null;
    saveDB(db);
  }

  res.json({ message: 'HWID успешно сброшен' });
});

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY.CC] Сервер активен на порту ${PORT}`);
});
