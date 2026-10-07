const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: {},
      invites: {
        'JOY-DEV-KEY1': { used: false },
        'JOY-TEST-2026': { used: false },
        'JOY-ALPHA-777': { used: false }
      },
      threads: [
        {
          id: 1,
          title: 'Правила закрытого сообщества и статус билда',
          author: 'dev',
          created_at: Date.now(),
          content: 'Добро пожаловать в закрытый альфа-билд. Публиковать материалы за пределы площадки строго запрещено.',
          posts: [
            { author: 'dev', text: 'По всем багам пишите в этот тред.', created_at: Date.now() }
          ]
        }
      ]
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    if (!parsed.threads) parsed.threads = [];
    return parsed;
  } catch (e) {
    return { users: {}, invites: {}, threads: [] };
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
    if (record.count > 25) {
      return res.status(429).json({ message: 'Слишком частые запросы. Подождите.' });
    }
  }
  next();
});

app.get('/api/verify-ip', (req, res) => res.json({ status: 'ok' }));

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

  db.invites[invite_code.trim()].used = true;
  db.invites[invite_code.trim()].used_by = username.trim();

  db.users[userKey] = {
    username: username.trim(),
    password: password,
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

// === API ФОРУМА ===

// Получить все темы
app.get('/api/forum/threads', (req, res) => {
  const db = loadDB();
  const list = db.threads.map(t => ({
    id: t.id,
    title: t.title,
    author: t.author,
    created_at: t.created_at,
    replies_count: t.posts ? t.posts.length : 0
  }));
  res.json({ threads: list });
});

// Получить один тред с сообщениями
app.get('/api/forum/threads/:id', (req, res) => {
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'Тема не найдена' });
  res.json({ thread });
});

// Создать новую тему
app.post('/api/forum/threads', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).json({ message: 'Требуется авторизация' });
  }

  const { title, content } = req.body;
  if (!title || !content) {
    return res.status(400).json({ message: 'Заполните название и текст' });
  }

  const db = loadDB();
  const userKey = token.replace('joy_session_', '');
  const user = db.users[userKey];
  if (!user) return res.status(401).json({ message: 'Пользователь не найден' });

  const newThread = {
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    author: user.username,
    created_at: Date.now(),
    posts: []
  };

  db.threads.unshift(newThread);
  saveDB(db);

  res.json({ thread: newThread });
});

// Добавить ответ в тему
app.post('/api/forum/threads/:id/reply', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).json({ message: 'Требуется авторизация' });
  }

  const { text } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ message: 'Введите сообщение' });
  }

  const db = loadDB();
  const userKey = token.replace('joy_session_', '');
  const user = db.users[userKey];
  if (!user) return res.status(401).json({ message: 'Пользователь не найден' });

  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'Тема не найдена' });

  if (!thread.posts) thread.posts = [];

  const newPost = {
    author: user.username,
    text: text.trim(),
    created_at: Date.now()
  };

  thread.posts.push(newPost);
  saveDB(db);

  res.json({ post: newPost });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY.CC] Сервер активен на порту ${PORT}`);
});
