const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');
const BUILDS_DIR = path.join(__dirname, 'builds');

if (!fs.existsSync(BUILDS_DIR)) {
  fs.mkdirSync(BUILDS_DIR, { recursive: true });
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: {},
      invites: {
        'JOY-DEV-KEY1': { used: false, used_by: null },
        'JOY-TEST-2026': { used: false, used_by: null },
        'JOY-ALPHA-777': { used: false, used_by: null }
      },
      threads: [
        {
          id: 1,
          title: 'Добро пожаловать в закрытый билд JOY.CC',
          author: 'dev',
          created_at: Date.now(),
          content: 'Тестирование начато. Баги и предложения пишите в этот тред.',
          posts: []
        }
      ],
      tickets: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    if (!data.threads) data.threads = [];
    if (!data.tickets) data.tickets = [];
    return data;
  } catch (e) {
    return { users: {}, invites: {}, threads: [], tickets: [] };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Защита от флуда
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
    if (record.count > 30) {
      return res.status(429).json({ message: 'Слишком много запросов. Подождите.' });
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
  const cleanInvite = invite_code.trim();
  const inv = db.invites[cleanInvite];

  if (!inv || inv.used) {
    return res.status(400).json({ message: 'Инвайт недействителен или уже использован' });
  }

  const userKey = username.trim().toLowerCase();
  if (db.users[userKey]) {
    return res.status(400).json({ message: 'Логин уже занят' });
  }

  db.invites[cleanInvite].used = true;
  db.invites[cleanInvite].used_by = username.trim();

  db.users[userKey] = {
    username: username.trim(),
    password: password,
    invite_code: cleanInvite,
    bio: 'Участник закрытого тестирования.',
    avatar_color: '#8b5cf6',
    avatar_url: '',
    hwid: null,
    sub_until: 0,
    created_at: Date.now()
  };

  saveDB(db);

  res.json({
    token: `joy_session_${userKey}`,
    user: db.users[userKey]
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
    user: user
  });
});

// Профиль
app.get('/api/profile', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'Сессия истекла' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user) return res.status(404).json({ message: 'Пользователь не найден' });
  res.json({ user });
});

// Обновление профиля
app.post('/api/profile/update', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'Не авторизован' });

  const { bio, avatar_color, avatar_url } = req.body;
  const userKey = token.replace('joy_session_', '');
  const db = loadDB();

  if (!db.users[userKey]) return res.status(404).json({ message: 'Пользователь не найден' });

  if (typeof bio === 'string') db.users[userKey].bio = bio.slice(0, 200);
  if (typeof avatar_color === 'string') db.users[userKey].avatar_color = avatar_color;
  if (typeof avatar_url === 'string') db.users[userKey].avatar_url = avatar_url.trim();

  saveDB(db);
  res.json({ message: 'Профиль обновлен', user: db.users[userKey] });
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

// Выдача реального бинарника
app.get('/api/download-loader', (req, res) => {
  const token = req.query.token;
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).send('Доступ запрещен: авторизуйтесь.');
  }

  const realLoaderPath = path.join(BUILDS_DIR, 'JoyLoader.exe');
  
  if (fs.existsSync(realLoaderPath)) {
    return res.download(realLoaderPath, 'JoyLoader.exe');
  }

  // Если файл еще не залит в builds/
  const tempPath = path.join(__dirname, 'JoyLoader_stub.exe');
  if (!fs.existsSync(tempPath)) {
    fs.writeFileSync(tempPath, 'JOY.CC CLIENT BINARY READY FOR REPLACE');
  }
  res.download(tempPath, 'JoyLoader.exe');
});

// Форум
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

app.get('/api/forum/threads/:id', (req, res) => {
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'Тема не найдена' });
  res.json({ thread });
});

app.post('/api/forum/threads', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Авторизуйтесь' });

  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'Заполните поля' });

  const db = loadDB();
  const userKey = token.replace('joy_session_', '');
  const user = db.users[userKey];

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

app.post('/api/forum/threads/:id/reply', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Авторизуйтесь' });

  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ message: 'Введите текст' });

  const db = loadDB();
  const userKey = token.replace('joy_session_', '');
  const user = db.users[userKey];

  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'Тема не найдена' });

  const post = { author: user.username, text: text.trim(), created_at: Date.now() };
  if (!thread.posts) thread.posts = [];
  thread.posts.push(post);
  saveDB(db);
  res.json({ post });
});

// Тикеты
app.post('/api/support/ticket', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Авторизуйтесь' });

  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'Заполните поля' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  const ticket = {
    id: 'TICK-' + Math.floor(1000 + Math.random() * 9000),
    userKey,
    username: user.username,
    subject: subject.trim(),
    message: message.trim(),
    status: 'На рассмотрении',
    reply: null,
    created_at: Date.now()
  };

  db.tickets.unshift(ticket);
  saveDB(db);
  console.log(`[FORWARD LOG] Тикет ${ticket.id} от ${user.username}`);
  res.json({ message: 'Обращение создано', ticket });
});

app.get('/api/support/my-tickets', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const myTickets = (db.tickets || []).filter(t => t.userKey === userKey);
  res.json({ tickets: myTickets });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY.CC] Сервер активен на порту ${PORT}`);
});
