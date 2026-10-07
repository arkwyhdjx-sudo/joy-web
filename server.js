const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ limit: '25mb', extended: true }));
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');
const BUILDS_DIR = path.join(__dirname, 'builds');

if (!fs.existsSync(BUILDS_DIR)) {
  fs.mkdirSync(BUILDS_DIR, { recursive: true });
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      next_uid: 1, // первый зарегистрировавшийся забирает честный UID 1
      users: {},   // никаких фейковых аккаунтов dev:dev
      invites: {
        'JOY-DEV-KEY1': { used: false, used_by: null },
        'JOY-TEST-2026': { used: false, used_by: null },
        'JOY-ALPHA-777': { used: false, used_by: null }
      },
      threads: [
        {
          id: 1,
          title: 'правила и статус закрытого билда',
          author: 'system',
          author_uid: 0,
          created_at: Date.now(),
          content: 'закрытый тест запущен. вопросы и найденные баги пишите сюда.',
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
    if (!data.next_uid) data.next_uid = 1;
    if (!data.users) data.users = {};
    if (!data.threads) data.threads = [];
    if (!data.tickets) data.tickets = [];
    return data;
  } catch (e) {
    return { next_uid: 1, users: {}, invites: {}, threads: [], tickets: [] };
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Ошибка базы:', e);
  }
}

// Защита от спама по IP
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
    if (record.count > 35) {
      return res.status(429).json({ message: 'лимит запросов превышен' });
    }
  }
  next();
});

const actionCooldowns = new Map();
function checkCooldown(username, action, cooldownSec) {
  const key = `${username}_${action}`;
  const now = Date.now();
  const last = actionCooldowns.get(key) || 0;
  if (now - last < cooldownSec * 1000) {
    const wait = Math.ceil((cooldownSec * 1000 - (now - last)) / 1000);
    return `подождите ${wait} сек.`;
  }
  actionCooldowns.set(key, now);
  return null;
}

app.get('/api/verify-ip', (req, res) => res.json({ status: 'ok' }));

// Регистрация с присвоением UID
app.post('/api/register', (req, res) => {
  const { invite_code, username, password } = req.body;
  if (!invite_code || !username || !password) {
    return res.status(400).json({ message: 'заполните все поля' });
  }

  const db = loadDB();
  const cleanInvite = invite_code.trim();
  const inv = db.invites[cleanInvite];

  if (!inv || inv.used) {
    return res.status(400).json({ message: 'инвайт недействителен или использован' });
  }

  const userKey = username.trim().toLowerCase();
  if (db.users[userKey]) {
    return res.status(400).json({ message: 'логин занят' });
  }

  // Присваиваем следующий порядковый UID
  const assignedUid = db.next_uid || 1;
  db.next_uid = assignedUid + 1;

  db.invites[cleanInvite].used = true;
  db.invites[cleanInvite].used_by = username.trim();

  db.users[userKey] = {
    uid: assignedUid,
    username: username.trim(),
    password: password,
    invite_code: cleanInvite,
    bio: '',
    avatar_color: '#8b5cf6',
    avatar_media: null,
    avatar_type: null,
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
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  res.json({
    token: `joy_session_${user.username.toLowerCase()}`,
    user: user
  });
});

// Профиль
app.get('/api/profile', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'сессия истекла' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ user });
});

// Обновление профиля
app.post('/api/profile/update', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(404).json({ message: 'пользователь не найден' });

  const { bio, avatar_color, avatar_media, avatar_type, reset_media } = req.body;

  if (typeof bio === 'string') user.bio = bio.slice(0, 250);
  if (typeof avatar_color === 'string') user.avatar_color = avatar_color;

  if (reset_media) {
    user.avatar_media = null;
    user.avatar_type = null;
  } else if (avatar_media && avatar_type) {
    user.avatar_media = avatar_media;
    user.avatar_type = avatar_type;
  }

  saveDB(db);
  res.json({ message: 'профиль сохранен', user });
});

// Сброс HWID
app.post('/api/hwid/reset', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  if (db.users[userKey]) {
    db.users[userKey].hwid = null;
    saveDB(db);
  }
  res.json({ message: 'hwid успешно сброшен' });
});

// Выдача лоадера
app.get('/api/download-loader', (req, res) => {
  const token = req.query.token;
  if (!token || !token.startsWith('joy_session_')) {
    return res.status(401).send('доступ запрещен');
  }

  const realLoader = path.join(BUILDS_DIR, 'JoyLoader.exe');
  if (fs.existsSync(realLoader)) {
    return res.download(realLoader, 'JoyLoader.exe');
  }

  const tempPath = path.join(__dirname, 'JoyLoader_stub.exe');
  if (!fs.existsSync(tempPath)) {
    fs.writeFileSync(tempPath, 'JOY.CC CLIENT BUILD');
  }
  res.download(tempPath, 'JoyLoader.exe');
});

// ФОРУМ
app.get('/api/forum/threads', (req, res) => {
  const db = loadDB();
  const list = db.threads.map(t => ({
    id: t.id,
    title: t.title,
    author: t.author,
    author_uid: t.author_uid || 1,
    created_at: t.created_at,
    replies_count: t.posts ? t.posts.length : 0
  }));
  res.json({ threads: list });
});

app.get('/api/forum/threads/:id', (req, res) => {
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });
  res.json({ thread });
});

app.post('/api/forum/threads', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(401).json({ message: 'пользователь не найден' });

  const cdError = checkCooldown(user.username, 'new_thread', 30);
  if (cdError) return res.status(429).json({ message: cdError });

  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните поля' });

  const newThread = {
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    author: user.username,
    author_uid: user.uid,
    created_at: Date.now(),
    posts: []
  };

  db.threads.unshift(newThread);
  saveDB(db);
  res.json({ thread: newThread });
});

app.post('/api/forum/threads/:id/reply', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(401).json({ message: 'пользователь не найден' });

  const cdError = checkCooldown(user.username, 'reply', 10);
  if (cdError) return res.status(429).json({ message: cdError });

  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ message: 'введите текст' });

  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  const post = {
    id: Date.now(),
    author: user.username,
    author_uid: user.uid,
    text: text.trim(),
    created_at: Date.now()
  };

  if (!thread.posts) thread.posts = [];
  thread.posts.push(post);
  saveDB(db);
  res.json({ post });
});

app.delete('/api/forum/threads/:id', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  const tId = parseInt(req.params.id);

  const idx = db.threads.findIndex(t => t.id === tId);
  if (idx === -1) return res.status(404).json({ message: 'тема не найдена' });

  if (db.threads[idx].author !== user.username && user.username !== 'dev') {
    return res.status(403).json({ message: 'нет прав на удаление' });
  }

  db.threads.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'тема удалена' });
});

app.delete('/api/forum/threads/:id/post/:postId', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  const tId = parseInt(req.params.id);
  const pId = parseInt(req.params.postId);

  const thread = db.threads.find(t => t.id === tId);
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  const pIdx = (thread.posts || []).findIndex(p => p.id === pId);
  if (pIdx === -1) return res.status(404).json({ message: 'сообщение не найдено' });

  if (thread.posts[pIdx].author !== user.username && user.username !== 'dev') {
    return res.status(403).json({ message: 'нет прав на удаление' });
  }

  thread.posts.splice(pIdx, 1);
  saveDB(db);
  res.json({ message: 'сообщение удалено' });
});

// ТИКЕТЫ
app.post('/api/support/ticket', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(401).json({ message: 'пользователь не найден' });

  const cdError = checkCooldown(user.username, 'ticket', 30);
  if (cdError) return res.status(429).json({ message: cdError });

  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'заполните все поля' });

  const ticket = {
    id: 'TICK-' + Math.floor(1000 + Math.random() * 9000),
    userKey,
    username: user.username,
    user_uid: user.uid,
    subject: subject.trim(),
    message: message.trim(),
    status: 'на рассмотрении',
    reply: null,
    created_at: Date.now()
  };

  db.tickets.unshift(ticket);
  saveDB(db);

  console.log(`[FORWARD LOG] arkwyhdjx@gmail.com -> Тикет ${ticket.id} от ${user.username} [UID: ${user.uid}]: ${ticket.subject}`);
  res.json({ message: 'обращение отправлено', ticket });
});

app.get('/api/support/my-tickets', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const myTickets = (db.tickets || []).filter(t => t.userKey === userKey);
  res.json({ tickets: myTickets });
});

app.delete('/api/support/ticket/:id', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const tId = req.params.id;

  const idx = (db.tickets || []).findIndex(t => t.id === tId && t.userKey === userKey);
  if (idx === -1) return res.status(404).json({ message: 'тикет не найден' });

  db.tickets.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'обращение удалено' });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY.CC] Сервер активен на порту ${PORT}`);
});
