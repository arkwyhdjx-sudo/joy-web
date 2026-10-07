const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

// Лимит на загрузку файлов лаунчера и медиа (до 100MB)
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');
const BUILDS_DIR = path.join(__dirname, 'builds');

if (!fs.existsSync(BUILDS_DIR)) {
  fs.mkdirSync(BUILDS_DIR, { recursive: true });
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      next_uid: 1,
      users: {},
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
      updates: [
        {
          id: 1,
          title: 'первый запуск закрытой альфы',
          content: '- инициализация веб-панели\n- запуск системы авторизации и тикетов\n- базовая защита от флуда',
          author: 'dev',
          created_at: Date.now()
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
    if (!data.updates) data.updates = [];
    if (!data.tickets) data.tickets = [];
    return data;
  } catch (e) {
    return { next_uid: 1, users: {}, invites: {}, threads: [], updates: [], tickets: [] };
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('ошибка базы:', e);
  }
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
    if (record.count > 40) {
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

// Регистрация
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

// Профиль текущего юзера
app.get('/api/profile', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'сессия истекла' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ user });
});

// Публичный профиль для модалки
app.get('/api/user/:username', (req, res) => {
  const db = loadDB();
  const target = db.users[req.params.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  res.json({
    user: {
      uid: target.uid,
      username: target.username,
      bio: target.bio || '',
      avatar_color: target.avatar_color,
      avatar_media: target.avatar_media,
      avatar_type: target.avatar_type,
      created_at: target.created_at
    }
  });
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

// Скачивание лаунчера
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

// === АДМИН-ПАНЕЛЬ (ТОЛЬКО ДЛЯ UID 1) ===

// 1. Загрузка файла лаунчера через браузер
app.post('/api/admin/upload-build', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user || user.uid !== 1) {
    return res.status(403).json({ message: 'доступ запрещен' });
  }

  const { file_base64 } = req.body;
  if (!file_base64) return res.status(400).json({ message: 'файл не передан' });

  try {
    const base64Data = file_base64.replace(/^data:.*?;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    const targetPath = path.join(BUILDS_DIR, 'JoyLoader.exe');
    fs.writeFileSync(targetPath, buffer);
    res.json({ message: 'новый билд JoyLoader.exe успешно загружен на сервер' });
  } catch (err) {
    res.status(500).json({ message: 'ошибка сохранения файла' });
  }
});

// 2. Создание инвайтов из админки
app.post('/api/admin/create-invite', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user || user.uid !== 1) {
    return res.status(403).json({ message: 'доступ запрещен' });
  }

  const code = 'JOY-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
  db.invites[code] = { used: false, used_by: null };
  saveDB(db);

  res.json({ invite: code, invites: db.invites });
});

// === ОБНОВЛЕНИЯ ===
app.get('/api/updates', (req, res) => {
  const db = loadDB();
  res.json({ updates: db.updates || [] });
});

app.post('/api/updates', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user || user.uid !== 1) {
    return res.status(403).json({ message: 'доступ только для разработчика' });
  }

  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните поля' });

  const item = {
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    author: user.username,
    created_at: Date.now()
  };

  db.updates.unshift(item);
  saveDB(db);
  res.json({ update: item });
});

app.delete('/api/updates/:id', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user || user.uid !== 1) {
    return res.status(403).json({ message: 'доступ только для разработчика' });
  }

  const uId = parseInt(req.params.id);
  const idx = (db.updates || []).findIndex(u => u.id === uId);
  if (idx === -1) return res.status(404).json({ message: 'обновление не найдено' });

  db.updates.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'обновление удалено' });
});

// === ФОРУМ ===
app.get('/api/forum/threads', (req, res) => {
  const db = loadDB();
  const list = db.threads.map(t => {
    const authorUser = db.users[t.author.toLowerCase()] || {};
    return {
      id: t.id,
      title: t.title,
      author: t.author,
      author_uid: t.author_uid || 1,
      author_avatar_media: authorUser.avatar_media || null,
      author_avatar_type: authorUser.avatar_type || null,
      author_avatar_color: authorUser.avatar_color || '#8b5cf6',
      created_at: t.created_at,
      replies_count: t.posts ? t.posts.length : 0
    };
  });
  res.json({ threads: list });
});

app.get('/api/forum/threads/:id', (req, res) => {
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  const authorUser = db.users[thread.author.toLowerCase()] || {};
  const enrichedThread = {
    ...thread,
    author_avatar_media: authorUser.avatar_media || null,
    author_avatar_type: authorUser.avatar_type || null,
    author_avatar_color: authorUser.avatar_color || '#8b5cf6',
    posts: (thread.posts || []).map(p => {
      const pUser = db.users[p.author.toLowerCase()] || {};
      return {
        ...p,
        author_avatar_media: pUser.avatar_media || null,
        author_avatar_type: pUser.avatar_type || null,
        author_avatar_color: pUser.avatar_color || '#8b5cf6'
      };
    })
  };

  res.json({ thread: enrichedThread });
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

  if (db.threads[idx].author !== user.username && user.uid !== 1) {
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

  if (thread.posts[pIdx].author !== user.username && user.uid !== 1) {
    return res.status(403).json({ message: 'нет прав на удаление' });
  }

  thread.posts.splice(pIdx, 1);
  saveDB(db);
  res.json({ message: 'сообщение удалено' });
});

// === ТИКЕТЫ ===
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

  console.log(`[FORWARD LOG] arkwyhdjx@gmail.com -> Тикет ${ticket.id} от ${user.username} [uid ${user.uid}]: ${ticket.subject}`);
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

  const idx = (db.tickets || []).findIndex(t => t.id === tId && (t.userKey === userKey || userKey === 'dev'));
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
