const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();

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
        'JOY-DEV-KEY1': { used: false, used_by: null, created_at: Date.now() },
        'JOY-TEST-2026': { used: false, used_by: null, created_at: Date.now() },
        'JOY-ALPHA-777': { used: false, used_by: null, created_at: Date.now() }
      },
      promos: {},
      threads: [
        {
          id: 1,
          title: 'правила и статус закрытого билда',
          author: 'system',
          author_uid: 0,
          author_role: 'system',
          created_at: Date.now(),
          content: 'закрытый тест запущен. вопросы и найденные баги пишите сюда.',
          posts: []
        }
      ],
      updates: [],
      tickets: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
    return initial;
  }
  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
    if (!data.next_uid) data.next_uid = 1;
    if (!data.users) data.users = {};
    if (!data.invites) data.invites = {};
    if (!data.promos) data.promos = {};
    if (!data.threads) data.threads = [];
    if (!data.updates) data.updates = [];
    if (!data.tickets) data.tickets = [];
    return data;
  } catch (e) {
    return { next_uid: 1, users: {}, invites: {}, promos: {}, threads: [], updates: [], tickets: [] };
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('ошибка базы:', e);
  }
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
    if (record.count > 50) {
      return res.status(429).json({ message: 'лимит запросов превышен' });
    }
  }
  next();
});

// Проверка прав овнера
function requireOwner(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];

  if (!user || (user.uid !== 1 && user.role !== 'owner' && user.username !== 'dev')) {
    return res.status(403).json({ message: 'доступ запрещен' });
  }

  req.adminUser = user;
  next();
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

  const isOwner = (assignedUid === 1 || userKey === 'dev');
  const defaultRole = isOwner ? 'owner' : 'user';

  db.users[userKey] = {
    uid: assignedUid,
    username: username.trim(),
    password: password,
    invite_code: cleanInvite,
    role: defaultRole,
    banned: false,
    ban_reason: '',
    bio: '',
    avatar_color: '#8b5cf6',
    avatar_media: null,
    avatar_type: null,
    hwid: null,
    sub_until: isOwner ? -1 : 0,
    created_at: Date.now()
  };

  saveDB(db);

  res.json({
    token: `joy_session_${userKey}`,
    user: db.users[userKey]
  });
});

// Вход с проверкой бана
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];

  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  if (user.banned) {
    return res.status(403).json({ 
      message: `аккаунт заблокирован. причина: ${user.ban_reason || 'нарушение правил'}`,
      banned: true 
    });
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
  if (user.banned) return res.status(403).json({ message: `аккаунт заблокирован: ${user.ban_reason || 'бан'}`, banned: true });

  res.json({ user });
});

// Публичный профиль
app.get('/api/user/:username', (req, res) => {
  const db = loadDB();
  const target = db.users[req.params.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  res.json({
    user: {
      uid: target.uid,
      username: target.username,
      role: target.role || 'user',
      banned: target.banned || false,
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
  if (user.banned) return res.status(403).json({ message: 'аккаунт заблокирован' });

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

// Активация промокода
app.post('/api/promo/redeem', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  const promoKey = (req.body.code || '').trim().toUpperCase();
  const promo = db.promos[promoKey];

  if (!promo) return res.status(400).json({ message: 'промокод не существует' });
  if (promo.used_count >= promo.max_uses) return res.status(400).json({ message: 'лимит активаций исчерпан' });
  if (promo.users_activated && promo.users_activated.includes(user.username)) {
    return res.status(400).json({ message: 'вы уже активировали этот промокод' });
  }

  const now = Date.now();
  const daysMs = promo.days * 24 * 60 * 60 * 1000;
  if (user.sub_until === -1) {
    return res.status(400).json({ message: 'у вас уже активна бессрочная подписка' });
  }

  if (user.sub_until > now) {
    user.sub_until += daysMs;
  } else {
    user.sub_until = now + daysMs;
  }

  promo.used_count++;
  if (!promo.users_activated) promo.users_activated = [];
  promo.users_activated.push(user.username);

  saveDB(db);
  res.json({ message: `активировано +${promo.days} дн. подписки`, user });
});

// Сброс HWID
app.post('/api/hwid/reset', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  user.hwid = null;
  saveDB(db);
  res.json({ message: 'hwid успешно сброшен' });
});

// Скачивание лаунчера
app.get('/api/download-loader', (req, res) => {
  const token = req.query.token;
  if (!token || !token.startsWith('joy_session_')) return res.status(401).send('доступ запрещен');

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).send('аккаунт заблокирован');

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

// === АДМИН-ФУНКЦИИ (ДЛЯ ОВНЕРА) ===

// 1. Выдать себе Lifetime подписку в 1 клик
app.post('/api/admin/self-lifetime', requireOwner, (req, res) => {
  const db = loadDB();
  const user = req.adminUser;
  user.sub_until = -1;
  user.role = 'owner';
  saveDB(db);
  res.json({ message: 'вам успешно выдана lifetime подписка и роль owner', user });
});

// 2. Список юзеров
app.get('/api/admin/users', requireOwner, (req, res) => {
  const db = loadDB();
  const list = Object.values(db.users).map(u => ({
    uid: u.uid,
    username: u.username,
    role: u.role || 'user',
    banned: u.banned || false,
    ban_reason: u.ban_reason || '',
    sub_until: u.sub_until,
    invite_code: u.invite_code,
    hwid: !!u.hwid,
    created_at: u.created_at
  }));
  list.sort((a, b) => a.uid - b.uid);
  res.json({ users: list });
});

// 3. Данные одного пользователя
app.get('/api/admin/user/:username', requireOwner, (req, res) => {
  const db = loadDB();
  const target = db.users[req.params.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ target });
});

// 4. Редактирование пользователя + Бан / Разбан
app.post('/api/admin/user/update', requireOwner, (req, res) => {
  const { username, role, uid, sub_mode, reset_hwid, banned, ban_reason } = req.body;
  const db = loadDB();
  const target = db.users[username.toLowerCase()];

  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  if (role) target.role = role;
  if (uid && !isNaN(parseInt(uid))) target.uid = parseInt(uid);

  const now = Date.now();
  if (sub_mode === 'reset') target.sub_until = 0;
  else if (sub_mode === 'lifetime') target.sub_until = -1;
  else if (sub_mode === '30d') target.sub_until = (target.sub_until > now ? target.sub_until : now) + (30 * 86400000);
  else if (sub_mode === '90d') target.sub_until = (target.sub_until > now ? target.sub_until : now) + (90 * 86400000);

  if (reset_hwid) target.hwid = null;

  if (typeof banned === 'boolean') {
    target.banned = banned;
    target.ban_reason = banned ? (ban_reason || 'нарушение правил') : '';
  }

  saveDB(db);
  res.json({ message: `аккаунт ${target.username} обновлен`, target });
});

// 5. Инвайты
app.get('/api/admin/invites', requireOwner, (req, res) => {
  const db = loadDB();
  const list = Object.entries(db.invites || {}).map(([code, info]) => ({
    code,
    used: info.used,
    used_by: info.used_by,
    created_at: info.created_at || null
  }));
  list.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  res.json({ invites: list });
});

app.post('/api/admin/create-invite', requireOwner, (req, res) => {
  const db = loadDB();
  const code = 'JOY-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
  db.invites[code] = { used: false, used_by: null, created_at: Date.now() };
  saveDB(db);
  res.json({ invite: code });
});

app.delete('/api/admin/invite/:code', requireOwner, (req, res) => {
  const db = loadDB();
  const code = req.params.code.trim();
  if (db.invites[code]) {
    delete db.invites[code];
    saveDB(db);
    return res.json({ message: 'инвайт удален' });
  }
  res.status(404).json({ message: 'инвайт не найден' });
});

// 6. Промокоды
app.post('/api/admin/promo/create', requireOwner, (req, res) => {
  const { code, days, max_uses } = req.body;
  if (!code || !days) return res.status(400).json({ message: 'заполните код и дни' });

  const db = loadDB();
  const promoKey = code.trim().toUpperCase();

  db.promos[promoKey] = {
    code: promoKey,
    days: parseInt(days),
    max_uses: parseInt(max_uses) || 1,
    used_count: 0,
    users_activated: []
  };

  saveDB(db);
  res.json({ message: `промокод ${promoKey} создан` });
});

// 7. Загрузка бинарника
app.post('/api/admin/upload-build', requireOwner, (req, res) => {
  const { file_base64 } = req.body;
  if (!file_base64) return res.status(400).json({ message: 'файл не передан' });

  try {
    const base64Data = file_base64.replace(/^data:.*?;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    fs.writeFileSync(path.join(BUILDS_DIR, 'JoyLoader.exe'), buffer);
    res.json({ message: 'билд JoyLoader.exe сохранен на сервере' });
  } catch (err) {
    res.status(500).json({ message: 'ошибка записи файла' });
  }
});

// 8. Все тикеты для админки и ответ на них
app.get('/api/admin/tickets', requireOwner, (req, res) => {
  const db = loadDB();
  res.json({ tickets: db.tickets || [] });
});

app.post('/api/admin/ticket/reply', requireOwner, (req, res) => {
  const { ticket_id, reply_text } = req.body;
  const db = loadDB();
  const ticket = (db.tickets || []).find(t => t.id === ticket_id);

  if (!ticket) return res.status(404).json({ message: 'тикет не найден' });

  ticket.reply = reply_text.trim();
  ticket.status = 'ответ получен';
  saveDB(db);
  res.json({ message: 'ответ отправлен пользователю', ticket });
});

// === ОБНОВЛЕНИЯ ===
app.get('/api/updates', (req, res) => {
  const db = loadDB();
  res.json({ updates: db.updates || [] });
});

app.post('/api/updates', requireOwner, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните поля' });

  const db = loadDB();
  const item = {
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    author: req.adminUser.username,
    created_at: Date.now()
  };

  db.updates.unshift(item);
  saveDB(db);
  res.json({ update: item });
});

app.delete('/api/updates/:id', requireOwner, (req, res) => {
  const db = loadDB();
  const uId = parseInt(req.params.id);
  const idx = (db.updates || []).findIndex(u => u.id === uId);
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  db.updates.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
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
      author_role: authorUser.role || 'user',
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
    author_role: authorUser.role || 'user',
    author_avatar_media: authorUser.avatar_media || null,
    author_avatar_type: authorUser.avatar_type || null,
    author_avatar_color: authorUser.avatar_color || '#8b5cf6',
    posts: (thread.posts || []).map(p => {
      const pUser = db.users[p.author.toLowerCase()] || {};
      return {
        ...p,
        author_role: pUser.role || 'user',
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
  if (!user || user.banned) return res.status(403).json({ message: 'доступ заблокирован' });

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
  if (!user || user.banned) return res.status(403).json({ message: 'доступ заблокирован' });

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
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  if (db.threads[idx].author !== user.username && user.role !== 'owner') {
    return res.status(403).json({ message: 'нет прав' });
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
  if (!thread) return res.status(404).json({ message: 'не найдено' });

  const pIdx = (thread.posts || []).findIndex(p => p.id === pId);
  if (pIdx === -1) return res.status(404).json({ message: 'не найдено' });

  if (thread.posts[pIdx].author !== user.username && user.role !== 'owner') {
    return res.status(403).json({ message: 'нет прав' });
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
  if (!user || user.banned) return res.status(403).json({ message: 'доступ заблокирован' });

  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'заполните поля' });

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
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  db.tickets.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY.CC] Сервер активен на порту ${PORT}`);
});
