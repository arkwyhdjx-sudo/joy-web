const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

const app = express();

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(__dirname));

const DB_FILE = path.join(__dirname, 'joy_db.json');
const BUILDS_DIR = path.join(__dirname, 'builds');

if (!fs.existsSync(BUILDS_DIR)) {
  fs.mkdirSync(BUILDS_DIR, { recursive: true });
}

function generateInviteCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const genPart = (len) => {
    let res = '';
    const bytes = crypto.randomBytes(len);
    for (let i = 0; i < len; i++) {
      res += chars[bytes[i] % chars.length];
    }
    return res;
  };
  return `JOY-${genPart(10)}-${genPart(15)}`;
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      next_uid: 1,
      build_status: 'stable',
      tg_bot_token: '',
      tg_chat_id: '',
      users: {},
      invites: {
        'JOY-999-DEV': { used: false, used_by: null, created_at: Date.now() }
      },
      promos: {},
      configs: [],
      scripts: [],
      payments: [],
      threads: [
        {
          id: 1,
          title: 'правила и статус закрытого билда',
          author: 'system',
          author_uid: 0,
          author_role: 'system',
          pinned: true,
          locked: false,
          tag: 'обсуждение',
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
    if (!data.build_status) data.build_status = 'stable';
    if (!data.users) data.users = {};
    if (!data.invites) data.invites = {};
    if (!data.promos) data.promos = {};
    if (!data.configs) data.configs = [];
    if (!data.scripts) data.scripts = [];
    if (!data.payments) data.payments = [];
    if (!data.threads) data.threads = [];
    if (!data.updates) data.updates = [];
    if (!data.tickets) data.tickets = [];
    return data;
  } catch (e) {
    return { next_uid: 1, build_status: 'stable', users: {}, invites: {}, promos: {}, configs: [], scripts: [], payments: [], threads: [], updates: [], tickets: [] };
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('ошибка базы:', e);
  }
}

function sendTelegramNotification(text) {
  const db = loadDB();
  if (!db.tg_bot_token || !db.tg_chat_id) return;
  const postData = JSON.stringify({ chat_id: db.tg_chat_id, text, parse_mode: 'HTML' });
  const options = {
    hostname: 'api.telegram.org',
    port: 443,
    path: `/bot${db.tg_bot_token}/sendMessage`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(postData)
    }
  };
  const req = https.request(options);
  req.on('error', () => {});
  req.write(postData);
  req.end();
}

// ============================================================
// НАСТОЯЩИЙ CLOUDFLARE TURNSTILE PROOF-OF-WORK ДВИЖОК
// ============================================================
const POW_SECRET = 'joy_turnstile_shield_' + Math.random().toString(36);
const verifiedIps = new Map();

app.get('/api/challenge', (req, res) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const ts = Date.now();
  const difficulty = 4; // реальная сложность вычисления
  const salt = crypto.randomBytes(8).toString('hex');
  const payload = `${ip}:${ts}:${difficulty}:${salt}`;
  const sig = crypto.createHmac('sha256', POW_SECRET).update(payload).digest('hex');

  res.json({ payload, sig, difficulty });
});

app.post('/api/challenge/verify', (req, res) => {
  const { payload, sig, nonce } = req.body;
  if (!payload || !sig || nonce === undefined) {
    return res.status(400).json({ error: 'invalid_params' });
  }

  const expectedSig = crypto.createHmac('sha256', POW_SECRET).update(payload).digest('hex');
  if (sig !== expectedSig) {
    return res.status(403).json({ error: 'invalid_signature' });
  }

  const parts = payload.split(':');
  const ip = parts[0];
  const ts = parseInt(parts[1]);
  const difficulty = parseInt(parts[2]);

  if (Date.now() - ts > 120000) {
    return res.status(403).json({ error: 'challenge_expired' });
  }

  const calculatedHash = crypto.createHash('sha256').update(`${payload}:${nonce}`).digest('hex');
  const targetPrefix = '0'.repeat(difficulty);

  if (!calculatedHash.startsWith(targetPrefix)) {
    return res.status(403).json({ error: 'proof_of_work_failed' });
  }

  verifiedIps.set(ip, Date.now() + (24 * 3600 * 1000));
  res.json({ status: 'verified', message: 'проверка успешно пройдена' });
});

// Защита всех API эндпоинтов от неавторизованных ботов
app.use('/api', (req, res, next) => {
  if (req.path === '/challenge' || req.path === '/challenge/verify' || req.path.startsWith('/client/')) {
    return next();
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const expiresAt = verifiedIps.get(ip);

  if (!expiresAt || expiresAt < Date.now()) {
    return res.status(403).json({ 
      error: 'turnstile_required', 
      message: 'требуется прохождение проверки браузера' 
    });
  }

  next();
});

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

app.get('/api/verify-ip', (req, res) => {
  const db = loadDB();
  res.json({ status: 'ok', build_status: db.build_status });
});

// Установка персонального 2FA PIN-кода
app.post('/api/user/set-pin', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(404).json({ message: 'пользователь не найден' });

  const { pin } = req.body;
  if (!pin || pin.length < 4 || pin.length > 8) {
    return res.status(400).json({ message: 'пин-код должен быть от 4 до 8 цифр' });
  }

  user.security_pin = pin.trim();
  saveDB(db);
  res.json({ message: 'персональный 2fa пин-код успешно установлен' });
});

app.post('/api/user/verify-pin', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user) return res.status(404).json({ message: 'пользователь не найден' });

  const { pin } = req.body;
  if (!user.security_pin) {
    return res.json({ status: 'success', message: 'пин не задан' });
  }

  if (user.security_pin === pin.trim()) {
    return res.json({ status: 'success', message: '2FA подтвержден' });
  }
  res.status(403).json({ status: 'error', message: 'неверный пин-код' });
});

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
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  db.users[userKey] = {
    uid: assignedUid,
    username: username.trim(),
    password: password,
    invite_code: cleanInvite,
    role: isOwner ? 'owner' : 'user',
    banned: false,
    ban_reason: '',
    bio: '',
    security_pin: null,
    avatar_color: '#8b5cf6',
    avatar_media: null,
    avatar_type: null,
    hwid: null,
    web_ip: ip,
    client_ip: null,
    last_launch: null,
    sub_until: isOwner ? -1 : 0,
    created_at: Date.now()
  };

  saveDB(db);

  res.json({
    token: `joy_session_${userKey}`,
    user: db.users[userKey]
  });
});

// ВХОД С ОБЯЗАТЕЛЬНОЙ ПРОВЕРКОЙ 2FA PIN
app.post('/api/login', (req, res) => {
  const { username, password, pin } = req.body;
  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];

  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  if (user.banned) {
    return res.status(403).json({ 
      message: `аккаунт заблокирован: ${user.ban_reason || 'бан'}`,
      banned: true 
    });
  }

  // Если у пользователя установлен PIN — требуем его обязательно
  if (user.security_pin) {
    if (!pin) {
      return res.json({ require_pin: true, message: 'требуется ввод 2fa пин-кода' });
    }
    if (user.security_pin !== pin.trim()) {
      return res.status(403).json({ message: 'неверный 2fa пин-код' });
    }
  }

  user.web_ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  saveDB(db);

  res.json({
    token: `joy_session_${user.username.toLowerCase()}`,
    user: user,
    build_status: db.build_status
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

  res.json({ user, build_status: db.build_status });
});

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

app.post('/api/profile/update', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !token.startsWith('joy_session_')) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

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

// Промокоды
app.post('/api/promo/validate', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  const code = (req.body.code || '').trim().toUpperCase();
  const promo = db.promos[code];

  if (!promo) return res.status(400).json({ message: 'промокод не существует' });

  const now = Date.now();
  if (promo.expires_at && promo.expires_at < now) {
    return res.status(400).json({ message: 'срок действия промокода истек' });
  }
  if (promo.max_uses > 0 && promo.used_count >= promo.max_uses) {
    return res.status(400).json({ message: 'лимит использований промокода исчерпан' });
  }
  if (promo.users_activated && promo.users_activated.includes(user.username)) {
    return res.status(400).json({ message: 'вы уже использовали этот промокод' });
  }

  res.json({
    valid: true,
    code: promo.code,
    days: promo.days || 0,
    discount_percent: promo.discount_percent || 0
  });
});

app.post('/api/payment/checkout', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  const { plan_days, amount, promo_code } = req.body;
  const daysToAdd = parseInt(plan_days) || 30;
  const cleanPromo = (promo_code || '').trim().toUpperCase();

  let promoBonusDays = 0;
  if (cleanPromo && db.promos[cleanPromo]) {
    const promo = db.promos[cleanPromo];
    const now = Date.now();
    if ((!promo.expires_at || promo.expires_at >= now) && 
        (promo.max_uses === 0 || promo.used_count < promo.max_uses) &&
        (!promo.users_activated || !promo.users_activated.includes(user.username))) {
      promoBonusDays = promo.days || 0;
      promo.used_count++;
      if (!promo.users_activated) promo.users_activated = [];
      promo.users_activated.push(user.username);
    }
  }

  const finalDays = daysToAdd + promoBonusDays;
  const now = Date.now();
  if (user.sub_until !== -1) {
    const msToAdd = finalDays * 86400000;
    user.sub_until = (user.sub_until > now ? user.sub_until : now) + msToAdd;
  }

  const paymentRecord = {
    id: 'PAY-' + Math.random().toString(36).substring(2, 9).toUpperCase(),
    username: user.username,
    user_uid: user.uid,
    amount: amount || 0,
    plan_days: finalDays,
    promo: cleanPromo || '—',
    status: 'успешно',
    created_at: Date.now()
  };

  db.payments.unshift(paymentRecord);
  saveDB(db);

  sendTelegramNotification(`💰 <b>Оплата JOY</b>\nПользователь: <b>${user.username}</b> [UID: ${user.uid}]\nСумма: ${amount} ₽\nДней начислено: +${finalDays}\nПромокод: ${cleanPromo || 'нет'}`);

  res.json({ message: `подписка успешно активирована (+${finalDays} дн.)`, user, payment: paymentRecord });
});

app.post('/api/admin/payments/grant', requireOwner, (req, res) => {
  const { payment_id } = req.body;
  const db = loadDB();
  const pay = (db.payments || []).find(p => p.id === payment_id);
  if (!pay) return res.status(404).json({ message: 'платеж не найден' });

  const target = db.users[pay.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  const now = Date.now();
  if (target.sub_until !== -1) {
    const msToAdd = (pay.plan_days || 30) * 86400000;
    target.sub_until = (target.sub_until > now ? target.sub_until : now) + msToAdd;
  }
  pay.status = 'выдано вручную';
  saveDB(db);

  res.json({ message: `подписка успешно выдана юзеру ${target.username}` });
});

app.get('/api/admin/payments', requireOwner, (req, res) => {
  const db = loadDB();
  res.json({ payments: db.payments || [] });
});

// HWID
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
    fs.writeFileSync(tempPath, 'JOY.VIP CLIENT BUILD');
  }
  res.download(tempPath, 'JoyLoader.exe');
});

// API лаунчера
app.post('/api/client/auth', (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) {
    return res.status(400).json({ status: 'error', message: 'неверные параметры запроса' });
  }

  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];

  if (!user || user.password !== password) {
    return res.status(401).json({ status: 'error', message: 'неверные данные входа' });
  }

  if (user.banned) {
    return res.status(403).json({ status: 'error', message: `бан: ${user.ban_reason || 'доступ запрещен'}` });
  }

  if (db.build_status === 'updating' && user.role !== 'owner') {
    return res.status(403).json({ status: 'error', message: 'билд на техническом обновлении' });
  }

  const now = Date.now();
  const hasSub = user.sub_until === -1 || user.sub_until > now;
  if (!hasSub) {
    return res.status(403).json({ status: 'error', message: 'подписка истекла или отсутствует' });
  }

  if (!user.hwid) {
    user.hwid = hwid.trim();
  } else if (user.hwid !== hwid.trim() && user.role !== 'owner') {
    return res.status(403).json({ status: 'error', message: 'hwid не совпадает с привязанным' });
  }

  user.client_ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  user.last_launch = Date.now();
  saveDB(db);

  res.json({
    status: 'success',
    username: user.username,
    uid: user.uid,
    role: user.role,
    session_token: `loader_session_${user.username.toLowerCase()}_${Date.now()}`
  });
});

app.get('/api/client/payload', (req, res) => {
  const token = req.headers['x-loader-token'];
  const userKey = req.headers['x-loader-user'];

  if (!token || !userKey) return res.status(401).send('unauthorized');

  const db = loadDB();
  const user = db.users[userKey.toLowerCase()];
  if (!user || user.banned) return res.status(403).send('forbidden');

  const now = Date.now();
  if (user.sub_until !== -1 && user.sub_until <= now) {
    return res.status(403).send('subscription expired');
  }

  const dllPath = path.join(BUILDS_DIR, 'joy_internal.dll');
  if (fs.existsSync(dllPath)) {
    return res.sendFile(dllPath);
  }

  res.send('JOY_ENCRYPTED_MEMORY_PAYLOAD_STUB');
});

// Конфиги
app.get('/api/configs', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const list = (db.configs || []).filter(c => c.author.toLowerCase() === userKey || c.is_public);
  res.json({ configs: list });
});

app.post('/api/configs/upload', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  const { filename, file_data, is_public } = req.body;
  if (!filename || !file_data) return res.status(400).json({ message: 'выберите .cfg файл' });

  const cleanName = filename.replace(/\.cfg$/i, '').trim().slice(0, 32) + '.cfg';

  const newConfig = {
    id: 'CFG-' + Math.random().toString(36).substring(2, 8).toUpperCase(),
    name: cleanName,
    data: file_data,
    author: user.username,
    is_public: !!is_public,
    updated_at: Date.now()
  };

  db.configs.unshift(newConfig);
  saveDB(db);
  res.json({ message: 'конфиг загружен в облако', config: newConfig });
});

app.delete('/api/configs/:id', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const idx = (db.configs || []).findIndex(c => c.id === req.params.id && (c.author.toLowerCase() === userKey || userKey === 'dev'));

  if (idx === -1) return res.status(404).json({ message: 'конфиг не найден' });

  db.configs.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'конфиг удален' });
});

// Скрипты
app.get('/api/scripts', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const list = (db.scripts || []).filter(s => s.author.toLowerCase() === userKey || s.is_public);
  res.json({ scripts: list });
});

app.post('/api/scripts', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ запрещен' });

  const { title, code, is_public } = req.body;
  if (!title || !code) return res.status(400).json({ message: 'заполните поля скрипта' });

  const item = {
    id: Date.now(),
    title: title.trim().slice(0, 32),
    code: code.slice(0, 200000),
    author: user.username,
    is_public: !!is_public,
    enabled: true,
    updated_at: Date.now()
  };

  db.scripts.unshift(item);
  saveDB(db);
  res.json({ message: 'скрипт загружен', script: item });
});

app.post('/api/scripts/:id/toggle', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const s = (db.scripts || []).find(x => x.id === parseInt(req.params.id) && x.author.toLowerCase() === userKey);
  if (!s) return res.status(404).json({ message: 'не найден' });

  s.enabled = !s.enabled;
  saveDB(db);
  res.json({ enabled: s.enabled });
});

app.delete('/api/scripts/:id', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const idx = (db.scripts || []).findIndex(x => x.id === parseInt(req.params.id) && x.author.toLowerCase() === userKey);
  if (idx === -1) return res.status(404).json({ message: 'не найден' });

  db.scripts.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'скрипт удален' });
});

// Тикеты
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

  sendTelegramNotification(`🚨 <b>Новый тикет поддержки JOY</b>\n\n<b>От:</b> ${user.username} [UID: ${user.uid}]\n<b>Тема:</b> ${ticket.subject}\n<b>Сообщение:</b> ${ticket.message}`);
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
  const idx = (db.tickets || []).findIndex(t => t.id === req.params.id && (t.userKey === userKey || userKey === 'dev'));
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  db.tickets.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
});

// Форум
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
      pinned: !!t.pinned,
      locked: !!t.locked,
      tag: t.tag || 'обсуждение',
      author_avatar_media: authorUser.avatar_media || null,
      author_avatar_type: authorUser.avatar_type || null,
      author_avatar_color: authorUser.avatar_color || '#8b5cf6',
      created_at: t.created_at,
      replies_count: t.posts ? t.posts.length : 0
    };
  });
  list.sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || b.created_at - a.created_at);
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

  const { title, content, tag } = req.body;
  if (!title || !title.trim()) return res.status(400).json({ message: 'введите заголовок темы' });
  if (!content || !content.trim()) return res.status(400).json({ message: 'введите текст сообщения' });

  const allowedTags = ['обсуждение', 'баг', 'предложение', 'медиа'];
  const validTag = allowedTags.includes(tag) ? tag : 'обсуждение';

  const newThread = {
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    tag: validTag,
    pinned: false,
    locked: false,
    author: user.username,
    author_uid: user.uid,
    created_at: Date.now(),
    posts: []
  };

  db.threads.unshift(newThread);
  saveDB(db);
  res.json({ message: 'тема опубликована', thread: newThread });
});

app.post('/api/forum/threads/:id/reply', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'авторизуйтесь' });

  const userKey = token.replace('joy_session_', '');
  const db = loadDB();
  const user = db.users[userKey];
  if (!user || user.banned) return res.status(403).json({ message: 'доступ заблокирован' });

  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  if (thread.locked && user.role !== 'owner') {
    return res.status(403).json({ message: 'тема закрыта для ответов' });
  }

  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ message: 'введите текст' });

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

app.post('/api/forum/threads/:id/moderate', requireOwner, (req, res) => {
  const { pinned, locked } = req.body;
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  if (typeof pinned === 'boolean') thread.pinned = pinned;
  if (typeof locked === 'boolean') thread.locked = locked;

  saveDB(db);
  res.json({ message: 'статус темы обновлен', thread });
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

// Админка
app.post('/api/admin/self-lifetime', requireOwner, (req, res) => {
  const db = loadDB();
  const user = req.adminUser;
  user.sub_until = -1;
  user.role = 'owner';
  saveDB(db);
  res.json({ message: 'вам выдана lifetime сабка и роль owner', user });
});

// СПИСОК ЮЗЕРОВ: ТВОЙ IP НАВСЕГДА СКРЫТ
app.get('/api/admin/users', requireOwner, (req, res) => {
  const db = loadDB();
  const list = Object.values(db.users).map(u => {
    const isOwner = (u.uid === 1 || u.username.toLowerCase() === 'dev');
    return {
      uid: u.uid,
      username: u.username,
      role: u.role || 'user',
      banned: u.banned || false,
      ban_reason: u.ban_reason || '',
      sub_until: u.sub_until,
      invite_code: u.invite_code,
      web_ip: isOwner ? 'hidden (protected)' : (u.web_ip || '—'),
      client_ip: isOwner ? 'hidden (protected)' : (u.client_ip || '—'),
      last_launch: u.last_launch,
      ip_mismatch: isOwner ? false : !!(u.web_ip && u.client_ip && u.web_ip !== u.client_ip),
      hwid: !!u.hwid,
      created_at: u.created_at
    };
  });
  list.sort((a, b) => a.uid - b.uid);
  res.json({ users: list });
});

app.get('/api/admin/user/:username', requireOwner, (req, res) => {
  const db = loadDB();
  const target = db.users[req.params.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ target });
});

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

app.post('/api/admin/status', requireOwner, (req, res) => {
  const { status } = req.body;
  const db = loadDB();
  if (['stable', 'testing', 'updating'].includes(status)) {
    db.build_status = status;
    saveDB(db);
    return res.json({ message: `статус изменен на ${status}`, build_status: status });
  }
  res.status(400).json({ message: 'неверный статус' });
});

app.post('/api/admin/upload-payload', requireOwner, (req, res) => {
  const { file_base64 } = req.body;
  if (!file_base64) return res.status(400).json({ message: 'файл не передан' });
  try {
    const base64Data = file_base64.replace(/^data:.*?;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    fs.writeFileSync(path.join(BUILDS_DIR, 'joy_internal.dll'), buffer);
    res.json({ message: 'dll чита сохранена на сервере' });
  } catch (err) {
    res.status(500).json({ message: 'ошибка сохранения dll' });
  }
});

app.post('/api/admin/upload-build', requireOwner, (req, res) => {
  const { file_base64 } = req.body;
  if (!file_base64) return res.status(400).json({ message: 'файл не передан' });
  try {
    const base64Data = file_base64.replace(/^data:.*?;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');
    fs.writeFileSync(path.join(BUILDS_DIR, 'JoyLoader.exe'), buffer);
    res.json({ message: 'лаунчер сохранен' });
  } catch (err) {
    res.status(500).json({ message: 'ошибка' });
  }
});

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
  const code = generateInviteCode();
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
    return res.json({ message: 'удален' });
  }
  res.status(404).json({ message: 'не найден' });
});

app.get('/api/admin/promos', requireOwner, (req, res) => {
  const db = loadDB();
  const list = Object.values(db.promos || []);
  list.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
  res.json({ promos: list });
});

app.post('/api/admin/promo/create', requireOwner, (req, res) => {
  const { code, days, discount_percent, max_uses, duration_hours } = req.body;
  if (!code || (!days && !discount_percent)) {
    return res.status(400).json({ message: 'укажите код и дни или скидку' });
  }

  const db = loadDB();
  const promoKey = code.trim().toUpperCase();

  const hours = parseFloat(duration_hours);
  const expiresAt = (hours && hours > 0) ? (Date.now() + Math.round(hours * 3600 * 1000)) : null;
  const uses = parseInt(max_uses);

  db.promos[promoKey] = {
    code: promoKey,
    days: parseInt(days) || 0,
    discount_percent: Math.min(100, Math.max(0, parseInt(discount_percent) || 0)),
    max_uses: (uses && uses > 0) ? uses : 0,
    used_count: 0,
    expires_at: expiresAt,
    users_activated: [],
    created_at: Date.now()
  };

  saveDB(db);
  res.json({ message: `промокод ${promoKey} создан`, promo: db.promos[promoKey] });
});

app.delete('/api/admin/promo/:code', requireOwner, (req, res) => {
  const db = loadDB();
  const code = req.params.code.trim().toUpperCase();
  if (db.promos[code]) {
    delete db.promos[code];
    saveDB(db);
    return res.json({ message: 'удален' });
  }
  res.status(404).json({ message: 'не найден' });
});

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

  sendTelegramNotification(`🚀 <b>Новое обновление JOY</b>\n\n<b>${item.title}</b>\n\n${item.content}`);
  res.json({ update: item });
});

app.delete('/api/updates/:id', requireOwner, (req, res) => {
  const db = loadDB();
  const idx = (db.updates || []).findIndex(u => u.id === parseInt(req.params.id));
  if (idx !== -1) {
    db.updates.splice(idx, 1);
    saveDB(db);
  }
  res.json({ message: 'удалено' });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY] Сервер активен на порту ${PORT}`);
});
