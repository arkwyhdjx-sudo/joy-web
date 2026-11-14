const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const bcrypt = require('bcryptjs');

const app = express();

const DB_FILE = path.join(__dirname, 'joy_db.json');
const BUILDS_DIR = path.join(__dirname, 'builds');

if (!fs.existsSync(BUILDS_DIR)) {
  fs.mkdirSync(BUILDS_DIR, { recursive: true });
}

// ============================================================
// ЗАЩИТА ОТ DDOS / ПЕРЕПОЛНЕНИЯ ПАМЯТИ И RATE LIMITER
// ============================================================
const rateLimits = new Map();
const bannedIps = new Map();

app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();

  if (bannedIps.has(ip)) {
    if (now < bannedIps.get(ip)) {
      return res.status(429).json({ error: 'rate_limited', message: 'IP временно заблокирован за спам запросами' });
    }
    bannedIps.delete(ip);
  }

  let record = rateLimits.get(ip);
  if (!record || now > record.resetTime) {
    record = { count: 0, resetTime: now + 5000 };
  }

  record.count++;
  rateLimits.set(ip, record);

  // Лимит: максимум 40 запросов за 5 секунд на один IP
  if (record.count > 40) {
    bannedIps.set(ip, now + 60000);
    return res.status(429).json({ error: 'rate_limited', message: 'Слишком много запросов. Подождите 1 минуту.' });
  }

  next();
});

// Безопасный лимит тела запроса: 15mb вместо 100mb
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use(express.static(__dirname));

// ============================================================
// БАЗА ДАННЫХ И МИГРАЦИЯ СТРУКТУРЫ
// ============================================================
function loadDB() {
  const defaultDB = {
    next_uid: 1,
    build_status: 'stable',
    tg_bot_token: '',
    tg_chat_id: '',
    users: {},
    sessions: {},
    invites: {
      'JOY-999-DEV': { used: false, used_by: null, created_at: Date.now() }
    },
    promos: {},
    promo_history: {},
    configs: [],
    scripts: [],
    item_subscriptions: {}, // key: `${itemId}_${username}` => expires_at
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

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultDB, null, 2));
    return defaultDB;
  }

  try {
    const raw = fs.readFileSync(DB_FILE, 'utf-8');
    const data = JSON.parse(raw);
    return { ...defaultDB, ...data };
  } catch (e) {
    console.error('Ошибка чтения БД, восстановление дефолта:', e);
    return defaultDB;
  }
}

function saveDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('Ошибка записи базы данных:', e);
  }
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
// CLOUDFLARE TURNSTILE PROOF-OF-WORK ДВИЖОК
// ============================================================
const POW_SECRET = crypto.randomBytes(32).toString('hex');
const verifiedIps = new Map();

app.get('/api/challenge', (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const ts = Date.now();
  const difficulty = 4;
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
  const ts = parseInt(parts[1], 10);
  const difficulty = parseInt(parts[2], 10);

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

app.use('/api', (req, res, next) => {
  if (req.path === '/challenge' || req.path === '/challenge/verify' || req.path.startsWith('/client/')) {
    return next();
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const expiresAt = verifiedIps.get(ip);

  if (!expiresAt || expiresAt < Date.now()) {
    return res.status(403).json({
      error: 'turnstile_required',
      message: 'требуется прохождение проверки браузера'
    });
  }

  next();
});

// ============================================================
// АВТОРИЗАЦИЯ И ПРОВЕРКА СЕССИЙ (БЕЗОПАСНЫЕ ТОКЕНЫ)
// ============================================================
function authUser(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const db = loadDB();
  const session = (db.sessions || {})[token];

  if (!session || session.expires_at < Date.now()) {
    return res.status(401).json({ message: 'сессия истекла' });
  }

  const user = db.users[session.username.toLowerCase()];
  if (!user) return res.status(401).json({ message: 'пользователь не найден' });

  if (user.banned) {
    return res.status(403).json({ message: `аккаунт заблокирован: ${user.ban_reason || 'бан'}`, banned: true });
  }

  req.user = user;
  req.sessionToken = token;
  next();
}

function requireOwner(req, res, next) {
  authUser(req, res, () => {
    const user = req.user;
    if (!user || (user.uid !== 1 && user.role !== 'owner' && user.username.toLowerCase() !== 'dev')) {
      return res.status(403).json({ message: 'доступ запрещен' });
    }
    req.adminUser = user;
    next();
  });
}

function safeUserObject(user) {
  const copy = { ...user };
  delete copy.password;
  delete copy.password_hash;
  return copy;
}

// ============================================================
// МАРШРУТЫ АККАУНТОВ И АВТОРИЗАЦИИ
// ============================================================
app.get('/api/verify-ip', (req, res) => {
  const db = loadDB();
  res.json({ status: 'ok', build_status: db.build_status });
});

app.post('/api/register', async (req, res) => {
  const { invite_code, username, password } = req.body;
  if (!invite_code || !username || !password) {
    return res.status(400).json({ message: 'заполните все поля' });
  }

  const db = loadDB();
  const cleanInvite = invite_code.trim();
  const inv = db.invites[cleanInvite];

  if (!inv || inv.used) {
    return res.status(400).json({ message: 'инвайт недействителен или уже использован' });
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
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

  // Хэширование пароля через bcrypt
  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(password, salt);

  db.users[userKey] = {
    uid: assignedUid,
    username: username.trim(),
    password_hash: password_hash,
    invite_code: cleanInvite,
    role: isOwner ? 'owner' : 'user',
    cookies: 0,
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

  // Генерация случайного токена сессии
  const token = crypto.randomBytes(32).toString('hex');
  if (!db.sessions) db.sessions = {};
  db.sessions[token] = {
    username: userKey,
    expires_at: Date.now() + (30 * 86400000)
  };

  saveDB(db);

  res.json({
    token: token,
    user: safeUserObject(db.users[userKey])
  });
});

app.post('/api/login', async (req, res) => {
  const { username, password, pin } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'введите логин и пароль' });
  }

  const db = loadDB();
  const userKey = username.trim().toLowerCase();
  const user = db.users[userKey];

  if (!user) {
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  // Проверка пароля (поддерживает и старый открытый, и новый bcrypt)
  let passwordMatch = false;
  if (user.password_hash) {
    passwordMatch = await bcrypt.compare(password, user.password_hash);
  } else if (user.password) {
    passwordMatch = (user.password === password);
    if (passwordMatch) {
      // Авто-миграция старого пароля в bcrypt
      user.password_hash = await bcrypt.hash(password, 10);
      delete user.password;
    }
  }

  if (!passwordMatch) {
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  if (user.banned) {
    return res.status(403).json({
      message: `аккаунт заблокирован: ${user.ban_reason || 'бан'}`,
      banned: true
    });
  }

  if (user.security_pin) {
    if (!pin) {
      return res.json({ require_pin: true, message: 'требуется ввод 2fa пин-кода' });
    }
    if (user.security_pin !== pin.trim()) {
      return res.status(403).json({ message: 'неверный 2fa пин-код' });
    }
  }

  user.web_ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

  const token = crypto.randomBytes(32).toString('hex');
  if (!db.sessions) db.sessions = {};
  db.sessions[token] = {
    username: userKey,
    expires_at: Date.now() + (30 * 86400000)
  };

  saveDB(db);

  res.json({
    token: token,
    user: safeUserObject(user),
    build_status: db.build_status
  });
});

app.get('/api/profile', authUser, (req, res) => {
  const db = loadDB();
  res.json({ user: safeUserObject(req.user), build_status: db.build_status });
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

app.post('/api/profile/update', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
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
  res.json({ message: 'профиль сохранен', user: safeUserObject(user) });
});

app.post('/api/user/set-pin', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  const { pin } = req.body;

  if (!pin || pin.length < 4 || pin.length > 8) {
    return res.status(400).json({ message: 'пин-код должен быть от 4 до 8 цифр' });
  }

  user.security_pin = pin.trim();
  saveDB(db);
  res.json({ message: 'персональный 2fa пин-код успешно установлен' });
});

app.post('/api/user/verify-pin', authUser, (req, res) => {
  const { pin } = req.body;
  if (!req.user.security_pin) {
    return res.json({ status: 'success', message: 'пин не задан' });
  }
  if (req.user.security_pin === pin?.trim()) {
    return res.json({ status: 'success', message: '2FA подтвержден' });
  }
  res.status(403).json({ status: 'error', message: 'неверный пин-код' });
});

app.post('/api/hwid/reset', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  user.hwid = null;
  saveDB(db);
  res.json({ message: 'hwid успешно сброшен' });
});

// ============================================================
// ВАЛЮТА COOKIES И РУЛЕТКА
// ============================================================

// Покупка cookies за рубли (1 cookie = 50 руб)
app.post('/api/cookies/buy', authUser, (req, res) => {
  const amount = parseInt(req.body.amount, 10);
  if (!amount || amount < 1 || amount > 500) {
    return res.status(400).json({ message: 'укажите количество от 1 до 500 cookies' });
  }

  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  user.cookies = (user.cookies || 0) + amount;

  const costRub = amount * 50;
  const payRecord = {
    id: 'PAY-CK-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
    username: user.username,
    user_uid: user.uid,
    amount: costRub,
    plan_days: 0,
    promo: `+${amount} cookies`,
    status: 'успешно',
    created_at: Date.now()
  };

  db.payments.unshift(payRecord);
  saveDB(db);

  sendTelegramNotification(`🍪 <b>Покупка Cookies JOY</b>\nПользователь: <b>${user.username}</b> [UID: ${user.uid}]\nКоличество: +${amount} 🍪\nСумма: ${costRub} ₽`);

  res.json({ message: `начислено +${amount} cookies!`, cookies: user.cookies });
});

// Прокрут рулетки: 1 cookie за спин
// Прокрут рулетки: ТОЛЬКО ПРИ НАЛИЧИИ АКТИВНОЙ ПОДПИСКИ
app.post('/api/roulette/spin', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];

  const now = Date.now();
  const hasActiveSub = user.sub_until === -1 || user.sub_until > now;

  if (!hasActiveSub) {
    return res.status(403).json({ message: 'рулетка доступна только пользователям с активной подпиской' });
  }

  if ((user.cookies || 0) < 1) {
    return res.status(400).json({ message: 'недостаточно cookies (требуется 1 cookie)' });
  }

  user.cookies -= 1;

  // Шансы: 1.5% на чит, 98.5% на cookies
  const roll = Math.random() * 100;
  let reward = {};

  if (roll < 0.2) {
    reward = { type: 'sub', value: 7, label: '7d sub', color: '#c084fc' };
  } else if (roll < 0.7) {
    reward = { type: 'sub', value: 3, label: '3d sub', color: '#a855f7' };
  } else if (roll < 1.5) {
    reward = { type: 'sub', value: 1, label: '1d sub', color: '#8b5cf6' };
  } else if (roll < 8.0) {
    reward = { type: 'cookies', value: 5, label: '5 cookies', color: '#e9d5ff' };
  } else if (roll < 30.0) {
    reward = { type: 'cookies', value: 3, label: '3 cookies', color: '#c4b5fd' };
  } else {
    reward = { type: 'cookies', value: 1, label: '1 cookie', color: '#a78bfa' };
  }

  if (reward.type === 'sub') {
    if (user.sub_until !== -1) {
      const ms = reward.value * 86400000;
      user.sub_until = (user.sub_until > now ? user.sub_until : now) + ms;
    }
  } else if (reward.type === 'cookies') {
    user.cookies = (user.cookies || 0) + reward.value;
  }

  saveDB(db);

  res.json({
    reward,
    cookies: user.cookies,
    sub_until: user.sub_until
  });
});

// Запрос на создание счёта/заявки на покупку cookies (для пользователей)
app.post('/api/cookies/invoice', authUser, (req, res) => {
  const { amount, method } = req.body;
  const count = parseInt(amount, 10);
  if (!count || count < 1 || count > 500) {
    return res.status(400).json({ message: 'неверное количество cookies' });
  }

  const costRub = count * 50;
  const invId = 'INV-' + crypto.randomBytes(3).toString('hex').toUpperCase();

  sendTelegramNotification(`🍪 <b>Заявка на Cookies JOY</b>\nПользователь: <b>${req.user.username}</b> [UID: ${req.user.uid}]\nКоличество: ${count} cookies\nСумма: ${costRub} ₽\nСпособ: ${method || 'tg_wallet'}`);

  res.json({
    invoice_id: invId,
    amount: count,
    cost_rub: costRub,
    message: 'заявка создана. после оплаты через бота или реселлера баланс зачислится автоматически'
  });
});

// ВЫДАЧА COOKIES СЕБЕ ИЛИ ДРУГИМ — ТОЛЬКО ДЛЯ OWNER
app.post('/api/admin/grant-cookies', requireOwner, (req, res) => {
  const { username, amount } = req.body;
  const db = loadDB();
  const target = db.users[(username || req.adminUser.username).toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  const val = parseInt(amount, 10);
  if (isNaN(val)) return res.status(400).json({ message: 'неверное число' });

  target.cookies = Math.max(0, (target.cookies || 0) + val);
  saveDB(db);

  res.json({ message: `пользователю ${target.username} установлено ${target.cookies} cookies`, cookies: target.cookies });
});
});

// ============================================================
// ПОКУПКА ЧИТА И ПРОМОКОДЫ
// ============================================================
app.post('/api/promo/validate', authUser, (req, res) => {
  const db = loadDB();
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
  if (promo.users_activated && promo.users_activated.includes(req.user.username.toLowerCase())) {
    return res.status(400).json({ message: 'вы уже использовали этот промокод' });
  }

  res.json({
    valid: true,
    code: promo.code,
    days: promo.days || 0,
    discount_percent: promo.discount_percent || 0,
    cookies: promo.cookies || 0
  });
});

app.post('/api/payment/checkout', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  const { plan_days, amount, promo_code } = req.body;
  const daysToAdd = parseInt(plan_days, 10) || 30;
  const cleanPromo = (promo_code || '').trim().toUpperCase();

  let promoBonusDays = 0;
  if (cleanPromo && db.promos[cleanPromo]) {
    const promo = db.promos[cleanPromo];
    const now = Date.now();
    if ((!promo.expires_at || promo.expires_at >= now) &&
        (promo.max_uses === 0 || promo.used_count < promo.max_uses) &&
        (!promo.users_activated || !promo.users_activated.includes(user.username.toLowerCase()))) {
      promoBonusDays = promo.days || 0;
      if (promo.cookies) {
        user.cookies = (user.cookies || 0) + promo.cookies;
      }
      promo.used_count++;
      if (!promo.users_activated) promo.users_activated = [];
      promo.users_activated.push(user.username.toLowerCase());
    }
  }

  const finalDays = daysToAdd + promoBonusDays;
  const now = Date.now();
  if (user.sub_until !== -1) {
    const msToAdd = finalDays * 86400000;
    user.sub_until = (user.sub_until > now ? user.sub_until : now) + msToAdd;
  }

  const paymentRecord = {
    id: 'PAY-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
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

  res.json({
    message: `подписка успешно активирована (+${finalDays} дн.)`,
    user: safeUserObject(user),
    payment: paymentRecord
  });
});

// ============================================================
// ОБЛАКО: КОНФИГИ И СКРИПТЫ (С ПОДПИСКОЙ ЗА COOKIES 0-10)
// ============================================================
app.get('/api/configs', authUser, (req, res) => {
  const db = loadDB();
  const userKey = req.user.username.toLowerCase();
  const now = Date.now();

  const list = (db.configs || []).filter(c => c.author.toLowerCase() === userKey || c.is_public).map(c => {
    const isAuthor = c.author.toLowerCase() === userKey || req.user.role === 'owner';
    const subKey = `${c.id}_${userKey}`;
    const subExpires = (db.item_subscriptions || {})[subKey] || 0;
    const isUnlocked = isAuthor || (c.price_cookies || 0) === 0 || subExpires > now;

    return {
      ...c,
      is_unlocked: isUnlocked,
      sub_until: subExpires,
      data: isUnlocked ? c.data : null // скрываем конфиг, если нет подписки
    };
  });

  res.json({ configs: list });
});

app.post('/api/configs/upload', authUser, (req, res) => {
  const db = loadDB();
  const { filename, file_data, is_public, price_cookies } = req.body;
  if (!filename || !file_data) return res.status(400).json({ message: 'выберите .cfg файл' });

  const cleanName = filename.replace(/\.cfg$/i, '').trim().slice(0, 32) + '.cfg';
  const price = Math.min(10, Math.max(0, parseInt(price_cookies, 10) || 0));

  const newConfig = {
    id: 'CFG-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
    name: cleanName,
    data: file_data,
    author: req.user.username,
    price_cookies: price,
    is_public: !!is_public,
    updated_at: Date.now()
  };

  db.configs.unshift(newConfig);
  saveDB(db);
  res.json({ message: 'конфиг загружен в облако', config: newConfig });
});

app.delete('/api/configs/:id', authUser, (req, res) => {
  const db = loadDB();
  const userKey = req.user.username.toLowerCase();
  const idx = (db.configs || []).findIndex(c => c.id === req.params.id && (c.author.toLowerCase() === userKey || req.user.role === 'owner'));

  if (idx === -1) return res.status(404).json({ message: 'конфиг не найден' });

  db.configs.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'конфиг удален' });
});

app.get('/api/scripts', authUser, (req, res) => {
  const db = loadDB();
  const userKey = req.user.username.toLowerCase();
  const now = Date.now();

  const list = (db.scripts || []).filter(s => s.author.toLowerCase() === userKey || s.is_public).map(s => {
    const isAuthor = s.author.toLowerCase() === userKey || req.user.role === 'owner';
    const subKey = `${s.id}_${userKey}`;
    const subExpires = (db.item_subscriptions || {})[subKey] || 0;
    const isUnlocked = isAuthor || (s.price_cookies || 0) === 0 || subExpires > now;

    return {
      ...s,
      is_unlocked: isUnlocked,
      sub_until: subExpires,
      code: isUnlocked ? s.code : '-- доступ заблокирован: требуется подписка за cookies'
    };
  });

  res.json({ scripts: list });
});

app.post('/api/scripts', authUser, (req, res) => {
  const db = loadDB();
  const { title, code, is_public, price_cookies } = req.body;
  if (!title || !code) return res.status(400).json({ message: 'заполните поля скрипта' });

  const price = Math.min(10, Math.max(0, parseInt(price_cookies, 10) || 0));

  const item = {
    id: Date.now(),
    title: title.trim().slice(0, 32),
    code: code.slice(0, 200000),
    author: req.user.username,
    price_cookies: price,
    is_public: !!is_public,
    enabled: true,
    updated_at: Date.now()
  };

  db.scripts.unshift(item);
  saveDB(db);
  res.json({ message: 'скрипт загружен', script: item });
});

app.post('/api/scripts/:id/toggle', authUser, (req, res) => {
  const db = loadDB();
  const userKey = req.user.username.toLowerCase();
  const s = (db.scripts || []).find(x => x.id === parseInt(req.params.id, 10) && x.author.toLowerCase() === userKey);
  if (!s) return res.status(404).json({ message: 'не найден' });

  s.enabled = !s.enabled;
  saveDB(db);
  res.json({ enabled: s.enabled });
});

app.delete('/api/scripts/:id', authUser, (req, res) => {
  const db = loadDB();
  const userKey = req.user.username.toLowerCase();
  const idx = (db.scripts || []).findIndex(x => x.id === parseInt(req.params.id, 10) && (x.author.toLowerCase() === userKey || req.user.role === 'owner'));
  if (idx === -1) return res.status(404).json({ message: 'не найден' });

  db.scripts.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'скрипт удален' });
});

// Покупка доступа к Lua или CFG на 30 дней за cookies
app.post('/api/cloud/subscribe', authUser, (req, res) => {
  const { item_id, item_type } = req.body;
  const db = loadDB();
  const buyer = db.users[req.user.username.toLowerCase()];

  let item = null;
  if (item_type === 'config') {
    item = (db.configs || []).find(c => c.id === item_id);
  } else {
    item = (db.scripts || []).find(s => s.id === parseInt(item_id, 10));
  }

  if (!item) return res.status(404).json({ message: 'товар не найден' });
  if (item.author.toLowerCase() === buyer.username.toLowerCase()) {
    return res.status(400).json({ message: 'вы автор данного товара' });
  }

  const price = item.price_cookies || 0;
  if ((buyer.cookies || 0) < price) {
    return res.status(400).json({ message: `недостаточно cookies (нужно ${price} 🍪)` });
  }

  buyer.cookies -= price;

  const author = db.users[item.author.toLowerCase()];
  if (author) {
    author.cookies = (author.cookies || 0) + price;
  }

  if (!db.item_subscriptions) db.item_subscriptions = {};
  const subKey = `${item.id}_${buyer.username.toLowerCase()}`;
  const now = Date.now();
  const currentExp = db.item_subscriptions[subKey] || 0;
  const base = currentExp > now ? currentExp : now;
  db.item_subscriptions[subKey] = base + (30 * 86400000);

  saveDB(db);

  res.json({
    message: `доступ к ${item.name || item.title} продлен на 30 дней!`,
    cookies: buyer.cookies
  });
});

// ============================================================
// СКАЧИВАНИЕ ЛАУНЧЕРА И КЛИЕНТСКИЙ API
// ============================================================
app.get('/api/download-loader', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).send('доступ запрещен');

  const db = loadDB();
  const session = (db.sessions || {})[token];
  if (!session || session.expires_at < Date.now()) return res.status(401).send('сессия истекла');

  const user = db.users[session.username.toLowerCase()];
  if (!user || user.banned) return res.status(403).send('аккаунт заблокирован');

  const realLoader = path.join(BUILDS_DIR, 'JoyLoader.exe');
  if (fs.existsSync(realLoader)) {
    return res.download(realLoader, 'JoyLoader.exe');
  }

  const tempPath = path.join(__dirname, 'JoyLoader_stub.exe');
  if (!fs.existsSync(tempPath)) {
    fs.writeFileSync(tempPath, 'JOY.VIP CLIENT BUILD STUB');
  }
  res.download(tempPath, 'JoyLoader.exe');
});

app.post('/api/client/auth', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) {
    return res.status(400).json({ status: 'error', message: 'неверные параметры запроса' });
  }

  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];
  if (!user) {
    return res.status(401).json({ status: 'error', message: 'неверные данные входа' });
  }

  let passOk = false;
  if (user.password_hash) {
    passOk = await bcrypt.compare(password, user.password_hash);
  } else if (user.password) {
    passOk = (user.password === password);
  }

  if (!passOk) {
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

  user.client_ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
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

// ============================================================
// ФОРУМ, ТИКЕТЫ И ОБНОВЛЕНИЯ
// ============================================================
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
  const thread = db.threads.find(t => t.id === parseInt(req.params.id, 10));
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

app.post('/api/forum/threads', authUser, (req, res) => {
  const db = loadDB();
  const user = req.user;
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

app.post('/api/forum/threads/:id/reply', authUser, (req, res) => {
  const db = loadDB();
  const user = req.user;
  const thread = db.threads.find(t => t.id === parseInt(req.params.id, 10));
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
  const thread = db.threads.find(t => t.id === parseInt(req.params.id, 10));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  if (typeof pinned === 'boolean') thread.pinned = pinned;
  if (typeof locked === 'boolean') thread.locked = locked;

  saveDB(db);
  res.json({ message: 'статус темы обновлен', thread });
});

app.delete('/api/forum/threads/:id', authUser, (req, res) => {
  const db = loadDB();
  const tId = parseInt(req.params.id, 10);
  const idx = db.threads.findIndex(t => t.id === tId);
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  if (db.threads[idx].author !== req.user.username && req.user.role !== 'owner') {
    return res.status(403).json({ message: 'нет прав' });
  }

  db.threads.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'тема удалена' });
});

app.delete('/api/forum/threads/:id/post/:postId', authUser, (req, res) => {
  const db = loadDB();
  const tId = parseInt(req.params.id, 10);
  const pId = parseInt(req.params.postId, 10);
  const thread = db.threads.find(t => t.id === tId);
  if (!thread) return res.status(404).json({ message: 'не найдено' });

  const pIdx = (thread.posts || []).findIndex(p => p.id === pId);
  if (pIdx === -1) return res.status(404).json({ message: 'не найдено' });

  if (thread.posts[pIdx].author !== req.user.username && req.user.role !== 'owner') {
    return res.status(403).json({ message: 'нет прав' });
  }

  thread.posts.splice(pIdx, 1);
  saveDB(db);
  res.json({ message: 'сообщение удалено' });
});

app.post('/api/support/ticket', authUser, (req, res) => {
  const db = loadDB();
  const user = req.user;
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'заполните поля' });

  const ticket = {
    id: 'TICK-' + Math.floor(1000 + Math.random() * 9000),
    userKey: user.username.toLowerCase(),
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

  sendTelegramNotification(`🚨 <b>Новый тикет JOY</b>\n\n<b>От:</b> ${user.username} [UID: ${user.uid}]\n<b>Тема:</b> ${ticket.subject}\n<b>Сообщение:</b> ${ticket.message}`);
  res.json({ message: 'обращение отправлено', ticket });
});

app.get('/api/support/my-tickets', authUser, (req, res) => {
  const db = loadDB();
  const myTickets = (db.tickets || []).filter(t => t.userKey === req.user.username.toLowerCase());
  res.json({ tickets: myTickets });
});

app.delete('/api/support/ticket/:id', authUser, (req, res) => {
  const db = loadDB();
  const idx = (db.tickets || []).findIndex(t => t.id === req.params.id && (t.userKey === req.user.username.toLowerCase() || req.user.role === 'owner'));
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });

  db.tickets.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
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
  const idx = (db.updates || []).findIndex(u => u.id === parseInt(req.params.id, 10));
  if (idx !== -1) {
    db.updates.splice(idx, 1);
    saveDB(db);
  }
  res.json({ message: 'удалено' });
});

// ============================================================
// АДМИНИСТРАТИВНАЯ ПАНЕЛЬ (ПОЛНЫЙ ДОСТУП)
// ============================================================
app.post('/api/admin/self-lifetime', requireOwner, (req, res) => {
  const db = loadDB();
  const user = db.users[req.adminUser.username.toLowerCase()];
  user.sub_until = -1;
  user.role = 'owner';
  saveDB(db);
  res.json({ message: 'вам выдана lifetime сабка и роль owner', user: safeUserObject(user) });
});

app.get('/api/admin/users', requireOwner, (req, res) => {
  const db = loadDB();
  const list = Object.values(db.users).map(u => {
    const isOwner = (u.uid === 1 || u.username.toLowerCase() === 'dev');
    return {
      uid: u.uid,
      username: u.username,
      role: u.role || 'user',
      cookies: u.cookies || 0,
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
  res.json({ target: safeUserObject(target) });
});

app.post('/api/admin/user/update', requireOwner, (req, res) => {
  const { username, role, uid, cookies, sub_mode, reset_hwid, banned, ban_reason } = req.body;
  const db = loadDB();
  const target = db.users[username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });

  if (role) target.role = role;
  if (uid && !isNaN(parseInt(uid, 10))) target.uid = parseInt(uid, 10);
  if (cookies !== undefined && !isNaN(parseInt(cookies, 10))) target.cookies = parseInt(cookies, 10);

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
  res.json({ message: `аккаунт ${target.username} обновлен`, target: safeUserObject(target) });
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

app.get('/api/admin/payments', requireOwner, (req, res) => {
  const db = loadDB();
  res.json({ payments: db.payments || [] });
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
  const { code, days, discount_percent, cookies, max_uses, duration_hours } = req.body;
  if (!code || (!days && !discount_percent && !cookies)) {
    return res.status(400).json({ message: 'укажите код и дни, скидку или cookies' });
  }

  const db = loadDB();
  const promoKey = code.trim().toUpperCase();

  const hours = parseFloat(duration_hours);
  const expiresAt = (hours && hours > 0) ? (Date.now() + Math.round(hours * 3600 * 1000)) : null;
  const uses = parseInt(max_uses, 10);

  db.promos[promoKey] = {
    code: promoKey,
    days: parseInt(days, 10) || 0,
    cookies: parseInt(cookies, 10) || 0,
    discount_percent: Math.min(100, Math.max(0, parseInt(discount_percent, 10) || 0)),
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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY] Сервер активен на порту ${PORT}`);
});
