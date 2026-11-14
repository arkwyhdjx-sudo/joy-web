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

// In-Memory Rate Limiter
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

  if (record.count > 45) {
    bannedIps.set(ip, now + 60000);
    return res.status(429).json({ error: 'rate_limited', message: 'Слишком много запросов. Подождите 1 минуту.' });
  }

  next();
});

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use(express.static(__dirname));

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
    resellers: [
      { id: 'res_1', name: 'Official Telegram Store', link: 'https://t.me/joy_support', region: 'CIS / Global' },
      { id: 'res_2', name: 'EU Crypto Reseller', link: 'https://t.me/joy_support', region: 'Global / Crypto' }
    ],
    feature_suggestions: [
      { id: 1, title: 'Grenade Prediction Helper', author: 'dev', votes: ['dev'], created_at: Date.now() }
    ],
    promos: {},
    configs: [],
    scripts: [],
    item_subscriptions: {},
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

function sendTelegramNotification(text) {
  const db = loadDB();
  if (!db.tg_bot_token || !db.tg_chat_id) return;
  const postData = JSON.stringify({ chat_id: db.tg_chat_id, text, parse_mode: 'HTML' });
  const req = https.request({
    hostname: 'api.telegram.org',
    port: 443,
    path: `/bot${db.tg_bot_token}/sendMessage`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postData) }
  });
  req.on('error', () => {});
  req.write(postData);
  req.end();
}

// PoW Shield
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
  if (!payload || !sig || nonce === undefined) return res.status(400).json({ error: 'invalid_params' });

  const expectedSig = crypto.createHmac('sha256', POW_SECRET).update(payload).digest('hex');
  if (sig !== expectedSig) return res.status(403).json({ error: 'invalid_signature' });

  const [ip, ts, diff] = payload.split(':');
  if (Date.now() - parseInt(ts, 10) > 120000) return res.status(403).json({ error: 'challenge_expired' });

  const hash = crypto.createHash('sha256').update(`${payload}:${nonce}`).digest('hex');
  if (!hash.startsWith('0'.repeat(parseInt(diff, 10)))) return res.status(403).json({ error: 'proof_of_work_failed' });

  verifiedIps.set(ip, Date.now() + 86400000);
  res.json({ status: 'verified' });
});

app.use('/api', (req, res, next) => {
  if (req.path === '/challenge' || req.path === '/challenge/verify' || req.path.startsWith('/client/')) return next();
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const expiresAt = verifiedIps.get(ip);
  if (!expiresAt || expiresAt < Date.now()) {
    return res.status(403).json({ error: 'turnstile_required' });
  }
  next();
});

function authUser(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const db = loadDB();
  const session = (db.sessions || {})[token];
  if (!session || session.expires_at < Date.now()) return res.status(401).json({ message: 'сессия истекла' });

  const user = db.users[session.username.toLowerCase()];
  if (!user) return res.status(401).json({ message: 'пользователь не найден' });
  if (user.banned) return res.status(403).json({ message: `аккаунт заблокирован: ${user.ban_reason}`, banned: true });

  req.user = user;
  next();
}

function requireOwner(req, res, next) {
  authUser(req, res, () => {
    if (req.user.role !== 'owner' && req.user.uid !== 1 && req.user.username.toLowerCase() !== 'dev') {
      return res.status(403).json({ message: 'доступ запрещен' });
    }
    req.adminUser = req.user;
    next();
  });
}

function safeUser(u) {
  const copy = { ...u };
  delete copy.password;
  delete copy.password_hash;
  return copy;
}

// Регистрация
app.post('/api/register', async (req, res) => {
  const { invite_code, username, password, referrer } = req.body;
  if (!invite_code || !username || !password) return res.status(400).json({ message: 'заполните все поля' });

  const db = loadDB();
  const cleanInvite = invite_code.trim();
  const inv = db.invites[cleanInvite];
  if (!inv || inv.used) return res.status(400).json({ message: 'инвайт недействителен' });

  const userKey = username.trim().toLowerCase();
  if (db.users[userKey]) return res.status(400).json({ message: 'логин занят' });

  const assignedUid = db.next_uid || 1;
  db.next_uid = assignedUid + 1;
  inv.used = true;
  inv.used_by = username.trim();

  const isOwner = (assignedUid === 1 || userKey === 'dev');
  const salt = await bcrypt.genSalt(10);
  const password_hash = await bcrypt.hash(password, salt);

  let cleanRef = null;
  if (referrer && db.users[referrer.toLowerCase()] && referrer.toLowerCase() !== userKey) {
    cleanRef = referrer.toLowerCase();
    db.users[cleanRef].cookies = (db.users[cleanRef].cookies || 0) + 1;
  }

  db.users[userKey] = {
    uid: assignedUid,
    username: username.trim(),
    password_hash,
    invite_code: cleanInvite,
    referrer: cleanRef,
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
    web_ip: req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1',
    client_ip: null,
    last_launch: null,
    sub_until: isOwner ? -1 : 0,
    created_at: Date.now()
  };

  const token = crypto.randomBytes(32).toString('hex');
  if (!db.sessions) db.sessions = {};
  db.sessions[token] = { username: userKey, expires_at: Date.now() + 30 * 86400000 };

  saveDB(db);
  res.json({ token, user: safeUser(db.users[userKey]) });
});

// Авторизация
app.post('/api/login', async (req, res) => {
  const { username, password, pin } = req.body;
  const db = loadDB();
  const user = db.users[username?.trim().toLowerCase()];
  if (!user) return res.status(401).json({ message: 'неверный логин или пароль' });

  let passOk = false;
  if (user.password_hash) passOk = await bcrypt.compare(password, user.password_hash);
  else if (user.password) {
    passOk = (user.password === password);
    if (passOk) {
      user.password_hash = await bcrypt.hash(password, 10);
      delete user.password;
    }
  }

  if (!passOk) return res.status(401).json({ message: 'неверный логин или пароль' });
  if (user.banned) return res.status(403).json({ message: `бан: ${user.ban_reason}`, banned: true });

  if (user.security_pin) {
    if (!pin) return res.json({ require_pin: true });
    if (user.security_pin !== pin.trim()) return res.status(403).json({ message: 'неверный 2fa пин' });
  }

  user.web_ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

  const token = crypto.randomBytes(32).toString('hex');
  if (!db.sessions) db.sessions = {};
  db.sessions[token] = { username: user.username.toLowerCase(), expires_at: Date.now() + 30 * 86400000 };

  saveDB(db);
  res.json({ token, user: safeUser(user), build_status: db.build_status });
});

app.get('/api/profile', authUser, (req, res) => {
  const db = loadDB();
  res.json({ user: safeUser(req.user), build_status: db.build_status });
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
  const u = db.users[req.user.username.toLowerCase()];
  if (req.body.bio !== undefined) u.bio = String(req.body.bio).slice(0, 250);
  if (req.body.avatar_color) u.avatar_color = req.body.avatar_color;
  if (req.body.reset_media) { u.avatar_media = null; u.avatar_type = null; }
  else if (req.body.avatar_media) { u.avatar_media = req.body.avatar_media; u.avatar_type = req.body.avatar_type; }
  saveDB(db);
  res.json({ message: 'профиль сохранен', user: safeUser(u) });
});

app.post('/api/user/set-pin', authUser, (req, res) => {
  const db = loadDB();
  db.users[req.user.username.toLowerCase()].security_pin = req.body.pin?.trim();
  saveDB(db);
  res.json({ message: 'пин установлен' });
});

app.post('/api/user/verify-pin', authUser, (req, res) => {
  if (!req.user.security_pin || req.user.security_pin === req.body.pin?.trim()) {
    return res.json({ status: 'success' });
  }
  res.status(403).json({ message: 'неверный пин' });
});

app.post('/api/hwid/reset', authUser, (req, res) => {
  const db = loadDB();
  db.users[req.user.username.toLowerCase()].hwid = null;
  saveDB(db);
  res.json({ message: 'hwid сброшен' });
});

// Рулетка
app.post('/api/roulette/spin', authUser, (req, res) => {
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  const now = Date.now();

  if (user.sub_until !== -1 && user.sub_until <= now) {
    return res.status(403).json({ message: 'рулетка доступна только владельцам активной подписки' });
  }

  if ((user.cookies || 0) < 1) {
    return res.status(400).json({ message: 'недостаточно cookies' });
  }

  user.cookies -= 1;
  const roll = Math.random() * 100;
  let reward = {};

  if (roll < 0.2) reward = { type: 'sub', value: 7, label: '7D SUB', color: '#c084fc' };
  else if (roll < 0.7) reward = { type: 'sub', value: 3, label: '3D SUB', color: '#a855f7' };
  else if (roll < 1.5) reward = { type: 'sub', value: 1, label: '1D SUB', color: '#8b5cf6' };
  else if (roll < 8.0) reward = { type: 'cookies', value: 5, label: '5 COOKIES', color: '#e9d5ff' };
  else if (roll < 30.0) reward = { type: 'cookies', value: 3, label: '3 COOKIES', color: '#c4b5fd' };
  else reward = { type: 'cookies', value: 1, label: '1 COOKIE', color: '#a78bfa' };

  if (reward.type === 'sub' && user.sub_until !== -1) {
    const base = user.sub_until > now ? user.sub_until : now;
    user.sub_until = base + (reward.value * 86400000);
  } else if (reward.type === 'cookies') {
    user.cookies = (user.cookies || 0) + reward.value;
  }

  saveDB(db);
  res.json({ reward, cookies: user.cookies, sub_until: user.sub_until });
});

// Промокоды
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

// Оплата подписки / cookies
app.post('/api/payment/checkout', authUser, (req, res) => {
  const { plan_days, amount, promo_code, target_type } = req.body;
  const db = loadDB();
  const user = db.users[req.user.username.toLowerCase()];
  const now = Date.now();

  if (target_type === 'cookies') {
    const cookiesToAdd = parseInt(plan_days, 10);
    user.cookies = (user.cookies || 0) + cookiesToAdd;
    saveDB(db);
    return res.json({ message: `начислено +${cookiesToAdd} cookies`, user: safeUser(user) });
  }

  const daysToAdd = parseInt(plan_days, 10) || 30;
  const cleanPromo = (promo_code || '').trim().toUpperCase();

  let promoBonusDays = 0;
  if (cleanPromo && db.promos[cleanPromo]) {
    const promo = db.promos[cleanPromo];
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
  if (user.sub_until !== -1) {
    const base = user.sub_until > now ? user.sub_until : now;
    user.sub_until = base + (finalDays * 86400000);
  }

  // Реферальный бонус
  if (user.referrer && db.users[user.referrer]) {
    const refOwner = db.users[user.referrer];
    refOwner.cookies = (refOwner.cookies || 0) + 2;
  }

  const paymentRecord = {
    id: 'PAY-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
    username: user.username,
    user_uid: user.uid,
    amount: amount || 0,
    plan_days: finalDays,
    promo: cleanPromo || '—',
    status: 'успешно',
    created_at: now
  };

  db.payments.unshift(paymentRecord);
  saveDB(db);

  sendTelegramNotification(`💰 <b>Оплата JOY</b>\nПользователь: <b>${user.username}</b> [UID: ${user.uid}]\nСумма: ${amount} ₽\nДней начислено: +${finalDays}`);

  res.json({ message: 'подписка успешно активирована', user: safeUser(user) });
});

// Реселлеры
app.get('/api/resellers', (req, res) => {
  const db = loadDB();
  res.json({ resellers: db.resellers || [] });
});

app.post('/api/admin/resellers/add', requireOwner, (req, res) => {
  const { name, link, region } = req.body;
  if (!name || !link) return res.status(400).json({ message: 'заполните поля' });
  const db = loadDB();
  if (!db.resellers) db.resellers = [];
  const item = { id: 'res_' + Date.now(), name: name.trim(), link: link.trim(), region: region || 'Global' };
  db.resellers.push(item);
  saveDB(db);
  res.json({ resellers: db.resellers });
});

app.delete('/api/admin/resellers/:id', requireOwner, (req, res) => {
  const db = loadDB();
  db.resellers = (db.resellers || []).filter(r => r.id !== req.params.id);
  saveDB(db);
  res.json({ resellers: db.resellers });
});

// Идеи обновлений
app.get('/api/features', (req, res) => {
  const db = loadDB();
  res.json({ suggestions: db.feature_suggestions || [] });
});

app.post('/api/features', authUser, (req, res) => {
  const { title } = req.body;
  if (!title) return res.status(400).json({ message: 'введите идею' });
  const db = loadDB();
  if (!db.feature_suggestions) db.feature_suggestions = [];
  const feat = { id: Date.now(), title: title.trim().slice(0, 100), author: req.user.username, votes: [req.user.username], created_at: Date.now() };
  db.feature_suggestions.unshift(feat);
  saveDB(db);
  res.json({ feature: feat });
});

app.post('/api/features/:id/vote', authUser, (req, res) => {
  const db = loadDB();
  const feat = (db.feature_suggestions || []).find(f => f.id === parseInt(req.params.id, 10));
  if (!feat) return res.status(404).json({ message: 'не найдено' });

  const uName = req.user.username;
  if (feat.votes.includes(uName)) feat.votes = feat.votes.filter(v => v !== uName);
  else feat.votes.push(uName);

  saveDB(db);
  res.json({ votes: feat.votes.length, userVoted: feat.votes.includes(uName) });
});

// Облако: Конфиги
app.get('/api/configs', authUser, (req, res) => {
  const db = loadDB();
  const uKey = req.user.username.toLowerCase();
  const now = Date.now();
  const list = (db.configs || []).filter(c => c.author.toLowerCase() === uKey || c.is_public).map(c => {
    const isOwner = c.author.toLowerCase() === uKey || req.user.role === 'owner';
    const subExp = (db.item_subscriptions || {})[`${c.id}_${uKey}`] || 0;
    const isUnlocked = isOwner || (c.price_cookies || 0) === 0 || subExp > now;
    return { ...c, is_unlocked: isUnlocked, data: isUnlocked ? c.data : null };
  });
  res.json({ configs: list });
});

app.post('/api/configs/upload', authUser, (req, res) => {
  const db = loadDB();
  const { filename, file_data, price_cookies, is_public } = req.body;
  const cfg = {
    id: 'CFG-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
    name: filename.replace(/\.cfg$/i, '').trim().slice(0, 32) + '.cfg',
    data: file_data,
    author: req.user.username,
    price_cookies: Math.min(10, Math.max(0, parseInt(price_cookies, 10) || 0)),
    is_public: !!is_public,
    updated_at: Date.now()
  };
  db.configs.unshift(cfg);
  saveDB(db);
  res.json({ config: cfg });
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

// Облако: Скрипты
app.get('/api/scripts', authUser, (req, res) => {
  const db = loadDB();
  const uKey = req.user.username.toLowerCase();
  const now = Date.now();
  const list = (db.scripts || []).filter(s => s.author.toLowerCase() === uKey || s.is_public).map(s => {
    const isOwner = s.author.toLowerCase() === uKey || req.user.role === 'owner';
    const subExp = (db.item_subscriptions || {})[`${s.id}_${uKey}`] || 0;
    const isUnlocked = isOwner || (s.price_cookies || 0) === 0 || subExp > now;
    return { ...s, is_unlocked: isUnlocked, code: isUnlocked ? s.code : '-- subscription required' };
  });
  res.json({ scripts: list });
});

app.post('/api/scripts', authUser, (req, res) => {
  const db = loadDB();
  const { title, code, price_cookies, is_public } = req.body;
  const script = {
    id: Date.now(),
    title: title.trim().slice(0, 32),
    code: code.slice(0, 200000),
    author: req.user.username,
    price_cookies: Math.min(10, Math.max(0, parseInt(price_cookies, 10) || 0)),
    is_public: !!is_public,
    enabled: true,
    updated_at: Date.now()
  };
  db.scripts.unshift(script);
  saveDB(db);
  res.json({ script });
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

app.post('/api/cloud/subscribe', authUser, (req, res) => {
  const { item_id, item_type } = req.body;
  const db = loadDB();
  const buyer = db.users[req.user.username.toLowerCase()];
  const item = item_type === 'config' ? (db.configs || []).find(c => c.id === item_id) : (db.scripts || []).find(s => s.id === parseInt(item_id, 10));

  if (!item) return res.status(404).json({ message: 'товар не найден' });
  const price = item.price_cookies || 0;
  if ((buyer.cookies || 0) < price) return res.status(400).json({ message: 'недостаточно cookies' });

  buyer.cookies -= price;
  if (db.users[item.author.toLowerCase()]) db.users[item.author.toLowerCase()].cookies = (db.users[item.author.toLowerCase()].cookies || 0) + price;

  if (!db.item_subscriptions) db.item_subscriptions = {};
  db.item_subscriptions[`${item.id}_${buyer.username.toLowerCase()}`] = Date.now() + 30 * 86400000;

  saveDB(db);
  res.json({ cookies: buyer.cookies });
});

// Лаунчер
app.get('/api/download-loader', (req, res) => {
  const realLoader = path.join(BUILDS_DIR, 'JoyLoader.exe');
  if (fs.existsSync(realLoader)) return res.download(realLoader, 'JoyLoader.exe');
  const temp = path.join(__dirname, 'JoyLoader_stub.exe');
  if (!fs.existsSync(temp)) fs.writeFileSync(temp, 'JOY CLIENT BUILD');
  res.download(temp, 'JoyLoader.exe');
});

app.post('/api/client/auth', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) {
    return res.status(400).json({ status: 'error', message: 'неверные параметры запроса' });
  }

  const db = loadDB();
  const user = db.users[username.trim().toLowerCase()];
  if (!user) return res.status(401).json({ status: 'error', message: 'неверные данные входа' });

  let passOk = false;
  if (user.password_hash) passOk = await bcrypt.compare(password, user.password_hash);
  else if (user.password) passOk = (user.password === password);

  if (!passOk) return res.status(401).json({ status: 'error', message: 'неверные данные входа' });
  if (user.banned) return res.status(403).json({ status: 'error', message: `бан: ${user.ban_reason || 'доступ запрещен'}` });

  if (db.build_status === 'updating' && user.role !== 'owner') {
    return res.status(403).json({ status: 'error', message: 'билд на техническом обновлении' });
  }

  const now = Date.now();
  const hasSub = user.sub_until === -1 || user.sub_until > now;
  if (!hasSub) return res.status(403).json({ status: 'error', message: 'подписка истекла или отсутствует' });

  if (!user.hwid) user.hwid = hwid.trim();
  else if (user.hwid !== hwid.trim() && user.role !== 'owner') {
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
  if (user.sub_until !== -1 && user.sub_until <= now) return res.status(403).send('subscription expired');

  const dllPath = path.join(BUILDS_DIR, 'joy_internal.dll');
  if (fs.existsSync(dllPath)) return res.sendFile(dllPath);

  res.send('JOY_ENCRYPTED_MEMORY_PAYLOAD_STUB');
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
  const thread = db.threads.find(t => t.id === parseInt(req.params.id, 10));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  const authorUser = db.users[thread.author.toLowerCase()] || {};
  res.json({
    thread: {
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
    }
  });
});

app.post('/api/forum/threads', authUser, (req, res) => {
  const db = loadDB();
  const { title, content, tag } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните тему' });

  const allowedTags = ['обсуждение', 'баг', 'предложение', 'медиа'];
  const newThread = {
    id: Date.now(),
    title: title.trim().slice(0, 90),
    content: content.trim().slice(0, 800),
    tag: allowedTags.includes(tag) ? tag : 'обсуждение',
    pinned: false,
    locked: false,
    author: req.user.username,
    author_uid: req.user.uid,
    created_at: Date.now(),
    posts: []
  };

  db.threads.unshift(newThread);
  saveDB(db);
  res.json({ thread: newThread });
});

app.post('/api/forum/threads/:id/reply', authUser, (req, res) => {
  const db = loadDB();
  const thread = db.threads.find(t => t.id === parseInt(req.params.id, 10));
  if (!thread) return res.status(404).json({ message: 'тема не найдена' });
  if (thread.locked && req.user.role !== 'owner') return res.status(403).json({ message: 'тема закрыта' });

  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ message: 'введите текст' });

  const post = { id: Date.now(), author: req.user.username, author_uid: req.user.uid, text: text.trim().slice(0, 500), created_at: Date.now() };
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
  res.json({ message: 'обновлено', thread });
});

app.delete('/api/forum/threads/:id', authUser, (req, res) => {
  const db = loadDB();
  const tId = parseInt(req.params.id, 10);
  const idx = db.threads.findIndex(t => t.id === tId);
  if (idx === -1) return res.status(404).json({ message: 'не найдено' });
  if (db.threads[idx].author !== req.user.username && req.user.role !== 'owner') return res.status(403).json({ message: 'нет прав' });
  db.threads.splice(idx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
});

app.delete('/api/forum/threads/:id/post/:postId', authUser, (req, res) => {
  const db = loadDB();
  const tId = parseInt(req.params.id, 10);
  const pId = parseInt(req.params.postId, 10);
  const thread = db.threads.find(t => t.id === tId);
  if (!thread) return res.status(404).json({ message: 'не найдено' });

  const pIdx = (thread.posts || []).findIndex(p => p.id === pId);
  if (pIdx === -1) return res.status(404).json({ message: 'не найдено' });
  if (thread.posts[pIdx].author !== req.user.username && req.user.role !== 'owner') return res.status(403).json({ message: 'нет прав' });

  thread.posts.splice(pIdx, 1);
  saveDB(db);
  res.json({ message: 'удалено' });
});

// Тикеты
app.post('/api/support/ticket', authUser, (req, res) => {
  const db = loadDB();
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'заполните поля' });

  const ticket = {
    id: 'TICK-' + Math.floor(1000 + Math.random() * 9000),
    userKey: req.user.username.toLowerCase(),
    username: req.user.username,
    user_uid: req.user.uid,
    subject: subject.trim(),
    message: message.trim(),
    status: 'на рассмотрении',
    reply: null,
    created_at: Date.now()
  };

  db.tickets.unshift(ticket);
  saveDB(db);
  sendTelegramNotification(`🚨 <b>Новый тикет JOY</b>\nОт: <b>${req.user.username}</b> [UID: ${req.user.uid}]\nТема: ${ticket.subject}\nТекст: ${ticket.message}`);
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

// Патчи
app.get('/api/updates', (req, res) => res.json({ updates: loadDB().updates || [] }));

app.post('/api/updates', requireOwner, (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните поля' });
  const db = loadDB();
  const item = { id: Date.now(), title: title.trim(), content: content.trim(), author: req.adminUser.username, created_at: Date.now() };
  db.updates.unshift(item);
  saveDB(db);
  sendTelegramNotification(`🚀 <b>Новое обновление JOY</b>\n<b>${item.title}</b>\n\n${item.content}`);
  res.json({ update: item });
});

app.delete('/api/updates/:id', requireOwner, (req, res) => {
  const db = loadDB();
  db.updates = (db.updates || []).filter(u => u.id !== parseInt(req.params.id, 10));
  saveDB(db);
  res.json({ message: 'удалено' });
});

// Админка
app.post('/api/admin/self-lifetime', requireOwner, (req, res) => {
  const db = loadDB();
  const u = db.users[req.adminUser.username.toLowerCase()];
  u.sub_until = -1;
  u.role = 'owner';
  saveDB(db);
  res.json({ message: 'вам выдана lifetime сабка и роль owner', user: safeUser(u) });
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

app.post('/api/admin/grant-cookies', requireOwner, (req, res) => {
  const { username, amount } = req.body;
  const db = loadDB();
  const target = db.users[(username || req.adminUser.username).toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });
  target.cookies = Math.max(0, (target.cookies || 0) + parseInt(amount, 10));
  saveDB(db);
  res.json({ message: `пользователю ${target.username} установлено ${target.cookies} cookies`, cookies: target.cookies });
});

app.get('/api/admin/user/:username', requireOwner, (req, res) => {
  const db = loadDB();
  const target = db.users[req.params.username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ target: safeUser(target) });
});

app.post('/api/admin/user/update', requireOwner, (req, res) => {
  const { username, role, uid, cookies, sub_mode, reset_hwid, banned, ban_reason } = req.body;
  const db = loadDB();
  const target = db.users[username.toLowerCase()];
  if (!target) return res.status(404).json({ message: 'не найден' });

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
  res.json({ message: `аккаунт ${target.username} обновлен`, target: safeUser(target) });
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

app.get('/api/admin/payments', requireOwner, (req, res) => res.json({ payments: loadDB().payments || [] }));

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
  const code = 'JOY-' + crypto.randomBytes(4).toString('hex').toUpperCase();
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
  const { code, days, cookies, discount_percent, max_uses, duration_hours } = req.body;
  if (!code || (!days && !discount_percent && !cookies)) {
    return res.status(400).json({ message: 'укажите код и дни, cookies или скидку' });
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

app.get('/api/verify-ip', (req, res) => res.json({ status: 'ok', build_status: loadDB().build_status }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`[JOY] Server live on ${PORT}`));
