const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();

const BUILDS_DIR = path.join(__dirname, 'builds');
if (!fs.existsSync(BUILDS_DIR)) fs.mkdirSync(BUILDS_DIR, { recursive: true });

// ============================================================
// 1. СЕТЕВАЯ ЗАЩИТА (Anti-DDoS Rate Limiter & Memory Shield)
// ============================================================
const rateLimits = new Map();
const bannedIps = new Map();

function rateLimiterMiddleware(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();

  if (bannedIps.has(ip)) {
    if (now < bannedIps.get(ip)) {
      return res.status(429).send('IP временно заблокирован за спам');
    }
    bannedIps.delete(ip);
  }

  let record = rateLimits.get(ip);
  if (!record || now > record.resetTime) {
    record = { count: 0, resetTime: now + 5000 }; // окно 5 сек
  }

  record.count++;
  rateLimits.set(ip, record);

  // Лимит: максимум 40 запросов за 5 секунд на один IP
  if (record.count > 40) {
    bannedIps.set(ip, now + 60000); // бан на 1 минуту
    return res.status(429).send('Превышен лимит запросов');
  }

  next();
}

app.use(rateLimiterMiddleware);

// Защита от переполнения RAM большими плейлоадами
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use(express.static(__dirname));

// ============================================================
// 2. ДВИЖОК PROOF-OF-WORK (Turnstile Shield)
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
  if (!payload || !sig || nonce === undefined) return res.status(400).json({ error: 'invalid_params' });

  const expectedSig = crypto.createHmac('sha256', POW_SECRET).update(payload).digest('hex');
  if (sig !== expectedSig) return res.status(403).json({ error: 'invalid_signature' });

  const [ip, tsStr, diffStr] = payload.split(':');
  const ts = parseInt(tsStr, 10);
  const difficulty = parseInt(diffStr, 10);

  if (Date.now() - ts > 120000) return res.status(403).json({ error: 'challenge_expired' });

  const hash = crypto.createHash('sha256').update(`${payload}:${nonce}`).digest('hex');
  if (!hash.startsWith('0'.repeat(difficulty))) return res.status(403).json({ error: 'proof_of_work_failed' });

  verifiedIps.set(ip, Date.now() + 24 * 3600 * 1000); // верификация на 24 часа
  res.json({ status: 'verified', message: 'проверка успешно пройдена' });
});

// Middleware проверки PoW
app.use('/api', (req, res, next) => {
  if (req.path === '/challenge' || req.path === '/challenge/verify' || req.path.startsWith('/client/')) {
    return next();
  }
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  const exp = verifiedIps.get(ip);
  if (!exp || exp < Date.now()) {
    return res.status(403).json({ error: 'turnstile_required', message: 'пройдите проверку браузера' });
  }
  next();
});

// ============================================================
// 3. АВТОРИЗАЦИЯ И СЕССИИ
// ============================================================
function authUser(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'не авторизован' });

  const session = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(token, Date.now());
  if (!session) return res.status(401).json({ message: 'сессия истекла' });

  const user = db.prepare('SELECT * FROM users WHERE uid = ?').get(session.uid);
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
    next();
  });
}

function generateInviteCode() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const genPart = (len) => {
    let r = '';
    const b = crypto.randomBytes(len);
    for (let i = 0; i < len; i++) r += chars[b[i] % chars.length];
    return r;
  };
  return `JOY-${genPart(10)}-${genPart(15)}`;
}

// ============================================================
// 4. ЭНДПОИНТЫ АВТОРИЗАЦИИ
// ============================================================
app.get('/api/verify-ip', (req, res) => {
  const status = db.prepare("SELECT value FROM system_meta WHERE key = 'build_status'").get()?.value || 'stable';
  res.json({ status: 'ok', build_status: status });
});

app.post('/api/register', async (req, res) => {
  const { invite_code, username, password } = req.body;
  if (!invite_code || !username || !password) return res.status(400).json({ message: 'заполните все поля' });

  const cleanInvite = invite_code.trim();
  const inv = db.prepare('SELECT * FROM invites WHERE code = ? AND used = 0').get(cleanInvite);
  if (!inv) return res.status(400).json({ message: 'инвайт недействителен или использован' });

  const cleanUser = username.trim();
  if (cleanUser.length < 3 || cleanUser.length > 24) return res.status(400).json({ message: 'логин от 3 до 24 символов' });

  const existing = db.prepare('SELECT uid FROM users WHERE username = ?').get(cleanUser);
  if (existing) return res.status(400).json({ message: 'логин уже занят' });

  const password_hash = await bcrypt.hash(password, 10);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';

  const isOwner = cleanUser.toLowerCase() === 'dev';
  const sub_until = isOwner ? -1 : 0;
  const role = isOwner ? 'owner' : 'user';

  const insert = db.prepare(`
    INSERT INTO users (username, password_hash, role, sub_until, web_ip, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(cleanUser, password_hash, role, sub_until, ip, Date.now());

  db.prepare('UPDATE invites SET used = 1, used_by = ? WHERE code = ?').run(cleanUser, cleanInvite);

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, uid, expires_at) VALUES (?, ?, ?)').run(token, insert.lastInsertRowid, Date.now() + 30 * 86400000);

  const user = db.prepare('SELECT * FROM users WHERE uid = ?').get(insert.lastInsertRowid);
  delete user.password_hash;
  res.json({ token, user });
});

app.post('/api/login', async (req, res) => {
  const { username, password, pin } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'введите логин и пароль' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ message: 'неверный логин или пароль' });
  }

  if (user.banned) {
    return res.status(403).json({ message: `аккаунт заблокирован: ${user.ban_reason}`, banned: true });
  }

  if (user.security_pin) {
    if (!pin) return res.json({ require_pin: true, message: 'требуется ввод 2fa пина' });
    if (user.security_pin !== pin.trim()) return res.status(403).json({ message: 'неверный 2fa пин-код' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, uid, expires_at) VALUES (?, ?, ?)').run(token, user.uid, Date.now() + 30 * 86400000);

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  db.prepare('UPDATE users SET web_ip = ? WHERE uid = ?').run(ip, user.uid);

  delete user.password_hash;
  const buildStatus = db.prepare("SELECT value FROM system_meta WHERE key = 'build_status'").get()?.value || 'stable';
  res.json({ token, user, build_status: buildStatus });
});

app.get('/api/profile', authUser, (req, res) => {
  delete req.user.password_hash;
  const buildStatus = db.prepare("SELECT value FROM system_meta WHERE key = 'build_status'").get()?.value || 'stable';
  res.json({ user: req.user, build_status: buildStatus });
});

app.get('/api/user/:username', (req, res) => {
  const target = db.prepare('SELECT uid, username, role, banned, bio, avatar_color, avatar_media, avatar_type, created_at FROM users WHERE username = ?').get(req.params.username.trim());
  if (!target) return res.status(404).json({ message: 'пользователь не найден' });
  res.json({ user: target });
});

app.post('/api/profile/update', authUser, (req, res) => {
  const { bio, avatar_color, avatar_media, avatar_type, reset_media } = req.body;
  let updateMedia = req.user.avatar_media;
  let updateType = req.user.avatar_type;

  if (reset_media) {
    updateMedia = null;
    updateType = null;
  } else if (avatar_media && avatar_type) {
    updateMedia = avatar_media;
    updateType = avatar_type;
  }

  const cleanBio = typeof bio === 'string' ? bio.slice(0, 250) : req.user.bio;
  const cleanColor = typeof avatar_color === 'string' ? avatar_color : req.user.avatar_color;

  db.prepare(`
    UPDATE users SET bio = ?, avatar_color = ?, avatar_media = ?, avatar_type = ? WHERE uid = ?
  `).run(cleanBio, cleanColor, updateMedia, updateType, req.user.uid);

  const updated = db.prepare('SELECT * FROM users WHERE uid = ?').get(req.user.uid);
  delete updated.password_hash;
  res.json({ message: 'профиль сохранен', user: updated });
});

app.post('/api/user/set-pin', authUser, (req, res) => {
  const { pin } = req.body;
  if (!pin || pin.length < 4 || pin.length > 8) return res.status(400).json({ message: 'пин-код от 4 до 8 цифр' });
  db.prepare('UPDATE users SET security_pin = ? WHERE uid = ?').run(pin.trim(), req.user.uid);
  res.json({ message: '2FA PIN-код успешно установлен' });
});

app.post('/api/user/verify-pin', authUser, (req, res) => {
  const { pin } = req.body;
  if (!req.user.security_pin || req.user.security_pin === pin?.trim()) {
    return res.json({ status: 'success' });
  }
  res.status(403).json({ message: 'неверный пин-код' });
});

app.post('/api/hwid/reset', authUser, (req, res) => {
  db.prepare('UPDATE users SET hwid = NULL WHERE uid = ?').run(req.user.uid);
  res.json({ message: 'HWID успешно сброшен' });
});

// ============================================================
// 5. РУЛЕТКА И ВАЛЮТА COOKIES
// ============================================================

// Покупка cookies за баланс/деньги (симуляция шлюза: 1 cookie = 50 руб)
app.post('/api/cookies/buy', authUser, (req, res) => {
  const amount = parseInt(req.body.amount, 10);
  if (!amount || amount < 1 || amount > 1000) return res.status(400).json({ message: 'неверное количество' });

  const priceRub = amount * 50;
  db.prepare('UPDATE users SET cookies = cookies + ? WHERE uid = ?').run(amount, req.user.uid);

  db.prepare(`
    INSERT INTO payments (id, user_uid, username, type, amount, details, created_at)
    VALUES (?, ?, ?, 'cookies', ?, ?, ?)
  `).run('PAY-CK-' + crypto.randomBytes(4).toString('hex').toUpperCase(), req.user.uid, req.user.username, priceRub, `+${amount} cookies`, Date.now());

  const u = db.prepare('SELECT cookies FROM users WHERE uid = ?').get(req.user.uid);
  res.json({ message: `начислено ${amount} cookies`, cookies: u.cookies });
});

// Ролл рулетки
app.post('/api/roulette/spin', authUser, (req, res) => {
  if (req.user.cookies < 1) return res.status(400).json({ message: 'недостаточно cookies для прокрута' });

  // Списываем 1 cookie
  db.prepare('UPDATE users SET cookies = cookies - 1 WHERE uid = ?').run(req.user.uid);

  // Шансы:
  // Сумма подписки: ровно 1.5% (1.5 / 100)
  //   - 7 дней: 0.2%
  //   - 3 дня: 0.5%
  //   - 1 день: 0.8%
  // Сумма cookies: ровно 98.5% (98.5 / 100)
  //   - 5 cookies: 6.5%
  //   - 3 cookies: 22.0%
  //   - 1 cookie: 70.0%
  const roll = Math.random() * 100;
  let reward = {};

  if (roll < 0.2) {
    reward = { type: 'sub', value: 7, label: '7 дней чита', color: '#f59e0b' };
  } else if (roll < 0.7) {
    reward = { type: 'sub', value: 3, label: '3 дня чита', color: '#a855f7' };
  } else if (roll < 1.5) {
    reward = { type: 'sub', value: 1, label: '1 день чита', color: '#3b82f6' };
  } else if (roll < 8.0) {
    reward = { type: 'cookies', value: 5, label: '5 cookies', color: '#10b981' };
  } else if (roll < 30.0) {
    reward = { type: 'cookies', value: 3, label: '3 cookies', color: '#14b8a6' };
  } else {
    reward = { type: 'cookies', value: 1, label: '1 cookie', color: '#8b5cf6' };
  }

  // Применяем выигрыш
  const now = Date.now();
  if (reward.type === 'sub') {
    if (req.user.sub_until !== -1) {
      const ms = reward.value * 86400000;
      const base = req.user.sub_until > now ? req.user.sub_until : now;
      db.prepare('UPDATE users SET sub_until = ? WHERE uid = ?').run(base + ms, req.user.uid);
    }
  } else if (reward.type === 'cookies') {
    db.prepare('UPDATE users SET cookies = cookies + ? WHERE uid = ?').run(reward.value, req.user.uid);
  }

  const updated = db.prepare('SELECT cookies, sub_until FROM users WHERE uid = ?').get(req.user.uid);
  res.json({ reward, cookies: updated.cookies, sub_until: updated.sub_until });
});

// ============================================================
// 6. МАРКЕТПЛЕЙС LUA И CFG (С ПОДПИСКОЙ ЗА COOKIES)
// ============================================================
app.get('/api/cloud/items', authUser, (req, res) => {
  const type = req.query.type || 'config';
  const items = db.prepare(`
    SELECT c.*, s.expires_at as my_sub_expires
    FROM cloud_items c
    LEFT JOIN item_subs s ON s.item_id = c.id AND s.user_uid = ?
    WHERE c.type = ? AND (c.is_public = 1 OR c.author_uid = ?)
    ORDER BY c.updated_at DESC
  `).all(req.user.uid, type, req.user.uid);

  // Скрываем исходный контент/код, если нет активной подписки или автор не я
  const safeItems = items.map(it => {
    const isOwner = req.user.role === 'owner' || it.author_uid === req.user.uid;
    const hasActiveSub = it.price_cookies === 0 || (it.my_sub_expires && it.my_sub_expires > Date.now());
    return {
      id: it.id,
      type: it.type,
      name: it.name,
      author_username: it.author_username,
      author_uid: it.author_uid,
      price_cookies: it.price_cookies,
      is_public: !!it.is_public,
      enabled: !!it.enabled,
      is_unlocked: isOwner || hasActiveSub,
      sub_until: it.my_sub_expires || 0,
      content: (isOwner || hasActiveSub) ? it.content : null
    };
  });

  res.json({ items: safeItems });
});

app.post('/api/cloud/upload', authUser, (req, res) => {
  const { type, name, content, price_cookies, is_public } = req.body;
  if (!name || !content || !type) return res.status(400).json({ message: 'заполните все поля' });

  const price = Math.min(10, Math.max(0, parseInt(price_cookies, 10) || 0));
  const id = (type === 'config' ? 'CFG-' : 'LUA-') + crypto.randomBytes(4).toString('hex').toUpperCase();

  db.prepare(`
    INSERT INTO cloud_items (id, type, name, content, author_uid, author_username, price_cookies, is_public, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, type, name.trim().slice(0, 40), content, req.user.uid, req.user.username, price, is_public ? 1 : 0, Date.now());

  res.json({ message: 'успешно загружено' });
});

app.post('/api/cloud/subscribe', authUser, (req, res) => {
  const { item_id } = req.body;
  const item = db.prepare('SELECT * FROM cloud_items WHERE id = ?').get(item_id);
  if (!item) return res.status(404).json({ message: 'товар не найден' });

  if (item.author_uid === req.user.uid) return res.status(400).json({ message: 'вы автор этого товара' });
  if (req.user.cookies < item.price_cookies) return res.status(400).json({ message: 'недостаточно cookies' });

  // Списание cookies и выдача автору (комиссия 0%)
  db.prepare('UPDATE users SET cookies = cookies - ? WHERE uid = ?').run(item.price_cookies, req.user.uid);
  db.prepare('UPDATE users SET cookies = cookies + ? WHERE uid = ?').run(item.price_cookies, item.author_uid);

  const now = Date.now();
  const currentSub = db.prepare('SELECT expires_at FROM item_subs WHERE item_id = ? AND user_uid = ?').get(item.id, req.user.uid);
  const base = currentSub && currentSub.expires_at > now ? currentSub.expires_at : now;
  const newExpires = base + (30 * 86400000); // +30 дней

  db.prepare(`
    INSERT INTO item_subs (item_id, user_uid, expires_at)
    VALUES (?, ?, ?)
    ON CONFLICT(item_id, user_uid) DO UPDATE SET expires_at = excluded.expires_at
  `).run(item.id, req.user.uid, newExpires);

  res.json({ message: 'доступ успешно приобретен на 30 дней' });
});

app.delete('/api/cloud/item/:id', authUser, (req, res) => {
  const item = db.prepare('SELECT * FROM cloud_items WHERE id = ?').get(req.params.id);
  if (!item) return res.status(404).json({ message: 'не найдено' });
  if (item.author_uid !== req.user.uid && req.user.role !== 'owner') return res.status(403).json({ message: 'нет прав' });

  db.prepare('DELETE FROM cloud_items WHERE id = ?').run(req.params.id);
  res.json({ message: 'удалено' });
});

// ============================================================
// 7. ПОКУПКА ЧИТА И ПРОМОКОДЫ
// ============================================================
app.post('/api/promo/validate', authUser, (req, res) => {
  const code = (req.body.code || '').trim();
  const promo = db.prepare('SELECT * FROM promos WHERE code = ?').get(code);
  if (!promo) return res.status(400).json({ message: 'промокод не существует' });

  const now = Date.now();
  if (promo.expires_at && promo.expires_at < now) return res.status(400).json({ message: 'срок действия истек' });
  if (promo.max_uses > 0 && promo.used_count >= promo.max_uses) return res.status(400).json({ message: 'лимит исчерпан' });

  const used = db.prepare('SELECT 1 FROM promo_history WHERE code = ? AND uid = ?').get(promo.code, req.user.uid);
  if (used) return res.status(400).json({ message: 'вы уже использовали этот промокод' });

  res.json({ valid: true, code: promo.code, days: promo.days, discount_percent: promo.discount_percent, cookies: promo.cookies });
});

app.post('/api/payment/checkout', authUser, (req, res) => {
  const { plan_days, amount, promo_code } = req.body;
  const daysToAdd = parseInt(plan_days, 10) || 30;
  let finalDays = daysToAdd;

  if (promo_code) {
    const promo = db.prepare('SELECT * FROM promos WHERE code = ?').get(promo_code.trim());
    if (promo) {
      finalDays += (promo.days || 0);
      if (promo.cookies > 0) {
        db.prepare('UPDATE users SET cookies = cookies + ? WHERE uid = ?').run(promo.cookies, req.user.uid);
      }
      db.prepare('UPDATE promos SET used_count = used_count + 1 WHERE code = ?').run(promo.code);
      db.prepare('INSERT OR IGNORE INTO promo_history (code, uid, activated_at) VALUES (?, ?, ?)').run(promo.code, req.user.uid, Date.now());
    }
  }

  const now = Date.now();
  if (req.user.sub_until !== -1) {
    const base = req.user.sub_until > now ? req.user.sub_until : now;
    db.prepare('UPDATE users SET sub_until = ? WHERE uid = ?').run(base + (finalDays * 86400000), req.user.uid);
  }

  db.prepare(`
    INSERT INTO payments (id, user_uid, username, type, amount, details, created_at)
    VALUES (?, ?, ?, 'sub', ?, ?, ?)
  `).run('PAY-' + crypto.randomBytes(4).toString('hex').toUpperCase(), req.user.uid, req.user.username, amount || 0, `+${finalDays} дн.`, Date.now());

  const u = db.prepare('SELECT * FROM users WHERE uid = ?').get(req.user.uid);
  delete u.password_hash;
  res.json({ message: `подписка продлена (+${finalDays} дн.)`, user: u });
});

// ============================================================
// 8. ФОРУМ, ТИКЕТЫ И ОБНОВЛЕНИЯ
// ============================================================
app.get('/api/forum/threads', (req, res) => {
  const threads = db.prepare(`
    SELECT t.*, u.username as author, u.role as author_role, u.avatar_color, u.avatar_media, u.avatar_type,
           (SELECT COUNT(*) FROM forum_posts WHERE thread_id = t.id) as replies_count
    FROM forum_threads t
    JOIN users u ON u.uid = t.author_uid
    ORDER BY t.pinned DESC, t.created_at DESC
  `).all();
  res.json({ threads });
});

app.get('/api/forum/threads/:id', (req, res) => {
  const thread = db.prepare(`
    SELECT t.*, u.username as author, u.role as author_role, u.avatar_color, u.avatar_media, u.avatar_type
    FROM forum_threads t
    JOIN users u ON u.uid = t.author_uid
    WHERE t.id = ?
  `).get(req.params.id);

  if (!thread) return res.status(404).json({ message: 'тема не найдена' });

  const posts = db.prepare(`
    SELECT p.*, u.username as author, u.role as author_role, u.avatar_color, u.avatar_media, u.avatar_type
    FROM forum_posts p
    JOIN users u ON u.uid = p.author_uid
    WHERE p.thread_id = ?
    ORDER BY p.created_at ASC
  `).all(req.params.id);

  res.json({ thread: { ...thread, posts } });
});

app.post('/api/forum/threads', authUser, (req, res) => {
  const { title, content, tag } = req.body;
  if (!title || !content) return res.status(400).json({ message: 'заполните тему' });

  const info = db.prepare(`
    INSERT INTO forum_threads (title, content, tag, author_uid, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(title.trim().slice(0, 90), content.trim().slice(0, 800), tag || 'обсуждение', req.user.uid, Date.now());

  res.json({ message: 'тема опубликована', id: info.lastInsertRowid });
});

app.post('/api/forum/threads/:id/reply', authUser, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ message: 'введите текст' });

  db.prepare(`
    INSERT INTO forum_posts (thread_id, author_uid, text, created_at)
    VALUES (?, ?, ?, ?)
  `).run(req.params.id, req.user.uid, text.trim().slice(0, 500), Date.now());

  res.json({ status: 'ok' });
});

app.get('/api/updates', (req, res) => {
  const list = db.prepare('SELECT * FROM updates ORDER BY created_at DESC').all();
  res.json({ updates: list });
});

app.post('/api/support/ticket', authUser, (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ message: 'заполните обращение' });

  const id = 'TICK-' + Math.floor(1000 + Math.random() * 9000);
  db.prepare(`
    INSERT INTO support_tickets (id, user_uid, subject, message, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(id, req.user.uid, subject.trim(), message.trim(), Date.now());

  res.json({ message: 'обращение отправлено' });
});

app.get('/api/support/my-tickets', authUser, (req, res) => {
  const tickets = db.prepare('SELECT * FROM support_tickets WHERE user_uid = ? ORDER BY created_at DESC').all(req.user.uid);
  res.json({ tickets });
});

// ============================================================
// 9. АДМИН-ПАНЕЛЬ
// ============================================================
app.get('/api/admin/users', requireOwner, (req, res) => {
  const list = db.prepare(`
    SELECT uid, username, role, cookies, banned, ban_reason, sub_until, hwid, web_ip, client_ip, created_at
    FROM users ORDER BY uid ASC
  `).all();
  res.json({ users: list });
});

app.post('/api/admin/user/update', requireOwner, (req, res) => {
  const { username, role, cookies, sub_mode, reset_hwid, banned, ban_reason } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user) return res.status(404).json({ message: 'пользователь не найден' });

  let sub = user.sub_until;
  const now = Date.now();
  if (sub_mode === 'reset') sub = 0;
  if (sub_mode === 'lifetime') sub = -1;
  if (sub_mode === '30d') sub = (sub > now ? sub : now) + (30 * 86400000);

  db.prepare(`
    UPDATE users SET
      role = COALESCE(?, role),
      cookies = COALESCE(?, cookies),
      sub_until = ?,
      hwid = CASE WHEN ? = 1 THEN NULL ELSE hwid END,
      banned = COALESCE(?, banned),
      ban_reason = COALESCE(?, ban_reason)
    WHERE uid = ?
  `).run(role || null, cookies !== undefined ? parseInt(cookies, 10) : null, sub, reset_hwid ? 1 : 0, banned !== undefined ? (banned ? 1 : 0) : null, ban_reason || null, user.uid);

  res.json({ message: 'аккаунт обновлен' });
});

app.post('/api/admin/create-invite', requireOwner, (req, res) => {
  const code = generateInviteCode();
  db.prepare('INSERT INTO invites (code, used, created_at) VALUES (?, 0, ?)').run(code, Date.now());
  res.json({ invite: code });
});

app.get('/api/admin/invites', requireOwner, (req, res) => {
  const invites = db.prepare('SELECT * FROM invites ORDER BY created_at DESC').all();
  res.json({ invites });
});

// ============================================================
// 10. API ДЛЯ ИГРОВОГО ЛАУНЧЕРА
// ============================================================
app.post('/api/client/auth', (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) return res.status(400).json({ status: 'error', message: 'неверные параметры' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ status: 'error', message: 'неверный логин или пароль' });
  }

  if (user.banned) return res.status(403).json({ status: 'error', message: `бан: ${user.ban_reason}` });

  const buildStatus = db.prepare("SELECT value FROM system_meta WHERE key = 'build_status'").get()?.value || 'stable';
  if (buildStatus === 'updating' && user.role !== 'owner') {
    return res.status(403).json({ status: 'error', message: 'билд на техобслуживании' });
  }

  const now = Date.now();
  if (user.sub_until !== -1 && user.sub_until <= now) {
    return res.status(403).json({ status: 'error', message: 'подписка истекла' });
  }

  if (!user.hwid) {
    db.prepare('UPDATE users SET hwid = ? WHERE uid = ?').run(hwid.trim(), user.uid);
  } else if (user.hwid !== hwid.trim() && user.role !== 'owner') {
    return res.status(403).json({ status: 'error', message: 'HWID не совпадает' });
  }

  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
  db.prepare('UPDATE users SET client_ip = ?, last_launch = ? WHERE uid = ?').run(ip, now, user.uid);

  res.json({
    status: 'success',
    username: user.username,
    uid: user.uid,
    role: user.role,
    token: `loader_${crypto.randomBytes(16).toString('hex')}`
  });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[JOY] Сервер активен на порту ${PORT}`);
});
