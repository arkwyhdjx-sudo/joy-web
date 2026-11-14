const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'joy.sqlite'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS system_meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS users (
    uid INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    cookies INTEGER DEFAULT 0,
    banned INTEGER DEFAULT 0,
    ban_reason TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    security_pin TEXT DEFAULT NULL,
    avatar_color TEXT DEFAULT '#8b5cf6',
    avatar_media TEXT DEFAULT NULL,
    avatar_type TEXT DEFAULT NULL,
    hwid TEXT DEFAULT NULL,
    web_ip TEXT,
    client_ip TEXT,
    last_launch INTEGER DEFAULT NULL,
    sub_until INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    uid INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    used INTEGER DEFAULT 0,
    used_by TEXT DEFAULT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS promos (
    code TEXT PRIMARY KEY COLLATE NOCASE,
    days INTEGER DEFAULT 0,
    cookies INTEGER DEFAULT 0,
    discount_percent INTEGER DEFAULT 0,
    max_uses INTEGER DEFAULT 0,
    used_count INTEGER DEFAULT 0,
    expires_at INTEGER DEFAULT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS promo_history (
    code TEXT,
    uid INTEGER,
    activated_at INTEGER,
    PRIMARY KEY(code, uid)
  );

  CREATE TABLE IF NOT EXISTS cloud_items (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL, -- 'config' | 'lua'
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    author_uid INTEGER NOT NULL,
    author_username TEXT NOT NULL,
    price_cookies INTEGER DEFAULT 0, -- 0 до 10
    is_public INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS item_subs (
    item_id TEXT NOT NULL,
    user_uid INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(item_id, user_uid)
  );

  CREATE TABLE IF NOT EXISTS forum_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    tag TEXT DEFAULT 'обсуждение',
    pinned INTEGER DEFAULT 0,
    locked INTEGER DEFAULT 0,
    author_uid INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS forum_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER NOT NULL,
    author_uid INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(thread_id) REFERENCES forum_threads(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS support_tickets (
    id TEXT PRIMARY KEY,
    user_uid INTEGER NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT DEFAULT 'на рассмотрении',
    reply TEXT DEFAULT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    user_uid INTEGER NOT NULL,
    username TEXT NOT NULL,
    type TEXT NOT NULL, -- 'sub' | 'cookies'
    amount INTEGER NOT NULL,
    details TEXT,
    created_at INTEGER NOT NULL
  );
`);

// Инициализация дефолтного билда и инвайта
const getMeta = db.prepare('SELECT value FROM system_meta WHERE key = ?');
const setMeta = db.prepare('INSERT OR REPLACE INTO system_meta (key, value) VALUES (?, ?)');

if (!getMeta.get('build_status')) setMeta.run('build_status', 'stable');

const checkDevInvite = db.prepare('SELECT code FROM invites WHERE code = ?').get('JOY-999-DEV');
if (!checkDevInvite) {
  db.prepare('INSERT INTO invites (code, used, created_at) VALUES (?, 0, ?)').run('JOY-999-DEV', Date.now());
}

module.exports = db;
