const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data.db');

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initTables();
  }
  return db;
}

function initTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      tags TEXT DEFAULT '',
      url TEXT NOT NULL,
      note TEXT DEFAULT '',
      domain TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1,
      testable INTEGER DEFAULT 0,
      url_modified INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      is_muted INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS muted_users (
      username TEXT PRIMARY KEY,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Add testable column if upgrading from old schema
  const cols = db.prepare("PRAGMA table_info(sites)").all().map(c => c.name);
  if (!cols.includes('testable')) {
    db.exec('ALTER TABLE sites ADD COLUMN testable INTEGER DEFAULT 0');
  }
  if (!cols.includes('url_modified')) {
    db.exec('ALTER TABLE sites ADD COLUMN url_modified INTEGER DEFAULT 0');
  }

  // Add site_id to messages if upgrading from old schema
  const msgCols = db.prepare("PRAGMA table_info(messages)").all().map(c => c.name);
  if (msgCols.length > 0 && !msgCols.includes('site_id')) {
    db.exec('ALTER TABLE messages ADD COLUMN site_id INTEGER DEFAULT 0');
  }

  // Add is_admin to users if upgrading
  const userCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
  if (userCols.length > 0 && !userCols.includes('is_admin')) {
    db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0');
    // First existing user becomes admin
    db.exec('UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users)');
  }

  // Add unique constraint on domain if missing
  const indexes = db.prepare("PRAGMA index_list(sites)").all();
  const hasUniqueDomain = indexes.some(idx => idx.origin === 'u' && idx.name.includes('domain'));
  if (!hasUniqueDomain) {
    // Remove old name-based unique index if exists
    if (indexes.some(idx => idx.name === 'idx_sites_name')) {
      db.exec('DROP INDEX IF EXISTS idx_sites_name');
    }
    // Remove any duplicate rows first (keep the one with lowest id)
    db.exec(`
      DELETE FROM sites WHERE id NOT IN (
        SELECT MIN(id) FROM sites GROUP BY domain
      )
    `);
    db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_domain ON sites(domain)');
  }

  // Default settings
  const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  insertSetting.run('scrape_frequency', '60');
  insertSetting.run('last_scrape', '');
  insertSetting.run('next_scrape', '');
}

// --- Sites ---

function getAllSites() {
  return getDb().prepare('SELECT * FROM sites ORDER BY enabled DESC, created_at DESC').all();
}

function getEnabledSites() {
  return getDb().prepare('SELECT * FROM sites WHERE enabled = 1 ORDER BY created_at DESC').all();
}

function getSiteByName(name) {
  return getDb().prepare('SELECT * FROM sites WHERE name = ?').get(name);
}

function getSiteByDomain(domain) {
  return getDb().prepare('SELECT * FROM sites WHERE domain = ?').get(domain);
}

function insertSite(site) {
  const stmt = getDb().prepare(`
    INSERT INTO sites (name, tags, url, note, domain, enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))
  `);
  return stmt.run(site.name, site.tags, site.url, site.note, site.domain);
}

function updateSite(id, fields) {
  const sets = [];
  const vals = [];
  for (const [k, v] of Object.entries(fields)) {
    sets.push(`${k} = ?`);
    vals.push(v);
  }
  if (sets.length === 0) return;
  sets.push("updated_at = datetime('now')");
  vals.push(id);
  getDb().prepare(`UPDATE sites SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
}

function updateSiteByName(name, fields) {
  const site = getSiteByName(name);
  if (site) updateSite(site.id, fields);
}

function insertOrUpdateSite(site) {
  const existing = getSiteByName(site.name);
  if (existing) {
    updateSite(existing.id, {
      tags: site.tags,
      url: site.url,
      note: site.note,
      domain: site.domain,
    });
  } else {
    insertSite(site);
  }
}

function deleteSite(id) {
  getDb().prepare('DELETE FROM sites WHERE id = ?').run(id);
}

function deleteDisabledSites() {
  const result = getDb().prepare('DELETE FROM sites WHERE enabled = 0').run();
  return result.changes;
}

// --- Settings ---

function getSetting(key) {
  const row = getDb().prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  getDb().prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, String(value));
}

// --- Users ---

function createUser(username, password) {
  const count = getDb().prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
  const is_admin = count === 0 ? 1 : 0; // first user is admin
  const hash = bcrypt.hashSync(password, 10);
  return getDb().prepare('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)').run(username, hash, is_admin);
}

function getAdminUser() {
  return getDb().prepare('SELECT * FROM users WHERE is_admin = 1 LIMIT 1').get();
}

function getUser(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function verifyPassword(username, password) {
  const user = getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return null;
  const ok = bcrypt.compareSync(password, user.password);
  if (!ok) return null;
  return user;
}

function getAllUsers() {
  return getDb().prepare('SELECT * FROM users ORDER BY created_at DESC').all();
}

function setUserMuted(id, is_muted) {
  getDb().prepare('UPDATE users SET is_muted = ? WHERE id = ?').run(is_muted ? 1 : 0, id);
}

function setUserAdmin(id, is_admin) {
  getDb().prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(is_admin ? 1 : 0, id);
}

// --- Muted Users (standalone, no user account required) ---

function isUserMutedStandalone(username) {
  const row = getDb().prepare('SELECT 1 FROM muted_users WHERE username = ?').get(username);
  return !!row;
}

function muteUserStandalone(username) {
  getDb().prepare('INSERT OR IGNORE INTO muted_users (username) VALUES (?)').run(username);
}

// --- Messages ---

function getMessages(siteId, limit = 20) {
  return getDb().prepare('SELECT * FROM messages WHERE site_id = ? ORDER BY created_at DESC LIMIT ?').all(siteId, limit);
}

function addMessage(username, siteId, content) {
  const result = getDb().prepare('INSERT INTO messages (site_id, username, content) VALUES (?, ?, ?)').run(siteId, username, content);
  // Keep only latest 20 per site
  getDb().prepare('DELETE FROM messages WHERE site_id = ? AND id NOT IN (SELECT id FROM messages WHERE site_id = ? ORDER BY created_at DESC LIMIT 20)').run(siteId, siteId);
  return result;
}

function getMessageCounts() {
  const rows = getDb().prepare('SELECT site_id, COUNT(*) as cnt FROM messages GROUP BY site_id').all();
  const map = {};
  rows.forEach(r => { map[r.site_id] = r.cnt; });
  return map;
}

module.exports = {
  getAllSites,
  getEnabledSites,
  getSiteByName,
  getSiteByDomain,
  insertSite,
  updateSite,
  updateSiteByName,
  insertOrUpdateSite,
  deleteSite,
  deleteDisabledSites,
  getSetting,
  setSetting,
  getDb,
  createUser,
  getUser,
  getUserById,
  verifyPassword,
  getAllUsers,
  setUserMuted,
  setUserAdmin,
  isUserMutedStandalone,
  muteUserStandalone,
  getMessages,
  addMessage,
  getMessageCounts,
};
