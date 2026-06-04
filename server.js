const express = require('express');
const crypto = require('crypto');
const cron = require('node-cron');
const path = require('path');
const db = require('./db');
const { scrape } = require('./scraper');

const app = express();
const PORT = process.env.PORT || 3456;

app.use('/api', (req, res, next) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  next();
});
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

let cronJob = null;

// --- Auth (unified user system) ---

const tokens = new Map(); // token -> { username, isAdmin, expiry }

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Required: user must be logged in
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }
  const data = tokens.get(auth.slice(7));
  if (!data || Date.now() > data.expiry) {
    tokens.delete(auth.slice(7));
    return res.status(401).json({ error: '登录已过期' });
  }
  req.username = data.username;
  req.isAdmin = data.isAdmin;
  next();
}

// Required: user must be admin
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.isAdmin) return res.status(403).json({ error: '需要管理员权限' });
    next();
  });
}

// --- API: Auth ---

app.post('/api/user/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '用户名2-20个字符' });
  if (password.length < 3) return res.status(400).json({ error: '密码至少3位' });
  if (!/^[a-zA-Z0-9_一-鿿]+$/.test(username)) return res.status(400).json({ error: '用户名只能包含中英文、数字、下划线' });

  const existing = db.getUser(username);
  if (existing) return res.status(409).json({ error: '用户名已存在' });

  try {
    db.createUser(username.trim(), password);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '注册失败' });
  }
});

app.post('/api/user/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.verifyPassword(username, password);
  if (!user) {
    return res.status(403).json({ error: '用户名或密码错误' });
  }
  const token = generateToken();
  tokens.set(token, { username: user.username, isAdmin: !!user.is_admin, expiry: Date.now() + 7 * 24 * 3600 * 1000 });
  res.json({ ok: true, token, username: user.username, isAdmin: !!user.is_admin, is_muted: !!user.is_muted });
});

app.get('/api/user/me', requireAuth, (req, res) => {
  const user = db.getUser(req.username);
  if (!user) return res.status(404).json({ error: '用户不存在' });
  res.json({ username: user.username, isAdmin: !!user.is_admin, is_muted: !!user.is_muted });
});

// --- API: Users (admin only) ---

app.get('/api/users', requireAdmin, (req, res) => {
  res.json(db.getAllUsers());
});

app.put('/api/users/:id/mute', requireAdmin, (req, res) => {
  db.setUserMuted(Number(req.params.id), req.body.is_muted ? 1 : 0);
  res.json({ ok: true });
});

app.post('/api/users/mute-by-username', requireAdmin, (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: '用户名不能为空' });
  db.muteUserStandalone(username);
  // Also mute via user account if exists
  const user = db.getUser(username);
  if (user) db.setUserMuted(user.id, 1);
  res.json({ ok: true });
});

app.put('/api/users/:id/admin', requireAdmin, (req, res) => {
  db.setUserAdmin(Number(req.params.id), req.body.is_admin ? 1 : 0);
  res.json({ ok: true });
});

// --- API: Sites ---

app.get('/api/sites', (req, res) => {
  const hideDisabled = req.query.hide_disabled === 'true';
  const sites = hideDisabled ? db.getEnabledSites() : db.getAllSites();
  res.json(sites);
});

app.post('/api/sites', requireAdmin, (req, res) => {
  const { name, url, tags, note } = req.body;
  if (!name || !url) return res.status(400).json({ error: '名称和链接不能为空' });

  let domain = '';
  try { domain = new URL(url).hostname; } catch {}
  if (!domain) return res.status(400).json({ error: '链接格式无效' });

  const existing = db.getSiteByDomain(domain);
  if (existing) return res.status(409).json({ error: `域名 ${domain} 已存在（站点「${existing.name}」）` });

  try {
    db.insertSite({ name: name.trim(), tags: (tags || '').trim(), url: url.trim(), note: (note || '').trim(), domain });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '保存失败' });
  }
});

app.put('/api/sites/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { enabled, testable, url, name, tags, note } = req.body;
  const fields = {};

  if (enabled !== undefined) fields.enabled = enabled ? 1 : 0;
  if (testable !== undefined) fields.testable = testable ? 1 : 0;
  if (name !== undefined) fields.name = name.trim();
  if (tags !== undefined) fields.tags = tags.trim();
  if (note !== undefined) fields.note = note.trim();
  if (url !== undefined) {
    fields.url = url.trim();
    fields.url_modified = 1;
    try { fields.domain = new URL(url).hostname; } catch {}
  }

  if (Object.keys(fields).length) {
    db.updateSite(Number(id), fields);
    res.json({ ok: true });
  } else {
    res.status(400).json({ error: 'Nothing to update' });
  }
});

app.delete('/api/sites/:id', requireAdmin, (req, res) => {
  db.deleteSite(Number(req.params.id));
  res.json({ ok: true });
});

app.post('/api/sites/clear-disabled', requireAdmin, (req, res) => {
  const count = db.deleteDisabledSites();
  res.json({ ok: true, deleted: count });
});

// --- API: Scrape ---

app.post('/api/sites/refresh', async (req, res) => {
  try {
    const result = await scrape();
    scheduleNext();
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- API: Messages ---

app.get('/api/messages/:siteId', (req, res) => {
  res.json(db.getMessages(Number(req.params.siteId), 20));
});

app.post('/api/messages/:siteId', requireAuth, (req, res) => {
  const user = db.getUser(req.username);
  if (user && user.is_muted) return res.status(403).json({ error: '你已被禁言' });
  if (db.isUserMutedStandalone(req.username)) return res.status(403).json({ error: '你已被禁言' });

  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: '内容不能为空' });
  if (content.length > 500) return res.status(400).json({ error: '内容最多500字' });

  db.addMessage(req.username, Number(req.params.siteId), content.trim());
  res.json({ ok: true });
});

app.get('/api/message-counts', (req, res) => {
  res.json(db.getMessageCounts());
});

// --- API: Settings ---

app.get('/api/settings', (req, res) => {
  res.json({
    scrape_frequency: Number(db.getSetting('scrape_frequency')) || 60,
    last_scrape: db.getSetting('last_scrape') || '',
    next_scrape: db.getSetting('next_scrape') || '',
  });
});

app.put('/api/settings', (req, res) => {
  const { scrape_frequency } = req.body;
  if (scrape_frequency !== undefined) {
    const freq = Math.max(1, Number(scrape_frequency));
    db.setSetting('scrape_frequency', String(freq));
    scheduleCron(freq);
    res.json({ ok: true, scrape_frequency: freq });
  } else {
    res.status(400).json({ error: 'Nothing to update' });
  }
});

// --- API: Status ---

app.get('/api/status', (req, res) => {
  const total = db.getAllSites().length;
  const enabled = db.getEnabledSites().length;
  res.json({
    total, enabled, disabled: total - enabled,
    last_scrape: db.getSetting('last_scrape') || null,
    next_scrape: db.getSetting('next_scrape') || null,
    scrape_frequency: Number(db.getSetting('scrape_frequency')) || 60,
  });
});

// --- Cron ---

function scheduleNext() { db.setSetting('next_scrape', computeNextTime()); }

function computeNextTime() {
  const freq = Number(db.getSetting('scrape_frequency')) || 60;
  return new Date(Date.now() + freq * 60 * 1000).toISOString();
}

function scheduleCron(freqMinutes) {
  if (cronJob) cronJob.stop();
  const mins = Math.max(1, Number(freqMinutes) || 60);
  // node-cron supports minute granularity up to 59; for >59 use an hourly approximation
  if (mins > 59) {
    // Run at a specific minute every N hours
    const hours = Math.round(mins / 60);
    const minute = Math.min(59, mins % 60);
    cronJob = cron.schedule(`${minute} */${Math.max(1, hours)} * * *`, runScheduledScrape);
  } else {
    cronJob = cron.schedule(`*/${mins} * * * *`, runScheduledScrape);
  }
  db.setSetting('scrape_frequency', String(mins));
  scheduleNext();
}

async function runScheduledScrape() {
  try { await scrape(); scheduleNext(); } catch (e) { console.error('[cron]', e.message); }
}

// --- Start ---

app.listen(PORT, async () => {
  console.log(`Server running at http://localhost:${PORT}`);
  const sites = db.getAllSites();
  if (sites.length === 0) {
    try { const r = await scrape(); console.log(`[init] Scraped ${r.total} sites`); scheduleNext(); } catch (e) { console.error('[init]', e.message); }
  }
  scheduleCron(Number(db.getSetting('scrape_frequency')) || 60);
});
