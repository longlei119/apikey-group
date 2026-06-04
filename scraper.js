const axios = require('axios');
const db = require('./db');

const SOURCE_URL = 'https://apinev.888.moe/sites.txt';

function parseDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

function parseSites(text) {
  return text
    .split('\n')
    .filter(line => line.trim())
    .map(line => {
      const parts = line.split('|');
      if (parts.length < 3) return null;
      const name = parts[0].trim();
      const tags = parts[1].trim();
      const url = parts[2].trim();
      const note = parts[3] ? parts[3].trim() : '';
      const domain = parseDomain(url);
      return { name, tags, url, note, domain };
    })
    .filter(Boolean);
}

async function scrape() {
  console.log(`[scraper] Fetching ${SOURCE_URL}...`);
  const res = await axios.get(SOURCE_URL, { timeout: 15000, responseType: 'text', responseEncoding: 'utf-8' });
  const sites = parseSites(res.data);
  console.log(`[scraper] Parsed ${sites.length} sites`);

  let inserted = 0;
  let updated = 0;

  // Upsert by domain: new → insert, existing → update name/tags/note only, keep user's URL
  const upsertStmt = db.getDb().prepare(`
    INSERT INTO sites (name, tags, url, note, domain, enabled, testable, url_modified, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 1, 0, 0, datetime('now'), datetime('now'))
    ON CONFLICT(domain) DO UPDATE SET
      name = excluded.name,
      tags = excluded.tags,
      note = excluded.note,
      updated_at = datetime('now')
  `);

  const tx = db.getDb().transaction(() => {
    for (const site of sites) {
      if (!site.domain) continue; // skip invalid domains
      const existing = db.getSiteByDomain(site.domain);
      if (existing) updated++;
      else inserted++;
      upsertStmt.run(site.name, site.tags, site.url, site.note, site.domain);
    }
  });

  tx();

  const now = new Date().toISOString();
  db.setSetting('last_scrape', now);

  console.log(`[scraper] Done: ${inserted} inserted, ${updated} updated`);
  return { inserted, updated, total: sites.length, time: now };
}

module.exports = { scrape, parseSites };
