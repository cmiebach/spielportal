const express = require('express');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const STORAGE_DIR = path.join(__dirname, 'storage');
const UPLOADS_DIR = path.join(STORAGE_DIR, 'uploads');
const DB_PATH = path.join(STORAGE_DIR, 'spielportal.db');
const HOUSE_PASSWORD = process.env.HOUSE_PASSWORD || 'change-me';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-session-secret';
const SESSION_COOKIE = 'spielportal_session';

const DEFAULT_GAME_TYPES = [
  { slug: 'dart', name: 'Dart', scoringMode: 'higher_wins' },
  { slug: 'billard', name: 'Billard', scoringMode: 'higher_wins' },
  { slug: 'golf', name: 'Golf', scoringMode: 'lower_wins' },
  { slug: 'fussball_tzt', name: 'Fußball Tor zu Tor', scoringMode: 'higher_wins' },
  { slug: 'capsen', name: 'Capsen', scoringMode: 'higher_wins' },
];

fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    color TEXT NOT NULL DEFAULT '#22c55e',
    avatar_path TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS game_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    scoring_mode TEXT NOT NULL CHECK(scoring_mode IN ('higher_wins', 'lower_wins')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    game_type_id INTEGER NOT NULL REFERENCES game_types(id),
    played_at TEXT NOT NULL,
    notes TEXT,
    photo_path TEXT,
    created_by_profile_id INTEGER REFERENCES profiles(id),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS match_sides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_id INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
    side_name TEXT NOT NULL,
    score REAL NOT NULL,
    is_winner INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS match_side_members (
    side_id INTEGER NOT NULL REFERENCES match_sides(id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (side_id, profile_id)
  );
`);

const insertGameType = db.prepare(`
  INSERT INTO game_types (slug, name, scoring_mode)
  VALUES (@slug, @name, @scoringMode)
  ON CONFLICT(slug) DO UPDATE SET
    name = excluded.name,
    scoring_mode = excluded.scoring_mode,
    is_active = 1
`);
DEFAULT_GAME_TYPES.forEach((gameType) => insertGameType.run(gameType));
db.prepare(`UPDATE game_types SET is_active = 0 WHERE slug IN ('tennis', 'padel', 'squash', 'fussball')`).run();

// Migration: extra_data column for game-specific side data (e.g. Capsen Restbecher/Verlängerungen)
const columns = db.prepare("PRAGMA table_info(match_sides)").all();
if (!columns.find(c => c.name === 'extra_data')) {
  db.exec('ALTER TABLE match_sides ADD COLUMN extra_data TEXT');
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const safeBase = file.originalname
        .replace(/\.[^.]+$/, '')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 40) || 'bild';
      const ext = path.extname(file.originalname || '').toLowerCase() || '.jpg';
      cb(null, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}-${safeBase}${ext}`);
    }
  }),
  limits: { fileSize: 8 * 1024 * 1024 }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(UPLOADS_DIR));

app.use((req, _res, next) => {
  req.currentUser = null;
  const token = req.cookies?.[SESSION_COOKIE];
  if (!token) return next();

  const session = db.prepare(`
    SELECT s.token_hash, p.id, p.name, p.color
    FROM sessions s
    JOIN profiles p ON p.id = s.profile_id
    WHERE s.token_hash = ?
  `).get(hashToken(token));

  if (session) {
    req.currentUser = { id: session.id, name: session.name, color: session.color };
    db.prepare('UPDATE sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ?').run(session.token_hash);
  }

  next();
});

function hashToken(token) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(token).digest('hex');
}

function issueSession(res, profileId) {
  const token = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions (token_hash, profile_id) VALUES (?, ?)').run(hashToken(token), profileId);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 90
  });
}

function clearSession(req, res) {
  const token = req.cookies?.[SESSION_COOKIE];
  if (token) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(token));
  }
  res.clearCookie(SESSION_COOKIE);
}

function requireUser(req, res, next) {
  if (!req.currentUser) {
    return res.redirect('/login');
  }
  next();
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDate(value) {
  if (!value) return '—';
  return new Date(value).toLocaleString('de-DE', {
    dateStyle: 'medium',
    timeStyle: 'short'
  });
}

function safeJson(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function nav(req) {
  const authBlock = req.currentUser
    ? `<div class="user-pill"><span class="dot" style="background:${escapeHtml(req.currentUser.color)}"></span>${escapeHtml(req.currentUser.name)}</div>
       <form method="POST" action="/logout"><button class="ghost small" type="submit">Abmelden</button></form>`
    : `<a class="button ghost small" href="/login">Login</a>`;

  return `
    <nav class="desktop-nav">
      <a href="/">Dashboard</a>
      <a href="/matches">Spiele</a>
      <a href="/matches/new">Neues Spiel</a>
      <a href="/leaderboard">Leaderboards</a>
      <a href="/profiles">Profile</a>
      <div class="nav-auth">${authBlock}</div>
    </nav>
    <nav class="bottom-nav">
      <a href="/" class="bnav-item">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>
        <span>Home</span>
      </a>
      <a href="/matches" class="bnav-item">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/></svg>
        <span>Spiele</span>
      </a>
      <a href="/matches/new" class="bnav-item bnav-plus">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg>
      </a>
      <a href="/leaderboard" class="bnav-item">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>
        <span>Ranking</span>
      </a>
      <a href="/profiles" class="bnav-item">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
        <span>Profile</span>
      </a>
    </nav>
  `;
}

function layout(req, title, body, flash = '') {
  return `<!DOCTYPE html>
  <html lang="de">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      :root {
        --bg: #09111f;
        --panel: #101c2f;
        --panel-2: #17243b;
        --text: #edf2f7;
        --muted: #98a7bf;
        --line: #223252;
        --green: #22c55e;
        --blue: #38bdf8;
        --orange: #fb923c;
        --danger: #ef4444;
        --gold: #F0B429;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
        background: linear-gradient(180deg, #060d18 0%, #0a1525 100%);
        color: var(--text);
      }
      a { color: inherit; text-decoration: none; }
      .page { max-width: 980px; margin: 0 auto; padding: 18px 14px 48px; }
      .hero { display: grid; gap: 10px; margin: 12px 0 18px; }
      .eyebrow { color: var(--gold); font-size: 13px; letter-spacing: 0.04em; text-transform: uppercase; font-weight: 700; }
      h1, h2, h3 { margin: 0; }
      .subtle { color: var(--muted); }
      .desktop-nav { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 18px; }
      .desktop-nav a, .button, button {
        border: 0; border-radius: 14px; padding: 14px 18px; min-height: 48px;
        background: var(--gold); color: #1a1204; font-weight: 700; cursor: pointer;
        font-size: 14px; display: inline-flex; align-items: center; justify-content: center;
      }
      .desktop-nav a:hover, .button:hover, button:hover { filter: brightness(1.08); }
      .ghost { background: var(--panel); color: var(--text); border: 1px solid var(--line); }
      .small { padding: 12px 14px; min-height: 48px; font-size: 14px; }
      .nav-auth { margin-left: auto; display: flex; gap: 8px; align-items: center; }
      .user-pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 14px; border-radius: 999px;
        background: var(--panel); border: 1px solid var(--line);
      }
      .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
      .grid { display: grid; gap: 14px; }
      .grid-2 { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
      .grid-3 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
      .card {
        background: rgba(16, 28, 47, 0.94); border: 1px solid var(--line);
        border-radius: 20px; padding: 16px; box-shadow: 0 14px 40px rgba(0,0,0,0.2);
        transition: border-color 0.2s;
      }
      .card:hover { border-color: rgba(240,180,41,0.25); }
      .card h2, .card h3 { margin-bottom: 12px; }
      .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
      .stat { background: var(--panel-2); border-radius: 18px; border: 1px solid var(--line); padding: 14px; }
      .stat-value { font-size: 28px; font-weight: 800; color: var(--gold); }
      .stat-label { font-size: 13px; color: var(--muted); }
      .match { display: grid; gap: 10px; padding: 14px 0; border-bottom: 1px solid var(--line); }
      .match:last-child { border-bottom: 0; padding-bottom: 0; }
      .row { display: flex; gap: 10px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
      .chips { display: flex; flex-wrap: wrap; gap: 8px; }
      .chip {
        display: inline-flex; align-items: center; gap: 6px;
        padding: 7px 10px; border-radius: 999px; font-size: 13px;
        background: #0a1526; border: 1px solid var(--line); color: var(--muted);
      }
      .tag { background: rgba(240,180,41,0.12); color: #f5d78e; }
      .winner { color: var(--green); font-weight: 800; }
      form { display: grid; gap: 12px; }
      label { display: grid; gap: 6px; font-size: 14px; color: var(--muted); }
      input, textarea, select {
        width: 100%; border-radius: 14px; border: 1px solid var(--line);
        background: #081321; color: var(--text); padding: 14px 16px; min-height: 48px; font: inherit;
      }
      textarea { min-height: 100px; resize: vertical; }
      .flash {
        margin-bottom: 14px; padding: 12px 14px; border-radius: 16px;
        border: 1px solid rgba(240,180,41,0.35); background: rgba(240,180,41,0.1); color: #f5d78e;
      }
      .profile-list { display: grid; gap: 10px; }
      .profile-card {
        display: flex; align-items: center; gap: 12px;
        padding: 12px; border-radius: 16px; border: 1px solid var(--line); background: #0b1525;
      }
      .avatar {
        width: 42px; height: 42px; border-radius: 14px;
        display: grid; place-items: center; font-size: 15px; font-weight: 800; color: #08111d;
      }
      .side-card {
        border: 1px solid var(--line); background: #0b1525;
        border-radius: 18px; padding: 14px; display: grid; gap: 12px;
      }
      .profile-btn-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 8px; }
      .profile-btn {
        display: flex; flex-direction: column; align-items: center; gap: 6px;
        padding: 12px 8px; border-radius: 14px; background: #09111f;
        border: 2px solid var(--line); cursor: pointer; min-height: 48px;
        color: var(--text); font-size: 12px; transition: border-color 0.15s, background 0.15s;
      }
      .profile-btn.selected { border-color: var(--gold); background: rgba(240,180,41,0.08); }
      .profile-btn-avatar {
        width: 40px; height: 40px; border-radius: 12px;
        display: grid; place-items: center; font-size: 14px; font-weight: 700; color: #08111d;
        background-size: cover; background-position: center;
      }
      .winner-toggle {
        transition: background 0.15s, color 0.15s;
      }
      .winner-toggle.active { background: var(--gold) !important; color: #1a1204 !important; border-color: var(--gold) !important; }
      .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
      .checkbox-pill {
        display: flex; align-items: center; gap: 8px;
        padding: 12px 14px; border-radius: 14px; background: #09111f; border: 1px solid var(--line);
        min-height: 48px;
      }
      .checkbox-pill input { width: auto; margin: 0; }
      .helper { font-size: 13px; color: var(--muted); }
      .empty { color: var(--muted); padding: 6px 0; }
      img.match-photo { width: 100%; border-radius: 16px; border: 1px solid var(--line); }

      /* Bottom Navigation */
      .bottom-nav {
        display: none; position: fixed; bottom: 0; left: 0; right: 0; z-index: 100;
        background: rgba(16,28,47,0.96); backdrop-filter: blur(12px);
        border-top: 1px solid var(--line);
        padding: 6px 0 env(safe-area-inset-bottom, 8px);
        justify-content: space-around; align-items: center;
      }
      .bnav-item {
        display: flex; flex-direction: column; align-items: center; gap: 2px;
        font-size: 10px; color: var(--muted); padding: 6px 12px;
        text-decoration: none; min-width: 48px; min-height: 48px;
        justify-content: center; background: none; border: none;
      }
      .bnav-item:hover, .bnav-item:active { color: var(--gold); }
      .bnav-plus {
        background: var(--gold); color: #1a1204; border-radius: 50%;
        width: 52px; height: 52px; margin-top: -18px; padding: 0;
        box-shadow: 0 4px 16px rgba(240,180,41,0.3);
        min-width: 52px;
      }
      .bnav-plus:hover, .bnav-plus:active { color: #1a1204; background: var(--gold); filter: brightness(1.1); }

      @media (max-width: 640px) {
        .desktop-nav { display: none; }
        .bottom-nav { display: flex; }
        .page { padding: 14px 12px 90px; }
      }
    </style>
  </head>
  <body>
    <main class="page">
      <section class="hero">
        <div class="eyebrow">Spielportal</div>
        <h1>${escapeHtml(title)}</h1>
        <div class="subtle">Mobile-first, hausintern, alles editierbar, lokal gespeichert.</div>
      </section>
      ${nav(req)}
      ${flash ? `<div class="flash">${flash}</div>` : ''}
      ${body}
    </main>
  </body>
  </html>`;
}

function getProfiles() {
  return db.prepare('SELECT id, name, color, avatar_path AS avatarPath, created_at FROM profiles ORDER BY lower(name)').all();
}

function getGameTypes() {
  return db.prepare('SELECT id, slug, name, scoring_mode AS scoringMode FROM game_types WHERE is_active = 1 ORDER BY name').all();
}

function getRecentMatches(limit = 20) {
  const matches = db.prepare(`
    SELECT m.id, m.played_at, m.notes, m.photo_path AS photoPath,
           gt.name AS gameName, gt.scoring_mode AS scoringMode,
           p.name AS createdBy
    FROM matches m
    JOIN game_types gt ON gt.id = m.game_type_id
    LEFT JOIN profiles p ON p.id = m.created_by_profile_id
    ORDER BY datetime(m.played_at) DESC, m.id DESC
    LIMIT ?
  `).all(limit);

  const sidesStmt = db.prepare(`
    SELECT ms.id, ms.side_name AS sideName, ms.score, ms.is_winner AS isWinner,
           GROUP_CONCAT(pr.name, ', ') AS memberNames
    FROM match_sides ms
    JOIN match_side_members msm ON msm.side_id = ms.id
    JOIN profiles pr ON pr.id = msm.profile_id
    WHERE ms.match_id = ?
    GROUP BY ms.id
    ORDER BY ms.id
  `);

  for (const match of matches) {
    match.sides = sidesStmt.all(match.id);
  }

  return matches;
}

function getMatchById(id) {
  const match = db.prepare(`
    SELECT m.id, m.game_type_id AS gameTypeId, m.played_at, m.notes, m.photo_path AS photoPath,
           gt.name AS gameName, gt.slug AS gameSlug, gt.scoring_mode AS scoringMode,
           p.name AS createdBy, m.created_by_profile_id AS createdById
    FROM matches m
    JOIN game_types gt ON gt.id = m.game_type_id
    LEFT JOIN profiles p ON p.id = m.created_by_profile_id
    WHERE m.id = ?
  `).get(id);
  if (!match) return null;

  match.sides = db.prepare(`
    SELECT ms.id, ms.side_name AS sideName, ms.score, ms.is_winner AS isWinner, ms.extra_data AS extraData
    FROM match_sides ms WHERE ms.match_id = ? ORDER BY ms.id
  `).all(match.id);

  for (const side of match.sides) {
    side.profileIds = db.prepare(`
      SELECT profile_id FROM match_side_members WHERE side_id = ?
    `).all(side.id).map(r => r.profile_id);
    side.extraData = side.extraData ? JSON.parse(side.extraData) : null;
  }

  return match;
}

function getProfileStats() {
  return db.prepare(`
    SELECT p.id, p.name, p.color,
           COUNT(DISTINCT ms.match_id) AS games,
           COALESCE(SUM(ms.is_winner), 0) AS wins
    FROM profiles p
    LEFT JOIN match_side_members msm ON msm.profile_id = p.id
    LEFT JOIN match_sides ms ON ms.id = msm.side_id
    GROUP BY p.id
    ORDER BY wins DESC, games DESC, lower(p.name) ASC
  `).all().map((row) => ({
    ...row,
    losses: Math.max(0, row.games - row.wins),
    winRate: row.games ? Math.round((row.wins / row.games) * 100) : 0
  }));
}

function getDuoStats() {
  const rows = db.prepare(`
    SELECT ms.is_winner AS isWinner, ms.match_id AS matchId,
           GROUP_CONCAT(p.id, '|') AS profileIds,
           GROUP_CONCAT(p.name, '|') AS profileNames
    FROM match_sides ms
    JOIN match_side_members msm ON msm.side_id = ms.id
    JOIN profiles p ON p.id = msm.profile_id
    GROUP BY ms.id
    HAVING COUNT(*) = 2
  `).all();

  const grouped = new Map();
  for (const row of rows) {
    const ids = row.profileIds.split('|').map(Number).sort((a, b) => a - b);
    const names = row.profileNames.split('|').sort((a, b) => a.localeCompare(b, 'de'));
    const key = ids.join('-');
    if (!grouped.has(key)) {
      grouped.set(key, { ids, names, games: 0, wins: 0 });
    }
    const entry = grouped.get(key);
    entry.games += 1;
    entry.wins += Number(row.isWinner);
  }

  return [...grouped.values()]
    .map((entry) => ({ ...entry, winRate: entry.games ? Math.round((entry.wins / entry.games) * 100) : 0 }))
    .sort((a, b) => b.wins - a.wins || b.games - a.games || a.names.join(',').localeCompare(b.names.join(','), 'de'));
}

function avatarHtml(profile, size = 42) {
  if (profile.avatarPath) {
    return `<img src="${escapeHtml(profile.avatarPath)}" alt="${escapeHtml(profile.name)}" style="width:${size}px;height:${size}px;border-radius:14px;object-fit:cover;border:2px solid var(--line);" />`;
  }
  return `<div class="avatar" style="background:${escapeHtml(profile.color)};width:${size}px;height:${size}px;">${escapeHtml(profile.name.slice(0,2).toUpperCase())}</div>`;
}

function removeUploadedFile(file) {
  if (file?.path && fs.existsSync(file.path)) {
    fs.unlinkSync(file.path);
  }
}

function redirectWithMessage(res, url, message) {
  res.redirect(`${url}${url.includes('?') ? '&' : '?'}msg=${encodeURIComponent(message)}`);
}

app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

app.get('/login', (req, res) => {
  const profiles = getProfiles();
  const empty = profiles.length === 0;
  const body = `
    <div class="grid grid-2">
      <section class="card">
        <h2>Haus-Login</h2>
        ${empty ? `<p class="empty">Noch kein Profil vorhanden. Leg zuerst eins an.</p>` : `
          <form method="POST" action="/login">
            <label>Haus-Passwort
              <input type="password" name="housePassword" placeholder="Haus-Passwort" required />
            </label>
            <label>Profil auswählen
              <select name="profileId" required>
                <option value="">Bitte wählen</option>
                ${profiles.map((profile) => `<option value="${profile.id}">${escapeHtml(profile.name)}</option>`).join('')}
              </select>
            </label>
            <button type="submit">Einloggen</button>
          </form>
        `}
      </section>
      <section class="card">
        <h2>Profile</h2>
        <div class="profile-list">
          ${profiles.length ? profiles.map((profile) => `
            <div class="profile-card">
              <div class="avatar" style="background:${escapeHtml(profile.color)}">${escapeHtml(profile.name.slice(0, 2).toUpperCase())}</div>
              <div>
                <div><strong>${escapeHtml(profile.name)}</strong></div>
                <div class="helper">Profil kann von allen im Haus genutzt werden.</div>
              </div>
            </div>
          `).join('') : '<div class="empty">Noch keine Profile.</div>'}
        </div>
        <div style="margin-top:12px;"><a class="button ghost" href="/profiles/new">Neues Profil anlegen</a></div>
      </section>
    </div>
  `;
  res.send(layout(req, 'Login & Profilwahl', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.post('/login', (req, res) => {
  const { housePassword, profileId } = req.body;
  if (housePassword !== HOUSE_PASSWORD) {
    return redirectWithMessage(res, '/login', 'Falsches Haus-Passwort.');
  }
  const profile = db.prepare('SELECT id FROM profiles WHERE id = ?').get(Number(profileId));
  if (!profile) {
    return redirectWithMessage(res, '/login', 'Profil nicht gefunden.');
  }
  issueSession(res, profile.id);
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  clearSession(req, res);
  redirectWithMessage(res, '/login', 'Abgemeldet.');
});

app.get('/profiles', requireUser, (req, res) => {
  const profiles = getProfiles();
  const body = `
    <div class="grid grid-2">
      <section class="card">
        <h2>Bestehende Profile</h2>
        <div class="profile-list">
          ${profiles.length ? profiles.map((profile) => `
            <div class="profile-card">
              ${avatarHtml(profile, 42)}
              <div style="flex:1">
                <div><strong>${escapeHtml(profile.name)}</strong></div>
                <div class="helper">Erstellt: ${formatDate(profile.created_at)}</div>
              </div>
              <a class="button ghost small" href="/profiles/${profile.id}/avatar">📷</a>
            </div>
          `).join('') : '<div class="empty">Noch keine Profile.</div>'}
        </div>
      </section>
      <section class="card">
        <h2>Neues Profil</h2>
        <form method="POST" action="/profiles">
          <label>Haus-Passwort
            <input type="password" name="housePassword" required />
          </label>
          <label>Name
            <input type="text" name="name" maxlength="40" placeholder="z.B. Caspar" required />
          </label>
          <label>Farbe
            <input type="color" name="color" value="#22c55e" required />
          </label>
          <button type="submit">Profil anlegen</button>
        </form>
      </section>
    </div>
  `;
  res.send(layout(req, 'Profile', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.get('/profiles/:id/avatar', requireUser, (req, res) => {
  const profile = db.prepare('SELECT id, name, color, avatar_path AS avatarPath FROM profiles WHERE id = ?').get(Number(req.params.id));
  if (!profile) return res.redirect('/profiles');
  const body = `
    <section class="card" style="max-width:480px;margin:0 auto;">
      <h2>Profilbild für ${escapeHtml(profile.name)}</h2>
      <div style="display:flex;justify-content:center;margin:16px 0;">
        ${avatarHtml(profile, 96)}
      </div>
      <form method="POST" action="/profiles/${profile.id}/avatar" enctype="multipart/form-data">
        <label>Haus-Passwort
          <input type="password" name="housePassword" required />
        </label>
        <label>Neues Foto (max. 8 MB)
          <input type="file" name="avatar" accept="image/*" required />
        </label>
        <button type="submit">Bild hochladen</button>
      </form>
      ${profile.avatarPath ? `
        <form method="POST" action="/profiles/${profile.id}/avatar/delete" style="margin-top:10px;">
          <button class="ghost small" type="submit" style="width:100%;color:var(--danger);border-color:var(--danger);">Bild entfernen</button>
        </form>
      ` : ''}
      <div style="margin-top:12px;"><a class="button ghost small" href="/profiles">← Zurück</a></div>
    </section>
  `;
  res.send(layout(req, 'Profilbild', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.post('/profiles/:id/avatar', requireUser, upload.single('avatar'), (req, res) => {
  const profile = db.prepare('SELECT id, avatar_path AS avatarPath FROM profiles WHERE id = ?').get(Number(req.params.id));
  if (!profile) { removeUploadedFile(req.file); return res.redirect('/profiles'); }
  if (req.body.housePassword !== HOUSE_PASSWORD) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, `/profiles/${req.params.id}/avatar`, 'Falsches Haus-Passwort.');
  }
  if (!req.file) return redirectWithMessage(res, `/profiles/${req.params.id}/avatar`, 'Kein Bild ausgewählt.');
  // altes Bild löschen
  if (profile.avatarPath) {
    const oldPath = path.join(UPLOADS_DIR, path.basename(profile.avatarPath));
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
  }
  db.prepare('UPDATE profiles SET avatar_path = ? WHERE id = ?').run(`/uploads/${req.file.filename}`, profile.id);
  redirectWithMessage(res, `/profiles/${req.params.id}/avatar`, 'Profilbild gespeichert!');
});

app.post('/profiles/:id/avatar/delete', requireUser, (req, res) => {
  const profile = db.prepare('SELECT id, avatar_path AS avatarPath FROM profiles WHERE id = ?').get(Number(req.params.id));
  if (!profile) return res.redirect('/profiles');
  if (profile.avatarPath) {
    const oldPath = path.join(UPLOADS_DIR, path.basename(profile.avatarPath));
    if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
  }
  db.prepare('UPDATE profiles SET avatar_path = NULL WHERE id = ?').run(profile.id);
  redirectWithMessage(res, `/profiles/${req.params.id}/avatar`, 'Profilbild entfernt.');
});

app.get('/profiles/new', (req, res) => {
  const body = `
    <section class="card" style="max-width:560px; margin:0 auto;">
      <h2>Neues Profil anlegen</h2>
      <form method="POST" action="/profiles">
        <label>Haus-Passwort
          <input type="password" name="housePassword" required />
        </label>
        <label>Name
          <input type="text" name="name" maxlength="40" placeholder="z.B. Caspar" required />
        </label>
        <label>Farbe
          <input type="color" name="color" value="#22c55e" required />
        </label>
        <button type="submit">Profil anlegen</button>
      </form>
    </section>
  `;
  res.send(layout(req, 'Profil erstellen', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.post('/profiles', (req, res) => {
  const { housePassword, name, color } = req.body;
  const trimmedName = String(name || '').trim();
  const safeColor = /^#[0-9a-fA-F]{6}$/.test(color || '') ? color : '#22c55e';
  if (housePassword !== HOUSE_PASSWORD) {
    return redirectWithMessage(res, '/profiles/new', 'Falsches Haus-Passwort.');
  }
  if (!trimmedName || trimmedName.length < 2) {
    return redirectWithMessage(res, '/profiles/new', 'Name ist zu kurz.');
  }
  try {
    const result = db.prepare('INSERT INTO profiles (name, color) VALUES (?, ?)').run(trimmedName, safeColor);
    clearSession(req, res);
    issueSession(res, result.lastInsertRowid);
    res.redirect('/');
  } catch (error) {
    if (String(error.message).includes('UNIQUE')) {
      return redirectWithMessage(res, '/profiles/new', 'Dieses Profil gibt es schon.');
    }
    throw error;
  }
});

app.get('/', requireUser, (req, res) => {
  const matches = getRecentMatches(6);
  const stats = getProfileStats();
  const gameTypes = getGameTypes();
  const profiles = getProfiles();

  const body = `
    <section class="card" style="margin-bottom:14px; border: 1px solid rgba(240,180,41,0.3);">
      <div class="row"><h3 style="color:var(--gold);">Schnellerfassung</h3></div>
      <div class="helper" style="margin-bottom:10px;">1v1 Spiel schnell eintragen</div>
      <form action="/matches/new" method="GET" style="display:flex; flex-wrap:wrap; gap:10px; align-items:end;">
        <label style="flex:1;min-width:120px;">Spielart
          <select name="gameTypeId" required>
            ${gameTypes.map(gt => `<option value="${gt.id}">${escapeHtml(gt.name)}</option>`).join('')}
          </select>
        </label>
        <label style="flex:1;min-width:100px;">Spieler 1
          <select name="p1" required>
            <option value="">---</option>
            ${profiles.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('')}
          </select>
        </label>
        <label style="flex:1;min-width:100px;">Spieler 2
          <select name="p2" required>
            <option value="">---</option>
            ${profiles.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join('')}
          </select>
        </label>
        <button type="submit" style="min-height:48px;background:var(--gold);color:#1a1204;">Los</button>
      </form>
    </section>

    <section class="stats">
      <div class="stat"><div class="stat-value">${matches.length}</div><div class="stat-label">Letzte Spiele</div></div>
      <div class="stat"><div class="stat-value">${stats.length}</div><div class="stat-label">Profile</div></div>
      <div class="stat"><div class="stat-value">${gameTypes.length}</div><div class="stat-label">Spielarten</div></div>
    </section>

    <div class="grid grid-2" style="margin-top:14px;">
      <section class="card">
        <div class="row"><h2>Letzte Spiele</h2><a class="button ghost small" href="/matches/new">+ Neues Spiel</a></div>
        ${matches.length ? matches.map((match) => `
          <article class="match">
            <div class="row">
              <div class="chips">
                <span class="chip tag">${escapeHtml(match.gameName)}</span>
                <span class="chip">${formatDate(match.played_at)}</span>
              </div>
              <div class="helper">eingetragen von ${escapeHtml(match.createdBy || 'unbekannt')}</div>
            </div>
            <div>
              ${match.sides.map((side) => `<div><span class="${side.isWinner ? 'winner' : ''}">${side.isWinner ? '🏆 ' : ''}${escapeHtml(side.sideName)}</span>: ${escapeHtml(side.memberNames)} — <strong>${side.score}</strong></div>`).join('')}
            </div>
            ${match.notes ? `<div class="helper">${escapeHtml(match.notes)}</div>` : ''}
            <a href="/matches/${match.id}/edit" class="ghost small" style="justify-self:start;font-size:12px;padding:8px 12px;">Bearbeiten</a>
          </article>
        `).join('') : '<div class="empty">Noch keine Spiele eingetragen.</div>'}
      </section>

      <section class="card">
        <h2>Schnelles Leaderboard</h2>
        ${stats.length ? stats.slice(0, 8).map((profile, index) => `
          <div class="match">
            <div class="row">
              <div style="display:flex; align-items:center; gap:10px;">
                <div class="avatar" style="background:${escapeHtml(profile.color)}">${index + 1}</div>
                <div>
                  <div><strong>${escapeHtml(profile.name)}</strong></div>
                  <div class="helper">${profile.games} Spiele · ${profile.losses} Niederlagen</div>
                </div>
              </div>
              <div class="winner">${profile.wins} Siege</div>
            </div>
          </div>
        `).join('') : '<div class="empty">Noch keine Stats vorhanden.</div>'}
      </section>
    </div>
  `;

  res.send(layout(req, 'Dashboard', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.get('/matches', requireUser, (req, res) => {
  const matches = getRecentMatches(50);
  const body = `
    <section class="card">
      <div class="row"><h2>Alle Spiele</h2><a class="button ghost small" href="/matches/new">+ Neues Spiel</a></div>
      ${matches.length ? matches.map((match) => `
        <article class="match">
          <div class="row">
            <div class="chips">
              <span class="chip tag">${escapeHtml(match.gameName)}</span>
              <span class="chip">${formatDate(match.played_at)}</span>
            </div>
            <div class="helper">eingetragen von ${escapeHtml(match.createdBy || 'unbekannt')}</div>
          </div>
          <div>
            ${match.sides.map((side) => `<div><span class="${side.isWinner ? 'winner' : ''}">${side.isWinner ? '🏆 ' : ''}${escapeHtml(side.sideName)}</span>: ${escapeHtml(side.memberNames)} — <strong>${side.score}</strong></div>`).join('')}
          </div>
          ${match.notes ? `<div class="helper">${escapeHtml(match.notes)}</div>` : ''}
          ${match.photoPath ? `<a href="${escapeHtml(match.photoPath)}" target="_blank" rel="noreferrer"><img class="match-photo" src="${escapeHtml(match.photoPath)}" alt="Matchfoto" /></a>` : ''}
          <a href="/matches/${match.id}/edit" class="ghost small" style="justify-self:start;font-size:12px;padding:8px 12px;">Bearbeiten</a>
        </article>
      `).join('') : '<div class="empty">Noch keine Spiele vorhanden.</div>'}
    </section>
  `;
  res.send(layout(req, 'Spiele', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.get('/matches/new', requireUser, (req, res) => {
  const profiles = getProfiles();
  const gameTypes = getGameTypes();

  const GOLF_PLAETZE = {
    'Bades Huk (18 Loch, Par 72)': {
      loecher: 18,
      par: {1:4,2:5,3:4,4:3,5:4,6:4,7:5,8:4,9:3,10:4,11:4,12:3,13:5,14:4,15:4,16:3,17:5,18:4}
    },
    'Eigener Platz': null
  };

  const GOLF_MODI = [
    { id: 'stroke', name: 'Stroke Play', info: 'Gesamtschlaege zaehlen - wenigste gewinnt.' },
    { id: 'match',  name: 'Match Play',  info: 'Jedes Loch einzeln - wer mehr Loecher gewinnt, siegt.' },
    { id: 'scramble', name: 'Scramble', info: 'Team spielt vom besten Ball weiter.' },
    { id: 'stableford', name: 'Stableford', info: 'Punkte statt Schlaege - unter Par gibt Bonuspunkte.' }
  ];

  const golfModiInfo = {};
  GOLF_MODI.forEach(function(m) { golfModiInfo[m.id] = m.info; });

  const golfId = gameTypes.find(g => g.slug === 'golf')?.id;

  const preselect = {
    gameTypeId: req.query.gameTypeId || '',
    p1: req.query.p1 || '',
    p2: req.query.p2 || ''
  };

  const body = `
    <section class="card">
      <h2>Neues Spiel</h2>
      <form method="POST" action="/matches" enctype="multipart/form-data" id="match-form">
        <label>Spielart
          <select name="gameTypeId" id="gameTypeId" required>
            <option value="">Bitte w\u00e4hlen</option>
            ${gameTypes.map((gameType) => `<option value="${gameType.id}" data-slug="${gameType.slug}" ${String(gameType.id) === String(preselect.gameTypeId) ? 'selected' : ''}>${escapeHtml(gameType.name)}</option>`).join('')}
          </select>
        </label>

        <label>Datum & Uhrzeit
          <input type="datetime-local" name="playedAt" required value="${new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)}" />
        </label>

        <!-- GOLF SECTION -->
        <div id="golf-section" style="display:none; background:#0b1525; border:1px solid var(--line); border-radius:18px; padding:16px;">
          <div class="eyebrow" style="margin-bottom:10px;">Golf-Optionen</div>
          <label>Spielmodus
            <select id="golf-modus" name="golfModus">
              ${GOLF_MODI.map(m => `<option value="${m.id}">${escapeHtml(m.name)}</option>`).join('')}
            </select>
          </label>
          <div id="golf-modus-info" class="helper" style="margin-top:4px; padding:8px 10px; background:var(--panel-2); border-radius:10px;"></div>
          <label style="margin-top:12px;">Golfplatz
            <select id="golf-platz" name="golfPlatz">
              ${Object.keys(GOLF_PLAETZE).map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('')}
            </select>
          </label>
          <div id="golf-platz-info" class="helper" style="margin-top:4px;"></div>
          <label style="margin-top:12px;">Eingabemodus
            <select id="golf-eingabe" name="golfEingabe">
              <option value="gesamt">Gesamt-Score</option>
              <option value="loch">Loch f\u00fcr Loch</option>
            </select>
          </label>
          <div id="golf-loch-section" style="display:none; margin-top:12px;">
            <div class="helper" style="margin-bottom:8px;">Par pro Loch (anpassbar)</div>
            <div id="golf-par-grid" style="display:grid; grid-template-columns:repeat(9,1fr); gap:4px; margin-bottom:12px;"></div>
            <div id="golf-scores-grid"></div>
          </div>
        </div>

        <label>Notizen
          <textarea name="notes" maxlength="1000" placeholder="z.B. Wetter, besondere Momente ..."></textarea>
        </label>

        <label>Match-Foto (optional)
          <input type="file" name="photo" accept="image/*" />
        </label>

        <div id="teams-section">
          <div class="row" style="margin-top:8px;">
            <h3>Spieler / Teams</h3>
            <button class="ghost small" type="button" id="add-side">+ Hinzuf\u00fcgen</button>
          </div>
          <div class="helper">Beliebige Kombis: 1v1, 2v2, free-for-all.</div>
          <div id="sides-container" class="grid" style="margin-top:10px;"></div>
        </div>

        <input type="hidden" name="sidesJson" id="sides-json" />
        <input type="hidden" name="golfLochJson" id="golf-loch-json" />
        <button type="submit" style="background:var(--gold);color:#1a1204;font-size:16px;font-weight:800;">Spiel speichern</button>
      </form>
    </section>

    <script>
      var profiles = ${safeJson(profiles)};
      var golfId = ${safeJson(golfId)};
      var GOLF_PLAETZE = ${safeJson(GOLF_PLAETZE)};
      var GOLF_MODI_INFO = ${safeJson(golfModiInfo)};
      var preP1 = ${safeJson(preselect.p1)};
      var preP2 = ${safeJson(preselect.p2)};

      const sidesContainer = document.getElementById('sides-container');
      const hiddenInput    = document.getElementById('sides-json');
      const lochInput      = document.getElementById('golf-loch-json');
      const form           = document.getElementById('match-form');
      const addSideButton  = document.getElementById('add-side');
      const golfSection    = document.getElementById('golf-section');
      const gameTypeSelect = document.getElementById('gameTypeId');
      const golfModusEl    = document.getElementById('golf-modus');
      const golfPlatzEl    = document.getElementById('golf-platz');
      const golfEingabeEl  = document.getElementById('golf-eingabe');
      const golfLochSec    = document.getElementById('golf-loch-section');
      const golfParGrid    = document.getElementById('golf-par-grid');
      const golfScoresGrid = document.getElementById('golf-scores-grid');
      let sideCounter = 0;
      let currentPar = {};

      function escapeAttr(v) {
        return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
      }

      function getSelectedSlug() {
        var opt = gameTypeSelect.options[gameTypeSelect.selectedIndex];
        return opt ? (opt.dataset.slug || '') : '';
      }

      function isGolf() { return getSelectedSlug() === 'golf'; }

      function renderProfileButtons(sideId) {
        var searchHtml = profiles.length > 6
          ? '<input type="text" class="profile-search" data-side="' + sideId + '" placeholder="Profil suchen..." style="margin-bottom:8px;" />'
          : '';
        return searchHtml + '<div class="profile-btn-grid">' + profiles.map(function(p) {
          var avatarStyle = p.avatarPath
            ? 'background-image:url(' + escapeAttr(p.avatarPath) + ');background-size:cover;background-position:center;'
            : 'background:' + escapeAttr(p.color) + ';';
          return '<button type="button" class="profile-btn" data-profile-id="' + p.id + '" data-side="' + sideId + '" data-name="' + escapeAttr(p.name.toLowerCase()) + '">'
            + '<div class="profile-btn-avatar" style="' + avatarStyle + '">'
            + (p.avatarPath ? '' : escapeAttr(p.name.slice(0,2).toUpperCase()))
            + '</div>'
            + '<span>' + escapeAttr(p.name) + '</span>'
            + '</button>';
        }).join('') + '</div>';
      }

      function scoreInputHtml(sid) {
        var slug = getSelectedSlug();
        switch(slug) {
          case 'billard':
            return '<label>Ergebnis<div style="display:flex;gap:8px;margin-top:6px;">'
              + '<button type="button" class="ghost small winner-toggle" data-sid="' + sid + '" data-val="1" style="flex:1">Gewonnen</button>'
              + '<button type="button" class="ghost small winner-toggle" data-sid="' + sid + '" data-val="0" style="flex:1">Verloren</button>'
              + '</div><input type="hidden" name="side_score_' + sid + '" value="0" class="winner-hidden" /></label>';
          case 'capsen':
            return '<label>Ergebnis<div style="display:flex;gap:8px;margin-top:6px;">'
              + '<button type="button" class="ghost small winner-toggle" data-sid="' + sid + '" data-val="1" style="flex:1">Gewonnen</button>'
              + '<button type="button" class="ghost small winner-toggle" data-sid="' + sid + '" data-val="0" style="flex:1">Verloren</button>'
              + '</div><input type="hidden" name="side_score_' + sid + '" value="0" class="winner-hidden" /></label>'
              + '<label>Restbecher (optional)<input type="number" name="side_restbecher_' + sid + '" min="0" max="30" placeholder="Anzahl" /></label>'
              + '<label>Verl\\u00e4ngerungen (optional)<input type="number" name="side_verlaengerungen_' + sid + '" min="0" max="20" placeholder="Anzahl" /></label>';
          case 'fussball_tzt':
            return '<label>Tore<input type="number" name="side_score_' + sid + '" min="0" placeholder="Tore" required /></label>';
          case 'golf':
            return '<input type="hidden" name="side_score_' + sid + '" value="0" class="golf-score-hidden" data-sid="' + sid + '" />';
          default:
            return '<label>Score<input type="number" step="0.01" name="side_score_' + sid + '" placeholder="z.B. 21" required /></label>';
        }
      }

      function sideLabel() {
        var slug = getSelectedSlug();
        return (slug === 'fussball_tzt') ? 'Team' : 'Spieler';
      }

      function addSide(defaultName) {
        sideCounter++;
        var sid = sideCounter;
        var lbl = defaultName || (sideLabel() + ' ' + sid);
        var card = document.createElement('section');
        card.className = 'side-card';
        card.dataset.sideId = String(sid);
        card.innerHTML = [
          '<div class="row"><h3>' + escapeAttr(lbl) + '</h3>',
          '<button class="ghost small" type="button" data-remove-side="' + sid + '">Entfernen</button></div>',
          '<label>Teamname (optional)<input type="text" name="side_name_' + sid + '" placeholder="' + escapeAttr(lbl) + '" maxlength="40" /></label>',
          scoreInputHtml(sid),
          '<div><div class="helper" style="margin-bottom:8px;">Profil(e)</div>' + renderProfileButtons(sid) + '</div>'
        ].join('');
        sidesContainer.appendChild(card);
      }

      function updateGolfSection() {
        var golf = isGolf();
        golfSection.style.display = golf ? 'block' : 'none';
        addSideButton.textContent = '+ ' + sideLabel() + ' hinzuf\\u00fcgen';
        if (golf) { updatePlatzInfo(); updateModusInfo(); updateLochSection(); }
      }

      function updateModusInfo() {
        var info = GOLF_MODI_INFO[golfModusEl.value] || '';
        document.getElementById('golf-modus-info').textContent = info;
      }

      function updatePlatzInfo() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var infoEl = document.getElementById('golf-platz-info');
        if (platz) {
          var parTotal = Object.values(platz.par).reduce(function(a,b){return a+b;},0);
          infoEl.textContent = platz.loecher + ' Loch, Par ' + parTotal;
          currentPar = platz.par;
        } else {
          infoEl.textContent = 'Eigener Platz';
          currentPar = {};
        }
        renderParGrid();
        renderGolfScores();
      }

      function renderParGrid() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var n = platz ? platz.loecher : 18;
        golfParGrid.innerHTML = '';
        for (var h = 1; h <= n; h++) {
          var par = (currentPar[h] || currentPar[String(h)] || 4);
          golfParGrid.innerHTML += '<div style="text-align:center">'
            + '<div style="font-size:10px;color:var(--muted)">L' + h + '</div>'
            + '<input type="number" id="par_' + h + '" value="' + par + '" min="3" max="5" '
            + 'style="width:100%;padding:4px 2px;text-align:center;font-size:12px;border-radius:8px;border:1px solid var(--line);background:#081321;color:var(--text)" '
            + 'onchange="renderGolfScores()" /></div>';
        }
      }

      function getCurrentPars() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var n = platz ? platz.loecher : 18;
        var pars = {};
        for (var h = 1; h <= n; h++) {
          var el = document.getElementById('par_' + h);
          pars[h] = el ? Number(el.value) : 4;
        }
        return pars;
      }

      function renderGolfScores() {
        if (golfEingabeEl.value !== 'loch') return;
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var n = platz ? platz.loecher : 18;
        var pars = getCurrentPars();
        var players = Array.from(document.querySelectorAll('.side-card'));
        golfScoresGrid.innerHTML = '';
        players.forEach(function(card) {
          var sid = card.dataset.sideId;
          var nameEl = card.querySelector('[name="side_name_' + sid + '"]');
          var pname = nameEl && nameEl.value ? nameEl.value : ('Spieler ' + sid);
          var html = '<div style="margin-bottom:12px;">'
            + '<div style="font-weight:600;color:var(--gold);font-size:13px;margin-bottom:6px;">' + escapeAttr(pname) + '</div>';
          if (n > 9) {
            ['OUT (1-9)', 'IN (10-' + n + ')'].forEach(function(lbl, half) {
              html += '<div style="font-size:11px;color:var(--muted);margin-bottom:3px">' + lbl + '</div>';
              html += '<div style="display:grid;grid-template-columns:repeat(9,1fr);gap:3px;margin-bottom:6px;">';
              var start = half === 0 ? 1 : 10;
              var end   = half === 0 ? 9 : n;
              for (var h = start; h <= end; h++) {
                html += '<div style="text-align:center">'
                  + '<div style="font-size:9px;color:var(--muted)">L' + h + ' P' + pars[h] + '</div>'
                  + '<input type="number" id="loch_' + sid + '_' + h + '" value="' + pars[h] + '" min="1" max="20" '
                  + 'style="width:100%;padding:3px 1px;text-align:center;font-size:12px;border-radius:6px;border:1px solid var(--line);background:#081321;color:var(--text)" '
                  + 'onchange="updateGolfTotal(\\'' + sid + '\\',' + n + ')" /></div>';
              }
              html += '</div>';
            });
          } else {
            html += '<div style="display:grid;grid-template-columns:repeat(9,1fr);gap:3px;margin-bottom:6px;">';
            for (var h = 1; h <= n; h++) {
              html += '<div style="text-align:center">'
                + '<div style="font-size:9px;color:var(--muted)">L' + h + ' P' + pars[h] + '</div>'
                + '<input type="number" id="loch_' + sid + '_' + h + '" value="' + pars[h] + '" min="1" max="20" '
                + 'style="width:100%;padding:3px 1px;text-align:center;font-size:12px;border-radius:6px;border:1px solid var(--line);background:#081321;color:var(--text)" '
                + 'onchange="updateGolfTotal(\\'' + sid + '\\',' + n + ')" /></div>';
            }
            html += '</div>';
          }
          html += '<div id="golf-total-' + sid + '" style="text-align:right;font-size:12px;color:var(--muted);"></div>';
          html += '</div>';
          golfScoresGrid.innerHTML += html;
          updateGolfTotal(sid, n);
        });
      }

      function updateGolfTotal(sid, n) {
        var pars = getCurrentPars();
        var total = 0; var parTotal = 0;
        for (var h = 1; h <= n; h++) {
          var el = document.getElementById('loch_' + sid + '_' + h);
          if (el) { total += Number(el.value); parTotal += (pars[h] || 4); }
        }
        var diff = total - parTotal;
        var col = diff > 0 ? '#ef4444' : (diff < 0 ? '#22c55e' : 'var(--gold)');
        var el2 = document.getElementById('golf-total-' + sid);
        if (el2) el2.innerHTML = '<span style="color:' + col + '">Total: ' + total + ' (' + (diff >= 0 ? '+' : '') + diff + ')</span>';
        var scoreEl = document.querySelector('[name="side_score_' + sid + '"]');
        if (scoreEl) scoreEl.value = total;
      }

      function updateLochSection() {
        var show = isGolf() && golfEingabeEl.value === 'loch';
        golfLochSec.style.display = show ? 'block' : 'none';
        if (show) { renderParGrid(); renderGolfScores(); }
      }

      function collectSides() {
        return Array.from(document.querySelectorAll('.side-card')).map(function(card) {
          var sid = card.dataset.sideId;
          var scoreEl = card.querySelector('[name="side_score_' + sid + '"]');
          var score = scoreEl ? scoreEl.value : 0;
          var nameEl = card.querySelector('[name="side_name_' + sid + '"]');
          var sideName = nameEl && nameEl.value.trim() ? nameEl.value.trim() : (nameEl ? nameEl.placeholder : ('Spieler ' + sid));
          var rbEl = card.querySelector('[name="side_restbecher_' + sid + '"]');
          var vlEl = card.querySelector('[name="side_verlaengerungen_' + sid + '"]');
          return {
            sideName: sideName,
            score: score,
            profileIds: Array.from(card.querySelectorAll('.profile-btn.selected')).map(function(b){ return Number(b.dataset.profileId); }),
            restbecher: rbEl && rbEl.value !== '' ? Number(rbEl.value) : null,
            verlaengerungen: vlEl && vlEl.value !== '' ? Number(vlEl.value) : null
          };
        });
      }

      function collectLochData() {
        if (!isGolf() || golfEingabeEl.value !== 'loch') return {};
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var n = platz ? platz.loecher : 18;
        var pars = getCurrentPars();
        var result = {};
        Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
          var sid = card.dataset.sideId;
          var lochDetails = {};
          for (var h = 1; h <= n; h++) {
            var el = document.getElementById('loch_' + sid + '_' + h);
            if (el) lochDetails[h] = { schlaege: Number(el.value), par: pars[h] || 4 };
          }
          result[sid] = lochDetails;
        });
        return result;
      }

      // --- Event Listeners ---

      gameTypeSelect.addEventListener('change', function() {
        updateGolfSection();
        sidesContainer.innerHTML = '';
        sideCounter = 0;
        var lbl = sideLabel();
        addSide(lbl + ' 1');
        addSide(lbl + ' 2');
      });

      golfModusEl.addEventListener('change', updateModusInfo);
      golfPlatzEl.addEventListener('change', updatePlatzInfo);
      golfEingabeEl.addEventListener('change', function() {
        updateLochSection();
        if (isGolf() && golfEingabeEl.value === 'gesamt') {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
            var sid = card.dataset.sideId;
            var scoreEl = card.querySelector('[name="side_score_' + sid + '"]');
            if (scoreEl && scoreEl.type === 'hidden') {
              scoreEl.type = 'number';
              scoreEl.placeholder = 'Gesamtschl\\u00e4ge';
              scoreEl.removeAttribute('class');
              var lbl = document.createElement('label');
              lbl.textContent = 'Gesamtschl\\u00e4ge';
              scoreEl.parentNode.insertBefore(lbl, scoreEl);
            }
          });
        }
        renderGolfScores();
      });

      addSideButton.addEventListener('click', function() {
        addSide();
        if (isGolf() && golfEingabeEl.value === 'loch') renderGolfScores();
      });

      // Profile button toggle
      document.addEventListener('click', function(e) {
        var btn = e.target.closest('.profile-btn');
        if (btn) { btn.classList.toggle('selected'); return; }
      });

      // Profile search filter
      document.addEventListener('input', function(e) {
        if (!e.target.classList.contains('profile-search')) return;
        var query = e.target.value.toLowerCase();
        var card = e.target.closest('.side-card') || e.target.parentNode;
        var btns = card.querySelectorAll('.profile-btn');
        btns.forEach(function(btn) {
          var name = btn.dataset.name || '';
          var isSelected = btn.classList.contains('selected');
          btn.style.display = (!query || name.indexOf(query) !== -1 || isSelected) ? '' : 'none';
        });
      });

      // Winner toggle (billard/capsen)
      document.addEventListener('click', function(e) {
        var btn = e.target.closest('.winner-toggle');
        if (!btn) return;
        var sid = btn.dataset.sid;
        var val = Number(btn.dataset.val);
        var card = btn.closest('.side-card');
        var hidden = card.querySelector('.winner-hidden');
        if (hidden) hidden.value = val;
        // Highlight selected
        card.querySelectorAll('.winner-toggle').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        // For billard/capsen: if marking as winner, set all other sides to loser
        if (val === 1) {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(otherCard) {
            if (otherCard === card) return;
            var otherHidden = otherCard.querySelector('.winner-hidden');
            if (otherHidden) otherHidden.value = '0';
            otherCard.querySelectorAll('.winner-toggle').forEach(function(b) { b.classList.remove('active'); });
            var loserBtn = otherCard.querySelector('.winner-toggle[data-val="0"]');
            if (loserBtn) loserBtn.classList.add('active');
          });
        }
      });

      // Remove side
      document.addEventListener('click', function(event) {
        var btn = event.target.closest('[data-remove-side]');
        if (!btn) return;
        if (document.querySelectorAll('.side-card').length <= 2) {
          window.alert('Mindestens zwei Spieler/Teams.');
          return;
        }
        btn.closest('.side-card').remove();
        if (isGolf() && golfEingabeEl.value === 'loch') renderGolfScores();
      });

      form.addEventListener('submit', function() {
        if (isGolf() && golfEingabeEl.value === 'loch') {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
            var sid = card.dataset.sideId;
            updateGolfTotal(sid, GOLF_PLAETZE[golfPlatzEl.value] ? GOLF_PLAETZE[golfPlatzEl.value].loecher : 18);
          });
        }
        hiddenInput.value = JSON.stringify(collectSides());
        lochInput.value   = JSON.stringify(collectLochData());
      });

      // --- Init ---
      updateModusInfo();
      sideCounter = 0;

      // If preselected game type, trigger change to build sides
      if (gameTypeSelect.value) {
        updateGolfSection();
        var lbl = sideLabel();
        addSide(lbl + ' 1');
        addSide(lbl + ' 2');
        // Pre-select profiles if provided
        if (preP1) {
          var btn1 = document.querySelector('.side-card[data-side-id="1"] .profile-btn[data-profile-id="' + preP1 + '"]');
          if (btn1) btn1.classList.add('selected');
        }
        if (preP2) {
          var btn2 = document.querySelector('.side-card[data-side-id="2"] .profile-btn[data-profile-id="' + preP2 + '"]');
          if (btn2) btn2.classList.add('selected');
        }
      } else {
        // Default: show two generic sides
        addSide('Spieler 1');
        addSide('Spieler 2');
      }
    </script>
  `;

  res.send(layout(req, 'Neues Spiel erfassen', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.post('/matches', requireUser, upload.single('photo'), (req, res) => {
  let sides;
  try {
    sides = JSON.parse(req.body.sidesJson || '[]');
  } catch (_error) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches/new', 'Team-Daten konnten nicht gelesen werden.');
  }

  const gameType = db.prepare('SELECT id, scoring_mode AS scoringMode FROM game_types WHERE id = ?').get(Number(req.body.gameTypeId));
  if (!gameType) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches/new', 'Ungültige Spielart.');
  }

  if (!Array.isArray(sides) || sides.length < 2) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches/new', 'Bitte mindestens zwei Teams/Seiten anlegen.');
  }

  const usedProfileIds = new Set();
  const normalizedSides = [];

  for (const [index, side] of sides.entries()) {
    const sideName = String(side.sideName || '').trim() || `Team ${index + 1}`;
    const score = Number(side.score);
    const profileIds = [...new Set((Array.isArray(side.profileIds) ? side.profileIds : []).map(Number).filter(Boolean))];

    if (!Number.isFinite(score)) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, '/matches/new', `Score für ${sideName} fehlt oder ist ungültig.`);
    }
    if (profileIds.length === 0) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, '/matches/new', `Bitte mindestens ein Profil für ${sideName} auswählen.`);
    }

    for (const profileId of profileIds) {
      if (usedProfileIds.has(profileId)) {
        removeUploadedFile(req.file);
        return redirectWithMessage(res, '/matches/new', 'Ein Profil wurde mehrfach in verschiedenen Teams ausgewählt.');
      }
      usedProfileIds.add(profileId);
    }

    normalizedSides.push({ sideName, score, profileIds, extraData: side.restbecher != null || side.verlaengerungen != null ? { restbecher: side.restbecher, verlaengerungen: side.verlaengerungen } : null });
  }

  // Validate winner-toggle games: exactly one winner
  const gameTypeRow = db.prepare('SELECT slug FROM game_types WHERE id = ?').get(Number(req.body.gameTypeId));
  if (gameTypeRow && (gameTypeRow.slug === 'billard' || gameTypeRow.slug === 'capsen')) {
    const winnerCount = normalizedSides.filter(s => s.score === 1).length;
    if (winnerCount !== 1) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, '/matches/new', 'Bitte genau einen Gewinner auswählen.');
    }
  }

  const profilesFound = db.prepare(`SELECT id FROM profiles WHERE id IN (${normalizedSides.flatMap((s) => s.profileIds).map(() => '?').join(',')})`).all(...normalizedSides.flatMap((s) => s.profileIds));
  if (profilesFound.length !== usedProfileIds.size) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches/new', 'Mindestens ein Profil existiert nicht mehr.');
  }

  const scores = normalizedSides.map((s) => s.score);
  const bestScore = gameType.scoringMode === 'lower_wins' ? Math.min(...scores) : Math.max(...scores);

  const insertMatch = db.prepare(`INSERT INTO matches (game_type_id, played_at, notes, photo_path, created_by_profile_id) VALUES (?, ?, ?, ?, ?)`);
  const insertSide = db.prepare(`INSERT INTO match_sides (match_id, side_name, score, is_winner, extra_data) VALUES (?, ?, ?, ?, ?)`);
  const insertSideMember = db.prepare('INSERT INTO match_side_members (side_id, profile_id) VALUES (?, ?)');

  const saveMatch = db.transaction(() => {
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    const result = insertMatch.run(
      gameType.id,
      new Date(req.body.playedAt).toISOString(),
      String(req.body.notes || '').trim() || null,
      photoPath,
      req.currentUser.id
    );
    for (const side of normalizedSides) {
      const sideResult = insertSide.run(
        result.lastInsertRowid, side.sideName, side.score,
        side.score === bestScore ? 1 : 0,
        side.extraData ? JSON.stringify(side.extraData) : null
      );
      for (const profileId of side.profileIds) {
        insertSideMember.run(sideResult.lastInsertRowid, profileId);
      }
    }
  });

  try {
    saveMatch();
  } catch (error) {
    removeUploadedFile(req.file);
    throw error;
  }

  redirectWithMessage(res, '/matches', 'Spiel gespeichert.');
});

// ── Edit match ──────────────────────────────────────────────────────────
app.get('/matches/:id/edit', requireUser, (req, res) => {
  const match = getMatchById(Number(req.params.id));
  if (!match) return redirectWithMessage(res, '/matches', 'Spiel nicht gefunden.');

  const profiles = getProfiles();
  const gameTypes = getGameTypes();

  const GOLF_PLAETZE = {
    'Bades Huk (18 Loch, Par 72)': {
      loecher: 18,
      par: {1:4,2:5,3:4,4:3,5:4,6:4,7:5,8:4,9:3,10:4,11:4,12:3,13:5,14:4,15:4,16:3,17:5,18:4}
    },
    'Eigener Platz': null
  };
  const GOLF_MODI = [
    { id: 'stroke', name: 'Stroke Play', info: 'Gesamtschlaege zaehlen - wenigste gewinnt.' },
    { id: 'match',  name: 'Match Play',  info: 'Jedes Loch einzeln - wer mehr Loecher gewinnt, siegt.' },
    { id: 'scramble', name: 'Scramble', info: 'Team spielt vom besten Ball weiter.' },
    { id: 'stableford', name: 'Stableford', info: 'Punkte statt Schlaege - unter Par gibt Bonuspunkte.' }
  ];
  const golfModiInfo = {};
  GOLF_MODI.forEach(function(m) { golfModiInfo[m.id] = m.info; });
  const golfId = gameTypes.find(g => g.slug === 'golf')?.id;

  const playedAtLocal = match.played_at
    ? new Date(new Date(match.played_at).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)
    : '';

  const body = `
    <section class="card">
      <h2>Spiel bearbeiten</h2>
      <form method="POST" action="/matches/${match.id}/edit" enctype="multipart/form-data" id="match-form">
        <label>Spielart
          <select name="gameTypeId" id="gameTypeId" required>
            ${gameTypes.map((gt) => `<option value="${gt.id}" data-slug="${gt.slug}" ${gt.id === match.gameTypeId ? 'selected' : ''}>${escapeHtml(gt.name)}</option>`).join('')}
          </select>
        </label>

        <label>Datum & Uhrzeit
          <input type="datetime-local" name="playedAt" required value="${playedAtLocal}" />
        </label>

        <div id="golf-section" style="display:none; background:#0b1525; border:1px solid var(--line); border-radius:18px; padding:16px;">
          <div class="eyebrow" style="margin-bottom:10px;">Golf-Optionen</div>
          <label>Spielmodus
            <select id="golf-modus" name="golfModus">
              ${GOLF_MODI.map(m => `<option value="${m.id}">${escapeHtml(m.name)}</option>`).join('')}
            </select>
          </label>
          <div id="golf-modus-info" class="helper" style="margin-top:4px; padding:8px 10px; background:var(--panel-2); border-radius:10px;"></div>
          <label style="margin-top:12px;">Golfplatz
            <select id="golf-platz" name="golfPlatz">
              ${Object.keys(GOLF_PLAETZE).map(p => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`).join('')}
            </select>
          </label>
          <div id="golf-platz-info" class="helper" style="margin-top:4px;"></div>
          <label style="margin-top:12px;">Eingabemodus
            <select id="golf-eingabe" name="golfEingabe">
              <option value="gesamt">Gesamt-Score</option>
              <option value="loch">Loch f\u00fcr Loch</option>
            </select>
          </label>
          <div id="golf-loch-section" style="display:none; margin-top:12px;">
            <div class="helper" style="margin-bottom:8px;">Par pro Loch (anpassbar)</div>
            <div id="golf-par-grid" style="display:grid; grid-template-columns:repeat(9,1fr); gap:4px; margin-bottom:12px;"></div>
            <div id="golf-scores-grid"></div>
          </div>
        </div>

        <label>Notizen
          <textarea name="notes" maxlength="1000" placeholder="z.B. Wetter, besondere Momente ...">${escapeHtml(match.notes || '')}</textarea>
        </label>

        ${match.photoPath ? `<div style="margin-bottom:8px;"><img class="match-photo" src="${escapeHtml(match.photoPath)}" alt="Matchfoto" style="max-height:200px;width:auto;" /></div>` : ''}
        <label>Match-Foto ${match.photoPath ? '(ersetzen)' : '(optional)'}
          <input type="file" name="photo" accept="image/*" />
        </label>

        <div id="teams-section">
          <div class="row" style="margin-top:8px;">
            <h3>Spieler / Teams</h3>
            <button class="ghost small" type="button" id="add-side">+ Hinzuf\u00fcgen</button>
          </div>
          <div class="helper">Beliebige Kombis: 1v1, 2v2, free-for-all.</div>
          <div id="sides-container" class="grid" style="margin-top:10px;"></div>
        </div>

        <input type="hidden" name="sidesJson" id="sides-json" />
        <input type="hidden" name="golfLochJson" id="golf-loch-json" />
        <button type="submit" style="background:var(--gold);color:#1a1204;font-size:16px;font-weight:800;">\u00c4nderungen speichern</button>
      </form>

      <form method="POST" action="/matches/${match.id}/delete" style="margin-top:16px;"
            onsubmit="return confirm('Spiel wirklich l\\u00f6schen? Das kann nicht r\\u00fcckg\\u00e4ngig gemacht werden.');">
        <button type="submit" style="background:var(--danger);color:white;width:100%;">Spiel l\u00f6schen</button>
      </form>
    </section>

    <script>
      var profiles = ${safeJson(profiles)};
      var golfId = ${safeJson(golfId)};
      var GOLF_PLAETZE = ${safeJson(GOLF_PLAETZE)};
      var GOLF_MODI_INFO = ${safeJson(golfModiInfo)};
      var existingSides = ${safeJson(match.sides)};

      const sidesContainer = document.getElementById('sides-container');
      const hiddenInput    = document.getElementById('sides-json');
      const lochInput      = document.getElementById('golf-loch-json');
      const form           = document.getElementById('match-form');
      const addSideButton  = document.getElementById('add-side');
      const golfSection    = document.getElementById('golf-section');
      const gameTypeSelect = document.getElementById('gameTypeId');
      const golfModusEl    = document.getElementById('golf-modus');
      const golfPlatzEl    = document.getElementById('golf-platz');
      const golfEingabeEl  = document.getElementById('golf-eingabe');
      const golfLochSec    = document.getElementById('golf-loch-section');
      const golfParGrid    = document.getElementById('golf-par-grid');
      const golfScoresGrid = document.getElementById('golf-scores-grid');
      let sideCounter = 0;
      let currentPar = {};

      function escapeAttr(v) {
        return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;');
      }
      function getSelectedSlug() {
        var opt = gameTypeSelect.options[gameTypeSelect.selectedIndex];
        return opt ? (opt.dataset.slug || '') : '';
      }
      function isGolf() { return getSelectedSlug() === 'golf'; }

      function renderProfileButtons(sideId, selectedIds) {
        var searchHtml = profiles.length > 6
          ? '<input type="text" class="profile-search" data-side="' + sideId + '" placeholder="Profil suchen..." style="margin-bottom:8px;" />'
          : '';
        return searchHtml + '<div class="profile-btn-grid">' + profiles.map(function(p) {
          var avatarStyle = p.avatarPath
            ? 'background-image:url(' + escapeAttr(p.avatarPath) + ');background-size:cover;background-position:center;'
            : 'background:' + escapeAttr(p.color) + ';';
          var sel = selectedIds && selectedIds.indexOf(p.id) !== -1 ? ' selected' : '';
          return '<button type="button" class="profile-btn' + sel + '" data-profile-id="' + p.id + '" data-side="' + sideId + '" data-name="' + escapeAttr(p.name.toLowerCase()) + '">'
            + '<div class="profile-btn-avatar" style="' + avatarStyle + '">'
            + (p.avatarPath ? '' : escapeAttr(p.name.slice(0,2).toUpperCase()))
            + '</div>'
            + '<span>' + escapeAttr(p.name) + '</span>'
            + '</button>';
        }).join('') + '</div>';
      }

      function scoreInputHtml(sid, existingScore) {
        var slug = getSelectedSlug();
        var val = existingScore != null ? existingScore : '';
        switch(slug) {
          case 'billard':
          case 'capsen':
            var w = Number(val) === 1;
            var html = '<label>Ergebnis<div style="display:flex;gap:8px;margin-top:6px;">'
              + '<button type="button" class="ghost small winner-toggle' + (w ? ' active' : '') + '" data-sid="' + sid + '" data-val="1" style="flex:1">Gewonnen</button>'
              + '<button type="button" class="ghost small winner-toggle' + (!w && val !== '' ? ' active' : '') + '" data-sid="' + sid + '" data-val="0" style="flex:1">Verloren</button>'
              + '</div><input type="hidden" name="side_score_' + sid + '" value="' + (val !== '' ? val : 0) + '" class="winner-hidden" /></label>';
            if (slug === 'capsen') {
              html += '<label>Restbecher (optional)<input type="number" name="side_restbecher_' + sid + '" min="0" max="30" placeholder="Anzahl" /></label>'
                + '<label>Verl\\u00e4ngerungen (optional)<input type="number" name="side_verlaengerungen_' + sid + '" min="0" max="20" placeholder="Anzahl" /></label>';
            }
            return html;
          case 'fussball_tzt':
            return '<label>Tore<input type="number" name="side_score_' + sid + '" min="0" placeholder="Tore" value="' + escapeAttr(val) + '" required /></label>';
          case 'golf':
            return '<input type="hidden" name="side_score_' + sid + '" value="' + (val || 0) + '" class="golf-score-hidden" data-sid="' + sid + '" />';
          default:
            return '<label>Score<input type="number" step="0.01" name="side_score_' + sid + '" placeholder="z.B. 21" value="' + escapeAttr(val) + '" required /></label>';
        }
      }

      function sideLabel() {
        return getSelectedSlug() === 'fussball_tzt' ? 'Team' : 'Spieler';
      }

      function addSide(defaultName, existingSide) {
        sideCounter++;
        var sid = sideCounter;
        var lbl = defaultName || (existingSide ? existingSide.sideName : sideLabel() + ' ' + sid);
        var score = existingSide ? existingSide.score : undefined;
        var profileIds = existingSide ? existingSide.profileIds : [];
        var card = document.createElement('section');
        card.className = 'side-card';
        card.dataset.sideId = String(sid);
        card.innerHTML = [
          '<div class="row"><h3>' + escapeAttr(lbl) + '</h3>',
          '<button class="ghost small" type="button" data-remove-side="' + sid + '">Entfernen</button></div>',
          '<label>Teamname (optional)<input type="text" name="side_name_' + sid + '" value="' + escapeAttr(existingSide ? existingSide.sideName : '') + '" placeholder="' + escapeAttr(lbl) + '" maxlength="40" /></label>',
          scoreInputHtml(sid, score),
          '<div><div class="helper" style="margin-bottom:8px;">Profil(e)</div>' + renderProfileButtons(sid, profileIds) + '</div>'
        ].join('');
        sidesContainer.appendChild(card);
        // Set restbecher/verlaengerungen if they exist
        if (existingSide && existingSide.extraData) {
          var rbEl = card.querySelector('[name="side_restbecher_' + sid + '"]');
          if (rbEl && existingSide.extraData.restbecher != null) rbEl.value = existingSide.extraData.restbecher;
          var vlEl = card.querySelector('[name="side_verlaengerungen_' + sid + '"]');
          if (vlEl && existingSide.extraData.verlaengerungen != null) vlEl.value = existingSide.extraData.verlaengerungen;
        }
      }

      function updateGolfSection() {
        var golf = isGolf();
        golfSection.style.display = golf ? 'block' : 'none';
        addSideButton.textContent = '+ ' + sideLabel() + ' hinzuf\\u00fcgen';
        if (golf) { updatePlatzInfo(); updateModusInfo(); updateLochSection(); }
      }
      function updateModusInfo() {
        var info = GOLF_MODI_INFO[golfModusEl.value] || '';
        document.getElementById('golf-modus-info').textContent = info;
      }
      function updatePlatzInfo() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value];
        var infoEl = document.getElementById('golf-platz-info');
        if (platz) {
          var parTotal = Object.values(platz.par).reduce(function(a,b){return a+b;},0);
          infoEl.textContent = platz.loecher + ' Loch, Par ' + parTotal;
          currentPar = platz.par;
        } else { infoEl.textContent = 'Eigener Platz'; currentPar = {}; }
        renderParGrid(); renderGolfScores();
      }
      function renderParGrid() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value]; var n = platz ? platz.loecher : 18;
        golfParGrid.innerHTML = '';
        for (var h = 1; h <= n; h++) {
          var par = (currentPar[h] || currentPar[String(h)] || 4);
          golfParGrid.innerHTML += '<div style="text-align:center"><div style="font-size:10px;color:var(--muted)">L' + h + '</div>'
            + '<input type="number" id="par_' + h + '" value="' + par + '" min="3" max="5" style="width:100%;padding:4px 2px;text-align:center;font-size:12px;border-radius:8px;border:1px solid var(--line);background:#081321;color:var(--text)" onchange="renderGolfScores()" /></div>';
        }
      }
      function getCurrentPars() {
        var platz = GOLF_PLAETZE[golfPlatzEl.value]; var n = platz ? platz.loecher : 18; var pars = {};
        for (var h = 1; h <= n; h++) { var el = document.getElementById('par_' + h); pars[h] = el ? Number(el.value) : 4; }
        return pars;
      }
      function renderGolfScores() { /* simplified for edit - use gesamt mode */ }
      function updateGolfTotal(sid, n) {
        var pars = getCurrentPars(); var total = 0; var parTotal = 0;
        for (var h = 1; h <= n; h++) { var el = document.getElementById('loch_' + sid + '_' + h); if (el) { total += Number(el.value); parTotal += (pars[h] || 4); } }
        var diff = total - parTotal; var col = diff > 0 ? '#ef4444' : (diff < 0 ? '#22c55e' : 'var(--gold)');
        var el2 = document.getElementById('golf-total-' + sid);
        if (el2) el2.innerHTML = '<span style="color:' + col + '">Total: ' + total + ' (' + (diff >= 0 ? '+' : '') + diff + ')</span>';
        var scoreEl = document.querySelector('[name="side_score_' + sid + '"]'); if (scoreEl) scoreEl.value = total;
      }
      function updateLochSection() {
        var show = isGolf() && golfEingabeEl.value === 'loch';
        golfLochSec.style.display = show ? 'block' : 'none';
        if (show) { renderParGrid(); renderGolfScores(); }
      }

      function collectSides() {
        return Array.from(document.querySelectorAll('.side-card')).map(function(card) {
          var sid = card.dataset.sideId;
          var scoreEl = card.querySelector('[name="side_score_' + sid + '"]');
          var score = scoreEl ? scoreEl.value : 0;
          var nameEl = card.querySelector('[name="side_name_' + sid + '"]');
          var sideName = nameEl && nameEl.value.trim() ? nameEl.value.trim() : (nameEl ? nameEl.placeholder : ('Spieler ' + sid));
          var rbEl = card.querySelector('[name="side_restbecher_' + sid + '"]');
          var vlEl = card.querySelector('[name="side_verlaengerungen_' + sid + '"]');
          return {
            sideName: sideName, score: score,
            profileIds: Array.from(card.querySelectorAll('.profile-btn.selected')).map(function(b){ return Number(b.dataset.profileId); }),
            restbecher: rbEl && rbEl.value !== '' ? Number(rbEl.value) : null,
            verlaengerungen: vlEl && vlEl.value !== '' ? Number(vlEl.value) : null
          };
        });
      }
      function collectLochData() { return {}; }

      gameTypeSelect.addEventListener('change', function() {
        updateGolfSection(); sidesContainer.innerHTML = ''; sideCounter = 0;
        var lbl = sideLabel(); addSide(lbl + ' 1'); addSide(lbl + ' 2');
      });
      golfModusEl.addEventListener('change', updateModusInfo);
      golfPlatzEl.addEventListener('change', updatePlatzInfo);
      golfEingabeEl.addEventListener('change', function() { updateLochSection(); });
      addSideButton.addEventListener('click', function() { addSide(); });

      document.addEventListener('click', function(e) {
        var btn = e.target.closest('.profile-btn');
        if (btn) { btn.classList.toggle('selected'); return; }
      });
      document.addEventListener('input', function(e) {
        if (!e.target.classList.contains('profile-search')) return;
        var query = e.target.value.toLowerCase();
        var card = e.target.closest('.side-card') || e.target.parentNode;
        card.querySelectorAll('.profile-btn').forEach(function(btn) {
          var name = btn.dataset.name || '';
          btn.style.display = (!query || name.indexOf(query) !== -1 || btn.classList.contains('selected')) ? '' : 'none';
        });
      });
      document.addEventListener('click', function(e) {
        var btn = e.target.closest('.winner-toggle');
        if (!btn) return;
        var sid = btn.dataset.sid; var val = Number(btn.dataset.val);
        var card = btn.closest('.side-card');
        var hidden = card.querySelector('.winner-hidden');
        if (hidden) hidden.value = val;
        card.querySelectorAll('.winner-toggle').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        if (val === 1) {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(oc) {
            if (oc === card) return;
            var oh = oc.querySelector('.winner-hidden'); if (oh) oh.value = '0';
            oc.querySelectorAll('.winner-toggle').forEach(function(b) { b.classList.remove('active'); });
            var lb = oc.querySelector('.winner-toggle[data-val="0"]'); if (lb) lb.classList.add('active');
          });
        }
      });
      document.addEventListener('click', function(event) {
        var btn = event.target.closest('[data-remove-side]');
        if (!btn) return;
        if (document.querySelectorAll('.side-card').length <= 2) { window.alert('Mindestens zwei Spieler/Teams.'); return; }
        btn.closest('.side-card').remove();
      });
      form.addEventListener('submit', function() {
        hiddenInput.value = JSON.stringify(collectSides());
        lochInput.value   = JSON.stringify(collectLochData());
      });

      // Init: load existing sides
      updateGolfSection();
      existingSides.forEach(function(side) { addSide(null, side); });
    </script>
  `;

  res.send(layout(req, 'Spiel bearbeiten', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.post('/matches/:id/edit', requireUser, upload.single('photo'), (req, res) => {
  const matchId = Number(req.params.id);
  const existingMatch = getMatchById(matchId);
  if (!existingMatch) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches', 'Spiel nicht gefunden.');
  }

  let sides;
  try {
    sides = JSON.parse(req.body.sidesJson || '[]');
  } catch (_error) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, `/matches/${matchId}/edit`, 'Team-Daten konnten nicht gelesen werden.');
  }

  const gameType = db.prepare('SELECT id, scoring_mode AS scoringMode, slug FROM game_types WHERE id = ?').get(Number(req.body.gameTypeId));
  if (!gameType) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, `/matches/${matchId}/edit`, 'Ung\u00fcltige Spielart.');
  }

  if (!Array.isArray(sides) || sides.length < 2) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, `/matches/${matchId}/edit`, 'Bitte mindestens zwei Teams/Seiten anlegen.');
  }

  const usedProfileIds = new Set();
  const normalizedSides = [];

  for (const [index, side] of sides.entries()) {
    const sideName = String(side.sideName || '').trim() || `Team ${index + 1}`;
    const score = Number(side.score);
    const profileIds = [...new Set((Array.isArray(side.profileIds) ? side.profileIds : []).map(Number).filter(Boolean))];

    if (!Number.isFinite(score)) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, `/matches/${matchId}/edit`, `Score f\u00fcr ${sideName} fehlt oder ist ung\u00fcltig.`);
    }
    if (profileIds.length === 0) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, `/matches/${matchId}/edit`, `Bitte mindestens ein Profil f\u00fcr ${sideName} ausw\u00e4hlen.`);
    }
    for (const profileId of profileIds) {
      if (usedProfileIds.has(profileId)) {
        removeUploadedFile(req.file);
        return redirectWithMessage(res, `/matches/${matchId}/edit`, 'Ein Profil wurde mehrfach in verschiedenen Teams ausgew\u00e4hlt.');
      }
      usedProfileIds.add(profileId);
    }
    normalizedSides.push({ sideName, score, profileIds, extraData: side.restbecher != null || side.verlaengerungen != null ? { restbecher: side.restbecher, verlaengerungen: side.verlaengerungen } : null });
  }

  if (gameType.slug === 'billard' || gameType.slug === 'capsen') {
    const winnerCount = normalizedSides.filter(s => s.score === 1).length;
    if (winnerCount !== 1) {
      removeUploadedFile(req.file);
      return redirectWithMessage(res, `/matches/${matchId}/edit`, 'Bitte genau einen Gewinner ausw\u00e4hlen.');
    }
  }

  const scores = normalizedSides.map((s) => s.score);
  const bestScore = gameType.scoringMode === 'lower_wins' ? Math.min(...scores) : Math.max(...scores);

  const updateMatch = db.prepare(`UPDATE matches SET game_type_id = ?, played_at = ?, notes = ?, photo_path = COALESCE(?, photo_path) WHERE id = ?`);
  const deleteSides = db.prepare(`DELETE FROM match_sides WHERE match_id = ?`);
  const insertSide = db.prepare(`INSERT INTO match_sides (match_id, side_name, score, is_winner, extra_data) VALUES (?, ?, ?, ?, ?)`);
  const insertSideMember = db.prepare('INSERT INTO match_side_members (side_id, profile_id) VALUES (?, ?)');

  const saveEdit = db.transaction(() => {
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    updateMatch.run(
      gameType.id,
      new Date(req.body.playedAt).toISOString(),
      String(req.body.notes || '').trim() || null,
      photoPath,
      matchId
    );
    // Delete old photo if replaced
    if (req.file && existingMatch.photoPath) {
      const oldPath = path.join(__dirname, 'storage', existingMatch.photoPath);
      try { fs.unlinkSync(oldPath); } catch (_e) { /* ignore */ }
    }
    deleteSides.run(matchId);
    for (const side of normalizedSides) {
      const sideResult = insertSide.run(
        matchId, side.sideName, side.score,
        side.score === bestScore ? 1 : 0,
        side.extraData ? JSON.stringify(side.extraData) : null
      );
      for (const profileId of side.profileIds) {
        insertSideMember.run(sideResult.lastInsertRowid, profileId);
      }
    }
  });

  try {
    saveEdit();
  } catch (error) {
    removeUploadedFile(req.file);
    throw error;
  }

  redirectWithMessage(res, '/matches', 'Spiel aktualisiert.');
});

// ── Delete match ────────────────────────────────────────────────────────
app.post('/matches/:id/delete', requireUser, (req, res) => {
  const matchId = Number(req.params.id);
  const match = getMatchById(matchId);
  if (!match) return redirectWithMessage(res, '/matches', 'Spiel nicht gefunden.');

  // Delete photo from disk
  if (match.photoPath) {
    const photoFile = path.join(__dirname, 'storage', match.photoPath);
    try { fs.unlinkSync(photoFile); } catch (_e) { /* ignore */ }
  }

  db.prepare('DELETE FROM matches WHERE id = ?').run(matchId);
  redirectWithMessage(res, '/matches', 'Spiel gel\u00f6scht.');
});

app.get('/leaderboard', requireUser, (req, res) => {
  const profiles = getProfileStats();
  const duos = getDuoStats();
  const body = `
    <div class="grid grid-2">
      <section class="card">
        <h2>Profile</h2>
        ${profiles.length ? profiles.map((profile, index) => `
          <div class="match">
            <div class="row">
              <div style="display:flex; align-items:center; gap:10px;">
                <div class="avatar" style="background:${escapeHtml(profile.color)}">${index + 1}</div>
                <div>
                  <div><strong>${escapeHtml(profile.name)}</strong></div>
                  <div class="helper">${profile.games} Spiele · ${profile.winRate}% Win-Rate</div>
                </div>
              </div>
              <div class="winner">${profile.wins} Siege</div>
            </div>
          </div>
        `).join('') : '<div class="empty">Noch keine Stats vorhanden.</div>'}
      </section>
      <section class="card">
        <h2>Beste 2er-Kombis</h2>
        ${duos.length ? duos.slice(0, 12).map((duo, index) => `
          <div class="match">
            <div class="row">
              <div>
                <div><strong>#${index + 1} ${escapeHtml(duo.names.join(' + '))}</strong></div>
                <div class="helper">${duo.games} Spiele · ${duo.winRate}% Win-Rate</div>
              </div>
              <div class="winner">${duo.wins} Siege</div>
            </div>
          </div>
        `).join('') : '<div class="empty">Noch keine 2er-Teams vorhanden.</div>'}
      </section>
    </div>
  `;
  res.send(layout(req, 'Leaderboards', body, req.query.msg ? escapeHtml(req.query.msg) : ''));
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).send('Interner Fehler');
});

app.listen(PORT, () => {
  console.log(`Spielportal läuft auf http://localhost:${PORT}`);
});
