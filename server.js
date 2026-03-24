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
  { slug: 'tennis', name: 'Tennis', scoringMode: 'higher_wins' },
  { slug: 'fussball', name: 'Fußball', scoringMode: 'higher_wins' },
  { slug: 'padel', name: 'Padel', scoringMode: 'higher_wins' },
  { slug: 'squash', name: 'Squash', scoringMode: 'higher_wins' }
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
    <nav class="nav">
      <a href="/">Dashboard</a>
      <a href="/matches">Spiele</a>
      <a href="/matches/new">Neues Spiel</a>
      <a href="/leaderboard">Leaderboards</a>
      <a href="/profiles">Profile</a>
      <div class="nav-auth">${authBlock}</div>
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
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
        background: linear-gradient(180deg, #08101d 0%, #0d1728 100%);
        color: var(--text);
      }
      a { color: inherit; text-decoration: none; }
      .page { max-width: 980px; margin: 0 auto; padding: 18px 14px 48px; }
      .hero { display: grid; gap: 10px; margin: 12px 0 18px; }
      .eyebrow { color: var(--blue); font-size: 13px; letter-spacing: 0.04em; text-transform: uppercase; }
      h1, h2, h3 { margin: 0; }
      .subtle { color: var(--muted); }
      .nav { display: flex; flex-wrap: wrap; gap: 10px; margin: 14px 0 18px; }
      .nav a, .button, button {
        border: 0; border-radius: 14px; padding: 12px 14px;
        background: var(--green); color: #05110a; font-weight: 700; cursor: pointer;
      }
      .nav a:hover, .button:hover, button:hover { filter: brightness(1.04); }
      .ghost { background: var(--panel); color: var(--text); border: 1px solid var(--line); }
      .small { padding: 9px 12px; font-size: 14px; }
      .nav-auth { margin-left: auto; display: flex; gap: 8px; align-items: center; }
      .user-pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px;
        background: var(--panel); border: 1px solid var(--line);
      }
      .dot { width: 10px; height: 10px; border-radius: 999px; display: inline-block; }
      .grid { display: grid; gap: 14px; }
      .grid-2 { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
      .grid-3 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
      .card {
        background: rgba(16, 28, 47, 0.94); border: 1px solid var(--line);
        border-radius: 20px; padding: 16px; box-shadow: 0 14px 40px rgba(0,0,0,0.2);
      }
      .card h2, .card h3 { margin-bottom: 12px; }
      .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
      .stat { background: var(--panel-2); border-radius: 18px; border: 1px solid var(--line); padding: 14px; }
      .stat-value { font-size: 28px; font-weight: 800; color: var(--green); }
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
      .tag { background: rgba(56,189,248,0.15); color: #8fdefc; }
      .winner { color: var(--green); font-weight: 800; }
      form { display: grid; gap: 12px; }
      label { display: grid; gap: 6px; font-size: 14px; color: var(--muted); }
      input, textarea, select {
        width: 100%; border-radius: 14px; border: 1px solid var(--line);
        background: #081321; color: var(--text); padding: 12px 14px; font: inherit;
      }
      textarea { min-height: 100px; resize: vertical; }
      .flash {
        margin-bottom: 14px; padding: 12px 14px; border-radius: 16px;
        border: 1px solid rgba(251,146,60,0.35); background: rgba(251,146,60,0.12); color: #ffd9b8;
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
      .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
      .checkbox-pill {
        display: flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 14px; background: #09111f; border: 1px solid var(--line);
      }
      .checkbox-pill input { width: auto; margin: 0; }
      .helper { font-size: 13px; color: var(--muted); }
      .empty { color: var(--muted); padding: 6px 0; }
      img.match-photo { width: 100%; border-radius: 16px; border: 1px solid var(--line); }
      @media (max-width: 640px) {
        .page { padding: 14px 12px 40px; }
        .nav-auth { width: 100%; margin-left: 0; justify-content: space-between; }
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

  const body = `
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

  const body = `
    <section class="card">
      <h2>Neues Spiel</h2>
      <form method="POST" action="/matches" enctype="multipart/form-data" id="match-form">
        <label>Spielart
          <select name="gameTypeId" id="gameTypeId" required>
            <option value="">Bitte wählen</option>
            ${gameTypes.map((gameType) => `<option value="${gameType.id}" data-slug="${gameType.slug}">${escapeHtml(gameType.name)} (${gameType.scoringMode === 'lower_wins' ? 'niedrigster Score gewinnt' : 'höchster Score gewinnt'})</option>`).join('')}
          </select>
        </label>

        <label>Datum & Uhrzeit
          <input type="datetime-local" name="playedAt" required value="${new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)}" />
        </label>

        <!-- GOLF SECTION -->
        <div id="golf-section" style="display:none; background:#0b1525; border:1px solid var(--line); border-radius:18px; padding:16px;">
          <div class="eyebrow" style="margin-bottom:10px;">⛳ Golf-Optionen</div>

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
              <option value="gesamt">⚡ Gesamt-Score</option>
              <option value="loch">🔍 Loch für Loch</option>
            </select>
          </label>

          <div id="golf-loch-section" style="display:none; margin-top:12px;">
            <div class="helper" style="margin-bottom:8px;">Par pro Loch (anpassbar)</div>
            <div id="golf-par-grid" style="display:grid; grid-template-columns:repeat(9,1fr); gap:4px; margin-bottom:12px;"></div>
            <div id="golf-scores-grid"></div>
          </div>
        </div>

        <label>Notizen
          <textarea name="notes" maxlength="1000" placeholder="z.B. Wetter, besondere Momente …"></textarea>
        </label>

        <label>Match-Foto (optional)
          <input type="file" name="photo" accept="image/*" />
        </label>

        <div id="teams-section">
          <div class="row" style="margin-top:8px;">
            <h3>Spieler / Teams</h3>
            <button class="ghost small" type="button" id="add-side">+ Team hinzufügen</button>
          </div>
          <div class="helper">Beliebige Kombis: 1v1, 2v2, free-for-all.</div>
          <div id="sides-container" class="grid" style="margin-top:10px;"></div>
        </div>

        <input type="hidden" name="sidesJson" id="sides-json" />
        <input type="hidden" name="golfLochJson" id="golf-loch-json" />
        <button type="submit">Spiel speichern</button>
      </form>
    </section>

    <script>
      var profiles = ${safeJson(profiles)};
      var golfId = ${safeJson(golfId)};
      var GOLF_PLAETZE = ${safeJson(GOLF_PLAETZE)};
      var GOLF_MODI_INFO = ${safeJson(golfModiInfo)};

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

      function isGolf() {
        const opt = gameTypeSelect.options[gameTypeSelect.selectedIndex];
        return opt && opt.dataset.slug === 'golf';
      }

      function renderProfileCheckboxes(sideId) {
        return profiles.map(function(p) {
          return '<label class="checkbox-pill"><input type="checkbox" value="' + p.id + '" name="side_players_' + sideId + '" /><span>' + escapeAttr(p.name) + '</span></label>';
        }).join('');
      }

      function addSide(defaultName) {
        sideCounter++;
        const sid = sideCounter;
        const lbl = defaultName || ('Team ' + sid);
        const card = document.createElement('section');
        card.className = 'side-card';
        card.dataset.sideId = String(sid);
        const showScore = !isGolf();
        card.innerHTML = [
          '<div class="row"><h3>' + (isGolf() ? 'Spieler ' + sid : 'Team ' + sid) + '</h3>',
          '<button class="ghost small" type="button" data-remove-side="' + sid + '">Entfernen</button></div>',
          '<label>Name<input type="text" name="side_name_' + sid + '" value="' + escapeAttr(lbl) + '" maxlength="40" required /></label>',
          showScore ? '<label>Score<input type="number" step="0.01" name="side_score_' + sid + '" placeholder="z.B. 21" required /></label>' :
                      '<input type="hidden" name="side_score_' + sid + '" value="0" class="golf-score-hidden" data-sid="' + sid + '" />',
          '<div><div class="helper" style="margin-bottom:8px;">Profil</div><div class="checkbox-grid">' + renderProfileCheckboxes(sid) + '</div></div>'
        ].join('');
        sidesContainer.appendChild(card);
      }

      function updateGolfSection() {
        const golf = isGolf();
        golfSection.style.display = golf ? 'block' : 'none';
        document.getElementById('add-side').textContent = golf ? '+ Spieler hinzufügen' : '+ Team hinzufügen';
        updatePlatzInfo();
        updateModusInfo();
        updateLochSection();
      }

      function updateModusInfo() {
        const info = GOLF_MODI_INFO[golfModusEl.value] || '';
        document.getElementById('golf-modus-info').textContent = '💡 ' + info;
      }

      function updatePlatzInfo() {
        const platz = GOLF_PLAETZE[golfPlatzEl.value];
        const infoEl = document.getElementById('golf-platz-info');
        if (platz) {
          const parTotal = Object.values(platz.par).reduce(function(a,b){return a+b;},0);
          infoEl.textContent = '📋 ' + platz.loecher + ' Loch · Par ' + parTotal;
          currentPar = platz.par;
        } else {
          infoEl.textContent = 'Eigener Platz – Par wird manuell eingegeben.';
          currentPar = {};
        }
        renderParGrid();
        renderGolfScores();
      }

      function renderParGrid() {
        const platz = GOLF_PLAETZE[golfPlatzEl.value];
        const n = platz ? platz.loecher : 18;
        golfParGrid.innerHTML = '';
        for (var h = 1; h <= n; h++) {
          const par = (currentPar[h] || currentPar[String(h)] || 4);
          golfParGrid.innerHTML += '<div style="text-align:center">'
            + '<div style="font-size:10px;color:var(--muted)">L' + h + '</div>'
            + '<input type="number" id="par_' + h + '" value="' + par + '" min="3" max="5" '
            + 'style="width:100%;padding:4px 2px;text-align:center;font-size:12px;border-radius:8px;border:1px solid var(--line);background:#081321;color:var(--text)" '
            + 'onchange="renderGolfScores()" /></div>';
        }
      }

      function getCurrentPars() {
        const platz = GOLF_PLAETZE[golfPlatzEl.value];
        const n = platz ? platz.loecher : 18;
        var pars = {};
        for (var h = 1; h <= n; h++) {
          var el = document.getElementById('par_' + h);
          pars[h] = el ? Number(el.value) : 4;
        }
        return pars;
      }

      function renderGolfScores() {
        if (golfEingabeEl.value !== 'loch') return;
        const platz = GOLF_PLAETZE[golfPlatzEl.value];
        const n = platz ? platz.loecher : 18;
        const pars = getCurrentPars();
        const players = Array.from(document.querySelectorAll('.side-card'));
        golfScoresGrid.innerHTML = '';
        players.forEach(function(card) {
          const sid = card.dataset.sideId;
          const nameEl = card.querySelector('[name="side_name_' + sid + '"]');
          const pname = nameEl ? nameEl.value : ('Spieler ' + sid);
          var html = '<div style="margin-bottom:12px;">'
            + '<div style="font-weight:600;color:var(--blue);font-size:13px;margin-bottom:6px;">⛳ ' + escapeAttr(pname) + '</div>';
          if (n > 9) {
            ['OUT (1–9)', 'IN (10–' + n + ')'].forEach(function(lbl, half) {
              html += '<div style="font-size:11px;color:var(--muted);margin-bottom:3px">' + lbl + '</div>';
              html += '<div style="display:grid;grid-template-columns:repeat(9,1fr);gap:3px;margin-bottom:6px;">';
              var start = half === 0 ? 1 : 10;
              var end   = half === 0 ? 9 : n;
              for (var h = start; h <= end; h++) {
                html += '<div style="text-align:center">'
                  + '<div style="font-size:9px;color:var(--muted)">L' + h + ' P' + pars[h] + '</div>'
                  + '<input type="number" id="loch_' + sid + '_' + h + '" value="' + pars[h] + '" min="1" max="20" '
                  + 'style="width:100%;padding:3px 1px;text-align:center;font-size:12px;border-radius:6px;border:1px solid var(--line);background:#081321;color:var(--text)" '
                  + 'onchange="updateGolfTotal(\'' + sid + '\',' + n + ')" /></div>';
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
                + 'onchange="updateGolfTotal(\'' + sid + '\',' + n + ')" /></div>';
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
        const pars = getCurrentPars();
        var total = 0; var parTotal = 0;
        for (var h = 1; h <= n; h++) {
          var el = document.getElementById('loch_' + sid + '_' + h);
          if (el) { total += Number(el.value); parTotal += (pars[h] || 4); }
        }
        var diff = total - parTotal;
        var col = diff > 0 ? '#ef4444' : (diff < 0 ? '#22c55e' : 'var(--gold)');
        var el2 = document.getElementById('golf-total-' + sid);
        if (el2) el2.innerHTML = '<span style="color:' + col + '">Total: ' + total + ' (' + (diff >= 0 ? '+' : '') + diff + ')</span>';
        // update hidden score
        var scoreEl = document.querySelector('[name="side_score_' + sid + '"]');
        if (scoreEl) scoreEl.value = total;
      }

      function updateLochSection() {
        const show = isGolf() && golfEingabeEl.value === 'loch';
        golfLochSec.style.display = show ? 'block' : 'none';
        if (show) { renderParGrid(); renderGolfScores(); }
      }

      function collectSides() {
        return Array.from(document.querySelectorAll('.side-card')).map(function(card) {
          const sid = card.dataset.sideId;
          var score;
          if (isGolf() && golfEingabeEl.value === 'gesamt') {
            var inp = card.querySelector('[name="side_score_' + sid + '"]');
            score = inp ? inp.value : 0;
          } else {
            var inp = card.querySelector('[name="side_score_' + sid + '"]');
            score = inp ? inp.value : 0;
          }
          return {
            sideName: card.querySelector('[name="side_name_' + sid + '"]').value.trim(),
            score: score,
            profileIds: Array.from(card.querySelectorAll('[name="side_players_' + sid + '"]:checked')).map(function(i){ return Number(i.value); })
          };
        });
      }

      function collectLochData() {
        if (!isGolf() || golfEingabeEl.value !== 'loch') return {};
        const platz = GOLF_PLAETZE[golfPlatzEl.value];
        const n = platz ? platz.loecher : 18;
        const pars = getCurrentPars();
        var result = {};
        Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
          const sid = card.dataset.sideId;
          var lochDetails = {};
          for (var h = 1; h <= n; h++) {
            var el = document.getElementById('loch_' + sid + '_' + h);
            if (el) lochDetails[h] = { schlaege: Number(el.value), par: pars[h] || 4 };
          }
          result[sid] = lochDetails;
        });
        return result;
      }

      gameTypeSelect.addEventListener('change', function() {
        updateGolfSection();
        sidesContainer.innerHTML = '';
        sideCounter = 0;
        if (isGolf()) { addSide('Spieler 1'); addSide('Spieler 2'); }
        else          { addSide('Team 1');    addSide('Team 2'); }
      });

      golfModusEl.addEventListener('change', updateModusInfo);
      golfPlatzEl.addEventListener('change', updatePlatzInfo);
      golfEingabeEl.addEventListener('change', function() {
        updateLochSection();
        if (isGolf() && golfEingabeEl.value === 'gesamt') {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
            const sid = card.dataset.sideId;
            var scoreEl = card.querySelector('[name="side_score_' + sid + '"]');
            if (scoreEl && scoreEl.type === 'hidden') {
              scoreEl.type = 'number';
              scoreEl.placeholder = 'Gesamtschläge';
              scoreEl.removeAttribute('class');
              var lbl = document.createElement('label');
              lbl.textContent = 'Gesamtschläge';
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

      document.addEventListener('click', function(event) {
        const btn = event.target.closest('[data-remove-side]');
        if (!btn) return;
        if (document.querySelectorAll('.side-card').length <= 2) {
          window.alert('Mindestens zwei Spieler/Teams werden benötigt.');
          return;
        }
        btn.closest('.side-card').remove();
        if (isGolf() && golfEingabeEl.value === 'loch') renderGolfScores();
      });

      form.addEventListener('submit', function() {
        if (isGolf() && golfEingabeEl.value === 'loch') {
          Array.from(document.querySelectorAll('.side-card')).forEach(function(card) {
            const sid = card.dataset.sideId;
            updateGolfTotal(sid, GOLF_PLAETZE[golfPlatzEl.value] ? GOLF_PLAETZE[golfPlatzEl.value].loecher : 18);
          });
        }
        hiddenInput.value = JSON.stringify(collectSides());
        lochInput.value   = JSON.stringify(collectLochData());
      });

      updateModusInfo();
      // Initiale Teams ohne Golf-Check
      sideCounter = 0;
      (function() {
        var s1 = ++sideCounter;
        var card1 = document.createElement('section');
        card1.className = 'side-card';
        card1.dataset.sideId = String(s1);
        card1.innerHTML = [
          '<div class="row"><h3>Team 1</h3>',
          '<button class="ghost small" type="button" data-remove-side="' + s1 + '">Entfernen</button></div>',
          '<label>Name<input type="text" name="side_name_' + s1 + '" value="Team 1" maxlength="40" required /></label>',
          '<label>Score<input type="number" step="0.01" name="side_score_' + s1 + '" placeholder="z.B. 21" required /></label>',
          '<div><div class="helper" style="margin-bottom:8px;">Profil</div><div class="checkbox-grid">' + renderProfileCheckboxes(s1) + '</div></div>'
        ].join('');
        sidesContainer.appendChild(card1);
        var s2 = ++sideCounter;
        var card2 = document.createElement('section');
        card2.className = 'side-card';
        card2.dataset.sideId = String(s2);
        card2.innerHTML = [
          '<div class="row"><h3>Team 2</h3>',
          '<button class="ghost small" type="button" data-remove-side="' + s2 + '">Entfernen</button></div>',
          '<label>Name<input type="text" name="side_name_' + s2 + '" value="Team 2" maxlength="40" required /></label>',
          '<label>Score<input type="number" step="0.01" name="side_score_' + s2 + '" placeholder="z.B. 21" required /></label>',
          '<div><div class="helper" style="margin-bottom:8px;">Profil</div><div class="checkbox-grid">' + renderProfileCheckboxes(s2) + '</div></div>'
        ].join('');
        sidesContainer.appendChild(card2);
      })();
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

    normalizedSides.push({ sideName, score, profileIds });
  }

  const profilesFound = db.prepare(`SELECT id FROM profiles WHERE id IN (${normalizedSides.flatMap((s) => s.profileIds).map(() => '?').join(',')})`).all(...normalizedSides.flatMap((s) => s.profileIds));
  if (profilesFound.length !== usedProfileIds.size) {
    removeUploadedFile(req.file);
    return redirectWithMessage(res, '/matches/new', 'Mindestens ein Profil existiert nicht mehr.');
  }

  const scores = normalizedSides.map((s) => s.score);
  const bestScore = gameType.scoringMode === 'lower_wins' ? Math.min(...scores) : Math.max(...scores);

  const insertMatch = db.prepare(`INSERT INTO matches (game_type_id, played_at, notes, photo_path, created_by_profile_id) VALUES (?, ?, ?, ?, ?)`);
  const insertSide = db.prepare(`INSERT INTO match_sides (match_id, side_name, score, is_winner) VALUES (?, ?, ?, ?)`);
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
      const sideResult = insertSide.run(result.lastInsertRowid, side.sideName, side.score, side.score === bestScore ? 1 : 0);
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
