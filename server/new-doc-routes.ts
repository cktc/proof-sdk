import { Router, urlencoded, type Request, type Response, type NextFunction } from 'express';
import { timingSafeEqual } from 'crypto';
import Database from 'better-sqlite3';
import path from 'path';

export const newDocRoutes = Router();

function timingSafeEqualStrings(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

function requireBasicAuth(req: Request, res: Response, next: NextFunction): void {
  const expected = (process.env.PROOF_CREATOR_PASSWORD || '').trim();
  if (!expected) {
    res.status(503).type('text/plain').send(
      'New-doc form is disabled.\n' +
      'Set the PROOF_CREATOR_PASSWORD environment variable on the server, then reload.\n',
    );
    return;
  }
  const header = req.header('authorization') || '';
  const match = header.match(/^Basic\s+(.+)$/i);
  let password: string | null = null;
  if (match) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      password = colon >= 0 ? decoded.slice(colon + 1) : decoded;
    } catch {
      password = null;
    }
  }
  if (!password || !timingSafeEqualStrings(password, expected)) {
    res
      .status(401)
      .set('WWW-Authenticate', 'Basic realm="Proof - Create new doc"')
      .type('text/plain')
      .send('Authentication required.');
    return;
  }
  next();
}

let creatorDb: Database.Database | null = null;
function getCreatorDb(): Database.Database {
  if (creatorDb) return creatorDb;
  const dbPath = (process.env.DATABASE_PATH || '').trim();
  if (!dbPath) {
    throw new Error('DATABASE_PATH not set; cannot open creator index');
  }
  creatorDb = new Database(dbPath);
  creatorDb.exec(`
    CREATE TABLE IF NOT EXISTS creator_doc_index (
      slug TEXT PRIMARY KEY,
      access_token TEXT NOT NULL,
      title TEXT NOT NULL,
      owner_name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      created_via TEXT NOT NULL DEFAULT 'web-form'
    )
  `);
  return creatorDb;
}

function recordCreatorDoc(record: { slug: string; accessToken: string; title: string; ownerName: string }): void {
  try {
    const db = getCreatorDb();
    const stmt = db.prepare(
      'INSERT OR REPLACE INTO creator_doc_index (slug, access_token, title, owner_name, created_at, created_via) VALUES (?, ?, ?, ?, ?, ?)',
    );
    stmt.run(record.slug, record.accessToken, record.title, record.ownerName, new Date().toISOString(), 'web-form');
  } catch (error) {
    console.error('[new-doc] failed to record creator-doc-index entry', error);
  }
}

function listCreatorDocs(): Array<{ slug: string; access_token: string; title: string; owner_name: string; created_at: string; share_state: string | null; doc_updated_at: string | null }> {
  const db = getCreatorDb();
  // Best-effort join with documents table to get current share_state and updated_at; tolerate missing rows
  let rows: Array<Record<string, unknown>> = [];
  try {
    rows = db.prepare(`
      SELECT
        c.slug,
        c.access_token,
        c.title,
        c.owner_name,
        c.created_at,
        d.share_state AS share_state,
        d.updated_at AS doc_updated_at,
        d.deleted_at AS deleted_at
      FROM creator_doc_index c
      LEFT JOIN documents d ON d.slug = c.slug
      ORDER BY c.created_at DESC
    `).all() as Array<Record<string, unknown>>;
  } catch {
    rows = db.prepare('SELECT slug, access_token, title, owner_name, created_at FROM creator_doc_index ORDER BY created_at DESC').all() as Array<Record<string, unknown>>;
  }
  return rows
    .filter((r) => r.deleted_at === null || r.deleted_at === undefined)
    .map((r) => ({
      slug: String(r.slug),
      access_token: String(r.access_token),
      title: String(r.title || '(untitled)'),
      owner_name: String(r.owner_name || ''),
      created_at: String(r.created_at || ''),
      share_state: r.share_state == null ? null : String(r.share_state),
      doc_updated_at: r.doc_updated_at == null ? null : String(r.doc_updated_at),
    }));
}

const FORM_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>New doc · Proof</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 720px; margin: 32px auto; padding: 0 20px; color: #17261d; background: #f7faf5; }
  @media (prefers-color-scheme: dark) { body { color: #e6f1e8; background: #14201a; } textarea, input { background: #1d2c24; color: inherit; border-color: #2c4034; } }
  h1 { font-size: 1.5rem; margin: 0 0 16px; }
  p { color: #4a6155; }
  label { display: block; font-weight: 600; margin: 16px 0 6px; }
  input[type=text], textarea { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #cfdbcf; box-sizing: border-box; font: inherit; }
  textarea { min-height: 280px; font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; resize: vertical; }
  button { margin-top: 20px; padding: 12px 20px; border-radius: 8px; border: 0; background: #266854; color: white; font: inherit; font-weight: 600; cursor: pointer; }
  button:hover { background: #2f7c63; }
  .help { margin-top: 28px; padding: 16px; border-left: 3px solid #2f7c63; background: rgba(47,124,99,0.06); border-radius: 0 8px 8px 0; }
  nav { margin-bottom: 16px; font-size: 0.9rem; }
  nav a { color: #266854; margin-right: 16px; text-decoration: none; }
  nav a:hover { text-decoration: underline; }
</style>
</head>
<body>
<nav><a href="/new">New doc</a> · <a href="/docs">My docs</a></nav>
<h1>Create a new Proof doc</h1>
<p>Submit a title and starter markdown. You'll be redirected to the editor URL with a share token attached.</p>

<form method="POST" action="/new">
  <label for="title">Title</label>
  <input type="text" id="title" name="title" required maxlength="200" autofocus />

  <label for="ownerName">Your name (for ownerId)</label>
  <input type="text" id="ownerName" name="ownerName" placeholder="e.g. chris, daniel" maxlength="80" />

  <label for="markdown">Starter markdown</label>
  <textarea id="markdown" name="markdown" placeholder="# My doc&#10;&#10;Write something to start..."></textarea>

  <button type="submit">Create doc</button>
</form>

<div class="help">
  <strong>What happens:</strong> the server creates the doc using the master API key, then redirects you to the editor URL <code>/d/&lt;slug&gt;?token=...</code>. The doc is also added to your <a href="/docs">My docs</a> list so you can find it later.
</div>
</body>
</html>
`;

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDateTime(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  // Local-time short format; readable
  return d.toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' });
}

function renderDocsHtml(rows: ReturnType<typeof listCreatorDocs>): string {
  const items = rows
    .map((r) => {
      const url = `/d/${encodeURIComponent(r.slug)}?token=${encodeURIComponent(r.access_token)}`;
      const stateBadge = r.share_state && r.share_state !== 'ACTIVE'
        ? `<span class="badge badge-warn">${escapeHtml(r.share_state)}</span>`
        : '';
      const updated = r.doc_updated_at ? formatDateTime(r.doc_updated_at) : formatDateTime(r.created_at);
      return `<li>
        <a class="title" href="${escapeHtml(url)}">${escapeHtml(r.title)}</a>
        ${stateBadge}
        <div class="meta">
          <span>by ${escapeHtml(r.owner_name)}</span>
          <span>·</span>
          <span>updated ${escapeHtml(updated)}</span>
          <span>·</span>
          <span class="slug">${escapeHtml(r.slug)}</span>
        </div>
      </li>`;
    })
    .join('\n');

  const empty = rows.length === 0
    ? '<p class="empty">No docs yet. <a href="/new">Create one →</a></p>'
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>My docs · Proof</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 ui-sans-serif, system-ui, sans-serif; max-width: 820px; margin: 32px auto; padding: 0 20px; color: #17261d; background: #f7faf5; }
  @media (prefers-color-scheme: dark) { body { color: #e6f1e8; background: #14201a; } li { background: #1d2c24; } }
  h1 { font-size: 1.5rem; margin: 0 0 16px; }
  nav { margin-bottom: 16px; font-size: 0.9rem; }
  nav a { color: #266854; margin-right: 16px; text-decoration: none; }
  nav a:hover { text-decoration: underline; }
  ul { list-style: none; padding: 0; margin: 0; }
  li { background: white; padding: 14px 18px; border-radius: 10px; margin-bottom: 10px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
  a.title { color: #266854; font-weight: 600; text-decoration: none; font-size: 1.05rem; }
  a.title:hover { text-decoration: underline; }
  .meta { color: #6b7d72; font-size: 0.85rem; margin-top: 4px; display: flex; gap: 8px; flex-wrap: wrap; }
  .meta .slug { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; vertical-align: middle; margin-left: 8px; }
  .badge-warn { background: #fff3cd; color: #856404; }
  @media (prefers-color-scheme: dark) { .badge-warn { background: #4a3a00; color: #ffd966; } }
  .empty { color: #6b7d72; font-style: italic; padding: 30px 0; text-align: center; }
</style>
</head>
<body>
<nav><a href="/new">New doc</a> · <a href="/docs">My docs</a></nav>
<h1>My docs (${rows.length})</h1>
${empty}
<ul>
${items}
</ul>
</body>
</html>
`;
}

newDocRoutes.get('/new', requireBasicAuth, (_req: Request, res: Response) => {
  res.type('html').send(FORM_HTML);
});

newDocRoutes.get('/docs', requireBasicAuth, (_req: Request, res: Response) => {
  try {
    const rows = listCreatorDocs();
    res.type('html').send(renderDocsHtml(rows));
  } catch (error) {
    console.error('[new-doc] /docs failed', error);
    res.status(500).type('text/plain').send('Failed to list docs: ' + String((error as Error)?.message || error));
  }
});

newDocRoutes.post(
  '/new',
  requireBasicAuth,
  urlencoded({ extended: false, limit: '10mb' }),
  async (req: Request, res: Response): Promise<void> => {
    const body = (req.body || {}) as Record<string, unknown>;
    const title = typeof body.title === 'string' ? body.title.trim().slice(0, 200) : '';
    const markdown = typeof body.markdown === 'string' ? body.markdown : '';
    const ownerName =
      typeof body.ownerName === 'string' && body.ownerName.trim().length > 0
        ? body.ownerName.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').slice(0, 80)
        : 'web';

    if (!title) {
      res.status(400).type('text/plain').send('Title is required.');
      return;
    }
    if (!markdown.trim()) {
      res.status(400).type('text/plain').send('Markdown body cannot be empty.');
      return;
    }

    const apiKey = (process.env.PROOF_SHARE_MARKDOWN_API_KEY || '').trim();
    if (!apiKey) {
      res
        .status(503)
        .type('text/plain')
        .send('Server has no PROOF_SHARE_MARKDOWN_API_KEY configured; cannot create docs.');
      return;
    }

    const port = Number.parseInt(process.env.PORT || '4000', 10);
    const internalPort = Number.isFinite(port) && port > 0 ? port : 4000;
    const internalUrl = `http://127.0.0.1:${internalPort}/api/share/markdown`;

    try {
      const r = await fetch(internalUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          markdown,
          title,
          ownerId: `human:${ownerName}`,
        }),
      });
      const text = await r.text();
      let data: Record<string, unknown> = {};
      try {
        data = JSON.parse(text) as Record<string, unknown>;
      } catch {
        data = {};
      }

      if (!r.ok || typeof data.tokenUrl !== 'string') {
        res
          .status(r.ok ? 502 : r.status)
          .type('text/plain')
          .send(
            'Failed to create doc.\n' +
              `Upstream HTTP ${r.status}\n` +
              `Response: ${text.slice(0, 500)}\n`,
          );
        return;
      }

      // Record into local creator index so /docs can list it
      const slug = typeof data.slug === 'string' ? data.slug : '';
      const accessToken = typeof data.accessToken === 'string' ? data.accessToken : '';
      if (slug && accessToken) {
        recordCreatorDoc({ slug, accessToken, title, ownerName });
      }

      res.redirect(302, data.tokenUrl);
    } catch (error) {
      console.error('[new-doc] internal create failed', error);
      res
        .status(502)
        .type('text/plain')
        .send('Could not reach internal share endpoint.\n' + String((error as Error)?.message || error));
    }
  },
);
