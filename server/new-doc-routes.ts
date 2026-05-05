import { Router, urlencoded, type Request, type Response, type NextFunction } from 'express';
import { timingSafeEqual } from 'crypto';

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
</style>
</head>
<body>
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
  <strong>What happens:</strong> the server creates the doc using the master API key, then redirects you to the editor URL <code>/d/&lt;slug&gt;?token=...</code>. Save or share that URL — it's how you (and any AI agents) come back to this doc.
</div>
</body>
</html>
`;

newDocRoutes.get('/new', requireBasicAuth, (_req: Request, res: Response) => {
  res.type('html').send(FORM_HTML);
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
