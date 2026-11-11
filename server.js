const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const bcrypt = require('bcryptjs');
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { Pool } = require('pg');
require('dotenv').config({ path: path.join(__dirname, 'config', '.env') });

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const BASE_URL = (process.env.OBRS_BASE_URL || 'https://obrs-api.ursb.go.ug').replace(/\/+$/, '');
const DATABASE_URL = process.env.DATABASE_URL || '';
const BOOTSTRAP_ADMIN_USERNAME = process.env.BOOTSTRAP_ADMIN_USERNAME || '';
const BOOTSTRAP_ADMIN_PASSWORD = process.env.BOOTSTRAP_ADMIN_PASSWORD || '';
const APP_ACCESS_PASSWORD = process.env.APP_ACCESS_PASSWORD || '';
const APP_SESSION_SECRET = process.env.APP_SESSION_SECRET || '';
const UNLOCK_METHOD = 'POST';
const PAYMENT_REFERENCE_QUERY_PARAM = 'reference';
const PUBLIC_DIR = path.join(__dirname, 'public');
const VALUE_LIMIT = 256;
const SESSION_COOKIE = 'obrs_helper_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const DATABASE_AUTH_ENABLED = Boolean(DATABASE_URL);
const LEGACY_AUTH_ENABLED = Boolean(APP_ACCESS_PASSWORD && APP_SESSION_SECRET);
const APP_AUTH_ENABLED = DATABASE_AUTH_ENABLED || LEGACY_AUTH_ENABLED;
const USER_TABLE = 'obrs_helper_users';
const BOOTSTRAP_LOCK_ID = 918273645;
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_BYTES = 72;
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), 12);
const authPool = DATABASE_AUTH_ENABLED
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
      max: 5,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 10000
    })
  : null;

if (!DATABASE_AUTH_ENABLED && Boolean(APP_ACCESS_PASSWORD) !== Boolean(APP_SESSION_SECRET)) {
  throw new Error('APP_ACCESS_PASSWORD and APP_SESSION_SECRET must both be configured.');
}
if (DATABASE_AUTH_ENABLED && !APP_SESSION_SECRET) {
  throw new Error('APP_SESSION_SECRET is required when DATABASE_URL is configured.');
}
if (process.env.NODE_ENV === 'production' && !APP_AUTH_ENABLED) {
  throw new Error('DATABASE_URL or the legacy app password settings are required in production.');
}
if (APP_AUTH_ENABLED && APP_SESSION_SECRET.length < 32) {
  throw new Error('APP_SESSION_SECRET must be at least 32 characters long.');
}

let parsedBaseUrl;
try {
  parsedBaseUrl = new URL(BASE_URL);
  if (!['http:', 'https:'].includes(parsedBaseUrl.protocol)) {
    throw new Error('OBRS_BASE_URL must use HTTP or HTTPS.');
  }
} catch (error) {
  throw new Error(`Invalid OBRS_BASE_URL: ${error.message}`);
}

app.disable('x-powered-by');
if (process.env.NODE_ENV === 'production') app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'; img-src 'self' blob: data:; frame-src blob:; object-src blob:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  next();
});
app.use(express.json({ limit: '2kb' }));

app.use(express.static(PUBLIC_DIR, { etag: false, lastModified: false, maxAge: 0 }));

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function cookieFromRequest(req) {
  const cookieHeader = req.get('cookie') || '';
  const sessionCookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  return sessionCookie ? sessionCookie.slice(SESSION_COOKIE.length + 1) : '';
}

function legacySessionCookieValue() {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const signature = crypto
    .createHmac('sha256', APP_SESSION_SECRET)
    .update(`${expiresAt}:${APP_ACCESS_PASSWORD}`)
    .digest('base64url');
  return `${expiresAt}.${signature}`;
}

function hasValidLegacySession(req) {
  if (!LEGACY_AUTH_ENABLED) return true;
  const value = cookieFromRequest(req);
  const [expiresText, providedSignature] = value.split('.');
  const expiresAt = Number(expiresText);
  if (!Number.isInteger(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000) || !providedSignature) {
    return false;
  }
  const expectedSignature = crypto
    .createHmac('sha256', APP_SESSION_SECRET)
    .update(`${expiresAt}:${APP_ACCESS_PASSWORD}`)
    .digest('base64url');
  return safeEqual(providedSignature, expectedSignature);
}

function accountSessionCookieValue(user) {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payload = `${user.id}:${expiresAt}:${user.session_version}`;
  const signature = crypto.createHmac('sha256', APP_SESSION_SECRET).update(payload).digest('base64url');
  return `${user.id}.${expiresAt}.${user.session_version}.${signature}`;
}

async function getAccountFromSession(req) {
  const value = cookieFromRequest(req);
  const [userId, expiresText, versionText, providedSignature] = value.split('.');
  const expiresAt = Number(expiresText);
  const sessionVersion = Number(versionText);
  if (!validUserId(userId) || !Number.isInteger(expiresAt) || expiresAt <= Math.floor(Date.now() / 1000)
    || !Number.isInteger(sessionVersion) || !providedSignature) return null;

  const payload = `${userId}:${expiresAt}:${sessionVersion}`;
  const expectedSignature = crypto.createHmac('sha256', APP_SESSION_SECRET).update(payload).digest('base64url');
  if (!safeEqual(providedSignature, expectedSignature)) return null;

  const result = await authPool.query(
    `SELECT id, username, role, session_version FROM ${USER_TABLE}
     WHERE id = $1 AND session_version = $2 AND is_active = TRUE`,
    [userId, sessionVersion]
  );
  return result.rows[0] || null;
}

function setAppSessionCookie(res, user) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  const value = DATABASE_AUTH_ENABLED ? accountSessionCookieValue(user) : legacySessionCookieValue();
  res.set('Set-Cookie', `${SESSION_COOKIE}=${value}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict${secure}`);
}

function clearAppSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.set('Set-Cookie', `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${secure}`);
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many sign-in attempts. Try again later.' }
});

app.get('/api/auth/session', asyncRoute(async (req, res) => {
  if (DATABASE_AUTH_ENABLED) {
    await authPool.query('SELECT 1');
    const user = await getAccountFromSession(req);
    return res.json({
      authenticated: Boolean(user),
      required: true,
      mode: 'accounts',
      username: user ? user.username : null,
      isAdmin: Boolean(user && user.role === 'admin')
    });
  }
  const authenticated = hasValidLegacySession(req);
  return res.json({
    authenticated,
    required: LEGACY_AUTH_ENABLED,
    mode: LEGACY_AUTH_ENABLED ? 'shared' : 'none',
    username: null,
    isAdmin: false
  });
}));

app.post('/api/auth/login', loginLimiter, asyncRoute(async (req, res) => {
  if (DATABASE_AUTH_ENABLED) {
    const rawUsername = req.body && typeof req.body.username === 'string' ? req.body.username : '';
    const username = rawUsername.trim().toLowerCase();
    const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
    const result = validUsername(username)
      ? await authPool.query(
          `SELECT id, username, password_hash, role, is_active, session_version FROM ${USER_TABLE} WHERE username = $1`,
          [username]
        )
      : { rows: [] };
    const user = result.rows[0];
    const passwordMatches = await bcrypt.compare(password, user ? user.password_hash : DUMMY_PASSWORD_HASH);
    if (!user || !user.is_active || !passwordMatches) {
      return res.status(401).json({ error: 'Incorrect username or password.' });
    }
    setAppSessionCookie(res, user);
    return res.json({
      authenticated: true,
      required: true,
      mode: 'accounts',
      username: user.username,
      isAdmin: user.role === 'admin'
    });
  }

  if (!LEGACY_AUTH_ENABLED) return res.json({ authenticated: true, required: false, mode: 'none' });
  const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  if (!safeEqual(password, APP_ACCESS_PASSWORD)) {
    return res.status(401).json({ error: 'Incorrect app password.' });
  }
  setAppSessionCookie(res);
  return res.json({ authenticated: true, required: true, mode: 'shared', isAdmin: false });
}));

app.post('/api/auth/logout', (req, res) => {
  clearAppSessionCookie(res);
  res.json({ authenticated: false });
});

function validUsername(value) {
  return typeof value === 'string'
    && value.length >= 3
    && value.length <= 32
    && /^[a-z0-9][a-z0-9._-]*$/i.test(value);
}

function validUserId(value) {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function validPassword(value) {
  return typeof value === 'string'
    && Array.from(value).length >= PASSWORD_MIN_LENGTH
    && Buffer.byteLength(value, 'utf8') <= PASSWORD_MAX_BYTES
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function accountPayload(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    active: user.is_active,
    createdAt: user.created_at
  };
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function requireAppSession(req, res, next) {
  if (DATABASE_AUTH_ENABLED) {
    return getAccountFromSession(req).then((user) => {
      if (!user) {
        return res.status(401).json({ error: 'Sign in to OBRS Helper.', code: 'APP_AUTH_REQUIRED' });
      }
      req.user = user;
      return next();
    }).catch(next);
  }
  if (!hasValidLegacySession(req)) {
    return res.status(401).json({ error: 'Sign in to OBRS Helper.', code: 'APP_AUTH_REQUIRED' });
  }
  return next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Administrator access is required.' });
  }
  next();
}

function validateNewPassword(req, res) {
  const password = req.body && req.body.password;
  if (!validPassword(password)) {
    res.status(400).json({ error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters and no more than ${PASSWORD_MAX_BYTES} UTF-8 bytes.` });
    return null;
  }
  return password;
}

async function initializeAccountDatabase() {
  await authPool.query(
    `CREATE TABLE IF NOT EXISTS ${USER_TABLE} (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      username varchar(32) NOT NULL UNIQUE,
      password_hash text NOT NULL,
      role varchar(16) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
      is_active boolean NOT NULL DEFAULT TRUE,
      session_version integer NOT NULL DEFAULT 0,
      created_at timestamptz NOT NULL DEFAULT now()
    )`
  );

  const client = await authPool.connect();
  let locked = false;
  try {
    await client.query('SELECT pg_advisory_lock($1)', [BOOTSTRAP_LOCK_ID]);
    locked = true;
    const result = await client.query(`SELECT COUNT(*)::integer AS count FROM ${USER_TABLE}`);
    if (result.rows[0].count === 0) {
      const username = BOOTSTRAP_ADMIN_USERNAME.trim().toLowerCase();
      if (!validUsername(username) || !validPassword(BOOTSTRAP_ADMIN_PASSWORD)) {
        throw new Error('Set a valid BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD before initializing the empty account database.');
      }
      const passwordHash = await bcrypt.hash(BOOTSTRAP_ADMIN_PASSWORD, 12);
      await client.query(
        `INSERT INTO ${USER_TABLE} (username, password_hash, role) VALUES ($1, $2, 'admin')`,
        [username, passwordHash]
      );
      process.stdout.write('Created the initial OBRS Helper administrator account.\n');
    }
  } finally {
    try {
      if (locked) await client.query('SELECT pg_advisory_unlock($1)', [BOOTSTRAP_LOCK_ID]);
    } finally {
      client.release();
    }
  }
}

function requireToken(req, res, next) {
  const authorization = req.get('authorization') || '';
  if (!/^Bearer\s+\S+$/i.test(authorization)) {
    return res.status(401).json({ error: 'Token expired or invalid, paste a new one' });
  }
  req.obrsAuthorization = authorization;
  next();
}

function requiredValue(req, res, name) {
  const value = typeof req.query[name] === 'string' ? req.query[name].trim() : '';
  if (!value || value.length > VALUE_LIMIT || /[\u0000-\u001f\u007f]/.test(value)) {
    res.status(400).json({ error: `${name} is required and must be valid` });
    return null;
  }
  return value;
}

function upstreamUrl(route, query) {
  const url = new URL(route, `${BASE_URL}/`);
  for (const [key, value] of Object.entries(query || {})) {
    url.searchParams.set(key, value);
  }
  return url;
}

function upstreamErrorMessage(body) {
  try {
    const parsed = JSON.parse(body);
    if (typeof parsed === 'string') return parsed;
    for (const key of ['message', 'error', 'detail', 'title']) {
      if (typeof parsed[key] === 'string' && parsed[key].trim()) return parsed[key].trim();
    }
  } catch {
    // The upstream may return a non-JSON error body.
  }
  return '';
}

function mappedError(status, body) {
  if (status === 401) return 'Token expired or invalid, paste a new one';
  if (status === 403) return 'Forbidden';
  if (status === 404) return 'Not found';
  if (status >= 500 || status === 0) return 'OBRS service unavailable';
  return upstreamErrorMessage(body) || `OBRS request failed (${status})`;
}

async function fetchUpstream(req, res, method, route, query, binary) {
  const targetUrl = upstreamUrl(route, query);
  let upstream;
  try {
    const headers = {
      Accept: binary ? 'application/pdf, image/*, application/json' : 'application/json'
    };
    if (req.obrsAuthorization) headers.Authorization = req.obrsAuthorization;
    upstream = await fetch(targetUrl, {
      method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(60000)
    });
  } catch {
    return res.status(503).json({ error: 'OBRS service unavailable' });
  }

  if (!upstream.ok) {
    const body = await upstream.text().catch(() => '');
    return res.status(upstream.status >= 500 ? 503 : upstream.status).json({
      error: mappedError(upstream.status, body)
    });
  }

  if (binary) {
    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    res.set('Content-Type', contentType);
    res.set('X-OBRS-Document-Link', targetUrl.toString());
    const disposition = upstream.headers.get('content-disposition');
    if (disposition) res.set('Content-Disposition', disposition);
    const contentLength = upstream.headers.get('content-length');
    if (contentLength) res.set('Content-Length', contentLength);
    if (!upstream.body) return res.status(502).json({ error: 'OBRS returned an empty document' });
    return Readable.fromWeb(upstream.body).pipe(res);
  }

  const body = await upstream.text();
  const contentType = upstream.headers.get('content-type') || '';
  if (contentType.includes('json')) {
    res.status(upstream.status).type('application/json').send(body);
  } else {
    res.status(upstream.status).type(contentType || 'text/plain').send(body);
  }
}

const api = express.Router();
api.use(requireAppSession);

api.get('/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const result = await authPool.query(
    `SELECT id, username, role, is_active, created_at FROM ${USER_TABLE} ORDER BY username`
  );
  res.json({ users: result.rows.map(accountPayload) });
}));

api.post('/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const username = req.body && typeof req.body.username === 'string'
    ? req.body.username.trim().toLowerCase()
    : '';
  if (!validUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3–32 letters, numbers, dots, underscores, or hyphens.' });
  }
  const password = validateNewPassword(req, res);
  if (!password) return;
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const result = await authPool.query(
      `INSERT INTO ${USER_TABLE} (username, password_hash) VALUES ($1, $2)
       RETURNING id, username, role, is_active, created_at`,
      [username, passwordHash]
    );
    return res.status(201).json({ user: accountPayload(result.rows[0]) });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'That username already exists.' });
    throw error;
  }
}));

api.put('/admin/users/:id/password', requireAdmin, asyncRoute(async (req, res) => {
  if (!validUserId(req.params.id)) return res.status(400).json({ error: 'Invalid user ID.' });
  const password = validateNewPassword(req, res);
  if (!password) return;
  const passwordHash = await bcrypt.hash(password, 12);
  const result = await authPool.query(
    `UPDATE ${USER_TABLE}
     SET password_hash = $1, session_version = session_version + 1
     WHERE id = $2
     RETURNING id`,
    [passwordHash, req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'User not found.' });
  res.json({ updated: true });
}));

api.patch('/admin/users/:id/status', requireAdmin, asyncRoute(async (req, res) => {
  if (!validUserId(req.params.id)) return res.status(400).json({ error: 'Invalid user ID.' });
  const active = req.body && req.body.active;
  if (typeof active !== 'boolean') {
    return res.status(400).json({ error: 'Active status must be true or false.' });
  }
  const result = await authPool.query(
    `UPDATE ${USER_TABLE}
     SET is_active = $1, session_version = session_version + 1
     WHERE id = $2 AND role = 'user'
     RETURNING id, username, role, is_active, created_at`,
    [active, req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'User not found or administrator status cannot be changed.' });
  res.json({ user: accountPayload(result.rows[0]) });
}));

api.delete('/admin/users/:id', requireAdmin, asyncRoute(async (req, res) => {
  if (!validUserId(req.params.id)) return res.status(400).json({ error: 'Invalid user ID.' });
  const result = await authPool.query(
    `DELETE FROM ${USER_TABLE} WHERE id = $1 AND role = 'user' RETURNING id`,
    [req.params.id]
  );
  if (!result.rowCount) return res.status(404).json({ error: 'User not found or administrator accounts cannot be deleted.' });
  res.json({ deleted: true });
}));

api.get('/documents', requireToken, (req, res) => {
  const brn = requiredValue(req, res, 'brn');
  if (!brn) return;
  const page = Number.parseInt(req.query.page, 10);
  const query = { pageSize: '150' };
  if (Number.isInteger(page) && page > 1 && page <= 1000) query.page = String(page);
  return fetchUpstream(
    req,
    res,
    'GET',
    `incorporation/companies/continuous-filing/get-registered-documents/${encodeURIComponent(brn)}`,
    query,
    false
  );
});

api.get('/document', (req, res) => {
  const signingCode = requiredValue(req, res, 'signingCode');
  if (!signingCode) return;
  return fetchUpstream(
    req,
    res,
    'GET',
    `incorporation/companies/continuous-filing/downloads/client-document/${encodeURIComponent(signingCode)}`,
    null,
    true
  );
});

api.post('/unlock', requireToken, (req, res) => {
  const brn = requiredValue(req, res, 'brn');
  if (!brn) return;
  return fetchUpstream(
    req,
    res,
    UNLOCK_METHOD,
    `data-correction/reconciliations/unlock-file/COMPANY/${encodeURIComponent(brn)}`,
    null,
    false
  );
});

api.get('/legal-document', (req, res) => {
  const instrumentNumber = requiredValue(req, res, 'instrumentNumber');
  if (!instrumentNumber) return;
  return fetchUpstream(
    req,
    res,
    'GET',
    'legal-documents/registry/client-copy',
    { instrumentNumber },
    true
  );
});

api.get('/payment', (req, res) => {
  const reference = requiredValue(req, res, 'reference');
  if (!reference) return;
  return fetchUpstream(
    req,
    res,
    'GET',
    'billing/transaction/query',
    { [PAYMENT_REFERENCE_QUERY_PARAM]: reference },
    false
  );
});

app.use('/api', api);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  const code = error && typeof error.code === 'string' ? error.code : 'unknown';
  process.stderr.write(`Request failed (${code}).\n`);
  return res.status(503).json({ error: 'Account service unavailable. Please try again.' });
});
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

async function startServer() {
  if (DATABASE_AUTH_ENABLED) await initializeAccountDatabase();
  app.listen(PORT, HOST, () => {
    process.stdout.write(`OBRS Helper listening on ${HOST}:${PORT}\n`);
  });
}

startServer().catch((error) => {
  const code = error && typeof error.code === 'string' ? ` (${error.code})` : '';
  process.stderr.write(`OBRS Helper could not start${code}. Check the database connection and bootstrap administrator settings.\n`);
  process.exitCode = 1;
});
