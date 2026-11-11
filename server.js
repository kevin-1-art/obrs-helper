const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const express = require('express');
const { rateLimit } = require('express-rate-limit');
require('dotenv').config({ path: path.join(__dirname, 'config', '.env') });

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const BASE_URL = (process.env.OBRS_BASE_URL || 'https://obrs-api.ursb.go.ug').replace(/\/+$/, '');
const APP_ACCESS_PASSWORD = process.env.APP_ACCESS_PASSWORD || '';
const APP_SESSION_SECRET = process.env.APP_SESSION_SECRET || '';
const UNLOCK_METHOD = 'POST';
const PAYMENT_REFERENCE_QUERY_PARAM = 'reference';
const PUBLIC_DIR = path.join(__dirname, 'public');
const VALUE_LIMIT = 256;
const SESSION_COOKIE = 'obrs_helper_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const APP_AUTH_ENABLED = Boolean(APP_ACCESS_PASSWORD && APP_SESSION_SECRET);

if (Boolean(APP_ACCESS_PASSWORD) !== Boolean(APP_SESSION_SECRET)) {
  throw new Error('APP_ACCESS_PASSWORD and APP_SESSION_SECRET must both be configured.');
}
if (process.env.NODE_ENV === 'production' && !APP_AUTH_ENABLED) {
  throw new Error('APP_ACCESS_PASSWORD and APP_SESSION_SECRET are required in production.');
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

function sessionCookieValue() {
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const signature = crypto
    .createHmac('sha256', APP_SESSION_SECRET)
    .update(`${expiresAt}:${APP_ACCESS_PASSWORD}`)
    .digest('base64url');
  return `${expiresAt}.${signature}`;
}

function hasValidAppSession(req) {
  if (!APP_AUTH_ENABLED) return true;
  const cookieHeader = req.get('cookie') || '';
  const sessionCookie = cookieHeader.split(';').map((part) => part.trim())
    .find((part) => part.startsWith(`${SESSION_COOKIE}=`));
  if (!sessionCookie) return false;
  const value = sessionCookie.slice(SESSION_COOKIE.length + 1);
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

function setAppSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.set('Set-Cookie', `${SESSION_COOKIE}=${sessionCookieValue()}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; SameSite=Strict${secure}`);
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

app.get('/api/auth/session', (req, res) => {
  res.json({ authenticated: hasValidAppSession(req), required: APP_AUTH_ENABLED });
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  if (!APP_AUTH_ENABLED) return res.json({ authenticated: true, required: false });
  const password = req.body && typeof req.body.password === 'string' ? req.body.password : '';
  if (!safeEqual(password, APP_ACCESS_PASSWORD)) {
    return res.status(401).json({ error: 'Incorrect app password.' });
  }
  setAppSessionCookie(res);
  return res.json({ authenticated: true, required: true });
});

app.post('/api/auth/logout', (req, res) => {
  clearAppSessionCookie(res);
  res.json({ authenticated: false });
});

function requireAppSession(req, res, next) {
  if (!hasValidAppSession(req)) {
    return res.status(401).json({ error: 'Sign in to OBRS Helper.', code: 'APP_AUTH_REQUIRED' });
  }
  next();
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
app.get('*', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

app.listen(PORT, HOST, () => {
  process.stdout.write(`OBRS Helper listening on ${HOST}:${PORT}\n`);
});
