const path = require('node:path');
const { Readable } = require('node:stream');
const express = require('express');
require('dotenv').config({ path: path.join(__dirname, 'config', '.env') });

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = (process.env.OBRS_BASE_URL || 'https://obrs-api.ursb.go.ug').replace(/\/+$/, '');
const UNLOCK_METHOD = 'POST';
const PAYMENT_REFERENCE_QUERY_PARAM = 'reference';
const PUBLIC_DIR = path.join(__dirname, 'public');
const VALUE_LIMIT = 256;

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

app.use(express.static(PUBLIC_DIR, { etag: false, lastModified: false, maxAge: 0 }));

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

app.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`OBRS Helper listening on port ${PORT}\n`);
});
