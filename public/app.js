const tokenInput = document.querySelector('#token');
const toggleTokenButton = document.querySelector('#toggle-token');
const clearTokenButton = document.querySelector('#clear-token');
const TOKEN_STORAGE_KEY = 'obrsBearerToken';
const recentActions = [];
let currentObjectUrl = null;
let documents = [];

tokenInput.value = sessionStorage.getItem(TOKEN_STORAGE_KEY) || '';

function setStatus(container, message, kind) {
  container.replaceChildren();
  const status = document.createElement('div');
  status.className = `status ${kind || ''}`;
  status.textContent = message;
  container.append(status);
}

function setLoading(container, button, text) {
  container.replaceChildren();
  const status = document.createElement('div');
  status.className = 'status';
  const spinner = document.createElement('span');
  spinner.className = 'spinner';
  spinner.setAttribute('aria-hidden', 'true');
  const label = document.createElement('span');
  label.textContent = text;
  status.append(spinner, label);
  container.append(status);
  button.disabled = true;
}

function tokenHeaders() {
  const token = tokenInput.value.trim();
  if (!token) throw new Error('Paste your bearer token before continuing.');
  return { Authorization: `Bearer ${token}` };
}

function clearBearerToken() {
  tokenInput.value = '';
  sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  tokenInput.type = 'password';
  toggleTokenButton.textContent = 'Show';
  toggleTokenButton.setAttribute('aria-pressed', 'false');
}

async function requestJson(url, options, includeToken = true) {
  let response;
  try {
    const headers = includeToken ? tokenHeaders() : {};
    response = await fetch(url, { ...options, headers: { ...headers, ...(options.headers || {}) } });
  } catch {
    throw new Error('OBRS service unavailable');
  }

  const text = await response.text();
  let parsed;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  if (!response.ok) {
    if (includeToken && response.status === 401) clearBearerToken();
    throw new Error(errorMessage(response.status, parsed));
  }
  return { response, parsed, raw: text };
}

function errorMessage(status, body) {
  if (status === 401) return 'Token expired or invalid, paste a new one';
  if (status === 403) return 'Forbidden';
  if (status === 404) return 'Not found';
  if (status >= 500) return 'OBRS service unavailable';
  return body && typeof body.error === 'string' ? body.error : `Request failed (${status})`;
}

function getDocumentRows(value) {
  if (Array.isArray(value)) return value;
  if (!value || typeof value !== 'object') return null;
  for (const key of ['documents', 'registeredDocuments', 'items', 'results', 'data', 'content']) {
    if (Array.isArray(value[key])) return value[key];
    if (value[key] && typeof value[key] === 'object') {
      const nested = getDocumentRows(value[key]);
      if (nested) return nested;
    }
  }
  return null;
}

function getField(record, names) {
  if (!record || typeof record !== 'object') return '';
  for (const [key, value] of Object.entries(record)) {
    if (names.includes(key.toLowerCase()) && value !== null && value !== undefined) {
      return typeof value === 'object' ? JSON.stringify(value) : String(value);
    }
  }
  return '';
}

function signingCode(document) {
  const candidates = [];
  function visit(value, depth) {
    if (!value || typeof value !== 'object' || depth > 6) return;
    if (Array.isArray(value)) {
      value.forEach((item) => visit(item, depth + 1));
      return;
    }
    for (const [key, fieldValue] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (typeof fieldValue === 'string' || typeof fieldValue === 'number') {
        const code = String(fieldValue).trim();
        if (!code) continue;
        if (['signingcode', 'signcode', 'documentsigningcode', 'signingdocumentcode'].includes(normalizedKey)) {
          candidates.push({ priority: 0, code });
        } else if (normalizedKey.includes('sign') && normalizedKey.includes('code')) {
          candidates.push({ priority: 1, code });
        } else if (normalizedKey === 'documentcode') {
          candidates.push({ priority: 2, code });
        } else if (normalizedKey === 'code') {
          candidates.push({ priority: 3, code });
        }
      } else {
        visit(fieldValue, depth + 1);
      }
    }
  }
  visit(document, 0);
  candidates.sort((left, right) => left.priority - right.priority);
  return candidates.length ? candidates[0].code : '';
}

function getPagination(value, requestedPage, rowCount) {
  if (!value || typeof value !== 'object') return null;
  const candidates = [value];
  for (const key of ['pagination', 'pageable', 'meta', 'data', 'result']) {
    if (value[key] && typeof value[key] === 'object' && !Array.isArray(value[key])) {
      candidates.push(value[key]);
    }
  }
  for (const info of candidates) {
    const current = info.number !== undefined
      ? Number(info.number) + 1
      : Number(info.currentPage ?? info.pageNumber ?? info.page ?? requestedPage);
    const totalPages = Number(info.totalPages ?? info.totalPage ?? info.pageCount);
    if (Number.isFinite(totalPages) && totalPages > current) return current + 1;
    if (info.hasNext === true || info.hasNextPage === true || info.hasMore === true || info.last === false) {
      return current + 1;
    }
    if (rowCount >= 150 && Number(info.total ?? info.totalCount ?? info.totalElements) > requestedPage * 150) {
      return current + 1;
    }
    const next = info.nextPage ?? info.next ?? info.nextLink;
    if (typeof next === 'number' && next > current) return next;
    if (typeof next === 'string' && next) {
      const pageMatch = next.match(/[?&](?:page|pageNumber)=([0-9]+)/i);
      return pageMatch ? Number(pageMatch[1]) : current + 1;
    }
    if (next && typeof next === 'object') return current + 1;
  }
  return null;
}

function addRawPanel(container, raw) {
  const details = document.createElement('details');
  details.className = 'raw-panel';
  const summary = document.createElement('summary');
  summary.textContent = 'Raw response';
  const pre = document.createElement('pre');
  pre.textContent = raw;
  details.append(summary, pre);
  container.append(details);
}

function renderDocuments(container, raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    setStatus(container, 'The response was not valid JSON.', 'error');
    addRawPanel(container, raw);
    return;
  }

  const rows = getDocumentRows(parsed);
  if (!rows) {
    setStatus(container, 'The response did not contain a document list.', 'error');
    addRawPanel(container, JSON.stringify(parsed, null, 2));
    return;
  }
  documents = rows;
  renderDocumentTable(container);
}

function renderDocumentTable(container) {
  container.replaceChildren();
  const status = document.createElement('div');
  status.className = 'status success';
  status.textContent = `Documents loaded. ${documents.length} document${documents.length === 1 ? '' : 's'} available.`;
  const toolbar = document.createElement('div');
  toolbar.className = 'table-tools';
  const search = document.createElement('input');
  search.type = 'search';
  search.placeholder = 'Filter documents';
  search.setAttribute('aria-label', 'Filter documents');
  const download = document.createElement('button');
  download.type = 'button';
  download.className = 'button button-muted';
  download.textContent = 'Download list as CSV';
  toolbar.append(search, download);

  const count = document.createElement('p');
  count.className = 'empty-note';
  const tableWrap = document.createElement('div');
  tableWrap.className = 'table-wrap';
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['Document', 'Type', 'Date', 'Signing code', 'Actions'].forEach((label) => {
    const th = document.createElement('th');
    th.textContent = label;
    headerRow.append(th);
  });
  thead.append(headerRow);
  const tbody = document.createElement('tbody');
  table.append(thead, tbody);
  tableWrap.append(table);
  container.append(status, count, toolbar, tableWrap);

  function updateTable() {
    const query = search.value.trim().toLowerCase();
    const matches = documents.filter((item) => JSON.stringify(item).toLowerCase().includes(query));
    count.textContent = `${matches.length} document${matches.length === 1 ? '' : 's'}${query ? ' found' : ''}`;
    tbody.replaceChildren();
    matches.forEach((item) => {
      const row = document.createElement('tr');
      const name = getField(item, ['name', 'documentname', 'document_name', 'documenttitle', 'filename', 'title']);
      const type = getField(item, ['type', 'documenttype', 'document_type', 'doctype', 'mimetype']);
      const date = getField(item, ['date', 'createddate', 'created_at', 'createdat', 'createdon', 'documentdate', 'dateuploaded', 'uploadeddate', 'uploadedat', 'registrationdate']);
      const code = signingCode(item);
      [name || '—', type || '—', date || '—', code || '—'].forEach((value, index) => {
        const cell = document.createElement('td');
        if (index === 3) cell.className = 'code-cell';
        cell.textContent = value;
        row.append(cell);
      });
      const actions = document.createElement('td');
      const actionGroup = document.createElement('div');
      actionGroup.className = 'row-actions';
      if (code) {
        const view = document.createElement('button');
        view.type = 'button';
        view.className = 'small-button';
        view.textContent = 'View';
        view.addEventListener('click', () => {
          document.querySelector('#signing-code').value = code;
          activateTab('view');
          document.querySelector('#view-form').requestSubmit();
        });
        const copy = document.createElement('button');
        copy.type = 'button';
        copy.className = 'small-button';
        copy.textContent = 'Copy signing code';
        copy.addEventListener('click', async () => {
          try {
            await navigator.clipboard.writeText(code);
            const status = container.querySelector('.status');
            if (status) status.textContent = 'Signing code copied.';
          } catch {
            const status = container.querySelector('.status');
            if (status) {
              status.className = 'status error';
              status.textContent = 'Could not copy signing code. Select and copy it from the table.';
            }
          }
        });
        actionGroup.append(view, copy);
      } else {
        actionGroup.textContent = 'No signing code';
      }
      actions.append(actionGroup);
      row.append(actions);
      tbody.append(row);
    });
  }

  search.addEventListener('input', updateTable);
  download.addEventListener('click', downloadCsv);
  updateTable();
}

function csvEscape(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function downloadCsv() {
  const headings = ['Document', 'Type', 'Date', 'Signing code'];
  const fields = [
    ['name', 'documentname', 'document_name', 'documenttitle', 'filename', 'title'],
    ['type', 'documenttype', 'document_type', 'doctype', 'mimetype'],
    ['date', 'createddate', 'created_at', 'createdat', 'createdon', 'documentdate', 'dateuploaded', 'uploadeddate', 'uploadedat', 'registrationdate'],
    ['signingcode', 'signing_code', 'signcode', 'code']
  ];
  const lines = [headings.map(csvEscape).join(',')];
  for (const item of documents) {
    const values = [
      getField(item, fields[0]),
      getField(item, fields[1]),
      getField(item, fields[2]),
      signingCode(item)
    ];
    lines.push(values.map(csvEscape).join(','));
  }
  const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'obrs-documents.csv';
  link.click();
  URL.revokeObjectURL(url);
}

async function getDocuments(brn, container, button) {
  const collected = [];
  let page = 1;
  let raw = '';
  try {
    while (page <= 1000) {
      const query = new URLSearchParams({ brn });
      if (page > 1) query.set('page', String(page));
      const result = await requestJson(`/api/documents?${query}`, { method: 'GET' });
      raw = result.raw;
      const rows = getDocumentRows(result.parsed);
      if (!rows) {
        if (page === 1) {
          renderDocuments(container, raw);
          return;
        }
        break;
      }
      collected.push(...rows);
      const next = getPagination(result.parsed, page, rows.length);
      if (!next || next <= page) break;
      page = next;
    }
    documents = collected;
    renderDocumentTable(container);
  } catch (error) {
    setStatus(container, error.message, 'error');
  } finally {
    button.disabled = false;
  }
}

function disposeObjectUrl() {
  if (currentObjectUrl) URL.revokeObjectURL(currentObjectUrl);
  currentObjectUrl = null;
}

async function showDocument(url, container, button, successText) {
  disposeObjectUrl();
  setLoading(container, button, 'Loading document…');
  try {
    const response = await fetch(url);
    if (!response.ok) {
      let body = null;
      try { body = await response.json(); } catch { /* No JSON error payload. */ }
      throw new Error(errorMessage(response.status, body));
    }
    const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (contentType !== 'application/pdf' && !contentType.startsWith('image/')) {
      const raw = await response.text();
      container.replaceChildren();
      setStatus(container, 'The response was not a PDF or image document.', 'error');
      addRawPanel(container, raw);
      return;
    }
    const blob = await response.blob();
    currentObjectUrl = URL.createObjectURL(blob);
    container.replaceChildren();
    setStatus(container, successText, 'success');
    const actions = document.createElement('div');
    actions.className = 'viewer-actions';
    const open = document.createElement('button');
    open.type = 'button';
    open.className = 'button button-muted';
    open.textContent = 'Open in new tab';
    open.addEventListener('click', () => window.open(currentObjectUrl, '_blank', 'noopener,noreferrer'));
    const download = document.createElement('a');
    download.className = 'button button-primary';
    download.href = currentObjectUrl;
    download.download = fileNameFromResponse(response.headers.get('content-disposition'), contentType);
    download.textContent = 'Download';
    actions.append(open);
    const directUrl = response.headers.get('x-obrs-document-link');
    if (directUrl) {
      const directLink = document.createElement('a');
      directLink.className = 'button button-outline';
      directLink.href = directUrl;
      directLink.target = '_blank';
      directLink.rel = 'noopener noreferrer';
      directLink.textContent = 'Open direct OBRS link';
      const copyLink = document.createElement('button');
      copyLink.type = 'button';
      copyLink.className = 'button button-muted';
      copyLink.textContent = 'Copy link';
      copyLink.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(directUrl);
          const status = container.querySelector('.status');
          if (status) status.textContent = 'Direct OBRS link copied.';
        } catch {
          const status = container.querySelector('.status');
          if (status) {
            status.className = 'status error';
            status.textContent = 'Could not copy the link. Use “Open direct OBRS link” instead.';
          }
        }
      });
      actions.append(directLink, copyLink);
    }
    actions.append(download);
    container.append(actions);
    if (contentType.startsWith('image/')) {
      const image = document.createElement('img');
      image.className = 'document-image';
      image.src = currentObjectUrl;
      image.alt = 'Requested document';
      container.append(image);
    } else {
      const frame = document.createElement('iframe');
      frame.className = 'document-viewer';
      frame.title = 'Requested PDF document';
      frame.src = currentObjectUrl;
      container.append(frame);
    }
  } catch (error) {
    setStatus(container, error.message === 'Failed to fetch' ? 'OBRS service unavailable' : error.message, 'error');
  } finally {
    button.disabled = false;
  }
}

function fileNameFromResponse(disposition, contentType) {
  if (disposition) {
    const utf8 = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    const regular = disposition.match(/filename="?([^";]+)"?/i);
    const encoded = utf8 ? utf8[1] : regular && regular[1];
    if (encoded) {
      try { return decodeURIComponent(encoded); } catch { return encoded; }
    }
  }
  return contentType.startsWith('image/') ? 'obrs-document' : 'obrs-document.pdf';
}

function activateTab(name) {
  document.querySelectorAll('.tab').forEach((tab) => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', String(active));
  });
  document.querySelectorAll('.tab-panel').forEach((panel) => {
    panel.hidden = panel.dataset.panel !== name;
  });
}

function addRecentAction(brn, result, success) {
  recentActions.unshift({ brn, result, success, time: new Date() });
  renderRecentActions();
}

function renderRecentActions() {
  const container = document.querySelector('#recent-actions');
  container.replaceChildren();
  if (!recentActions.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-note';
    empty.textContent = 'No actions yet.';
    container.append(empty);
    return;
  }
  recentActions.forEach((action) => {
    const item = document.createElement('div');
    item.className = 'recent-item';
    const summary = document.createElement('span');
    summary.textContent = `${action.brn} · ${action.time.toLocaleString()}`;
    const result = document.createElement('span');
    result.className = `recent-result ${action.success ? 'success' : 'error'}`;
    result.textContent = action.result;
    item.append(summary, result);
    container.append(item);
  });
}

toggleTokenButton.addEventListener('click', () => {
  const showing = tokenInput.type === 'text';
  tokenInput.type = showing ? 'password' : 'text';
  toggleTokenButton.textContent = showing ? 'Show' : 'Hide';
  toggleTokenButton.setAttribute('aria-pressed', String(!showing));
});

tokenInput.addEventListener('input', () => {
  const token = tokenInput.value.trim();
  if (token) sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  else sessionStorage.removeItem(TOKEN_STORAGE_KEY);
});

clearTokenButton.addEventListener('click', () => {
  clearBearerToken();
  tokenInput.focus();
});

document.querySelectorAll('.tab').forEach((tab) => {
  tab.addEventListener('click', () => activateTab(tab.dataset.tab));
});

document.querySelector('#documents-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const brnInput = form.elements.brn;
  const brn = brnInput.value.trim();
  brnInput.value = brn;
  const container = document.querySelector('#documents-result');
  const button = form.querySelector('button[type="submit"]');
  if (!brn) return setStatus(container, 'Enter a BRN to continue.', 'error');
  try {
    tokenHeaders();
    setLoading(container, button, 'Getting EDMS documents…');
    getDocuments(brn, container, button);
  } catch (error) {
    setStatus(container, error.message, 'error');
  }
});

document.querySelector('#view-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = form.elements.signingCode;
  const code = input.value.trim();
  input.value = code;
  const container = document.querySelector('#view-result');
  const button = form.querySelector('button[type="submit"]');
  if (!code) return setStatus(container, 'Enter a signing code to continue.', 'error');
  try {
    showDocument(`/api/document?${new URLSearchParams({ signingCode: code })}`, container, button, 'Document loaded.');
  } catch (error) {
    setStatus(container, error.message, 'error');
  }
});

document.querySelector('#unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = form.elements.brn;
  const brn = input.value.trim();
  input.value = brn;
  const container = document.querySelector('#unlock-result');
  const button = form.querySelector('button[type="submit"]');
  if (!brn) return setStatus(container, 'Enter a BRN to continue.', 'error');
  if (!window.confirm(`Remove banner/unlock file for BRN ${brn}?`)) return;
  try {
    tokenHeaders();
    setLoading(container, button, 'Removing banner…');
    const { parsed, raw } = await requestJson(`/api/unlock?${new URLSearchParams({ brn })}`, { method: 'POST' });
    const successMessage = `Banner cleared for BRN ${brn}`;
    const message = parsed && typeof parsed.message === 'string' && parsed.message.trim()
      ? parsed.message.trim()
      : successMessage;
    setStatus(container, message, 'success');
    addRecentAction(brn, message, true);
    if (!parsed && raw) addRawPanel(container, raw);
  } catch (error) {
    setStatus(container, error.message, 'error');
    addRecentAction(brn, error.message, false);
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#legal-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = form.elements.instrumentNumber;
  const instrumentNumber = input.value.trim();
  input.value = instrumentNumber;
  const container = document.querySelector('#legal-result');
  const button = form.querySelector('button[type="submit"]');
  if (!instrumentNumber) return setStatus(container, 'Enter an instrument number to continue.', 'error');
  try {
    showDocument(`/api/legal-document?${new URLSearchParams({ instrumentNumber })}`, container, button, 'Legal document loaded.');
  } catch (error) {
    setStatus(container, error.message, 'error');
  }
});

document.querySelector('#payment-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const input = form.elements.reference;
  const reference = input.value.trim();
  input.value = reference;
  const container = document.querySelector('#payment-result');
  const button = form.querySelector('button[type="submit"]');
  if (!reference) return setStatus(container, 'Enter a tracking number or PRN to continue.', 'error');

  setLoading(container, button, 'Checking payment…');
  try {
    const { parsed, raw } = await requestJson(
      `/api/payment?${new URLSearchParams({ reference })}`,
      { method: 'GET' },
      false
    );
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || typeof parsed.message !== 'string') {
      setStatus(container, 'Payment response received in an unexpected format.', 'error');
      addRawPanel(container, raw || JSON.stringify(parsed, null, 2));
      return;
    }

    const message = parsed.message.trim();
    if (parsed.error !== null && parsed.error !== undefined) {
      setStatus(container, message || String(parsed.error), 'error');
    } else if (Number(parsed.status) === 200) {
      setStatus(container, message || 'Payment confirmed.', 'success');
    } else {
      setStatus(container, message || `Payment query returned status ${parsed.status ?? 'unknown'}.`, 'error');
      addRawPanel(container, raw || JSON.stringify(parsed, null, 2));
    }
  } catch (error) {
    setStatus(container, error.message, 'error');
  } finally {
    button.disabled = false;
  }
});
