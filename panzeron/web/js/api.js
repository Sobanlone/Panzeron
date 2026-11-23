const token = document.querySelector('meta[name="panzeron-token"]').content;

export class ApiError extends Error {
  constructor(status, body) { super(body.message || body.error || `HTTP ${status}`); this.status = status; this.body = body; }
}

const inflight = new Map();   // identical concurrent GETs share one request

async function doRequest(method, path, { json, raw, headers, timeout, keepalive }) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeout);
  const opts = { method, headers: { 'X-Session-Token': token, ...(headers || {}) }, signal: ctl.signal, keepalive: !!keepalive };
  if (json !== undefined) { opts.body = JSON.stringify(json); opts.headers['Content-Type'] = 'application/json'; }
  if (raw !== undefined) opts.body = raw;
  try {
    const res = await fetch(path, opts);
    let body = {};
    try { body = await res.json(); } catch { /* empty body */ }
    if (!res.ok) throw new ApiError(res.status, body);
    return body;
  } catch (e) {
    if (e.name === 'AbortError') throw new ApiError(0, { error: 'Panzeron’s engine did not respond in time. Try again.' });
    if (e instanceof ApiError) throw e;
    throw new ApiError(0, { error: 'Cannot reach the Panzeron engine. Is the app still running?' });
  } finally { clearTimeout(timer); }
}

function request(method, path, o = {}) {
  const opts = { timeout: 20000, ...o };
  if (method !== 'GET') return doRequest(method, path, opts);
  if (!inflight.has(path)) inflight.set(path, doRequest(method, path, opts).finally(() => inflight.delete(path)));
  return inflight.get(path);
}

export const api = {
  get: (p) => request('GET', p),
  post: (p, json = {}) => request('POST', p, { json, timeout: 120000 }),
  put: (p, json, o = {}) => request('PUT', p, { json, ...o }),
  del: (p) => request('DELETE', p),
  upload: (file) => request('POST', '/api/vision/upload', { raw: file, headers: { 'X-Filename': file.name }, timeout: 180000 }),
};
