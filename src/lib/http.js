import fs from 'node:fs';
import path from 'node:path';
import { normalizeIp } from './security.js';

const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.ico', 'image/x-icon']
]);

export class HttpError extends Error {
  constructor(statusCode, message, code = 'request_error', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end(body);
}

export function sendText(response, statusCode, body, contentType = 'text/plain; charset=utf-8') {
  response.writeHead(statusCode, {
    'content-type': contentType,
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end(body);
}

export async function readBody(request, maxBytes = 32768) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBytes) throw new HttpError(413, 'Request body is too large', 'body_too_large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export async function readJson(request, maxBytes = 32768) {
  const raw = await readBody(request, maxBytes);
  if (raw.length === 0) return { raw, value: {} };
  try {
    return { raw, value: JSON.parse(raw.toString('utf8')) };
  } catch {
    throw new HttpError(400, 'Invalid JSON body', 'invalid_json');
  }
}

export function getClientIp(request, trustProxy = false) {
  if (trustProxy) {
    const forwarded = request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded) {
      return normalizeIp(forwarded.split(',')[0]);
    }
  }
  return normalizeIp(request.socket.remoteAddress || '0.0.0.0');
}

export function serveStatic(response, publicDir, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = path.resolve(publicDir, relative);
  const root = path.resolve(publicDir) + path.sep;
  if (!filePath.startsWith(root) && filePath !== path.resolve(publicDir, 'index.html')) return false;
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return false;
  const extension = path.extname(filePath).toLowerCase();
  const body = fs.readFileSync(filePath);
  response.writeHead(200, {
    'content-type': MIME_TYPES.get(extension) || 'application/octet-stream',
    'content-length': body.length,
    'cache-control': extension === '.html' ? 'no-store' : 'public, max-age=3600',
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://api.ipify.org; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY'
  });
  response.end(body);
  return true;
}
