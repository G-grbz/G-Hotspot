import fs from 'node:fs';
import path from 'node:path';
import { BlockList, isIP } from 'node:net';
import { normalizeIp } from './security.js';

const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.png', 'image/png'],
  ['.ico', 'image/x-icon'],
  ['.woff2', 'font/woff2']
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

const DEFAULT_TRUSTED_PROXY_CIDRS = '127.0.0.1/32,::1/128';
const trustedProxyMatcherCache = new Map();

function normalizeProxyAddress(value) {
  const text = normalizeIp(String(value || '').trim().replace(/^\[|\]$/gu, ''));
  return isIP(text) ? text : '';
}

export function normalizeTrustedProxyCidrs(value = DEFAULT_TRUSTED_PROXY_CIDRS) {
  const input = String(value || DEFAULT_TRUSTED_PROXY_CIDRS);
  const normalized = [];
  for (const rawEntry of input.split(/[\n;,]+/u)) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const slashIndex = entry.lastIndexOf('/');
    const address = normalizeProxyAddress(slashIndex >= 0 ? entry.slice(0, slashIndex) : entry);
    if (!address) throw new Error(`Invalid trusted proxy address: ${entry}`);
    const version = isIP(address);
    const maxPrefix = version === 4 ? 32 : 128;
    const prefix = slashIndex >= 0 ? Number(entry.slice(slashIndex + 1)) : maxPrefix;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      throw new Error(`Invalid trusted proxy CIDR prefix: ${entry}`);
    }
    normalized.push(`${address}/${prefix}`);
  }
  if (!normalized.length) return DEFAULT_TRUSTED_PROXY_CIDRS;
  return [...new Set(normalized)].join(',');
}

function trustedProxyMatcher(value) {
  const normalized = normalizeTrustedProxyCidrs(value);
  if (trustedProxyMatcherCache.has(normalized)) return trustedProxyMatcherCache.get(normalized);
  const matcher = new BlockList();
  for (const entry of normalized.split(',')) {
    const slashIndex = entry.lastIndexOf('/');
    const address = entry.slice(0, slashIndex);
    const prefix = Number(entry.slice(slashIndex + 1));
    const type = isIP(address) === 6 ? 'ipv6' : 'ipv4';
    matcher.addSubnet(address, prefix, type);
  }
  trustedProxyMatcherCache.set(normalized, matcher);
  return matcher;
}

export function isTrustedProxyRequest(request, trustProxy = false, trustedProxyCidrs = DEFAULT_TRUSTED_PROXY_CIDRS) {
  if (!trustProxy) return false;
  const remoteAddress = normalizeProxyAddress(request.socket?.remoteAddress || '');
  if (!remoteAddress) return false;
  const type = isIP(remoteAddress) === 6 ? 'ipv6' : 'ipv4';
  return trustedProxyMatcher(trustedProxyCidrs).check(remoteAddress, type);
}

export function getClientIp(request, trustProxy = false, trustedProxyCidrs = DEFAULT_TRUSTED_PROXY_CIDRS) {
  if (isTrustedProxyRequest(request, trustProxy, trustedProxyCidrs)) {
    const forwarded = request.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded) {
      const candidate = normalizeProxyAddress(forwarded.split(',')[0]);
      if (candidate) return candidate;
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
    'content-security-policy': [
      "default-src 'self'",
      "script-src 'self'",
      "script-src-attr 'none'",
      "style-src 'self'",
      "font-src 'self'",
      "img-src 'self' data:",
      pathname.startsWith('/admin') ? "connect-src 'self' https://api.ipify.org" : "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'"
    ].join('; '),
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY'
  });
  response.end(body);
  return true;
}
