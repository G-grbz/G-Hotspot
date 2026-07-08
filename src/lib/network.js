import os from 'node:os';

const DEFAULT_LISTEN_PORT = 8080;
const EXAMPLE_PUBLIC_BASE_URL = 'http://192.168.1.50:8080';

export function localServerIp() {
  let interfaces;
  try {
    interfaces = os.networkInterfaces();
  } catch {
    return '127.0.0.1';
  }
  for (const entries of Object.values(interfaces)) {
    for (const entry of entries || []) {
      if (entry.family !== 'IPv4' || entry.internal) continue;
      if (String(entry.address || '').startsWith('169.254.')) continue;
      return entry.address;
    }
  }
  return '127.0.0.1';
}

export function automaticListenHost(value) {
  const text = String(value || '').trim();
  return text && text !== '0.0.0.0' ? text : localServerIp();
}

export function automaticListenPort(value) {
  const text = String(value ?? '').trim();
  if (!text) return DEFAULT_LISTEN_PORT;
  const port = Number.parseInt(text, 10);
  if (!Number.isInteger(port)) throw new Error('PORT must be an integer');
  if (port < 1) throw new Error('PORT must be >= 1');
  if (port > 65535) throw new Error('PORT must be <= 65535');
  return port;
}

export function automaticPublicBaseUrl({ publicBaseUrl = '', host = '', port = '' } = {}) {
  const current = String(publicBaseUrl || '').trim();
  if (current && current !== EXAMPLE_PUBLIC_BASE_URL) return current;
  return `http://${automaticListenHost(host)}:${automaticListenPort(port)}`;
}

function parseIpv4(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${value}`);
  let result = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/u.test(part)) throw new Error(`Invalid IPv4 address: ${value}`);
    const octet = Number(part);
    if (octet < 0 || octet > 255) throw new Error(`Invalid IPv4 address: ${value}`);
    result = (result << 8n) + BigInt(octet);
  }
  return result;
}

function formatIpv4(value) {
  return [24n, 16n, 8n, 0n]
    .map(shift => Number((value >> shift) & 255n))
    .join('.');
}

export function ipv4InNetworkList(ipValue, networkList) {
  const ip = parseIpv4(ipValue);
  const normalized = normalizeNetworkList(networkList);
  if (normalized === 'any') return true;
  for (const rawEntry of normalized.split(',')) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const [address, prefixValue] = entry.split('/');
    const network = parseIpv4(address);
    if (prefixValue == null) {
      if (ip === network) return true;
      continue;
    }
    const prefix = Number(prefixValue);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`Invalid CIDR prefix: ${entry}`);
    }
    const bits = 32n - BigInt(prefix);
    const mask = prefix === 0 ? 0n : ((1n << 32n) - 1n) ^ ((1n << bits) - 1n);
    if ((ip & mask) === (network & mask)) return true;
  }
  return false;
}

export function isPrivateIpv4(value) {
  try {
    const parts = String(value || '').trim().split('.').map(part => Number(part));
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) {
      return false;
    }
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    return false;
  } catch {
    return false;
  }
}

export function ipv4RangeToCidrs(startValue, endValue) {
  let start = parseIpv4(startValue);
  const end = parseIpv4(endValue);
  if (start > end) throw new Error('The IP range start must not be after the end');
  const output = [];
  while (start <= end) {
    let blockSize = start === 0n ? 1n << 32n : start & -start;
    const remaining = end - start + 1n;
    while (blockSize > remaining) blockSize >>= 1n;
    let prefix = 32;
    for (let size = blockSize; size > 1n; size >>= 1n) prefix -= 1;
    output.push(`${formatIpv4(start)}/${prefix}`);
    start += blockSize;
  }
  return output;
}

export function normalizeNetworkList(value) {
  const text = String(value || '').trim();
  if (!text || text.toLowerCase() === 'any') return 'any';
  const output = [];
  for (const rawEntry of text.split(',')) {
    const entry = rawEntry.trim();
    if (!entry) continue;
    const range = entry.match(
      /^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$/u
    );
    if (range) output.push(...ipv4RangeToCidrs(range[1], range[2]));
    else output.push(entry.replace(/\s+/gu, ''));
  }
  if (!output.length) throw new Error('Guest network or CIDR cannot be empty');
  return [...new Set(output)].join(',');
}
