import fs from 'node:fs';
import path from 'node:path';

function unquote(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try { return JSON.parse(trimmed); } catch {}
    return trimmed.slice(1, -1).replace(/\\n/g, '\n');
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/\\n/g, '\n');
  }
  return trimmed;
}

export function loadEnv(filePath = path.resolve('.env')) {
  if (!fs.existsSync(filePath)) return;
  const content = fs.readFileSync(filePath, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    const key = line.slice(0, index).trim();
    const value = unquote(line.slice(index + 1));
    if (!(key in process.env)) process.env[key] = value;
  }
}

function quote(value) {
  const text = String(value ?? '');
  if (!text || /[\s#"'\\]/u.test(text)) {
    return JSON.stringify(text);
  }
  return text;
}

export function readEnvFile(filePath = path.resolve('.env')) {
  const values = {};
  if (!fs.existsSync(filePath)) return values;
  const content = fs.readFileSync(filePath, 'utf8');
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    values[line.slice(0, index).trim()] = unquote(line.slice(index + 1));
  }
  return values;
}

export function updateEnvFile(changes, filePath = path.resolve('.env')) {
  const lines = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8').split(/\r?\n/) : [];
  const pending = new Map(Object.entries(changes).map(([key, value]) => [key, String(value ?? '')]));
  const changedKeys = new Set(pending.keys());
  const written = new Set();
  const output = lines.flatMap(line => {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=/u);
    if (!match || !changedKeys.has(match[1])) return [line];
    if (written.has(match[1])) return [];
    const value = pending.get(match[1]);
    written.add(match[1]);
    pending.delete(match[1]);
    return [`${match[1]}=${quote(value)}`];
  });
  if (pending.size) {
    if (output.length && output.at(-1) !== '') output.push('');
    output.push('# Settings managed by the G-Hotspot admin panel');
    for (const [key, value] of pending) output.push(`${key}=${quote(value)}`);
  }
  fs.writeFileSync(filePath, output.join('\n').replace(/\n*$/u, '\n'), { mode: 0o600 });
  for (const [key, value] of Object.entries(changes)) process.env[key] = String(value ?? '');
}

export function envBoolean(name, fallback = false) {
  const value = process.env[name];
  if (value == null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

export function envInteger(name, fallback, { min, max } = {}) {
  const raw = process.env[name];
  const value = raw == null || raw === '' ? fallback : Number.parseInt(raw, 10);
  if (!Number.isInteger(value)) throw new Error(`${name} must be an integer`);
  if (min != null && value < min) throw new Error(`${name} must be >= ${min}`);
  if (max != null && value > max) throw new Error(`${name} must be <= ${max}`);
  return value;
}
