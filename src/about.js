import fs from 'node:fs';

const PACKAGE_URL = new URL('../package.json', import.meta.url);
const packageJson = JSON.parse(fs.readFileSync(PACKAGE_URL, 'utf8'));

function authorName(value) {
  if (typeof value === 'string') return value.trim();
  if (value && typeof value === 'object') return String(value.name || '').trim();
  return '';
}

function repositoryUrl(value) {
  if (typeof value === 'string') return value.trim();
  if (value && typeof value === 'object') return String(value.url || '').trim();
  return '';
}

function authorUrl(value) {
  if (value && typeof value === 'object') return String(value.url || '').trim();
  return '';
}

export function projectAbout() {
  const githubUrl = authorUrl(packageJson.author) || packageJson.homepage || 'https://github.com/G-grbz';
  return {
    name: packageJson.name || 'g-hotspot',
    displayName: 'G-Hotspot',
    version: packageJson.version || '',
    license: packageJson.license || 'AGPL-3.0-only',
    source: repositoryUrl(packageJson.repository) ||
      githubUrl ||
      'Complete corresponding source is included with this distribution.',
    author: authorName(packageJson.author) || 'Gökhan GÜRBÜZ',
    githubUsername: 'G-grbz',
    githubUrl,
    notice: 'Copyright (C) 2026 Gökhan GÜRBÜZ and G-Hotspot contributors. Original project attribution: Gökhan GÜRBÜZ (G-grbz).'
  };
}
