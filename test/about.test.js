import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { projectAbout } from '../src/about.js';

test('project about metadata exposes LicenseRef-G-Hotspot-NC-1.0 license and attribution', () => {
  const packageJson = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const about = projectAbout();

  assert.equal(packageJson.license, 'LicenseRef-G-Hotspot-NC-1.0');
  assert.equal(packageJson.author.name, 'Gökhan GÜRBÜZ');
  assert.equal(packageJson.author.url, 'https://github.com/G-grbz');
  assert.equal(about.name, packageJson.name);
  assert.equal(about.version, packageJson.version);
  assert.equal(about.license, 'LicenseRef-G-Hotspot-NC-1.0');
  assert.equal(about.author, 'Gökhan GÜRBÜZ');
  assert.equal(about.githubUsername, 'G-grbz');
  assert.equal(about.githubUrl, 'https://github.com/G-grbz');
  assert.equal(about.source, 'https://github.com/G-grbz');
});

test('license and notice files preserve LicenseRef-G-Hotspot-NC-1.0 attribution', () => {
  const license = fs.readFileSync(new URL('../LICENSE', import.meta.url), 'utf8');
  const notice = fs.readFileSync(new URL('../NOTICE', import.meta.url), 'utf8');

  assert.match(license, /G-Hotspot Noncommercial Source-Available License 1\.0/u);
  assert.match(license, /Copyright © 2026 G-grbz/u);
  assert.match(license, /Commercial Use Is Prohibited/u);
  assert.match(notice, /G-Hotspot/u);
  assert.match(notice, /Gökhan GÜRBÜZ/u);
  assert.match(notice, /G-grbz/u);
  assert.match(notice, /https:\/\/github\.com\/G-grbz/u);
  assert.match(notice, /LicenseRef-G-Hotspot-NC-1\.0/u);
});
