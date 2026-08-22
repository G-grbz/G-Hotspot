import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const pkg = JSON.parse(read('package.json'));
const lock = JSON.parse(read('package-lock.json'));
const version = String(pkg.version || '').trim();
const errors = [];

if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  errors.push(`package.json has an invalid release version: ${version || '(empty)'}`);
}

const exactChecks = [
  ['package-lock.json root version', String(lock.version || '')],
  ['package-lock.json package version', String(lock.packages?.['']?.version || '')],
];
for (const [label, actual] of exactChecks) {
  if (actual !== version) errors.push(`${label} is ${actual || '(empty)'}, expected ${version}`);
}

const textChecks = [
  ['README.md', `Version: \`${version}\``],
  ['docs/README.en.md', `Application version: \`${version}\``],
  ['docs/README.tr.md', `Uygulama sürümü: \`${version}\``],
  ['public/app.js', `const APP_VERSION = '${version}';`],
  ['public/admin/admin.js', `const APP_VERSION = '${version}';`],
  ['android/app/build.gradle', `versionName "${version}"`],
  ['android/app/src/main/java/com/ghotspot/admin/MainActivity.java', `return "${version}";`],
];
for (const [file, expected] of textChecks) {
  if (!read(file).includes(expected)) errors.push(`${file} is not synchronized to ${version}`);
}

for (const file of [
  'public/index.html',
  'public/session.html',
  'public/install.html',
  'public/admin/index.html',
]) {
  const text = read(file);
  const seen = [...text.matchAll(/[?&]v=([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)/g)].map((m) => m[1]);
  for (const assetVersion of seen) {
    if (assetVersion !== version) errors.push(`${file} contains cache version ${assetVersion}, expected ${version}`);
  }
}

if (errors.length) {
  console.error('Version consistency check failed:');
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log(`Version consistency check passed (${version}).`);
