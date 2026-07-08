import fs from 'node:fs';
import path from 'node:path';
import { readSystemSettings, systemDatabasePath } from './system.js';

const target = path.resolve('.env');
const auto = process.argv.includes('--auto');

fs.mkdirSync(path.resolve('data'), { recursive: true });
readSystemSettings(systemDatabasePath());

if (!auto) {
  console.log(fs.existsSync(target)
    ? 'data directory and system.db are ready. Existing .env values will be imported on startup.'
    : 'data directory and system.db are ready. Start the app and open /install.');
}
