import { config } from './config.js';
import { HotspotDatabase } from './db.js';
import { generateVoucherCode, keyedHash, normalizeVoucher } from './lib/security.js';

function parseArgs(values) {
  const options = {};
  const positional = [];
  for (const value of values) {
    if (value.startsWith('--')) {
      const [key, raw = 'true'] = value.slice(2).split('=', 2);
      options[key] = raw;
    } else positional.push(value);
  }
  return { options, positional };
}

function integerOption(options, key, fallback, min = 1) {
  const value = options[key] == null ? fallback : Number.parseInt(options[key], 10);
  if (!Number.isInteger(value) || value < min) throw new Error(`--${key} must be an integer >= ${min}`);
  return value;
}

const [domain, action, ...rest] = process.argv.slice(2);
if (domain !== 'voucher') {
  console.error('Usage: node src/cli.js voucher create|list|disable [options]');
  process.exit(1);
}

const db = new HotspotDatabase(config.databasePath);
try {
  const { options } = parseArgs(rest);
  if (action === 'create') {
    const count = integerOption(options, 'count', 1);
    const minutes = integerOption(options, 'minutes', config.sessionMinutes);
    const uses = integerOption(options, 'uses', 1);
    const expiresDays = options['expires-days'] == null ? null : integerOption(options, 'expires-days', 1);
    const expiresAt = expiresDays ? Date.now() + expiresDays * 86400000 : null;
    const label = options.label || '';
    const rows = [];
    for (let index = 0; index < count; index += 1) {
      const code = generateVoucherCode();
      db.createVoucher({
        codeHash: keyedHash(config.appSecret, normalizeVoucher(code)),
        codeHint: code.slice(-4),
        codePrefix: normalizeVoucher(code).slice(0, 4),
        label,
        maxUses: uses,
        durationMinutes: minutes,
        validFrom: null,
        expiresAt
      });
      rows.push(code);
    }
    console.log(rows.join('\n'));
  } else if (action === 'list') {
    console.table(db.listVouchers().map(row => ({
      id: row.id,
      hint: `…${row.code_hint}`,
      label: row.label || '',
      uses: `${row.used_count}/${row.max_uses}`,
      minutes: row.duration_minutes,
      enabled: Boolean(row.enabled),
      expires: row.expires_at ? new Date(row.expires_at).toISOString() : 'never'
    })));
  } else if (action === 'disable') {
    if (!options.id) throw new Error('--id is required');
    console.log(db.disableVoucher(options.id) ? 'Voucher disabled.' : 'Voucher not found.');
  } else {
    throw new Error('Action must be create, list or disable');
  }
} finally {
  db.close();
}
