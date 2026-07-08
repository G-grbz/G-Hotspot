export const QUOTA_METHODS = [
  { method: 'voucher', prefix: 'VOUCHER', label: 'Kupon' },
  { method: 'admin-approval', prefix: 'ADMIN_APPROVAL', label: 'Yönetici Onayı' },
  { method: 'nvi', prefix: 'NVI', label: 'T.C. Kimlik' },
  { method: 'email', prefix: 'EMAIL', label: 'E-posta' },
  { method: 'whatsapp', prefix: 'WHATSAPP', label: 'WhatsApp' },
  { method: 'telegram', prefix: 'TELEGRAM', label: 'Telegram' },
  { method: 'sms', prefix: 'SMS', label: 'SMS' }
];

export const QUOTA_PERIODS = ['daily', 'weekly', 'monthly'];

export function methodQuotaPrefix(method) {
  return QUOTA_METHODS.find(item => item.method === method)?.prefix || '';
}

export function quotaLimitBytes(gigabytes) {
  const value = Number(gigabytes);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.trunc(value * 1024 * 1024 * 1024);
}

function zonedDateParts(timestamp, timeZone) {
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
  const parts = Object.fromEntries(
    formatter.formatToParts(new Date(timestamp))
      .filter(part => part.type !== 'literal')
      .map(part => [part.type, part.value])
  );
  return {
    year: Number(parts.year),
    month: Number(parts.month),
    day: Number(parts.day),
    hour: Number(parts.hour),
    minute: Number(parts.minute),
    second: Number(parts.second)
  };
}

function timeZoneOffsetMs(timestamp, timeZone) {
  const parts = zonedDateParts(timestamp, timeZone);
  const asUtc = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second
  );
  return asUtc - timestamp;
}

function zonedMidnightUtc(year, month, day, timeZone) {
  const targetUtc = Date.UTC(year, month - 1, day, 0, 0, 0);
  let guess = targetUtc;
  for (let index = 0; index < 3; index += 1) {
    guess = targetUtc - timeZoneOffsetMs(guess, timeZone);
  }
  return guess;
}

function addUtcDays(timestamp, days) {
  return timestamp + days * 24 * 60 * 60 * 1000;
}

function dateKey(timestamp, timeZone) {
  const parts = zonedDateParts(timestamp, timeZone);
  return [
    String(parts.year).padStart(4, '0'),
    String(parts.month).padStart(2, '0'),
    String(parts.day).padStart(2, '0')
  ].join('-');
}

function monthStart(year, month, offset) {
  const date = new Date(Date.UTC(year, month - 1 + offset, 1));
  return {
    year: date.getUTCFullYear(),
    month: date.getUTCMonth() + 1,
    day: 1
  };
}

export function quotaPeriodWindow(period, now = Date.now(), timeZone = 'UTC') {
  const resolvedPeriod = QUOTA_PERIODS.includes(period) ? period : 'daily';
  const parts = zonedDateParts(now, timeZone);
  let startAt;
  let endAt;

  if (resolvedPeriod === 'monthly') {
    startAt = zonedMidnightUtc(parts.year, parts.month, 1, timeZone);
    const next = monthStart(parts.year, parts.month, 1);
    endAt = zonedMidnightUtc(next.year, next.month, next.day, timeZone);
  } else {
    const localMidnight = zonedMidnightUtc(parts.year, parts.month, parts.day, timeZone);
    if (resolvedPeriod === 'weekly') {
      const weekday = new Date(Date.UTC(parts.year, parts.month - 1, parts.day)).getUTCDay();
      const daysSinceMonday = (weekday + 6) % 7;
      startAt = addUtcDays(localMidnight, -daysSinceMonday);
      endAt = addUtcDays(startAt, 7);
    } else {
      startAt = localMidnight;
      endAt = addUtcDays(startAt, 1);
    }
  }

  return {
    period: resolvedPeriod,
    key: `${resolvedPeriod}:${dateKey(startAt, timeZone)}`,
    startAt,
    endAt
  };
}

export function quotaProfileForMethod(config, method) {
  return config?.gateway?.bandwidthProfiles?.[method] || null;
}

export function quotaEnabled(profile) {
  return Boolean(quotaLimitBytes(profile?.downloadQuotaGb) || quotaLimitBytes(profile?.uploadQuotaGb));
}

export function quotaExceeded(profile, usage) {
  const downloadLimit = quotaLimitBytes(profile?.downloadQuotaGb);
  const uploadLimit = quotaLimitBytes(profile?.uploadQuotaGb);
  const downloadBytes = Number(usage?.downloadBytes || 0);
  const uploadBytes = Number(usage?.uploadBytes || 0);
  if (downloadLimit && downloadBytes >= downloadLimit) return 'download';
  if (uploadLimit && uploadBytes >= uploadLimit) return 'upload';
  return '';
}

export function authorizationQuotaBlocked(authorization, now = Date.now()) {
  return Number(authorization?.quota_blocked_until || 0) > now;
}

export function bandwidthProfileConfigured(profile) {
  return Boolean(Number(profile?.downloadSpeedMbps || 0) || Number(profile?.uploadSpeedMbps || 0));
}

export function gatewayHasBandwidthProfiles(gateway) {
  return Object.values(gateway?.bandwidthProfiles || {}).some(bandwidthProfileConfigured);
}
