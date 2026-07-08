import http from 'node:http';
import https from 'node:https';
import { translate } from '../i18n.js';

const DEFAULT_TELEGRAM_MESSAGE_TEMPLATE =
  '{appName} Telegram access code: {code}. The code is valid for {minutes} minutes.';

function requestJson(url, { body, timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const payload = JSON.stringify(body);
    const transport = target.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method: 'POST',
      timeout: timeoutMs,
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        accept: 'application/json'
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = {};
        try { parsed = text ? JSON.parse(text) : {}; } catch {}
        if ((response.statusCode || 500) >= 400 || parsed.ok === false) {
          const description = parsed.description || text.slice(0, 500) || `HTTP ${response.statusCode}`;
          reject(new Error(`Telegram Bot API rejected the request: ${description}`));
          return;
        }
        resolve(parsed);
      });
    });
    request.on('timeout', () => request.destroy(new Error('Telegram Bot API request timed out')));
    request.on('error', reject);
    request.end(payload);
  });
}

function apiUrl(telegram, method) {
  const baseUrl = telegram.botApiBaseUrl.replace(/\/$/, '');
  return `${baseUrl}/bot${telegram.botToken}/${method}`;
}

function replaceVariables(value, variables) {
  return String(value ?? '').replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, key) =>
    Object.hasOwn(variables, key) ? String(variables[key]) : match
  );
}

export function telegramStartUrl(telegram, challengeId) {
  const username = String(telegram.botUsername || '').replace(/^@/u, '');
  if (!username) throw new Error('Telegram bot username is not configured');
  return `https://t.me/${encodeURIComponent(username)}?start=${encodeURIComponent(challengeId)}`;
}

export function telegramAppUrl(telegram, challengeId) {
  const username = String(telegram.botUsername || '').replace(/^@/u, '');
  if (!username) throw new Error('Telegram bot username is not configured');
  return `tg://resolve?domain=${encodeURIComponent(username)}&start=${encodeURIComponent(challengeId)}`;
}

export function telegramStartCommand(challengeId) {
  return `/start ${challengeId}`;
}

export function renderTelegramMessage(telegram, variables, language = 'en') {
  const template = String(telegram.template || DEFAULT_TELEGRAM_MESSAGE_TEMPLATE);
  if (template === DEFAULT_TELEGRAM_MESSAGE_TEMPLATE) {
    return translate(language, 'telegramOtpText', variables);
  }
  return replaceVariables(template, variables);
}

export async function sendTelegramText(telegram, { chatId, text, replyMarkup = undefined }) {
  if (!telegram.enabled) throw new Error('Telegram bot is not configured');
  return requestJson(apiUrl(telegram, 'sendMessage'), {
    body: {
      chat_id: chatId,
      text,
      ...(replyMarkup ? { reply_markup: replyMarkup } : {})
    }
  });
}

export async function sendTelegramContactRequest(telegram, { chatId, appName, language = 'en' }) {
  return sendTelegramText(telegram, {
    chatId,
    text: translate(language, 'telegramContactRequest', { appName }),
    replyMarkup: {
        keyboard: [[{ text: translate(language, 'telegramContactButton'), request_contact: true }]],
        resize_keyboard: true,
        one_time_keyboard: true
    }
  });
}

export async function sendTelegramOtp(telegram, { chatId, phone, code, appName, language = 'en' }) {
  if (!telegram.enabled) throw new Error('Telegram bot is not configured');
  const message = renderTelegramMessage(telegram, {
    phone,
    code,
    appName,
    minutes: telegram.otpMinutes
  }, language);
  const response = await sendTelegramText(telegram, {
    chatId,
    text: message,
    replyMarkup: { remove_keyboard: true }
  });
  const messageId = response?.result?.message_id || '';
  if (!messageId) throw new Error('Telegram Bot API did not return a message ID');
  return { provider: 'telegram', messageId: String(messageId), response };
}

export async function getTelegramUpdates(telegram, { offset = 0, timeout = 0, limit = 25 } = {}) {
  if (!telegram.enabled) throw new Error('Telegram bot is not configured');
  const response = await requestJson(apiUrl(telegram, 'getUpdates'), {
    timeoutMs: (Number(timeout) + 5) * 1000,
    body: {
      ...(offset ? { offset } : {}),
      timeout,
      limit,
      allowed_updates: ['message', 'edited_message']
    }
  });
  return Array.isArray(response.result) ? response.result : [];
}

export async function deleteTelegramWebhook(telegram) {
  if (!telegram.enabled) throw new Error('Telegram bot is not configured');
  return requestJson(apiUrl(telegram, 'deleteWebhook'), {
    body: { drop_pending_updates: false }
  });
}

export const telegramInternals = { replaceVariables };
