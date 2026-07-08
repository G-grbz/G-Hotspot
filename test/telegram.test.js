import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  deleteTelegramWebhook,
  getTelegramUpdates,
  renderTelegramMessage,
  sendTelegramContactRequest,
  sendTelegramOtp,
  telegramAppUrl,
  telegramStartCommand,
  telegramStartUrl
} from '../src/services/telegram.js';

const baseConfig = {
  enabled: true,
  botToken: '123456:test-token',
  botUsername: 'GHotspotBot',
  botApiBaseUrl: 'http://127.0.0.1',
  otpMinutes: 5,
  template: '{appName} Telegram code: {code}. Valid for {minutes} minutes.'
};

const defaultTemplateConfig = {
  ...baseConfig,
  template: '{appName} Telegram access code: {code}. The code is valid for {minutes} minutes.'
};

test('Telegram start URL uses the configured bot username and challenge ID', () => {
  assert.equal(
    telegramStartUrl(baseConfig, 'challenge-123'),
    'https://t.me/GHotspotBot?start=challenge-123'
  );
  assert.equal(
    telegramAppUrl(baseConfig, 'challenge-123'),
    'tg://resolve?domain=GHotspotBot&start=challenge-123'
  );
  assert.equal(telegramStartCommand('challenge-123'), '/start challenge-123');
});

test('Telegram message templates replace supported variables', () => {
  assert.equal(
    renderTelegramMessage(baseConfig, {
      appName: 'G-Hotspot',
      code: '482913',
      minutes: 5
    }),
    'G-Hotspot Telegram code: 482913. Valid for 5 minutes.'
  );
});

test('Telegram default OTP message follows the selected language', () => {
  assert.equal(
    renderTelegramMessage(defaultTemplateConfig, {
      appName: 'G-Hotspot',
      code: '482913',
      minutes: 5
    }, 'tr'),
    'G-Hotspot Telegram doğrulama kodunuz: 482913. Bu kod 5 dakika boyunca geçerlidir. Kodu hotspot portalındaki Telegram doğrulama kodu alanına girin.'
  );
});

test('Telegram Bot API client requests contact sharing and sends OTP', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
    });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ ok: true, result: { message_id: 42 } }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const telegram = {
      ...baseConfig,
      botApiBaseUrl: `http://127.0.0.1:${port}`
    };
    await sendTelegramContactRequest(telegram, { chatId: '1001', appName: 'G-Hotspot' });
    const result = await sendTelegramOtp(telegram, {
      chatId: '1001',
      phone: '905551112233',
      code: '482913',
      appName: 'G-Hotspot'
    });

    assert.equal(result.messageId, '42');
    assert.equal(requests[0].url, '/bot123456:test-token/sendMessage');
    assert.equal(requests[0].body.chat_id, '1001');
    assert.match(requests[0].body.text, /Entering the phone number manually will not trigger/u);
    assert.equal(requests[0].body.reply_markup.keyboard[0][0].request_contact, true);
    assert.equal(requests[1].body.text, 'G-Hotspot Telegram code: 482913. Valid for 5 minutes.');
    assert.equal(requests[1].body.reply_markup.remove_keyboard, true);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('Telegram polling helpers delete webhook and read updates with offset', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      url: request.url,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
    });
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      ok: true,
      result: request.url.endsWith('/getUpdates')
        ? [{ update_id: 12, message: { text: '/start abc' } }]
        : true
    }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const telegram = {
      ...baseConfig,
      botApiBaseUrl: `http://127.0.0.1:${port}`
    };
    await deleteTelegramWebhook(telegram);
    const updates = await getTelegramUpdates(telegram, { offset: 12, timeout: 20, limit: 10 });

    assert.equal(requests[0].url, '/bot123456:test-token/deleteWebhook');
    assert.equal(requests[0].body.drop_pending_updates, false);
    assert.equal(requests[1].url, '/bot123456:test-token/getUpdates');
    assert.equal(requests[1].body.offset, 12);
    assert.equal(requests[1].body.timeout, 20);
    assert.equal(requests[1].body.limit, 10);
    assert.equal(updates[0].update_id, 12);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
