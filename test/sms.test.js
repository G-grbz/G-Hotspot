import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { sendSmsOtp, smsInternals } from '../src/services/sms.js';

test('SMS message templates replace supported variables', () => {
  const message = smsInternals.renderMessage({
    template: '{appName} code: {code}, valid for {minutes} minutes.'
  }, { appName: 'G-Hotspot', code: '123456', minutes: 5 });
  assert.equal(message, 'G-Hotspot code: 123456, valid for 5 minutes.');
});

test('custom SMS provider sends the configured JSON request', async () => {
  let observed = null;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed = {
      method: request.method,
      authorization: request.headers.authorization,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
    };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ data: { accepted: true }, messageId: 'sms-test-1' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await sendSmsOtp({
      enabled: true,
      provider: 'custom',
      sender: 'GHotspot',
      otpMinutes: 5,
      template: '{appName} access code: {code}',
      custom: {
        url: `http://127.0.0.1:${port}/send`,
        method: 'POST',
        authorization: 'Bearer test-token',
        headersJson: '{"x-service":"hotspot"}',
        bodyTemplate: '{"to":"{phone}","text":"{message}","otp":"{code}"}',
        successPath: 'data.accepted'
      }
    }, { phone: '905551112233', code: '482913', appName: 'G-Hotspot' });

    assert.equal(result.provider, 'custom');
    assert.equal(result.messageId, 'sms-test-1');
    assert.equal(observed.method, 'POST');
    assert.equal(observed.authorization, 'Bearer test-token');
    assert.deepEqual(observed.body, {
      to: '905551112233',
      text: 'G-Hotspot access code: 482913',
      otp: '482913'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
