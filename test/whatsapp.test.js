import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { buildOtpTemplatePayload, sendWhatsAppOtp } from '../src/services/whatsapp.js';

const baseConfig = {
  enabled: true,
  phoneNumberId: '123456789',
  accessToken: 'test-token',
  templateName: 'hotspot_otp',
  templateLanguage: 'tr',
  templateButton: true,
  graphApiVersion: 'v22.0',
  graphBaseUrl: 'http://127.0.0.1'
};

test('WhatsApp OTP payload uses an authentication template and copy-code button', () => {
  assert.deepEqual(buildOtpTemplatePayload(baseConfig, {
    to: '905551112233',
    code: '482913'
  }), {
    messaging_product: 'whatsapp',
    recipient_type: 'individual',
    to: '905551112233',
    type: 'template',
    template: {
      name: 'hotspot_otp',
      language: { code: 'tr' },
      components: [
        {
          type: 'body',
          parameters: [{ type: 'text', text: '482913' }]
        },
        {
          type: 'button',
          sub_type: 'url',
          index: '0',
          parameters: [{ type: 'text', text: '482913' }]
        }
      ]
    }
  });
});

test('WhatsApp Cloud API client posts the template and returns message ID', async () => {
  let observed = null;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed = {
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8'))
    };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ messages: [{ id: 'wamid.test-message' }] }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await sendWhatsAppOtp({
      ...baseConfig,
      graphBaseUrl: `http://127.0.0.1:${port}`
    }, { to: '905551112233', code: '482913' });

    assert.equal(result.messageId, 'wamid.test-message');
    assert.equal(observed.method, 'POST');
    assert.equal(observed.url, '/v22.0/123456789/messages');
    assert.equal(observed.authorization, 'Bearer test-token');
    assert.equal(observed.body.template.name, 'hotspot_otp');
    assert.equal(observed.body.template.components[0].parameters[0].text, '482913');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
