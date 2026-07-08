import http from 'node:http';
import https from 'node:https';

function requestJson(url, { token, body, timeoutMs = 15000 }) {
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
        authorization: `Bearer ${token}`,
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
        if ((response.statusCode || 500) >= 400) {
          const message = parsed?.error?.message || text.slice(0, 500) || `HTTP ${response.statusCode}`;
          const code = parsed?.error?.code ? ` (Meta ${parsed.error.code})` : '';
          reject(new Error(`WhatsApp Cloud API rejected the message${code}: ${message}`));
          return;
        }
        resolve(parsed);
      });
    });
    request.on('timeout', () => request.destroy(new Error('WhatsApp Cloud API request timed out')));
    request.on('error', reject);
    request.end(payload);
  });
}

export function buildOtpTemplatePayload(whatsapp, { to, code }) {
  const components = [{
    type: 'body',
    parameters: [{ type: 'text', text: code }]
  }];
  if (whatsapp.templateButton) {
    components.push({
      type: 'button',
      sub_type: 'url',
      index: '0',
      parameters: [{ type: 'text', text: code }]
    });
  }
  return {
    messaging_product: 'whatsapp',
    recipient_type: 'individual',
    to,
    type: 'template',
    template: {
      name: whatsapp.templateName,
      language: { code: whatsapp.templateLanguage },
      components
    }
  };
}

export async function sendWhatsAppOtp(whatsapp, { to, code }) {
  if (!whatsapp.enabled) throw new Error('WhatsApp Cloud API is not configured');
  const baseUrl = whatsapp.graphBaseUrl.replace(/\/$/, '');
  const endpoint = `${baseUrl}/${whatsapp.graphApiVersion}/${encodeURIComponent(whatsapp.phoneNumberId)}/messages`;
  const response = await requestJson(endpoint, {
    token: whatsapp.accessToken,
    body: buildOtpTemplatePayload(whatsapp, { to, code })
  });
  const messageId = response?.messages?.[0]?.id || '';
  if (!messageId) throw new Error('WhatsApp Cloud API did not return a message ID');
  return { messageId, response };
}
