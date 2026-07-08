import http from 'node:http';
import https from 'node:https';

function request(url, { method = 'POST', headers = {}, body = '', timeoutMs = 15000 }) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const payload = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
    const transport = target.protocol === 'https:' ? https : http;
    const req = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method,
      timeout: timeoutMs,
      headers: {
        accept: 'application/json, text/plain, */*',
        ...(payload.length ? { 'content-length': payload.length } : {}),
        ...headers
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = text ? JSON.parse(text) : null; } catch {}
        if ((response.statusCode || 500) >= 400) {
          reject(new Error(`SMS provider returned HTTP ${response.statusCode}: ${text.slice(0, 500)}`));
          return;
        }
        resolve({ statusCode: response.statusCode, text, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('SMS provider request timed out')));
    req.on('error', reject);
    req.end(payload);
  });
}

function jsonRequest(url, body, options = {}) {
  return request(url, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    body: JSON.stringify(body)
  });
}

function replaceVariables(value, variables) {
  return String(value ?? '').replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, key) =>
    Object.hasOwn(variables, key) ? String(variables[key]) : match
  );
}

function replaceJsonVariables(value, variables) {
  return String(value ?? '').replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (match, key) => {
    if (!Object.hasOwn(variables, key)) return match;
    return JSON.stringify(String(variables[key])).slice(1, -1);
  });
}

function renderMessage(sms, variables) {
  return replaceVariables(sms.template, variables);
}

function getPath(value, path) {
  if (!path) return value;
  return String(path).split('.').reduce((current, key) => current?.[key], value);
}

function assertConfigured(values, provider) {
  if (values.some(value => !String(value || '').trim())) {
    throw new Error(`${provider} SMS settings are incomplete`);
  }
}

async function sendNetgsm(sms, phone, message) {
  const settings = sms.netgsm;
  assertConfigured([settings.usercode, settings.password, settings.header || sms.sender], 'Netgsm');
  const auth = Buffer.from(`${settings.usercode}:${settings.password}`).toString('base64');
  const response = await jsonRequest('https://api.netgsm.com.tr/sms/rest/v2/send', {
    msgheader: settings.header || sms.sender,
    encoding: 'TR',
    messages: [{ msg: message, no: phone }]
  }, { headers: { authorization: `Basic ${auth}` } });
  const code = String(response.json?.code ?? response.text.split(/\s+/u)[0] ?? '');
  if (code && !['00', '0'].includes(code)) throw new Error(`Netgsm rejected the message with code ${code}`);
  return { provider: 'netgsm', messageId: response.json?.jobid || response.json?.jobId || '' };
}

async function sendIletiMerkezi(sms, phone, message) {
  const settings = sms.iletimerkezi;
  assertConfigured([settings.apiKey, settings.apiSecret, settings.sender || sms.sender], 'İleti Merkezi');
  const response = await jsonRequest('https://api.iletimerkezi.com/v1/send-sms/json', {
    request: {
      authentication: { key: settings.apiKey, hash: settings.apiSecret },
      order: {
        sender: settings.sender || sms.sender,
        sendDateTime: [],
        message: {
          text: message,
          receipents: { number: [phone] }
        }
      }
    }
  });
  const statusCode = String(response.json?.response?.status?.code ?? '');
  if (statusCode && statusCode !== '200') {
    throw new Error(`İleti Merkezi rejected the message with code ${statusCode}`);
  }
  return {
    provider: 'iletimerkezi',
    messageId: response.json?.response?.order?.id || response.json?.response?.orderId || ''
  };
}

async function sendTwilio(sms, phone, message) {
  const settings = sms.twilio;
  assertConfigured([settings.accountSid, settings.authToken, settings.from], 'Twilio');
  const body = new URLSearchParams({ To: `+${phone}`, From: settings.from, Body: message }).toString();
  const auth = Buffer.from(`${settings.accountSid}:${settings.authToken}`).toString('base64');
  const response = await request(
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(settings.accountSid)}/Messages.json`,
    {
      headers: {
        authorization: `Basic ${auth}`,
        'content-type': 'application/x-www-form-urlencoded'
      },
      body
    }
  );
  return { provider: 'twilio', messageId: response.json?.sid || '' };
}

async function sendCustom(sms, variables) {
  const settings = sms.custom;
  assertConfigured([settings.url, settings.bodyTemplate], 'Custom');
  let headers;
  let body;
  try {
    headers = JSON.parse(replaceJsonVariables(settings.headersJson || '{}', variables));
    body = JSON.parse(replaceJsonVariables(settings.bodyTemplate, variables));
  } catch (error) {
    throw new Error(`Custom SMS JSON configuration is invalid: ${error.message}`);
  }
  if (settings.authorization) headers.authorization = replaceVariables(settings.authorization, variables);
  const response = await jsonRequest(settings.url, body, {
    method: settings.method,
    headers
  });
  if (settings.successPath && !getPath(response.json, settings.successPath)) {
    throw new Error(`Custom SMS response did not satisfy success path: ${settings.successPath}`);
  }
  return {
    provider: 'custom',
    messageId: response.json?.messageId || response.json?.id || ''
  };
}

export async function sendSmsMessage(sms, { phone, message, appName = '', code = '', minutes = '' }) {
  if (!sms.enabled) throw new Error('SMS is disabled');
  const variables = {
    phone,
    code,
    appName,
    minutes: minutes || sms.otpMinutes,
    sender: sms.sender,
    message
  };
  if (sms.provider === 'netgsm') return sendNetgsm(sms, phone, variables.message);
  if (sms.provider === 'iletimerkezi') return sendIletiMerkezi(sms, phone, variables.message);
  if (sms.provider === 'twilio') return sendTwilio(sms, phone, variables.message);
  return sendCustom(sms, variables);
}

export async function sendSmsOtp(sms, { phone, code, appName }) {
  if (!sms.enabled) throw new Error('SMS OTP is disabled');
  const message = renderMessage(sms, {
    phone,
    code,
    appName,
    minutes: sms.otpMinutes,
    sender: sms.sender
  });
  return sendSmsMessage(sms, { phone, code, appName, message, minutes: sms.otpMinutes });
}

export const smsInternals = { replaceVariables, replaceJsonVariables, renderMessage };
