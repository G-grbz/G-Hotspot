import net from 'node:net';
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';

function encodeHeader(value) {
  const clean = String(value).replace(/[\r\n]+/g, ' ').trim();
  return `=?UTF-8?B?${Buffer.from(clean, 'utf8').toString('base64')}?=`;
}

function extractAddress(value) {
  const match = String(value).match(/<([^>]+)>/u);
  return (match ? match[1] : value).trim();
}

function wrapBase64(value) {
  return Buffer.from(value, 'utf8').toString('base64').match(/.{1,76}/g)?.join('\r\n') || '';
}

function createReader(socket) {
  let buffer = '';
  const lines = [];
  const waiters = [];

  function flush() {
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index + 1).replace(/\r?\n$/, '');
      buffer = buffer.slice(index + 1);
      if (waiters.length) waiters.shift().resolve(line);
      else lines.push(line);
    }
  }

  const onData = chunk => {
    buffer += chunk.toString('utf8');
    flush();
  };
  const onError = error => {
    while (waiters.length) waiters.shift().reject(error);
  };
  const onClose = () => onError(new Error('SMTP connection closed unexpectedly'));
  socket.on('data', onData);
  socket.on('error', onError);
  socket.on('close', onClose);

  return {
    async line() {
      if (lines.length) return lines.shift();
      return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
    },
    detach() {
      socket.off('data', onData);
      socket.off('error', onError);
      socket.off('close', onClose);
    }
  };
}

async function readResponse(reader) {
  const first = await reader.line();
  const match = first.match(/^(\d{3})([ -])(.*)$/u);
  if (!match) throw new Error(`Invalid SMTP response: ${first}`);
  const code = Number(match[1]);
  const lines = [first];
  if (match[2] === '-') {
    while (true) {
      const line = await reader.line();
      lines.push(line);
      if (line.startsWith(`${match[1]} `)) break;
    }
  }
  return { code, text: lines.join('\n'), lines };
}

function expect(response, allowed, action) {
  if (!allowed.includes(response.code)) {
    if (response.code === 535) {
      throw new Error('SMTP authentication failed. Check the username and use an application-specific password if required by the mail provider.');
    }
    if (response.code === 530 && /SSL|TLS|encrypt/iu.test(response.text)) {
      throw new Error('SMTP authentication requires TLS. Use implicit TLS on port 465 or STARTTLS on port 587.');
    }
    throw new Error(`SMTP ${action} failed (${response.code}): ${response.text}`);
  }
}

function connectSocket(options) {
  return new Promise((resolve, reject) => {
    const socket = options.secure
      ? tls.connect({ host: options.host, port: options.port, servername: options.host, rejectUnauthorized: true }, () => resolve(socket))
      : net.createConnection({ host: options.host, port: options.port }, () => resolve(socket));
    socket.setTimeout(15000, () => socket.destroy(new Error('SMTP connection timed out')));
    socket.once('error', reject);
  });
}

function upgradeTls(socket, host) {
  return new Promise((resolve, reject) => {
    const secureSocket = tls.connect({ socket, servername: host, rejectUnauthorized: true }, () => resolve(secureSocket));
    secureSocket.setTimeout(15000, () => secureSocket.destroy(new Error('SMTP TLS connection timed out')));
    secureSocket.once('error', reject);
  });
}

async function command(socket, reader, value, allowed, action) {
  socket.write(`${value}\r\n`);
  const response = await readResponse(reader);
  expect(response, allowed, action);
  return response;
}

function buildMessage({ from, to, subject, text, html }) {
  const boundary = `g-hotspot-${randomUUID()}`;
  const domain = extractAddress(from).split('@')[1] || 'localhost';
  return [
    `From: ${from.replace(/[\r\n]+/g, ' ')}`,
    `To: ${to.replace(/[\r\n]+/g, ' ')}`,
    `Subject: ${encodeHeader(subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomUUID()}@${domain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    wrapBase64(text),
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    wrapBase64(html),
    `--${boundary}--`,
    ''
  ].join('\r\n').replace(/^\./gm, '..');
}

export async function sendMail(smtp, message) {
  if (!smtp.enabled) throw new Error('SMTP is not configured');
  let socket = await connectSocket(smtp);
  let reader = createReader(socket);
  try {
    expect(await readResponse(reader), [220], 'greeting');
    let ehlo = await command(socket, reader, `EHLO ${smtp.host}`, [250], 'EHLO');
    const supportsStartTls = ehlo.text.toUpperCase().includes('STARTTLS');

    if (!smtp.secure && smtp.starttls) {
      if (!supportsStartTls) throw new Error('SMTP server does not offer STARTTLS');
      await command(socket, reader, 'STARTTLS', [220], 'STARTTLS');
      reader.detach();
      socket = await upgradeTls(socket, smtp.host);
      reader = createReader(socket);
      ehlo = await command(socket, reader, `EHLO ${smtp.host}`, [250], 'EHLO after STARTTLS');
    }

    if (smtp.user) {
      if (!socket.encrypted) {
        throw new Error('SMTP authentication refused because the connection is not encrypted');
      }
      await command(socket, reader, 'AUTH LOGIN', [334], 'AUTH LOGIN');
      await command(socket, reader, Buffer.from(smtp.user).toString('base64'), [334], 'SMTP username');
      await command(socket, reader, Buffer.from(smtp.pass).toString('base64'), [235], 'SMTP password');
    }

    const fromAddress = extractAddress(smtp.from);
    await command(socket, reader, `MAIL FROM:<${fromAddress}>`, [250], 'MAIL FROM');
    await command(socket, reader, `RCPT TO:<${message.to}>`, [250, 251], 'RCPT TO');
    await command(socket, reader, 'DATA', [354], 'DATA');
    socket.write(`${buildMessage({ ...message, from: smtp.from })}\r\n.\r\n`);
    expect(await readResponse(reader), [250], 'message delivery');
    await command(socket, reader, 'QUIT', [221], 'QUIT');
  } finally {
    reader.detach();
    socket.destroy();
  }
}
