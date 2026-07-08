import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { sendMail } from '../src/services/smtp.js';

function startSmtpServer() {
  let captured = '';
  let dataMode = false;
  let dataBuffer = '';

  const server = net.createServer(socket => {
    socket.setEncoding('utf8');
    socket.write('220 mock.smtp ESMTP ready\r\n');
    let commandBuffer = '';

    socket.on('data', chunk => {
      if (dataMode) {
        dataBuffer += chunk;
        const end = dataBuffer.indexOf('\r\n.\r\n');
        if (end >= 0) {
          captured = dataBuffer.slice(0, end);
          dataMode = false;
          dataBuffer = dataBuffer.slice(end + 5);
          socket.write('250 2.0.0 queued\r\n');
        }
        return;
      }

      commandBuffer += chunk;
      let index;
      while ((index = commandBuffer.indexOf('\r\n')) >= 0) {
        const line = commandBuffer.slice(0, index);
        commandBuffer = commandBuffer.slice(index + 2);
        if (line.startsWith('EHLO ')) socket.write('250-mock.smtp\r\n250 SIZE 1000000\r\n');
        else if (line.startsWith('MAIL FROM:')) socket.write('250 2.1.0 ok\r\n');
        else if (line.startsWith('RCPT TO:')) socket.write('250 2.1.5 ok\r\n');
        else if (line === 'DATA') {
          dataMode = true;
          socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        } else if (line === 'QUIT') {
          socket.write('221 2.0.0 bye\r\n');
          socket.end();
        } else socket.write('500 unsupported\r\n');
      }
    });
  });

  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      port: server.address().port,
      getCaptured: () => captured
    }));
  });
}

test('SMTP client sends a multipart message', async () => {
  const mock = await startSmtpServer();
  try {
    await sendMail({
      enabled: true,
      host: '127.0.0.1',
      port: mock.port,
      secure: false,
      starttls: false,
      user: '',
      pass: '',
      from: 'G-Hotspot <hotspot@example.com>'
    }, {
      to: 'guest@example.net',
      subject: 'Doğrulama kodu',
      text: 'Kod: 123456',
      html: '<p>Kod: <b>123456</b></p>'
    });
    const message = mock.getCaptured();
    assert.match(message, /To: guest@example\.net/u);
    assert.match(message, /Content-Type: multipart\/alternative/u);
    assert.match(message, /S29kOiAxMjM0NTY=/u);
  } finally {
    await new Promise(resolve => mock.server.close(resolve));
  }
});

test('SMTP client refuses authentication over an unencrypted connection', async () => {
  const mock = await startSmtpServer();
  try {
    await assert.rejects(() => sendMail({
      enabled: true,
      host: '127.0.0.1',
      port: mock.port,
      secure: false,
      starttls: false,
      user: 'user@example.com',
      pass: 'password',
      from: 'user@example.com'
    }, {
      to: 'guest@example.net',
      subject: 'Test',
      text: 'Test',
      html: '<p>Test</p>'
    }), /connection is not encrypted/u);
  } finally {
    await new Promise(resolve => mock.server.close(resolve));
  }
});
