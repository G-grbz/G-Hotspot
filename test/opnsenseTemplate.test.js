import test from 'node:test';
import assert from 'node:assert/strict';
import { inflateRawSync } from 'node:zlib';
import {
  OPNSENSE_TEMPLATE_DEFAULTS,
  createOpnsenseTemplateZip,
  renderOpnsenseTemplateHtml
} from '../src/services/opnsenseTemplate.js';

function unzipFirstEntry(buffer) {
  assert.equal(buffer.readUInt32LE(0), 0x04034b50);
  const compression = buffer.readUInt16LE(8);
  const compressedSize = buffer.readUInt32LE(18);
  const nameLength = buffer.readUInt16LE(26);
  const extraLength = buffer.readUInt16LE(28);
  const nameStart = 30;
  const dataStart = nameStart + nameLength + extraLength;
  const name = buffer.subarray(nameStart, nameStart + nameLength).toString('utf8');
  const compressed = buffer.subarray(dataStart, dataStart + compressedSize);
  const data = compression === 8 ? inflateRawSync(compressed) : compressed;
  return { name, data: data.toString('utf8') };
}

test('OPNsense template renderer keeps the captive portal redirect behavior', () => {
  const html = renderOpnsenseTemplateHtml(OPNSENSE_TEMPLATE_DEFAULTS);

  assert.match(html, /<html lang="en">/u);
  assert.match(html, /<title>Redirecting<\/title>/u);
  assert.match(html, /content="3;url=http:\/\/172\.16\.2\.2:8080\/"/u);
  assert.match(html, /<a href="http:\/\/172\.16\.2\.2:8080\/">Continue to G-Hotspot<\/a>/u);
  assert.match(html, /var target = "http:\/\/172\.16\.2\.2:8080\/";/u);
  assert.match(html, /window\.location\.replace\(target \+ query \+ hash\)/u);
});

test('OPNsense template renderer escapes editable fields', () => {
  const html = renderOpnsenseTemplateHtml({
    lang: 'tr',
    title: 'Yönlendiriliyor <test>',
    refreshSeconds: 1,
    targetUrl: 'http://172.16.2.2:9090/portal?next=1&name=g',
    redirectText: 'Misafir portalına yönlendiriliyorsunuz <script>',
    linkText: 'G-Hotspot ile devam et',
    noscriptText: 'JavaScript kapalı.'
  });

  assert.match(html, /<html lang="tr">/u);
  assert.match(html, /<title>Yönlendiriliyor &lt;test&gt;<\/title>/u);
  assert.match(html, /content="1;url=http:\/\/172\.16\.2\.2:9090\/portal\?next=1&amp;name=g"/u);
  assert.match(html, /Misafir portalına yönlendiriliyorsunuz &lt;script&gt;/u);
  assert.match(html, /var target = "http:\/\/172\.16\.2\.2:9090\/portal\?next=1&name=g";/u);
});

test('OPNsense template ZIP contains index.html at archive root', () => {
  const archive = createOpnsenseTemplateZip({
    lang: 'tr',
    title: 'Yönlendiriliyor',
    targetUrl: 'http://172.16.2.2:8081/'
  });
  const entry = unzipFirstEntry(archive.buffer);

  assert.equal(archive.filename, 'opnsense-captiveportal-template.zip');
  assert.equal(entry.name, 'index.html');
  assert.match(entry.data, /<html lang="tr">/u);
  assert.match(entry.data, /http:\/\/172\.16\.2\.2:8081\//u);
});

test('OPNsense template validation rejects invalid language and URL values', () => {
  assert.throws(
    () => renderOpnsenseTemplateHtml({ lang: 'tr<script>' }),
    /valid HTML language/u
  );
  assert.throws(
    () => renderOpnsenseTemplateHtml({ targetUrl: 'ftp://172.16.2.2/' }),
    /http:\/\/ or https:\/\//u
  );
});
