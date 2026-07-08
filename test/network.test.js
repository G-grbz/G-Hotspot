import test from 'node:test';
import assert from 'node:assert/strict';
import {
  automaticListenHost,
  automaticListenPort,
  automaticPublicBaseUrl,
  ipv4RangeToCidrs,
  normalizeNetworkList
} from '../src/lib/network.js';

test('IPv4 ranges are converted to the smallest CIDR list', () => {
  assert.deepEqual(ipv4RangeToCidrs('172.16.2.100', '172.16.2.254'), [
    '172.16.2.100/30',
    '172.16.2.104/29',
    '172.16.2.112/28',
    '172.16.2.128/26',
    '172.16.2.192/27',
    '172.16.2.224/28',
    '172.16.2.240/29',
    '172.16.2.248/30',
    '172.16.2.252/31',
    '172.16.2.254/32'
  ]);
});

test('network lists accept ranges, CIDRs, individual IPs and any', () => {
  assert.equal(normalizeNetworkList('any'), 'any');
  assert.equal(normalizeNetworkList('172.16.2.0/24'), '172.16.2.0/24');
  assert.equal(
    normalizeNetworkList('172.16.2.100 - 172.16.2.103, 192.0.2.20'),
    '172.16.2.100/30,192.0.2.20'
  );
  assert.throws(
    () => normalizeNetworkList('172.16.2.254 - 172.16.2.100'),
    /start must not be after/u
  );
});

test('runtime network defaults ignore example env values', () => {
  const host = automaticListenHost('0.0.0.0');
  assert.notEqual(host, '0.0.0.0');
  assert.match(host, /^\d{1,3}(?:\.\d{1,3}){3}$/u);
  assert.equal(automaticListenHost('10.20.30.40'), '10.20.30.40');
  assert.equal(automaticListenPort(''), 8080);
  assert.equal(automaticListenPort('9090'), 9090);
  assert.equal(
    automaticPublicBaseUrl({
      publicBaseUrl: 'http://192.168.1.50:8080',
      host: '10.20.30.40',
      port: '9090'
    }),
    'http://10.20.30.40:9090'
  );
  assert.equal(
    automaticPublicBaseUrl({
      publicBaseUrl: 'https://hotspot.example.com',
      host: '10.20.30.40',
      port: '9090'
    }),
    'https://hotspot.example.com'
  );
});
