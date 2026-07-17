import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {
  authorizeGateway, deleteGatewayKeaDhcpLease, disconnectGatewaySession, ensureGatewayBandwidthLimits,
  ensureGatewayKeaDhcpLease, listGatewayArpEntries, listGatewayDhcpLeases, listGatewayInterfaces,
  listGatewayNetworkChoices, listGatewaySessions, readGatewayInterfaceTrafficCounters
} from '../src/services/opnsense.js';

test('OPNsense adapter posts user and client IP with basic auth', async () => {
  let observed = null;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed = {
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      body: Buffer.concat(chunks).toString('utf8')
    };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      sessionId: 'session-1',
      ipAddress: '192.0.2.20',
      macAddress: 'AA:BB:CC:DD:EE:FF'
    }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await authorizeGateway({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 3,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }, { user: 'email:guest@example.com', clientIp: '192.0.2.20' });

    assert.equal(result.sessionId, 'session-1');
    assert.equal(result.clientMac, 'AA:BB:CC:DD:EE:FF');
    assert.equal(observed.method, 'POST');
    assert.equal(observed.url, '/api/captiveportal/session/connect/3');
    assert.equal(observed.authorization, `Basic ${Buffer.from('key:secret').toString('base64')}`);
    assert.deepEqual(Object.fromEntries(new URLSearchParams(observed.body)), {
      user: 'email:guest@example.com',
      ip: '192.0.2.20'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter maps client networks to captive portal zones', async () => {
  let observed = null;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    observed = {
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    };
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ sessionId: 'session-zone-2' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await authorizeGateway({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 0,
      zoneMap: [
        { network: '172.16.2.0/24', zoneId: 0 },
        { network: '172.16.3.0/24', zoneId: 2 }
      ],
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }, { user: 'sms:905551112233', clientIp: '172.16.3.44' });

    assert.equal(result.zoneId, 2);
    assert.equal(result.sessionId, 'session-zone-2');
    assert.equal(result.storedSessionId, '2:session-zone-2');
    assert.equal(observed.method, 'POST');
    assert.equal(observed.url, '/api/captiveportal/session/connect/2');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(observed.body)), {
      user: 'sms:905551112233',
      ip: '172.16.3.44'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

// TODO(pfSense): Re-enable these adapter tests when pfSense support resumes.
test.skip('pfSense adapter returns browser captive portal login payload', async () => {
  const result = await authorizeGateway({
    mode: 'pfsense-api',
    baseUrl: 'https://192.0.2.1',
    captivePortalUrl: 'http://192.0.2.1:8000/index.php',
    zoneId: 4,
    apiKey: 'portal-user',
    apiSecret: 'portal-pass',
    tlsRejectUnauthorized: true
  }, { user: 'voucher:guest', clientIp: '192.0.2.44' });

  assert.equal(result.zoneId, 4);
  assert.match(result.sessionId, /^pfsense-browser-login-/u);
  assert.equal(result.gatewayLogin.provider, 'pfSense');
  assert.equal(result.gatewayLogin.method, 'POST');
  assert.equal(result.gatewayLogin.action, 'http://192.0.2.1:8000/index.php?zone=4');
  assert.equal(result.gatewayLogin.fields.auth_user, 'portal-user');
  assert.equal(result.gatewayLogin.fields.auth_pass, 'portal-pass');
  assert.equal(result.gatewayLogin.fields.clientip, '192.0.2.44');
});

test.skip('pfSense adapter reads ARP and DHCP ownership from REST API package endpoints', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    if (request.url === '/api/v2/diagnostics/arp_table') {
      response.end(JSON.stringify({ data: [
        { ip_address: '192.0.2.44', mac_address: 'aa:bb:cc:dd:ee:ff', interface: 'lan' }
      ] }));
      return;
    }
    if (request.url === '/api/v2/status/dhcp_server/leases') {
      response.end(JSON.stringify({ data: [
        { ip: '192.0.2.45', mac: '11:22:33:44:55:66', hostname: 'phone', if: 'lan', active_status: 'active' }
      ] }));
      return;
    }
    response.end(JSON.stringify({ data: [] }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const gateway = {
    mode: 'pfsense-api',
    baseUrl: `http://127.0.0.1:${port}`,
    apiKey: 'key',
    apiSecret: 'secret',
    tlsRejectUnauthorized: true
  };
  try {
    const arpRows = await listGatewayArpEntries(gateway);
    const dhcpRows = await listGatewayDhcpLeases(gateway);

    assert.deepEqual(requests, [
      '/api/v2/diagnostics/arp_table',
      '/api/v2/status/dhcp_server/leases'
    ]);
    assert.equal(arpRows[0].clientIp, '192.0.2.44');
    assert.equal(arpRows[0].clientMac, 'AA:BB:CC:DD:EE:FF');
    assert.equal(dhcpRows[0].clientIp, '192.0.2.45');
    assert.equal(dhcpRows[0].clientMac, '11:22:33:44:55:66');
    assert.equal(dhcpRows[0].source, 'pfsense-dhcpv4');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter lists and disconnects mapped captive portal zones', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({ method: request.method, url: request.url, body });
    if (request.url === '/api/captiveportal/session/list/0') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [{ sessionId: 'old-zone', ipAddress: '172.16.2.20' }] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/list/2') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ rows: [{ sessionId: 'new-zone', ipAddress: '172.16.3.20' }] }));
      return;
    }
    if (request.url === '/api/captiveportal/session/disconnect/2') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const gateway = {
    mode: 'opnsense-api',
    baseUrl: `http://127.0.0.1:${port}`,
    zoneId: 0,
    zoneMap: [
      { network: '172.16.2.0/24', zoneId: 0 },
      { network: '172.16.3.0/24', zoneId: 2 }
    ],
    apiKey: 'key',
    apiSecret: 'secret',
    tlsRejectUnauthorized: true
  };
  try {
    const rows = await listGatewaySessions(gateway);
    assert.deepEqual(rows.map(row => ({
      sessionId: row.sessionId,
      zoneId: row.gHotspotZoneId
    })), [
      { sessionId: 'old-zone', zoneId: 0 },
      { sessionId: 'new-zone', zoneId: 2 }
    ]);

    await disconnectGatewaySession(gateway, '2:new-zone');
    const disconnect = requests.find(item => item.url === '/api/captiveportal/session/disconnect/2');
    assert.equal(disconnect.method, 'POST');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(disconnect.body)), {
      sessionId: 'new-zone'
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reads ARP entries for IP and MAC ownership checks', async () => {
  const server = http.createServer((request, response) => {
    assert.equal(request.url, '/api/diagnostics/interface/get_arp');
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({
      rows: [
        { ipAddress: '172.16.2.100', macAddress: '28:16:7f:27:46:71', intf: 'igb1' },
        { address: '? (172.16.2.101) at 6e:8c:cf:bb:84:9b on igb1 expires in 1199 seconds' }
      ]
    }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    assert.deepEqual(await listGatewayArpEntries({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }), [
      {
        clientIp: '172.16.2.100',
        clientMac: '28:16:7F:27:46:71',
        interface: 'igb1',
        raw: { ipAddress: '172.16.2.100', macAddress: '28:16:7f:27:46:71', intf: 'igb1' }
      },
      {
        clientIp: '172.16.2.101',
        clientMac: '6E:8C:CF:BB:84:9B',
        interface: '',
        raw: { address: '? (172.16.2.101) at 6e:8c:cf:bb:84:9b on igb1 expires in 1199 seconds' }
      }
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reads DHCPv4 leases for IP and MAC ownership checks', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    if (request.url === '/api/kea/leases4/search') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [
          {
            if: 'wifiap',
            address: '172.16.3.2',
            mac: 'fa:93:8f:47:d5:8b',
            hostname: 'xiaomi-13t-pro',
            state: 'assigned'
          }
        ]
      }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    assert.deepEqual(await listGatewayDhcpLeases({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }), [
      {
        clientIp: '172.16.3.2',
        clientMac: 'FA:93:8F:47:D5:8B',
        deviceName: 'xiaomi-13t-pro',
        interface: 'wifiap',
        state: 'assigned',
        source: 'opnsense-dhcpv4',
        raw: {
          if: 'wifiap',
          address: '172.16.3.2',
          mac: 'fa:93:8f:47:d5:8b',
          hostname: 'xiaomi-13t-pro',
          state: 'assigned'
        }
      }
    ]);
    assert.deepEqual(requests, [{ method: 'POST', url: '/api/kea/leases4/search' }]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter falls back across unavailable DHCP lease APIs', async () => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({ method: request.method, url: request.url });
    if (request.url === '/api/kea/leases4/search') {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 403, message: 'Forbidden' }));
      return;
    }
    if (request.url === '/api/kea/leases/search') {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 404, message: 'Not found' }));
      return;
    }
    if (request.url === '/api/dhcpv4/leases/searchLease') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [{ address: '172.16.3.3', mac: '36:90:70:af:4d:b0' }]
      }));
      return;
    }
    response.writeHead(404);
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    assert.deepEqual(await listGatewayDhcpLeases({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }), [
      {
        clientIp: '172.16.3.3',
        clientMac: '36:90:70:AF:4D:B0',
        deviceName: '',
        interface: '',
        state: '',
        source: 'opnsense-dhcpv4',
        raw: { address: '172.16.3.3', mac: '36:90:70:af:4d:b0' }
      }
    ]);
    assert.deepEqual(requests, [
      { method: 'POST', url: '/api/kea/leases4/search' },
      { method: 'POST', url: '/api/kea/leases/search' },
      { method: 'GET', url: '/api/dhcpv4/leases/searchLease' }
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter creates a Kea DHCP lease-time reservation for verified access', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bodyText = Buffer.concat(chunks).toString('utf8');
    requests.push({
      method: request.method,
      url: request.url,
      body: bodyText ? JSON.parse(bodyText) : null
    });
    let payload = {};
    if (request.url === '/api/kea/dhcpv4/searchSubnet') {
      payload = { rows: [{ uuid: 'subnet-1', subnet: '172.16.3.0/24' }] };
    } else if (request.url === '/api/kea/dhcpv4/searchOption') {
      payload = { rows: [] };
    } else if (request.url === '/api/kea/dhcpv4/addOption') {
      payload = { result: 'saved', uuid: 'option-1' };
    } else if (request.url === '/api/kea/dhcpv4/searchReservation') {
      payload = { rows: [] };
    } else if (request.url === '/api/kea/dhcpv4/addReservation') {
      payload = { result: 'saved', uuid: 'reservation-1' };
    } else if (request.url === '/api/kea/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await ensureGatewayKeaDhcpLease({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }, {
      authorizationId: 'auth-1',
      method: 'email',
      identity: 'guest.user@example.com',
      clientIp: '172.16.3.4',
      clientMac: '36:90:70:af:4d:b0',
      expiresAt: Date.now() + 86400_000
    });

    assert.equal(result.applied, true);
    assert.equal(result.changed, true);
    assert.equal(result.leaseSeconds, 86400);
    assert.deepEqual(requests.find(item => item.url === '/api/kea/dhcpv4/addOption').body.option, {
      code: '51',
      encoding: 'uint32',
      data: '86400',
      force: '1',
      description: 'G-Hotspot DHCP lease 86400s'
    });
    assert.deepEqual(requests.find(item => item.url === '/api/kea/dhcpv4/addReservation').body.reservation, {
      subnet: 'subnet-1',
      ip_address: '172.16.3.4',
      hw_address: '36:90:70:AF:4D:B0',
      hostname: 'gh-email-guest-user-example-com',
      description: 'G-Hotspot access auth-1',
      option: 'option-1'
    });
    assert.equal(
      requests.filter(item => item.url === '/api/kea/service/reconfigure').length,
      1
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter removes the managed Kea DHCP reservation for an ended authorization', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      method: request.method,
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    let payload = {};
    if (request.url === '/api/kea/dhcpv4/searchReservation') {
      payload = {
        rows: [
          {
            uuid: 'reservation-1',
            description: 'G-Hotspot access auth-1',
            ip_address: '172.16.3.4',
            hw_address: '36:90:70:AF:4D:B0'
          },
          {
            uuid: 'reservation-2',
            description: 'Office printer',
            ip_address: '172.16.3.20',
            hw_address: 'AA:BB:CC:DD:EE:FF'
          }
        ]
      };
    } else if (request.url === '/api/kea/dhcpv4/delReservation/reservation-1') {
      payload = { result: 'deleted' };
    } else if (request.url === '/api/kea/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await deleteGatewayKeaDhcpLease({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    }, {
      id: 'auth-1',
      client_ip: '172.16.3.4',
      client_mac: '36:90:70:AF:4D:B0'
    });

    assert.equal(result.deleted, 1);
    assert.deepEqual(requests.map(item => ({ method: item.method, url: item.url })), [
      { method: 'POST', url: '/api/kea/dhcpv4/searchReservation' },
      { method: 'POST', url: '/api/kea/dhcpv4/delReservation/reservation-1' },
      { method: 'POST', url: '/api/kea/service/reconfigure' }
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense network discovery returns an empty list when overview API is unavailable', async () => {
  const server = http.createServer((request, response) => {
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ errorMessage: 'Endpoint not found' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const choices = await listGatewayNetworkChoices({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    });
    assert.deepEqual(choices, []);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense interface discovery lists selectable shaper interfaces', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/api/interfaces/overview/export') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        rows: [
          { name: 'wan', descr: 'WAN', device: 'igb1' },
          { name: 'lan', descr: 'LAN', device: 'igb0' }
        ]
      }));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ errorMessage: 'Endpoint not found' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const interfaces = await listGatewayInterfaces({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true
    });
    assert.deepEqual(interfaces, [
      { name: 'lan', label: 'LAN', description: 'LAN', aliases: ['lan', 'igb0'] },
      { name: 'wan', label: 'WAN', description: 'WAN', aliases: ['wan', 'igb1'] }
    ]);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reads interface traffic counters', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/api/diagnostics/interface/getInterfaceStatistics') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        interfaces: {
          wan: {
            name: 'wan',
            rx_bytes: 123456,
            tx_bytes: 654321
          }
        }
      }));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ errorMessage: 'Endpoint not found' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const counters = await readGatewayInterfaceTrafficCounters({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan'
    });
    assert.equal(counters.interfaceName, 'wan');
    assert.equal(counters.rxBytes, 123456);
    assert.equal(counters.txBytes, 654321);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reads hyphenated interface counters from diagnostics statistics', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/api/diagnostics/interface/getInterfaceStatistics') {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ status: 403, message: 'Forbidden' }));
      return;
    }
    if (request.url === '/api/diagnostics/interface/get_interface_statistics') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        statistics: {
          '[LAN] (igb0) / aa:bb:cc:dd:ee:ff': {
            name: 'igb0',
            'received-bytes': 111,
            'sent-bytes': 222
          },
          '[WAN] (igb1) / aa:bb:cc:dd:ee:00': {
            name: 'igb1',
            'received-bytes': 123456,
            'sent-bytes': 654321
          }
        }
      }));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ errorMessage: 'Endpoint not found' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const counters = await readGatewayInterfaceTrafficCounters({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan'
    });
    assert.equal(counters.interfaceName, 'igb1');
    assert.equal(counters.rxBytes, 123456);
    assert.equal(counters.txBytes, 654321);
    assert.equal(counters.endpoint, '/api/diagnostics/interface/get_interface_statistics');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reports missing interface counter privileges', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/api/diagnostics/interface/getInterfaceStatistics') {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ errorMessage: 'Forbidden' }));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ errorMessage: 'Endpoint not found' }));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    await assert.rejects(
      () => readGatewayInterfaceTrafficCounters({
        mode: 'opnsense-api',
        baseUrl: `http://127.0.0.1:${port}`,
        apiKey: 'key',
        apiSecret: 'secret',
        tlsRejectUnauthorized: true,
        shaperInterface: 'wan'
      }),
      error => {
        assert.equal(error.code, 'opnsense_interface_forbidden');
        return true;
      }
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter creates per-user download and upload shaper rules', async () => {
  const requests = [];
  let pipeIndex = 0;
  let ruleIndex = 0;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({
      method: request.method,
      url: request.url,
      body: body ? JSON.parse(body) : null
    });
    let payload = {};
    if (request.url === '/api/trafficshaper/settings/search_pipes') payload = { rows: [] };
    else if (request.url === '/api/trafficshaper/settings/search_rules') payload = { rows: [] };
    else if (request.url === '/api/trafficshaper/settings/add_pipe') {
      pipeIndex += 1;
      payload = { result: 'saved', uuid: `pipe-${pipeIndex}` };
    } else if (request.url === '/api/trafficshaper/settings/add_rule') {
      ruleIndex += 1;
      payload = { result: 'saved', uuid: `rule-${ruleIndex}` };
    } else if (request.url === '/api/trafficshaper/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const gateway = {
    mode: 'opnsense-api',
    baseUrl: `http://127.0.0.1:${port}`,
    zoneId: 3,
    apiKey: 'key',
    apiSecret: 'secret',
    tlsRejectUnauthorized: true,
    shaperInterface: 'wan',
    shaperNetwork: '192.0.2.100 - 192.0.2.103',
    downloadSpeedMbps: 12,
    uploadSpeedMbps: 3
  };
  try {
    const result = await ensureGatewayBandwidthLimits(gateway, { force: true });
    assert.equal(result.applied, true);

    const pipeBodies = requests
      .filter(item => item.url === '/api/trafficshaper/settings/add_pipe')
      .map(item => item.body.pipe);
    assert.deepEqual(pipeBodies.map(item => ({
      bandwidth: item.bandwidth,
      metric: item.bandwidthMetric,
      mask: item.mask
    })), [
      { bandwidth: '12', metric: 'Mbit', mask: 'dst-ip' },
      { bandwidth: '3', metric: 'Mbit', mask: 'src-ip' }
    ]);

    const ruleBodies = requests
      .filter(item => item.url === '/api/trafficshaper/settings/add_rule')
      .map(item => item.body.rule);
    assert.deepEqual(ruleBodies.map(item => ({
      interface: item.interface,
      source: item.source,
      destination: item.destination,
      target: item.target
    })), [
      {
        interface: 'wan',
        source: 'any',
        destination: '192.0.2.100/30',
        target: 'pipe-1'
      },
      {
        interface: 'wan',
        source: '192.0.2.100/30',
        destination: 'any',
        target: 'pipe-2'
      }
    ]);
    assert.equal(
      requests.filter(item => item.url === '/api/trafficshaper/service/reconfigure').length,
      1
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter creates method bandwidth rules for active authorization IPs', async () => {
  const requests = [];
  let pipeIndex = 0;
  let ruleIndex = 0;
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    requests.push({
      method: request.method,
      url: request.url,
      body: body ? JSON.parse(body) : null
    });
    let payload = {};
    if (request.url === '/api/trafficshaper/settings/search_pipes') payload = { rows: [] };
    else if (request.url === '/api/trafficshaper/settings/search_rules') payload = { rows: [] };
    else if (request.url === '/api/trafficshaper/settings/add_pipe') {
      pipeIndex += 1;
      payload = { result: 'saved', uuid: `profile-pipe-${pipeIndex}` };
    } else if (request.url === '/api/trafficshaper/settings/add_rule') {
      ruleIndex += 1;
      payload = { result: 'saved', uuid: `profile-rule-${ruleIndex}` };
    } else if (request.url === '/api/trafficshaper/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await ensureGatewayBandwidthLimits({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 0,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan',
      bandwidthProfiles: {
        sms: { downloadSpeedMbps: 8, uploadSpeedMbps: 2 },
        email: { downloadSpeedMbps: 4, uploadSpeedMbps: 1 }
      }
    }, {
      force: true,
      authorizations: [
        { id: 'sms-auth', method: 'sms', client_ip: '172.16.2.44' },
        {
          id: 'email-auth',
          method: 'email',
          client_ip: '172.16.2.50',
          quota_blocked_until: Date.now() + 60000
        }
      ]
    });

    assert.equal(result.applied, true);
    assert.deepEqual(result.profiles.sms, ['172.16.2.44']);
    assert.deepEqual(result.profiles.email, []);
    assert.deepEqual(
      requests.filter(item => item.url === '/api/trafficshaper/settings/add_pipe').map(item => ({
        bandwidth: item.body.pipe.bandwidth,
        description: item.body.pipe.description,
        mask: item.body.pipe.mask
      })),
      [
        { bandwidth: '8', description: 'G-Hotspot managed sms download pipe', mask: 'dst-ip' },
        { bandwidth: '2', description: 'G-Hotspot managed sms upload pipe', mask: 'src-ip' }
      ]
    );
    assert.deepEqual(
      requests.filter(item => item.url === '/api/trafficshaper/settings/add_rule').map(item => ({
        source: item.body.rule.source,
        destination: item.body.rule.destination,
        description: item.body.rule.description
      })),
      [
        {
          source: 'any',
          destination: '172.16.2.44',
          description: 'G-Hotspot managed sms download rule'
        },
        {
          source: '172.16.2.44',
          destination: 'any',
          description: 'G-Hotspot managed sms upload rule'
        }
      ]
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter removes managed shaper objects when limits are disabled', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    requests.push(request.url);
    let payload = {};
    if (request.url === '/api/trafficshaper/settings/search_pipes') {
      payload = {
        rows: [
          {
            uuid: 'pipe-down',
            description: 'G-Hotspot managed download pipe',
            origin: 'GHotspot'
          },
          {
            uuid: 'pipe-up',
            description: 'G-Hotspot managed upload pipe',
            origin: 'GHotspot'
          }
        ]
      };
    } else if (request.url === '/api/trafficshaper/settings/search_rules') {
      payload = {
        rows: [
          {
            uuid: 'rule-down',
            description: 'G-Hotspot managed download rule',
            origin: 'GHotspot'
          },
          {
            uuid: 'rule-up',
            description: 'G-Hotspot managed upload rule',
            origin: 'GHotspot'
          }
        ]
      };
    } else if (request.url.startsWith('/api/trafficshaper/settings/del_')) {
      payload = { result: 'deleted' };
    } else if (request.url === '/api/trafficshaper/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    const result = await ensureGatewayBandwidthLimits({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 0,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan',
      shaperNetwork: 'any',
      downloadSpeedMbps: 0,
      uploadSpeedMbps: 0
    }, { force: true });
    assert.equal(result.applied, false);
    assert.deepEqual(requests.filter(url => url.includes('/del_')), [
      '/api/trafficshaper/settings/del_rule/rule-down',
      '/api/trafficshaper/settings/del_pipe/pipe-down',
      '/api/trafficshaper/settings/del_rule/rule-up',
      '/api/trafficshaper/settings/del_pipe/pipe-up'
    ]);
    assert.equal(
      requests.filter(url => url === '/api/trafficshaper/service/reconfigure').length,
      1
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense adapter reuses one managed pipe and removes duplicate pipes', async () => {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({
      url: request.url,
      body: Buffer.concat(chunks).toString('utf8')
    });
    let payload = {};
    if (request.url === '/api/trafficshaper/settings/search_pipes') {
      payload = {
        rows: [
          {
            uuid: 'pipe-1',
            number: '10000',
            description: 'G-Hotspot managed download pipe',
            origin: 'TrafficShaper'
          },
          {
            uuid: 'pipe-2',
            number: '10001',
            description: 'G-Hotspot managed download pipe',
            origin: 'TrafficShaper'
          },
          {
            uuid: 'pipe-3',
            number: '10002',
            description: 'G-Hotspot managed download pipe',
            origin: 'TrafficShaper'
          }
        ]
      };
    } else if (request.url === '/api/trafficshaper/settings/search_rules') {
      payload = { rows: [] };
    } else if (request.url === '/api/trafficshaper/settings/set_pipe/pipe-1') {
      payload = { result: 'saved' };
    } else if (request.url === '/api/trafficshaper/settings/add_rule') {
      payload = { result: 'saved', uuid: 'rule-1' };
    } else if (request.url.startsWith('/api/trafficshaper/settings/del_pipe/')) {
      payload = { result: 'deleted' };
    } else if (request.url === '/api/trafficshaper/service/reconfigure') {
      payload = { status: 'ok' };
    } else {
      response.writeHead(404);
      response.end();
      return;
    }
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    await ensureGatewayBandwidthLimits({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 0,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan',
      shaperNetwork: 'any',
      downloadSpeedMbps: 10,
      uploadSpeedMbps: 0
    }, { force: true });
    assert.equal(
      requests.filter(item => item.url === '/api/trafficshaper/settings/add_pipe').length,
      0
    );
    assert.equal(
      requests.filter(item => item.url === '/api/trafficshaper/settings/set_pipe/pipe-1').length,
      1
    );
    assert.deepEqual(
      requests.filter(item => item.url.includes('/del_pipe/')).map(item => item.url),
      [
        '/api/trafficshaper/settings/del_pipe/pipe-2',
        '/api/trafficshaper/settings/del_pipe/pipe-3'
      ]
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('OPNsense shaper permission errors name the required privilege', async () => {
  const server = http.createServer((request, response) => {
    response.writeHead(403, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ status: 403, message: 'Forbidden' }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    await assert.rejects(() => ensureGatewayBandwidthLimits({
      mode: 'opnsense-api',
      baseUrl: `http://127.0.0.1:${port}`,
      zoneId: 0,
      apiKey: 'key',
      apiSecret: 'secret',
      tlsRejectUnauthorized: true,
      shaperInterface: 'wan',
      shaperNetwork: 'any',
      downloadSpeedMbps: 10,
      uploadSpeedMbps: 2
    }, { force: true }), error => {
      assert.equal(error.code, 'opnsense_shaper_forbidden');
      assert.match(error.message, /Firewall: Shaper/u);
      return true;
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
