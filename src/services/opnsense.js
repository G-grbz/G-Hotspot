import http from 'node:http';
import https from 'node:https';
import { randomUUID } from 'node:crypto';
import { ipv4InNetworkList, normalizeNetworkList } from '../lib/network.js';
import { normalizeMac } from '../lib/security.js';
import { authorizationQuotaBlocked } from './quotas.js';

function requestApi(url, {
  username, password, rejectUnauthorized, method = 'GET', form = null, json = null, timeout = 15000,
  providerName = 'Gateway'
}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const body = json != null
      ? JSON.stringify(json)
      : (form ? new URLSearchParams(form).toString() : '');
    const transport = target.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method,
      auth: `${username}:${password}`,
      rejectUnauthorized,
      timeout,
      headers: {
        ...(form ? {
          'content-type': 'application/x-www-form-urlencoded',
          'content-length': Buffer.byteLength(body)
        } : {}),
        ...(json != null ? {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body)
        } : {}),
        accept: 'application/json'
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = text;
        try { parsed = text ? JSON.parse(text) : {}; } catch {}
        if ((response.statusCode || 500) >= 400) {
          const error = new Error(
            `${providerName} API returned HTTP ${response.statusCode}: ${text.slice(0, 500)}`
          );
          error.statusCode = response.statusCode;
          error.response = parsed;
          reject(error);
          return;
        }
        resolve(parsed);
      });
    });
    request.on('timeout', () => request.destroy(new Error(`${providerName} API request timed out`)));
    request.on('error', reject);
    request.end(body);
  });
}

const SHAPER_ORIGIN = 'GHotspot';
const SHAPER_DESCRIPTIONS = {
  downloadPipe: 'G-Hotspot managed download pipe',
  uploadPipe: 'G-Hotspot managed upload pipe',
  downloadRule: 'G-Hotspot managed download rule',
  uploadRule: 'G-Hotspot managed upload rule'
};
const SHAPER_PROFILE_METHODS = ['voucher', 'admin-approval', 'nvi', 'email', 'whatsapp', 'telegram', 'sms'];
const KEA_RESERVATION_DESCRIPTION_PREFIX = 'G-Hotspot access ';
const KEA_LEASE_OPTION_DESCRIPTION_PREFIX = 'G-Hotspot DHCP lease ';
const DHCP_LEASE_TIME_OPTION_CODE = '51';
const DHCP_UINT32_MAX_SECONDS = 4294967295;
const MIN_DHCP_LEASE_SECONDS = 60;
const CLIENT_OWNERSHIP_CACHE_TTL_MS = 5000;
let appliedBandwidthKey = '';
const clientOwnershipCache = new Map();

function gatewayProviderName(gateway = {}) {
  return gateway.mode === 'pfsense-api' ? 'pfSense' : 'OPNsense';
}

function gatewayIsPfsense(gateway = {}) {
  return gateway.mode === 'pfsense-api';
}

function gatewayIsOpnsense(gateway = {}) {
  return gateway.mode === 'opnsense-api';
}

function defaultZoneId(gateway) {
  return Number(gateway.zoneId || 0);
}

export function resolveGatewayZoneId(gateway, clientIp = '') {
  for (const entry of gateway.zoneMap || []) {
    if (clientIp && ipv4InNetworkList(clientIp, entry.network)) return Number(entry.zoneId);
  }
  return defaultZoneId(gateway);
}

function gatewayZoneIds(gateway) {
  return [...new Set([
    defaultZoneId(gateway),
    ...(gateway.zoneMap || []).map(entry => Number(entry.zoneId))
  ])];
}

function storedGatewaySessionId(gateway, sessionId, zoneId) {
  if (!sessionId) return null;
  const resolvedZoneId = Number(zoneId);
  if ((gateway.zoneMap || []).length || resolvedZoneId !== defaultZoneId(gateway)) {
    return `${resolvedZoneId}:${sessionId}`;
  }
  return sessionId;
}

function splitGatewaySessionId(gateway, value) {
  const text = String(value || '');
  const match = text.match(/^(\d{1,2}):(.+)$/u);
  if (match) return { zoneId: Number(match[1]), sessionId: match[2] };
  return { zoneId: defaultZoneId(gateway), sessionId: text };
}

async function gatewayRequest(gateway, endpoint, options = {}) {
  try {
    return await requestApi(`${gateway.baseUrl}${endpoint}`, {
      username: gateway.apiKey,
      password: gateway.apiSecret,
      rejectUnauthorized: gateway.tlsRejectUnauthorized,
      providerName: gatewayProviderName(gateway),
      ...options
    });
  } catch (error) {
    if (error.statusCode === 403 && endpoint.startsWith('/api/trafficshaper/')) {
      const forbidden = new Error(
        'OPNsense API user is missing the "Firewall: Shaper" privilege.'
      );
      forbidden.code = 'opnsense_shaper_forbidden';
      forbidden.statusCode = 403;
      throw forbidden;
    }
    throw error;
  }
}

function responseRows(response) {
  if (Array.isArray(response)) return response;
  if (Array.isArray(response?.rows)) return response.rows;
  if (Array.isArray(response?.items)) return response.items;
  if (Array.isArray(response?.data)) return response.data;
  if (Array.isArray(response?.data?.rows)) return response.data.rows;
  if (Array.isArray(response?.data?.items)) return response.data.items;
  return [];
}

function numericField(row, names) {
  for (const name of names) {
    const value = row?.[name];
    if (value == null || value === '') continue;
    const number = Number(String(value).replace(/[^\d.-]/gu, ''));
    if (Number.isFinite(number)) return Math.max(0, Math.trunc(number));
  }
  return null;
}

function textField(row, names) {
  for (const name of names) {
    const value = row?.[name];
    if (value != null && String(value).trim()) return String(value).trim();
  }
  return '';
}

function normalizedInterfaceName(value) {
  return String(value || '').trim().toLowerCase();
}

function interfaceNameAliases(value) {
  const text = String(value || '').trim();
  if (!text) return [];
  return [
    text,
    ...[...text.matchAll(/\[([^\]]+)\]|\(([^)]+)\)/gu)]
      .map(match => match[1] || match[2])
  ].map(normalizedInterfaceName).filter(Boolean);
}

function interfaceNameMatches(row, interfaceName) {
  const wanted = normalizedInterfaceName(interfaceName);
  if (!wanted) return true;
  return [
    row.name,
    row.if,
    row.interface,
    row.identifier,
    row.device,
    row.descr,
    row.description
  ].some(value => interfaceNameAliases(value).includes(wanted));
}

function trafficCounterCandidate(row, interfaceName) {
  if (!row || typeof row !== 'object' || !interfaceNameMatches(row, interfaceName)) return null;
  const rxBytes = numericField(row, [
    'rxBytes', 'rx_bytes', 'bytesIn', 'bytes_in', 'inBytes', 'inbytes',
    'inputBytes', 'input_bytes', 'receivedBytes', 'received_bytes',
    'received-bytes', 'ifInOctets', 'if_in_octets', 'ibytes'
  ]);
  const txBytes = numericField(row, [
    'txBytes', 'tx_bytes', 'bytesOut', 'bytes_out', 'outBytes', 'outbytes',
    'outputBytes', 'output_bytes', 'transmittedBytes', 'transmitted_bytes',
    'sentBytes', 'sent_bytes', 'sent-bytes', 'ifOutOctets', 'if_out_octets', 'obytes'
  ]);
  if (rxBytes == null || txBytes == null) return null;
  return {
    interfaceName: String(row.name || row.if || row.interface || row.identifier || interfaceName || ''),
    rxBytes,
    txBytes
  };
}

function collectTrafficCounterCandidates(value, interfaceName, output = []) {
  if (!value || typeof value !== 'object') return output;
  if (Array.isArray(value)) {
    for (const item of value) collectTrafficCounterCandidates(item, interfaceName, output);
    return output;
  }
  const direct = trafficCounterCandidate(value, interfaceName);
  if (direct) output.push(direct);
  for (const [key, item] of Object.entries(value)) {
    if (item && typeof item === 'object') {
      const nested = typeof item === 'object' && !Array.isArray(item)
        ? { name: item.name || key, identifier: item.identifier || key, ...item }
        : item;
      collectTrafficCounterCandidates(nested, interfaceName, output);
    }
  }
  return output;
}

function firstIpv4(value) {
  const match = String(value || '').match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/u);
  return match ? match[0] : '';
}

function firstMac(value) {
  const match = String(value || '').match(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/iu) ||
    String(value || '').match(/\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b/iu);
  return match ? match[0].replaceAll('-', ':').toUpperCase() : '';
}

function managedRows(rows, description) {
  return rows
    .filter(row => String(row.description || '') === description)
    .sort((left, right) =>
      Number(left.number || left.sequence || 0) - Number(right.number || right.sequence || 0)
    );
}

function shaperProfileDescriptions(method) {
  return {
    downloadPipe: `G-Hotspot managed ${method} download pipe`,
    uploadPipe: `G-Hotspot managed ${method} upload pipe`,
    downloadRule: `G-Hotspot managed ${method} download rule`,
    uploadRule: `G-Hotspot managed ${method} upload rule`
  };
}

function validShaperIp(value) {
  try {
    ipv4InNetworkList(value, value);
    return true;
  } catch {
    return false;
  }
}

function activeProfileIps(authorizations = [], now = Date.now()) {
  const groups = new Map(SHAPER_PROFILE_METHODS.map(method => [method, new Set()]));
  for (const authorization of authorizations || []) {
    const method = authorization?.method;
    if (!groups.has(method)) continue;
    if (authorizationQuotaBlocked(authorization, now)) continue;
    const clientIp = String(authorization.client_ip || authorization.clientIp || '').trim();
    if (!validShaperIp(clientIp)) continue;
    groups.get(method).add(clientIp);
  }
  return Object.fromEntries([...groups].map(([method, ips]) => [method, [...ips].sort()]));
}

function mutationError(response) {
  const validations = response?.validations || response?.validation || {};
  const detail = Object.values(validations).flat().filter(Boolean).join('; ');
  return detail || response?.message || response?.status || response?.result || 'unknown error';
}

function assertMutation(response, action) {
  if (response?.result === 'failed' || response?.status === 'failed') {
    throw new Error(`OPNsense Traffic Shaper ${action} failed: ${mutationError(response)}`);
  }
  return response;
}

function assertKeaMutation(response, action) {
  if (response?.result === 'failed' || response?.status === 'failed') {
    throw new Error(`OPNsense Kea DHCP ${action} failed: ${mutationError(response)}`);
  }
  return response;
}

async function addOrUpdate(gateway, kind, existing, payload) {
  const endpoint = existing
    ? `/api/trafficshaper/settings/set_${kind}/${encodeURIComponent(existing.uuid)}`
    : `/api/trafficshaper/settings/add_${kind}`;
  const response = assertMutation(await gatewayRequest(gateway, endpoint, {
    method: 'POST',
    json: { [kind]: payload }
  }), `${existing ? 'update' : 'create'} ${kind}`);
  return existing?.uuid || response?.uuid || '';
}

async function deleteManaged(gateway, kind, existing) {
  if (!existing?.uuid) return false;
  assertMutation(await gatewayRequest(
    gateway,
    `/api/trafficshaper/settings/del_${kind}/${encodeURIComponent(existing.uuid)}`,
    { method: 'POST' }
  ), `delete ${kind}`);
  return true;
}

async function findCreatedUuid(gateway, kind, description) {
  const response = await gatewayRequest(gateway, `/api/trafficshaper/settings/search_${kind}s`);
  return managedRows(responseRows(response), description)[0]?.uuid || '';
}

async function ensureBandwidthDirection(gateway, {
  limitMbps, pipeDescription, ruleDescription, mask, source, destination, sequence,
  pipes, rules
}) {
  const matchingPipes = managedRows(pipes, pipeDescription);
  const matchingRules = managedRows(rules, ruleDescription);
  const existingPipe = matchingPipes[0] || null;
  const existingRule = matchingRules[0] || null;
  const extraPipes = matchingPipes.slice(1);
  const extraRules = matchingRules.slice(1);
  if (limitMbps <= 0) {
    let changed = false;
    for (const rule of matchingRules) {
      changed = await deleteManaged(gateway, 'rule', rule) || changed;
    }
    for (const pipe of matchingPipes) {
      changed = await deleteManaged(gateway, 'pipe', pipe) || changed;
    }
    return changed;
  }

  let pipeUuid = await addOrUpdate(gateway, 'pipe', existingPipe, {
    enabled: '1',
    bandwidth: String(limitMbps),
    bandwidthMetric: 'Mbit',
    mask,
    description: pipeDescription,
    origin: SHAPER_ORIGIN
  });
  if (!pipeUuid) pipeUuid = await findCreatedUuid(gateway, 'pipe', pipeDescription);
  if (!pipeUuid) throw new Error(`OPNsense Traffic Shaper did not return the UUID for ${pipeDescription}`);

  await addOrUpdate(gateway, 'rule', existingRule, {
    enabled: '1',
    sequence: String(existingRule?.sequence || sequence),
    interface: gateway.shaperInterface,
    proto: 'ip',
    source,
    source_not: '0',
    src_port: 'any',
    destination,
    destination_not: '0',
    dst_port: 'any',
    direction: '',
    target: pipeUuid,
    description: ruleDescription,
    origin: SHAPER_ORIGIN
  });
  for (const rule of extraRules) await deleteManaged(gateway, 'rule', rule);
  for (const pipe of extraPipes) await deleteManaged(gateway, 'pipe', pipe);
  return true;
}

async function deleteBandwidthDescriptions(gateway, { pipes, rules, descriptions }) {
  let changed = false;
  for (const description of [descriptions.downloadRule, descriptions.uploadRule]) {
    for (const rule of managedRows(rules, description)) {
      changed = await deleteManaged(gateway, 'rule', rule) || changed;
    }
  }
  for (const description of [descriptions.downloadPipe, descriptions.uploadPipe]) {
    for (const pipe of managedRows(pipes, description)) {
      changed = await deleteManaged(gateway, 'pipe', pipe) || changed;
    }
  }
  return changed;
}

function profileBandwidthKey(gateway, authorizations = []) {
  const profiles = Object.entries(gateway.bandwidthProfiles || {})
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([method, profile]) => [
      method,
      Number(profile.downloadSpeedMbps || 0),
      Number(profile.uploadSpeedMbps || 0)
    ]);
  const rows = (authorizations || [])
    .map(row => [
      row?.id || '',
      row?.method || '',
      row?.client_ip || row?.clientIp || '',
      Number(row?.quota_blocked_until || 0)
    ])
    .sort((left, right) => left.join('|').localeCompare(right.join('|')));
  return JSON.stringify({
    baseUrl: gateway.baseUrl,
    zoneId: gateway.zoneId,
    shaperInterface: gateway.shaperInterface,
    profiles,
    rows
  });
}

async function ensureGatewayBandwidthProfiles(gateway, authorizations, { force = false } = {}) {
  const bandwidthKey = profileBandwidthKey(gateway, authorizations);
  if (!force && appliedBandwidthKey === bandwidthKey) return { applied: true, cached: true };
  const profileValues = Object.values(gateway.bandwidthProfiles || {});
  const configured = profileValues.some(profile =>
    Number(profile.downloadSpeedMbps || 0) || Number(profile.uploadSpeedMbps || 0)
  );
  if (!force && !configured) return { applied: false, disabled: true };

  const [pipeResponse, ruleResponse] = await Promise.all([
    gatewayRequest(gateway, '/api/trafficshaper/settings/search_pipes'),
    gatewayRequest(gateway, '/api/trafficshaper/settings/search_rules')
  ]);
  const pipes = responseRows(pipeResponse);
  const rules = responseRows(ruleResponse);
  const ipsByMethod = activeProfileIps(authorizations);
  let changed = await deleteBandwidthDescriptions(gateway, {
    pipes,
    rules,
    descriptions: SHAPER_DESCRIPTIONS
  });
  let applied = false;
  for (const [index, method] of SHAPER_PROFILE_METHODS.entries()) {
    const profile = gateway.bandwidthProfiles?.[method] || {};
    const descriptions = shaperProfileDescriptions(method);
    const ips = ipsByMethod[method] || [];
    const shaperNetwork = ips.length ? normalizeNetworkList(ips.join(',')) : '';
    const downloadSpeedMbps = ips.length ? Number(profile.downloadSpeedMbps || 0) : 0;
    const uploadSpeedMbps = ips.length ? Number(profile.uploadSpeedMbps || 0) : 0;
    applied = applied || Boolean(downloadSpeedMbps || uploadSpeedMbps);
    const sequence = 20 + index * 4;
    changed = await ensureBandwidthDirection(gateway, {
      limitMbps: downloadSpeedMbps,
      pipeDescription: descriptions.downloadPipe,
      ruleDescription: descriptions.downloadRule,
      mask: 'dst-ip',
      source: 'any',
      destination: shaperNetwork || 'any',
      sequence,
      pipes,
      rules
    }) || changed;
    changed = await ensureBandwidthDirection(gateway, {
      limitMbps: uploadSpeedMbps,
      pipeDescription: descriptions.uploadPipe,
      ruleDescription: descriptions.uploadRule,
      mask: 'src-ip',
      source: shaperNetwork || 'any',
      destination: 'any',
      sequence: sequence + 1,
      pipes,
      rules
    }) || changed;
  }
  if (changed) {
    await gatewayRequest(gateway, '/api/trafficshaper/service/reconfigure', { method: 'POST' });
  }
  appliedBandwidthKey = bandwidthKey;
  return { applied, profiles: ipsByMethod };
}

export async function ensureGatewayBandwidthLimits(gateway, { force = false, authorizations = null } = {}) {
  if (gateway.mode === 'mock') {
    return {
      applied: false,
      downloadSpeedMbps: gateway.downloadSpeedMbps || 0,
      uploadSpeedMbps: gateway.uploadSpeedMbps || 0
    };
  }
  if (gatewayIsPfsense(gateway)) {
    return { applied: false, skipped: true, reason: 'gateway_not_opnsense' };
  }
  if (gateway.bandwidthProfiles && Array.isArray(authorizations)) {
    return ensureGatewayBandwidthProfiles(gateway, authorizations, { force });
  }
  const bandwidthKey = [
    gateway.baseUrl,
    gateway.zoneId,
    gateway.shaperInterface,
    gateway.shaperNetwork,
    gateway.downloadSpeedMbps,
    gateway.uploadSpeedMbps
  ].join('|');
  if (!force && appliedBandwidthKey === bandwidthKey) return { applied: true, cached: true };
  if (!force && !gateway.downloadSpeedMbps && !gateway.uploadSpeedMbps) {
    return { applied: false, disabled: true };
  }

  const [pipeResponse, ruleResponse] = await Promise.all([
    gatewayRequest(gateway, '/api/trafficshaper/settings/search_pipes'),
    gatewayRequest(gateway, '/api/trafficshaper/settings/search_rules')
  ]);
  const pipes = responseRows(pipeResponse);
  const rules = responseRows(ruleResponse);
  const shaperNetwork = normalizeNetworkList(gateway.shaperNetwork);
  const changedDownload = await ensureBandwidthDirection(gateway, {
    limitMbps: gateway.downloadSpeedMbps,
    pipeDescription: SHAPER_DESCRIPTIONS.downloadPipe,
    ruleDescription: SHAPER_DESCRIPTIONS.downloadRule,
    mask: 'dst-ip',
    source: 'any',
    destination: shaperNetwork,
    sequence: 10,
    pipes,
    rules
  });
  const changedUpload = await ensureBandwidthDirection(gateway, {
    limitMbps: gateway.uploadSpeedMbps,
    pipeDescription: SHAPER_DESCRIPTIONS.uploadPipe,
    ruleDescription: SHAPER_DESCRIPTIONS.uploadRule,
    mask: 'src-ip',
    source: shaperNetwork,
    destination: 'any',
    sequence: 11,
    pipes,
    rules
  });
  if (changedDownload || changedUpload) {
    await gatewayRequest(gateway, '/api/trafficshaper/service/reconfigure', { method: 'POST' });
  }
  appliedBandwidthKey = bandwidthKey;
  return {
    applied: Boolean(gateway.downloadSpeedMbps || gateway.uploadSpeedMbps),
    downloadSpeedMbps: gateway.downloadSpeedMbps,
    uploadSpeedMbps: gateway.uploadSpeedMbps
  };
}

export async function authorizeGateway(gateway, { user, clientIp }) {
  const zoneId = resolveGatewayZoneId(gateway, clientIp);
  if (gateway.mode === 'mock') {
    const sessionId = `mock-${randomUUID()}`;
    return {
      sessionId,
      storedSessionId: storedGatewaySessionId(gateway, sessionId, zoneId),
      clientMac: '',
      zoneId,
      response: {
        status: 'mock-authorized',
        user,
        ipAddress: clientIp,
        gHotspotZoneId: zoneId,
        downloadSpeedMbps: gateway.downloadSpeedMbps || 0,
        uploadSpeedMbps: gateway.uploadSpeedMbps || 0
      }
    };
  }
  if (gatewayIsPfsense(gateway)) {
    const sessionId = `pfsense-browser-login-${randomUUID()}`;
    const gatewayLogin = pfsenseGatewayLogin(gateway, { user, clientIp, zoneId });
    return {
      sessionId,
      storedSessionId: storedGatewaySessionId(gateway, sessionId, zoneId),
      clientMac: '',
      zoneId,
      gatewayLogin,
      response: {
        status: 'pfsense-browser-login-required',
        user,
        ipAddress: clientIp,
        gHotspotZoneId: zoneId,
        gatewayLogin
      }
    };
  }

  const endpoint = `${gateway.baseUrl}/api/captiveportal/session/connect/${zoneId}`;
  const response = await requestApi(endpoint, {
    username: gateway.apiKey,
    password: gateway.apiSecret,
    rejectUnauthorized: gateway.tlsRejectUnauthorized,
    providerName: gatewayProviderName(gateway),
    method: 'POST',
    form: { user, ip: clientIp }
  });

  if (!response || (typeof response === 'object' && Object.keys(response).length === 0)) {
    throw new Error('OPNsense returned an empty captive portal session response');
  }

  const sessionId = response.sessionId || response.session_id || response.id || null;
  const clientMac = response.macAddress || response.mac_address || response.mac || '';
  return {
    sessionId,
    storedSessionId: storedGatewaySessionId(gateway, sessionId, zoneId),
    clientMac,
    zoneId,
    response: { ...response, gHotspotZoneId: zoneId }
  };
}

function pfsenseGatewayLogin(gateway, { user, clientIp, zoneId }) {
  const action = pfsenseCaptivePortalUrl(gateway, zoneId);
  return {
    provider: 'pfSense',
    method: 'POST',
    action,
    fields: {
      auth_user: gateway.portalUsername || gateway.apiKey || user,
      auth_pass: gateway.portalPassword || gateway.apiSecret || '',
      zone: String(zoneId),
      redirurl: '',
      accept: 'Continue',
      user,
      ip: clientIp,
      clientip: clientIp
    }
  };
}

function pfsenseCaptivePortalUrl(gateway, zoneId) {
  const raw = String(gateway.captivePortalUrl || gateway.portalUrl || gateway.baseUrl || '').trim();
  const target = new URL(raw || 'http://127.0.0.1/');
  if (!target.pathname || target.pathname === '/') target.pathname = '/index.php';
  if (!target.searchParams.has('zone')) target.searchParams.set('zone', String(zoneId));
  return target.toString();
}

async function listGatewaySessionsForZone(gateway, zoneId, annotateZone) {
  const endpoint = `${gateway.baseUrl}/api/captiveportal/session/list/${zoneId}`;
  const response = await requestApi(endpoint, {
    username: gateway.apiKey,
    password: gateway.apiSecret,
    rejectUnauthorized: gateway.tlsRejectUnauthorized,
    providerName: gatewayProviderName(gateway)
  });
  const rows = Array.isArray(response)
    ? response
    : (Array.isArray(response?.rows) && response.rows) ||
      (Array.isArray(response?.items) && response.items) ||
      (Array.isArray(response?.sessions) && response.sessions) ||
      (Array.isArray(response?.data) && response.data) ||
      [];
  return annotateZone ? rows.map(row => ({ ...row, gHotspotZoneId: zoneId })) : rows;
}

export async function listGatewaySessions(gateway) {
  if (gateway.mode === 'mock') return [];
  if (gatewayIsPfsense(gateway)) return [];
  const zoneIds = gatewayZoneIds(gateway);
  const annotateZone = (gateway.zoneMap || []).length || zoneIds.length > 1;
  const results = await Promise.all(
    zoneIds.map(zoneId => listGatewaySessionsForZone(gateway, zoneId, annotateZone))
  );
  return results.flat();
}

export async function listGatewayArpEntries(gateway) {
  if (gateway.mode === 'mock') return [];
  const endpoints = gatewayIsPfsense(gateway)
    ? ['/api/v2/diagnostics/arp_table']
    : ['/api/diagnostics/interface/get_arp'];
  const response = await firstGatewayResponse(gateway, endpoints);
  return responseRows(response).map(row => ({
    clientIp: firstIpv4(textField(row, [
      'ipAddress', 'ip_address', 'ip-address', 'ip', 'address', 'host', 'hostname'
    ]) || JSON.stringify(row)),
    clientMac: firstMac(textField(row, [
      'macAddress', 'mac_address', 'mac-address', 'mac', 'lladdr', 'ether', 'linkAddress'
    ]) || JSON.stringify(row)),
    interface: textField(row, ['intf', 'interface', 'if', 'intf_description']),
    raw: row
  })).filter(row => row.clientIp && row.clientMac);
}

async function firstGatewayResponse(gateway, endpoints, options = {}) {
  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      return await gatewayRequest(gateway, endpoint, options[endpoint] || {});
    } catch (error) {
      lastError = error;
      if (![403, 404, 405].includes(Number(error.statusCode || 0))) throw error;
    }
  }
  if (lastError) throw lastError;
  return [];
}

function leaseRow(row, source = 'opnsense-dhcpv4') {
  return {
    clientIp: firstIpv4(textField(row, [
      'ipAddress', 'ip_address', 'ip-address', 'address', 'ip', 'leaseAddress', 'lease_address'
    ]) || JSON.stringify(row)),
    clientMac: firstMac(textField(row, [
      'macAddress', 'mac_address', 'mac-address', 'mac', 'hwaddr', 'hwAddress',
      'hardwareAddress', 'hardware_address', 'chaddr', 'clientMac'
    ]) || JSON.stringify(row)),
    deviceName: textField(row, ['hostname', 'hostName', 'clientHostname', 'name', 'descr', 'description']),
    interface: textField(row, ['interface', 'if', 'ifDescr', 'if_descr']),
    state: textField(row, ['state', 'status', 'binding_state', 'active_status', 'online_status', 'act', 'online']),
    source,
    raw: row
  };
}

export async function listGatewayDhcpLeases(gateway) {
  if (gateway.mode === 'mock') return [];
  const source = gatewayIsPfsense(gateway) ? 'pfsense-dhcpv4' : 'opnsense-dhcpv4';
  const candidates = gatewayIsPfsense(gateway)
    ? [{ endpoint: '/api/v2/status/dhcp_server/leases' }]
    : [
        { endpoint: '/api/kea/leases4/search', options: { method: 'POST', json: {} } },
        { endpoint: '/api/kea/leases/search', options: { method: 'POST', json: {} } },
        { endpoint: '/api/dhcpv4/leases/searchLease' },
        { endpoint: '/api/dhcpv4/leases/search' },
        { endpoint: '/api/kea/dhcpv4/searchLease' }
      ];
  let lastError = null;
  for (const candidate of candidates) {
    try {
      const response = await gatewayRequest(gateway, candidate.endpoint, candidate.options || {});
      const rows = responseRows(response).map(row => leaseRow(row, source))
        .filter(row => row.clientIp && row.clientMac);
      if (rows.length || responseRows(response).length) return rows;
    } catch (error) {
      lastError = error;
      if (![403, 404, 405].includes(Number(error.statusCode || 0))) throw error;
    }
  }
  if (lastError && ![403, 404, 405].includes(Number(lastError.statusCode || 0))) throw lastError;
  return [];
}

function clientOwnership(rows) {
  const ipToMac = new Map();
  for (const row of rows) {
    const clientIp = String(row?.clientIp || '').trim();
    const clientMac = normalizeMac(row?.clientMac);
    if (!clientIp || !clientMac) continue;
    ipToMac.set(clientIp, clientMac);
  }
  return { rows, ipToMac };
}

function clientOwnershipCacheKey(gateway) {
  return [
    gateway.mode,
    gateway.baseUrl,
    gateway.zoneId,
    JSON.stringify(gateway.zoneMap || [])
  ].join('|');
}

export async function listGatewayClientOwnership(gateway, {
  cacheTtlMs = CLIENT_OWNERSHIP_CACHE_TTL_MS,
  context = 'resolving client ownership'
} = {}) {
  if (gateway.mode === 'mock') return clientOwnership([]);
  const key = clientOwnershipCacheKey(gateway);
  const now = Date.now();
  const ttl = Math.max(0, Number(cacheTtlMs) || 0);
  const cached = clientOwnershipCache.get(key);
  if (cached?.value && cached.expiresAt > now) return cached.value;
  if (cached?.promise) return cached.promise;

  const promise = (async () => {
    const [arpResult, dhcpResult] = await Promise.allSettled([
      listGatewayArpEntries(gateway),
      listGatewayDhcpLeases(gateway)
    ]);
    if (arpResult.status === 'rejected') {
      console.warn(`${gatewayProviderName(gateway)} ARP lookup failed while ${context}: ${arpResult.reason.message}`);
    }
    if (dhcpResult.status === 'rejected') {
      console.warn(`${gatewayProviderName(gateway)} DHCP lease lookup failed while ${context}: ${dhcpResult.reason.message}`);
    }
    const value = clientOwnership([
      ...(arpResult.status === 'fulfilled' ? arpResult.value : []),
      ...(dhcpResult.status === 'fulfilled' ? dhcpResult.value : [])
    ]);
    clientOwnershipCache.set(key, {
      value,
      expiresAt: Date.now() + ttl
    });
    return value;
  })();

  clientOwnershipCache.set(key, {
    promise,
    expiresAt: now + ttl
  });
  try {
    return await promise;
  } catch (error) {
    clientOwnershipCache.delete(key);
    throw error;
  }
}

function rowUuid(row) {
  return String(row?.uuid || row?.id || row?.__uuid || row?.['@uuid'] || '').trim();
}

function relationValue(value) {
  if (value == null) return '';
  if (Array.isArray(value)) return value.map(relationValue).filter(Boolean);
  if (typeof value === 'object') {
    return String(
      value.value || value.uuid || value.id || value.selected || value.display || value.label || ''
    ).trim();
  }
  return String(value).trim();
}

function relationValues(value) {
  const resolved = relationValue(value);
  if (Array.isArray(resolved)) return resolved;
  return resolved ? resolved.split(',').map(item => item.trim()).filter(Boolean) : [];
}

function keaRows(response) {
  return responseRows(response).filter(row => row && typeof row === 'object');
}

function keaReservationDescription(authorizationId) {
  return `${KEA_RESERVATION_DESCRIPTION_PREFIX}${authorizationId}`;
}

function keaLeaseOptionDescription(seconds) {
  return `${KEA_LEASE_OPTION_DESCRIPTION_PREFIX}${seconds}s`;
}

function dhcpLeaseSeconds(expiresAt, now = Date.now()) {
  const target = Number(expiresAt);
  if (!Number.isFinite(target)) return 0;
  const seconds = Math.ceil((target - now) / 1000);
  return normalizeDhcpLeaseSeconds(seconds);
}

function normalizeDhcpLeaseSeconds(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds)) return 0;
  if (seconds <= 0) return 0;
  return Math.min(DHCP_UINT32_MAX_SECONDS, Math.max(MIN_DHCP_LEASE_SECONDS, seconds));
}

function reservationIp(row) {
  return firstIpv4(textField(row, ['ip_address', 'ipAddress', 'ip-address', 'address', 'ip']));
}

function reservationMac(row) {
  return normalizeMac(textField(row, [
    'hw_address', 'hwAddress', 'hw-address', 'macAddress', 'mac_address', 'mac', 'clientMac'
  ]));
}

function reservationDescription(row) {
  return textField(row, ['description', 'descr']);
}

function reservationHostname(row) {
  return textField(row, ['hostname', 'hostName', 'host_name']);
}

function reservationSubnetValues(row) {
  return relationValues(row?.subnet || row?.subnet_id || row?.subnetId);
}

function reservationOptionValues(row) {
  return relationValues(row?.option || row?.options || row?.option_data || row?.optionData);
}

function isManagedKeaReservation(row) {
  return reservationDescription(row).startsWith(KEA_RESERVATION_DESCRIPTION_PREFIX);
}

function matchesManagedReservation(row, { authorizationId = '', clientIp = '', clientMac = '', subnetUuid = '' }) {
  const description = reservationDescription(row);
  if (authorizationId && description === keaReservationDescription(authorizationId)) return true;
  if (!isManagedKeaReservation(row)) return false;
  const rowIp = reservationIp(row);
  const rowMac = reservationMac(row);
  const subnetValues = reservationSubnetValues(row);
  const sameSubnet = !subnetUuid || !subnetValues.length || subnetValues.includes(subnetUuid);
  return sameSubnet && (
    Boolean(clientIp && rowIp === clientIp) ||
    Boolean(clientMac && rowMac && rowMac === clientMac)
  );
}

async function searchKeaSubnets(gateway) {
  const response = await gatewayRequest(gateway, '/api/kea/dhcpv4/searchSubnet', {
    method: 'POST',
    json: {}
  });
  return keaRows(response);
}

async function searchKeaOptions(gateway) {
  const response = await gatewayRequest(gateway, '/api/kea/dhcpv4/searchOption', {
    method: 'POST',
    json: {}
  });
  return keaRows(response);
}

async function searchKeaReservations(gateway) {
  const response = await gatewayRequest(gateway, '/api/kea/dhcpv4/searchReservation', {
    method: 'POST',
    json: {}
  });
  return keaRows(response);
}

async function reconfigureKea(gateway) {
  assertKeaMutation(await gatewayRequest(gateway, '/api/kea/service/reconfigure', {
    method: 'POST'
  }), 'reconfigure');
}

async function findKeaSubnetForIp(gateway, clientIp) {
  const subnets = await searchKeaSubnets(gateway);
  for (const row of subnets) {
    const uuid = rowUuid(row);
    if (!uuid) continue;
    const networks = [...collectNetworkStrings(row?.subnet ?? row?.network ?? row?.cidr ?? row)];
    for (const network of networks) {
      if (ipv4InNetworkList(clientIp, normalizeNetworkList(network))) {
        return { uuid, network, row };
      }
    }
  }
  return null;
}

function keaOptionCode(row) {
  return textField(row, ['code', 'option_code', 'optionCode']);
}

function keaOptionData(row) {
  return textField(row, ['data', 'value', 'option_data', 'optionData']);
}

function hostnameSlug(value) {
  return String(value || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/gu, '-')
    .replace(/^-+|-+$/gu, '');
}

function keaReservationHostname({ method = '', identity = '', authorizationId = '' }) {
  const slug = hostnameSlug([method, identity].filter(Boolean).join('-')) ||
    hostnameSlug(authorizationId) ||
    'user';
  const hostname = `gh-${slug}`.slice(0, 63).replace(/-+$/gu, '');
  return hostname || 'gh-user';
}

async function ensureKeaLeaseOption(gateway, seconds) {
  const description = keaLeaseOptionDescription(seconds);
  const options = await searchKeaOptions(gateway);
  const existing = options.find(row => reservationDescription(row) === description) ||
    options.find(row =>
      keaOptionCode(row) === DHCP_LEASE_TIME_OPTION_CODE &&
      keaOptionData(row) === String(seconds)
    );
  if (existing) {
    const uuid = rowUuid(existing);
    if (uuid) return uuid;
  }

  const response = assertKeaMutation(await gatewayRequest(gateway, '/api/kea/dhcpv4/addOption', {
    method: 'POST',
    json: {
      option: {
        code: DHCP_LEASE_TIME_OPTION_CODE,
        encoding: 'uint32',
        data: String(seconds),
        force: '1',
        description
      }
    }
  }), 'create lease option');
  const createdUuid = response?.uuid || response?.id || response?.option?.uuid || '';
  if (createdUuid) return String(createdUuid);

  const refreshed = await searchKeaOptions(gateway);
  const created = refreshed.find(row => reservationDescription(row) === description);
  const uuid = rowUuid(created);
  if (!uuid) throw new Error(`OPNsense Kea DHCP did not return the UUID for ${description}`);
  return uuid;
}

function keaReservationPayload({
  authorizationId, clientIp, clientMac, subnetUuid, optionUuid, method, identity
}) {
  return {
    subnet: subnetUuid,
    ip_address: clientIp,
    hw_address: clientMac,
    hostname: keaReservationHostname({ method, identity, authorizationId }),
    description: keaReservationDescription(authorizationId),
    option: optionUuid
  };
}

function sameKeaReservation(row, payload) {
  const subnetValues = reservationSubnetValues(row);
  const optionValues = reservationOptionValues(row);
  return reservationIp(row) === payload.ip_address &&
    reservationMac(row) === payload.hw_address &&
    (!subnetValues.length || subnetValues.includes(payload.subnet)) &&
    optionValues.includes(payload.option) &&
    reservationHostname(row) === payload.hostname &&
    reservationDescription(row) === payload.description;
}

async function ensureKeaReservation(gateway, payload) {
  const rows = await searchKeaReservations(gateway);
  const unmanagedConflict = rows.find(row =>
    !isManagedKeaReservation(row) &&
    reservationIp(row) === payload.ip_address &&
    reservationMac(row) === payload.hw_address
  );
  if (unmanagedConflict) {
    return {
      changed: false,
      skipped: true,
      reason: 'existing_unmanaged_reservation',
      uuid: rowUuid(unmanagedConflict)
    };
  }

  const existing = rows.find(row => matchesManagedReservation(row, {
    authorizationId: payload.description.slice(KEA_RESERVATION_DESCRIPTION_PREFIX.length),
    clientIp: payload.ip_address,
    clientMac: payload.hw_address,
    subnetUuid: payload.subnet
  }));
  if (existing && sameKeaReservation(existing, payload)) {
    return { changed: false, uuid: rowUuid(existing) };
  }

  const existingUuid = rowUuid(existing);
  if (existing && !existingUuid) {
    throw new Error(`OPNsense Kea DHCP did not return the UUID for ${reservationDescription(existing)}`);
  }
  const endpoint = existing
    ? `/api/kea/dhcpv4/setReservation/${encodeURIComponent(existingUuid)}`
    : '/api/kea/dhcpv4/addReservation';
  const response = assertKeaMutation(await gatewayRequest(gateway, endpoint, {
    method: 'POST',
    json: { reservation: payload }
  }), `${existing ? 'update' : 'create'} reservation`);
  return {
    changed: true,
    uuid: existingUuid || response?.uuid || response?.id || response?.reservation?.uuid || ''
  };
}

export async function ensureGatewayKeaDhcpLease(gateway, {
  authorizationId, clientIp, clientMac, expiresAt, leaseSeconds, method, identity
}) {
  if (!gatewayIsOpnsense(gateway)) return { applied: false, skipped: true, reason: 'gateway_not_opnsense' };
  const ip = firstIpv4(clientIp);
  const mac = normalizeMac(clientMac);
  const id = String(authorizationId || '').trim();
  if (!id || !ip || !mac) {
    return { applied: false, skipped: true, reason: 'missing_client_identity' };
  }
  const seconds = normalizeDhcpLeaseSeconds(leaseSeconds) || dhcpLeaseSeconds(expiresAt);
  if (!seconds) return { applied: false, skipped: true, reason: 'authorization_expired' };

  const subnet = await findKeaSubnetForIp(gateway, ip);
  if (!subnet) throw new Error(`No OPNsense Kea DHCPv4 subnet contains ${ip}`);
  const optionUuid = await ensureKeaLeaseOption(gateway, seconds);
  const reservation = await ensureKeaReservation(gateway, keaReservationPayload({
    authorizationId: id,
    clientIp: ip,
    clientMac: mac,
    subnetUuid: subnet.uuid,
    optionUuid,
    method,
    identity
  }));
  if (reservation.changed) await reconfigureKea(gateway);
  return {
    applied: !reservation.skipped,
    changed: reservation.changed,
    skipped: Boolean(reservation.skipped),
    reason: reservation.reason || '',
    reservationUuid: reservation.uuid,
    optionUuid,
    subnetUuid: subnet.uuid,
    leaseSeconds: seconds
  };
}

export async function deleteGatewayKeaDhcpLease(gateway, authorization) {
  if (!gatewayIsOpnsense(gateway)) return { deleted: 0, skipped: true, reason: 'gateway_not_opnsense' };
  const authorizationId = String(authorization?.id || authorization?.authorizationId || '').trim();
  const clientIp = firstIpv4(authorization?.client_ip || authorization?.clientIp);
  const clientMac = normalizeMac(authorization?.client_mac || authorization?.clientMac);
  if (!authorizationId && !clientIp && !clientMac) {
    return { deleted: 0, skipped: true, reason: 'missing_client_identity' };
  }
  const rows = await searchKeaReservations(gateway);
  const matches = rows.filter(row => matchesManagedReservation(row, {
    authorizationId,
    clientIp,
    clientMac
  }));
  let deleted = 0;
  for (const row of matches) {
    const uuid = rowUuid(row);
    if (!uuid) continue;
    assertKeaMutation(await gatewayRequest(
      gateway,
      `/api/kea/dhcpv4/delReservation/${encodeURIComponent(uuid)}`,
      { method: 'POST', json: {} }
    ), 'delete reservation');
    deleted += 1;
  }
  if (deleted) await reconfigureKea(gateway);
  return { deleted, skipped: false };
}

function collectNetworkStrings(value, output = new Set()) {
  if (value == null) return output;
  if (typeof value === 'string') {
    for (const match of value.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}\b/gu)) {
      output.add(match[0]);
    }
    return output;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectNetworkStrings(item, output);
    return output;
  }
  if (typeof value === 'object') {
    const address = value.ipaddr || value.ipAddress || value.address || value.ipv4 || value.addr4;
    const subnet = value.subnet || value.prefix || value.cidr;
    if (address && subnet && !String(address).includes('/')) {
      output.add(`${address}/${subnet}`);
    }
    for (const item of Object.values(value)) collectNetworkStrings(item, output);
  }
  return output;
}

function networkChoice(row) {
  const networks = [...collectNetworkStrings(row)];
  if (!networks.length) return [];
  const label = row.description || row.descr || row.name || row.identifier || row.if || row.interface || 'OPNsense network';
  return networks.map(network => ({ label: String(label), network }));
}

function interfaceChoice(row) {
  if (!row || typeof row !== 'object') return null;
  const name = textField(row, ['name', 'if', 'interface', 'identifier', 'device']);
  const value = interfaceNameAliases(name)[0] || interfaceNameAliases(row.identifier || row.device || row.if)[0] || '';
  if (!value) return null;
  const label = textField(row, ['descr', 'description', 'label']) || name || value;
  const aliases = [...new Set([
    ...interfaceNameAliases(name),
    ...interfaceNameAliases(row.if),
    ...interfaceNameAliases(row.interface),
    ...interfaceNameAliases(row.identifier),
    ...interfaceNameAliases(row.device),
    ...interfaceNameAliases(label)
  ])];
  return {
    name: value,
    label,
    description: textField(row, ['description', 'descr']) || label,
    aliases
  };
}

function collectInterfaceChoices(value, output = new Map()) {
  if (!value || typeof value !== 'object') return output;
  if (Array.isArray(value)) {
    for (const item of value) collectInterfaceChoices(item, output);
    return output;
  }
  const direct = interfaceChoice(value);
  if (direct) output.set(direct.name, direct);
  for (const [key, item] of Object.entries(value)) {
    if (item && typeof item === 'object') {
      const nested = typeof item === 'object' && !Array.isArray(item)
        ? { name: item.name || key, identifier: item.identifier || key, ...item }
        : item;
      collectInterfaceChoices(nested, output);
    }
  }
  return output;
}

export async function listGatewayNetworkChoices(gateway) {
  if (gateway.mode === 'mock') return [];
  if (gatewayIsPfsense(gateway)) return [];
  const endpoints = [
    '/api/interfaces/overview/export',
    '/api/interfaces/overview/search'
  ];
  const choices = new Map();
  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      const response = await gatewayRequest(gateway, endpoint);
      const rows = responseRows(response);
      const candidates = rows.length || !response || Array.isArray(response)
        ? rows
        : Object.values(response).filter(value => value && typeof value === 'object');
      for (const row of candidates) {
        for (const choice of networkChoice(row)) {
          choices.set(choice.network, choice);
        }
      }
      if (choices.size) break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!choices.size && lastError?.statusCode === 404) return [];
  if (!choices.size && lastError) {
    lastError.message = `OPNsense network discovery failed: ${lastError.message}`;
    throw lastError;
  }
  return [...choices.values()].sort((left, right) => left.network.localeCompare(right.network));
}

export async function listGatewayInterfaces(gateway) {
  if (gateway.mode === 'mock') return [];
  const endpoints = gatewayIsPfsense(gateway)
    ? ['/api/v2/status/interfaces', '/api/v2/interface']
    : [
        '/api/interfaces/overview/export',
        '/api/interfaces/overview/search',
        '/api/diagnostics/interface/get_interface_statistics',
        '/api/diagnostics/interface/getInterfaceStatistics'
      ];
  const choices = new Map();
  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      const response = await gatewayRequest(gateway, endpoint);
      collectInterfaceChoices(response, choices);
      if (choices.size) break;
    } catch (error) {
      lastError = error;
    }
  }
  if (!choices.size && lastError?.statusCode === 404) return [];
  if (!choices.size && lastError) {
    lastError.message = `OPNsense interface discovery failed: ${lastError.message}`;
    throw lastError;
  }
  return [...choices.values()].sort((left, right) => left.name.localeCompare(right.name));
}

export async function readGatewayInterfaceTrafficCounters(gateway, interfaceName = gateway.shaperInterface || 'wan') {
  if (gateway.mode === 'mock') {
    return {
      interfaceName,
      rxBytes: 0,
      txBytes: 0,
      endpoint: 'mock',
      sampledAt: Date.now()
    };
  }
  const endpoints = gatewayIsPfsense(gateway)
    ? ['/api/v2/status/interfaces']
    : [
        '/api/diagnostics/interface/get_interface_statistics',
        '/api/diagnostics/interface/getInterfaceStatistics',
        '/api/diagnostics/traffic/interface',
        '/api/interfaces/overview/export'
      ];
  let lastError = null;
  let forbiddenError = null;
  for (const endpoint of endpoints) {
    try {
      const response = await gatewayRequest(gateway, endpoint, { timeout: 2500 });
      const candidates = collectTrafficCounterCandidates(response, interfaceName);
      if (candidates.length) {
        return {
          ...candidates[0],
          endpoint,
          sampledAt: Date.now()
        };
      }
    } catch (error) {
      if (error.statusCode === 403) {
        error.code = gatewayIsPfsense(gateway) ? 'pfsense_interface_forbidden' : 'opnsense_interface_forbidden';
        error.message = `${gatewayProviderName(gateway)} API user is missing the interface statistics privilege.`;
        forbiddenError = error;
      }
      lastError = error;
      if (error.statusCode && error.statusCode !== 404 && error.statusCode !== 403) break;
    }
  }
  const error = forbiddenError || lastError ||
    new Error(`${gatewayProviderName(gateway)} interface counters were not found for ${interfaceName}`);
  if (!error.code) {
    error.code = error.statusCode === 403
      ? `${gatewayIsPfsense(gateway) ? 'pfsense' : 'opnsense'}_interface_forbidden`
      : `${gatewayIsPfsense(gateway) ? 'pfsense' : 'opnsense'}_interface_counters_unavailable`;
  }
  throw error;
}

export async function disconnectGatewaySession(gateway, sessionId) {
  if (gateway.mode === 'mock') return { status: 'mock-disconnected', sessionId };
  if (gatewayIsPfsense(gateway)) return { skipped: true, reason: 'pfsense_browser_managed_session', sessionId };
  const stored = splitGatewaySessionId(gateway, sessionId);
  const endpoint = `${gateway.baseUrl}/api/captiveportal/session/disconnect/${stored.zoneId}`;
  return requestApi(endpoint, {
    username: gateway.apiKey,
    password: gateway.apiSecret,
    rejectUnauthorized: gateway.tlsRejectUnauthorized,
    providerName: gatewayProviderName(gateway),
    method: 'POST',
    form: { sessionId: stored.sessionId }
  });
}
