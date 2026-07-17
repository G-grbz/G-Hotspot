import * as opnsense from './opnsense.js';

const adapters = {
  mock: opnsense,
  'opnsense-api': opnsense
  // TODO(pfSense): Restore this adapter mapping after pfSense support is completed.
  // 'pfsense-api': opnsense
};

function adapterFor(gateway = {}) {
  const adapter = adapters[gateway.mode || 'mock'];
  if (!adapter) throw new Error(`Unsupported gateway mode: ${gateway.mode}`);
  return adapter;
}

export function gatewayIsMock(gateway = {}) {
  return (gateway.mode || 'mock') === 'mock';
}

export function gatewayIsManaged(gateway = {}) {
  return !gatewayIsMock(gateway);
}

export function gatewayProviderName(gateway = {}) {
  // TODO(pfSense): Restore the pfSense provider label with the adapter mapping.
  // if (gateway.mode === 'pfsense-api') return 'pfSense';
  if (gateway.mode === 'opnsense-api') return 'OPNsense';
  return 'Mock';
}

export function resolveGatewayZoneId(gateway, clientIp = '') {
  return adapterFor(gateway).resolveGatewayZoneId(gateway, clientIp);
}

export async function ensureGatewayBandwidthLimits(gateway, options = {}) {
  return adapterFor(gateway).ensureGatewayBandwidthLimits(gateway, options);
}

export async function authorizeGateway(gateway, options) {
  return adapterFor(gateway).authorizeGateway(gateway, options);
}

export async function listGatewaySessions(gateway) {
  return adapterFor(gateway).listGatewaySessions(gateway);
}

export async function listGatewayArpEntries(gateway) {
  return adapterFor(gateway).listGatewayArpEntries(gateway);
}

export async function listGatewayDhcpLeases(gateway) {
  return adapterFor(gateway).listGatewayDhcpLeases(gateway);
}

export async function listGatewayClientOwnership(gateway, options = {}) {
  return adapterFor(gateway).listGatewayClientOwnership(gateway, options);
}

export async function ensureGatewayDhcpLease(gateway, options = {}) {
  const adapter = adapterFor(gateway);
  const ensure = adapter.ensureGatewayDhcpLease || adapter.ensureGatewayKeaDhcpLease;
  return ensure(gateway, options);
}

export async function ensureGatewayKeaDhcpLease(gateway, options = {}) {
  return ensureGatewayDhcpLease(gateway, options);
}

export async function deleteGatewayDhcpLease(gateway, authorization) {
  const adapter = adapterFor(gateway);
  const remove = adapter.deleteGatewayDhcpLease || adapter.deleteGatewayKeaDhcpLease;
  return remove(gateway, authorization);
}

export async function deleteGatewayKeaDhcpLease(gateway, authorization) {
  return deleteGatewayDhcpLease(gateway, authorization);
}

export async function listGatewayNetworkChoices(gateway) {
  return adapterFor(gateway).listGatewayNetworkChoices(gateway);
}

export async function listGatewayInterfaces(gateway) {
  return adapterFor(gateway).listGatewayInterfaces(gateway);
}

export async function readGatewayInterfaceTrafficCounters(gateway, interfaceName) {
  return adapterFor(gateway).readGatewayInterfaceTrafficCounters(gateway, interfaceName);
}

export async function disconnectGatewaySession(gateway, sessionId) {
  return adapterFor(gateway).disconnectGatewaySession(gateway, sessionId);
}
