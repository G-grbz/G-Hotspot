const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const i18n = window.GH_I18N;
const t = (text, variables) => i18n.t(text, variables);

const stepTitles = [
  'Application settings',
  'Gateway settings',
  'Verification methods'
];

const verificationGroups = [
  { id: 'voucher', enabledKey: 'VOUCHER_ENABLED' },
  { id: 'admin-approval', enabledKey: 'ADMIN_APPROVAL_ENABLED' },
  { id: 'nvi', enabledKey: 'NVI_ENABLED' },
  { id: 'email', enabledKey: 'EMAIL_ENABLED' },
  { id: 'whatsapp', enabledKey: 'WHATSAPP_ENABLED' },
  { id: 'telegram', enabledKey: 'TELEGRAM_ENABLED' },
  { id: 'sms', enabledKey: 'SMS_ENABLED' }
];

const optionLabels = {
  mock: 'Mock / test',
  'opnsense-api': 'OPNsense API',
  // TODO(pfSense): Restore the pfSense option label when its installer option is enabled.
  // 'pfsense-api': 'pfSense API',
  netgsm: 'Netgsm',
  iletimerkezi: 'İleti Merkezi',
  twilio: 'Twilio',
  custom: 'Create custom service',
  webhook: 'Webhook',
  polling: 'Polling',
  hours: 'Hours',
  days: 'Days',
  months: 'Months',
  years: 'Years',
  minutes: 'Minutes',
  unlimited: 'Unlimited',
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly'
};

const state = {
  currentStep: 0,
  settings: null,
  activeMethodId: '',
  gatewayNetworks: null,
  opnsenseTestOk: false,
  opnsenseTestedSignature: '',
  submitting: false
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    cache: 'no-store',
    headers: {
      'content-type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || payload.message || `HTTP ${response.status}`);
    error.code = payload.code || '';
    throw error;
  }
  return payload;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

function showNotice(message, type = 'error') {
  const notice = $('#installNotice');
  notice.textContent = message;
  notice.className = `notice ${type}`;
}

function clearNotice() {
  $('#installNotice').className = 'notice hidden';
  $('#installNotice').textContent = '';
}

function setTestStatus(message = '', type = '') {
  const target = $('#opnsenseTestStatus');
  target.textContent = message;
  target.className = `test-status ${type}`.trim();
}

function selectedGatewayMode() {
  return $('input[name="GATEWAY_MODE"]:checked')?.value || 'mock';
}

function settingGroup(id) {
  return state.settings?.schema?.find(group => group.id === id) || null;
}

function settingValue(field) {
  return state.settings?.values?.[field.key] ?? field.defaultValue ?? '';
}

function isBooleanField(field) {
  return field.type === 'boolean';
}

function fieldElement(key) {
  return $(`[data-setting="${CSS.escape(key)}"]`);
}

function fieldValue(field) {
  const element = fieldElement(field.key);
  if (!element) return '';
  return isBooleanField(field) ? element.checked : element.value;
}

function setInputValue(selector, value) {
  const input = $(selector);
  if (!input || value == null || value === '') return;
  input.value = value;
}

function optionLabel(value) {
  return optionLabels[value] || value;
}

function fieldHelp(field) {
  return field.warning ? `<small>${escapeHtml(field.warning)}</small>` : '';
}

function inputAttributes(field) {
  const attributes = [
    `id="setting_${escapeHtml(field.key)}"`,
    `name="${escapeHtml(field.key)}"`,
    `data-setting="${escapeHtml(field.key)}"`,
    `data-optional-field="${escapeHtml(field.key)}"`
  ];
  if (field.derivedFrom) attributes.push(`data-derived-from="${escapeHtml(field.derivedFrom)}"`);
  if (field.readOnly) attributes.push('readonly aria-readonly="true"');
  if (field.min != null) attributes.push(`min="${escapeHtml(field.min)}"`);
  if (field.max != null) attributes.push(`max="${escapeHtml(field.max)}"`);
  return attributes.join(' ');
}

function providerAttribute(field) {
  return field.provider ? ` data-provider="${escapeHtml(field.provider)}"` : '';
}

function renderSettingField(field) {
  const value = settingValue(field);
  const provider = providerAttribute(field);
  const help = fieldHelp(field);
  const label = escapeHtml(field.label);

  if (isBooleanField(field)) {
    return `<div class="setting-field setting-field--boolean"${provider}>
      <label for="setting_${escapeHtml(field.key)}">
        <input ${inputAttributes(field)} type="checkbox" ${String(value) === 'true' ? 'checked' : ''}>
        <span>${label}</span>
      </label>
      ${help}
    </div>`;
  }

  let control = '';
  if (field.type === 'select') {
    control = `<select ${inputAttributes(field)}>${(field.options || []).map(option =>
      `<option value="${escapeHtml(option)}" ${String(value) === String(option) ? 'selected' : ''}>${escapeHtml(optionLabel(option))}</option>`
    ).join('')}</select>`;
  } else if (field.type === 'textarea') {
    control = `<textarea ${inputAttributes(field)} placeholder="${escapeHtml(field.placeholder || '')}">${escapeHtml(value)}</textarea>`;
  } else {
    const type = field.type === 'secret' ? 'password' : (field.type || 'text');
    const placeholder = field.type === 'secret' && state.settings?.configured?.[field.key]
      ? 'Configured — leave blank to keep the current value'
      : (field.placeholder || '');
    control = `<input ${inputAttributes(field)} type="${escapeHtml(type)}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" spellcheck="false">`;
  }

  const full = ['textarea', 'secret'].includes(field.type) ? ' full' : '';
  return `<div class="setting-field${full}"${provider}>
    <label for="setting_${escapeHtml(field.key)}">${label}</label>
    ${control}
    ${help}
  </div>`;
}

function renderDurationField(valueField, unitField) {
  const value = settingValue(valueField);
  const unitValue = settingValue(unitField);
  const pair = valueField.durationPair;
  const help = unitField.warning || valueField.warning
    ? `<small>${escapeHtml(unitField.warning || valueField.warning)}</small>`
    : '';
  const unitOptions = (unitField.options || []).map(option =>
    `<option value="${escapeHtml(option)}" ${String(unitValue) === String(option) ? 'selected' : ''}>${escapeHtml(optionLabel(option))}</option>`
  ).join('');
  return `<div class="setting-field duration-field" data-duration-field="${escapeHtml(pair)}">
    <label for="setting_${escapeHtml(valueField.key)}">${escapeHtml(valueField.label)}</label>
    <div class="duration-control">
      <input ${inputAttributes(valueField)} data-duration-pair="${escapeHtml(pair)}" data-duration-role="value" type="number" value="${escapeHtml(value)}">
      <select ${inputAttributes(unitField)} data-duration-pair="${escapeHtml(pair)}" data-duration-role="unit" aria-label="${escapeHtml(unitField.label)}">${unitOptions}</select>
    </div>
    ${help}
  </div>`;
}

function renderMethodFields(group, enabledKey) {
  const fields = group.fields.filter(field => field.key !== enabledKey);
  if (!fields.length) return `<div class="method-fields hidden"><small>${escapeHtml(t('No extra setup required.'))}</small></div>`;

  let currentSection = '';
  const html = [];
  for (const field of fields) {
    if (field.durationRole === 'unit') continue;
    if (field.section && field.section !== currentSection) {
      currentSection = field.section;
      html.push(`<div class="setting-section">${escapeHtml(field.section)}</div>`);
    }
    const durationUnit = field.durationRole === 'value'
      ? fields.find(item => item.durationPair === field.durationPair && item.durationRole === 'unit')
      : null;
    if (durationUnit) {
      html.push(renderDurationField(field, durationUnit));
      continue;
    }
    html.push(renderSettingField(field));
  }
  return `<div class="method-fields">${html.join('')}</div>`;
}

function renderVerificationMethods() {
  const container = $('#verificationMethods');
  const groups = verificationGroups.map(item => ({
    ...item,
    group: settingGroup(item.id)
  })).filter(item => item.group);
  state.activeMethodId ||= groups.find(item => {
    const enabledField = item.group.fields.find(field => field.key === item.enabledKey);
    return String(settingValue(enabledField || { key: item.enabledKey, defaultValue: 'false' })) === 'true';
  })?.id || groups[0]?.id || '';

  container.innerHTML = `<div class="method-tabs" role="tablist" aria-label="${escapeHtml(t('Verification methods'))}">
    ${groups.map(item => {
      const active = item.id === state.activeMethodId;
      return `<button class="method-tab${active ? ' active' : ''}" type="button" role="tab" aria-selected="${active ? 'true' : 'false'}" data-method-tab="${escapeHtml(item.id)}">
        <span>${escapeHtml(item.group.label)}</span>
      </button>`;
    }).join('')}
  </div>
  <div class="method-panels">
    ${groups.map(item => {
      const group = item.group;
      const enabledField = group.fields.find(field => field.key === item.enabledKey);
      const enabled = String(settingValue(enabledField || { key: item.enabledKey, defaultValue: 'false' })) === 'true';
      const active = item.id === state.activeMethodId;
      return `<article class="method-panel${active ? '' : ' hidden'}" data-method-panel="${escapeHtml(item.id)}" role="tabpanel">
        <label class="method-toggle" for="method_${escapeHtml(item.enabledKey)}">
          <input id="method_${escapeHtml(item.enabledKey)}" name="${escapeHtml(item.enabledKey)}" data-method-enabled="${escapeHtml(item.enabledKey)}" type="checkbox" ${enabled ? 'checked' : ''}>
          <span>
            <strong>${escapeHtml(group.label)}</strong>
            <span>${escapeHtml(group.description || '')}</span>
          </span>
        </label>
        ${renderMethodFields(group, item.enabledKey)}
      </article>`;
    }).join('')}
  </div>`;

  container.addEventListener('click', event => {
    const tab = event.target.closest('[data-method-tab]');
    if (tab) activateMethodTab(tab.dataset.methodTab);
  });
  container.addEventListener('change', event => {
    if (event.target.matches('[data-method-enabled], [data-setting="SMS_PROVIDER"]')) {
      syncOptionalControls();
    }
    if (event.target.matches('[data-setting="SMTP_SECURE"], [data-setting="SMTP_STARTTLS"], [name="SMTP_SECURE"], [name="SMTP_STARTTLS"]')) {
      syncSmtpTlsFields(event.target.name || event.target.dataset.setting);
    }
  });
  container.addEventListener('input', event => {
    if (event.target.matches('[data-derived-from]')) syncDerivedSettings();
  });
  $$('#verificationMethods input, #verificationMethods select, #verificationMethods textarea').forEach(input => {
    input.addEventListener('input', () => {
      syncDerivedSettings();
      syncProviderFields();
    });
  });
  bindSmtpTlsFields();
  syncOptionalControls();
  i18n.translateDom(container);
}

function activateMethodTab(methodId) {
  state.activeMethodId = methodId;
  $$('[data-method-tab]').forEach(tab => {
    const active = tab.dataset.methodTab === methodId;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  $$('[data-method-panel]').forEach(panel => {
    panel.classList.toggle('hidden', panel.dataset.methodPanel !== methodId);
  });
}

function applySettingsDefaults() {
  const values = state.settings?.values || {};
  setInputValue('#appName', values.APP_NAME || 'G-Hotspot');
  setInputValue('#databasePath', values.DATABASE_PATH || './data/hotspot.db');
  setInputValue('#adminUsername', values.ADMIN_USERNAME || 'admin');
  setInputValue('#adminSessionHours', values.ADMIN_SESSION_HOURS || '12');
  setInputValue('#opnsenseBaseUrl', values.OPNSENSE_BASE_URL || '');
  // TODO(pfSense): Restore the captive portal URL default when its field is enabled.
  setInputValue('#opnsenseZoneId', values.OPNSENSE_ZONE_ID || '0');
  setInputValue('#opnsenseApiKey', values.OPNSENSE_API_KEY || '');
  setInputValue('#opnsenseApiSecret', values.OPNSENSE_API_SECRET || '');
  setInputValue('#opnsenseZoneMap', values.OPNSENSE_ZONE_MAP || '');
  $('#opnsenseTls').checked = String(values.OPNSENSE_TLS_REJECT_UNAUTHORIZED ?? 'true') === 'true';
}

function opnsenseSignature() {
  const mode = selectedGatewayMode();
  return JSON.stringify({
    mode,
    baseUrl: $('#opnsenseBaseUrl').value.trim(),
    // TODO(pfSense): Add captivePortalUrl back to this signature when support resumes.
    zoneId: $('#opnsenseZoneId').value.trim(),
    apiKey: $('#opnsenseApiKey').value.trim(),
    apiSecret: $('#opnsenseApiSecret').value,
    tlsRejectUnauthorized: $('#opnsenseTls').checked
  });
}

function resetOpnsenseTest() {
  if (state.opnsenseTestOk && state.opnsenseTestedSignature === opnsenseSignature()) return;
  state.opnsenseTestOk = false;
  state.opnsenseTestedSignature = '';
  state.gatewayNetworks = null;
  renderGatewayNetworkChoices({
    choices: [],
    error: selectedGatewayMode() !== 'mock'
      ? 'Run a successful connection test to continue.'
      : ''
  });
  if (selectedGatewayMode() !== 'mock') {
    setTestStatus(t('Run a successful connection test to continue.'));
  } else {
    setTestStatus('');
  }
  syncActions();
}

function syncGatewayMode() {
  const mode = selectedGatewayMode();
  const realGateway = mode !== 'mock';
  $('#opnsenseFields').classList.toggle('hidden', !realGateway);
  $('#opnsenseZoneFields').classList.toggle('hidden', !realGateway);
  // TODO(pfSense): Restore the provider-specific portal URL row toggle.
  for (const selector of ['#opnsenseBaseUrl', '#opnsenseApiKey', '#opnsenseApiSecret']) {
    $(selector).required = realGateway;
  }
  $('[data-step-indicator="2"]').classList.toggle('disabled', mode === 'mock');
  resetOpnsenseTest();
  syncActions();
}

function appendZoneMapNetwork(network) {
  const input = $('#opnsenseZoneMap');
  const zoneId = $('#opnsenseZoneId').value || '0';
  const lines = input.value.split(/\n/u).map(item => item.trim()).filter(Boolean);
  if (!lines.some(line => line.split('=')[0]?.trim() === network)) {
    lines.push(`${network}=${zoneId}`);
  }
  input.value = lines.join('\n');
}

function renderGatewayNetworkChoices(payload = {}) {
  const target = $('#opnsenseNetworkChoices');
  if (!target) return;
  const choices = payload.choices || [];
  if (!choices.length) {
    target.innerHTML = payload.error
      ? `<span>${escapeHtml(t(payload.error))}</span>`
      : '';
    return;
  }
  target.innerHTML = `<span>${escapeHtml(t('Gateway networks'))}</span>${choices.map(choice =>
    `<button class="network-choice" type="button" data-network-choice="${escapeHtml(choice.network)}" title="${escapeHtml(choice.label)}">${escapeHtml(choice.network)}</button>`
  ).join('')}`;
}

async function loadGatewayNetworks() {
  if (selectedGatewayMode() === 'mock' || !state.opnsenseTestOk) return;
  if (state.gatewayNetworks) {
    renderGatewayNetworkChoices(state.gatewayNetworks);
    return;
  }
  renderGatewayNetworkChoices({
    choices: [],
    error: 'Loading gateway networks…'
  });
  try {
    state.gatewayNetworks = await api('/api/install/gateway/networks', {
      method: 'POST',
      body: JSON.stringify({ settings: formSettings({ includeOptional: false }) })
    });
    renderGatewayNetworkChoices(state.gatewayNetworks);
  } catch {
    renderGatewayNetworkChoices({
      choices: [],
      error: 'Gateway networks could not be discovered automatically. You can enter networks manually.'
    });
  }
}

function syncProviderFields() {
  const provider = fieldElement('SMS_PROVIDER')?.value || 'netgsm';
  $$('[data-provider]').forEach(element => {
    const visible = element.dataset.provider === provider;
    element.classList.toggle('hidden', !visible);
    element.querySelectorAll('input, select, textarea').forEach(input => {
      input.disabled = !visible || Boolean(input.closest('.method-fields.hidden'));
    });
  });
}

function syncDerivedSettings() {
  $$('[data-derived-from]').forEach(target => {
    const source = fieldElement(target.dataset.derivedFrom);
    if (source) target.value = source.value;
  });
}

function smtpTlsFields() {
  return {
    smtpSecure: fieldElement('SMTP_SECURE') || $('[name="SMTP_SECURE"]'),
    smtpStartTls: fieldElement('SMTP_STARTTLS') || $('[name="SMTP_STARTTLS"]'),
    smtpPort: fieldElement('SMTP_PORT') || $('[name="SMTP_PORT"]')
  };
}

function syncSmtpTlsFields(changedKey = '') {
  const { smtpSecure, smtpStartTls, smtpPort } = smtpTlsFields();
  if (!smtpSecure || !smtpStartTls || !smtpPort) return;

  if (changedKey === 'SMTP_SECURE' && smtpSecure.checked) {
    smtpStartTls.checked = false;
    smtpPort.value = '465';
  } else if (changedKey === 'SMTP_STARTTLS' && smtpStartTls.checked) {
    smtpSecure.checked = false;
    smtpPort.value = '587';
  }
}

function normalizeSmtpTlsFields() {
  const { smtpSecure, smtpStartTls, smtpPort } = smtpTlsFields();
  if (!smtpSecure || !smtpStartTls || !smtpPort) return;
  if (smtpSecure.checked) {
    smtpStartTls.checked = false;
    if (!smtpPort.value) smtpPort.value = '465';
  } else if (smtpStartTls.checked) {
    if (!smtpPort.value) smtpPort.value = '587';
  }
}

function bindSmtpTlsFields() {
  const { smtpSecure, smtpStartTls } = smtpTlsFields();
  smtpSecure?.addEventListener('change', () => syncSmtpTlsFields('SMTP_SECURE'));
  smtpSecure?.addEventListener('input', () => syncSmtpTlsFields('SMTP_SECURE'));
  smtpStartTls?.addEventListener('change', () => syncSmtpTlsFields('SMTP_STARTTLS'));
  smtpStartTls?.addEventListener('input', () => syncSmtpTlsFields('SMTP_STARTTLS'));
}

function syncOptionalControls() {
  $$('[data-method-panel]').forEach(panel => {
    const enabled = panel.querySelector('[data-method-enabled]')?.checked || false;
    const fields = panel.querySelector('.method-fields');
    if (fields) fields.classList.toggle('hidden', !enabled);
    fields?.querySelectorAll('input, select, textarea').forEach(input => {
      input.disabled = !enabled;
    });
  });
  syncDerivedSettings();
  syncProviderFields();
  syncSmtpTlsFields();
}

function validateStep(step = state.currentStep, { requireOpnsenseTest = true } = {}) {
  const root = $(`[data-step="${step}"]`);
  const fields = [...root.querySelectorAll('input, select, textarea')]
    .filter(input => !input.disabled && !input.closest('.hidden'));
  for (const input of fields) {
    if (!input.checkValidity()) {
      input.reportValidity();
      return false;
    }
  }
  if (requireOpnsenseTest && step === 1 && selectedGatewayMode() !== 'mock') {
    if (!state.opnsenseTestOk || state.opnsenseTestedSignature !== opnsenseSignature()) {
      showNotice(t('Test gateway connection before continuing.'));
      return false;
    }
  }
  return true;
}

function goToStep(step) {
  state.currentStep = Math.max(0, Math.min(2, step));
  $$('.wizard-step').forEach(panel => {
    panel.classList.toggle('hidden', Number(panel.dataset.step) !== state.currentStep);
  });
  $$('[data-step-indicator]').forEach(indicator => {
    const index = Number(indicator.dataset.stepIndicator);
    indicator.classList.toggle('active', index === state.currentStep);
    indicator.classList.toggle('complete', index < state.currentStep);
  });
  $('#stepTitle').textContent = t(stepTitles[state.currentStep]);
  clearNotice();
  syncActions();
  if (state.currentStep === 2) void loadGatewayNetworks();
}

function syncActions() {
  const mode = selectedGatewayMode();
  const onApplication = state.currentStep === 0;
  const onGateway = state.currentStep === 1;
  const onVerification = state.currentStep === 2;
  const mockGatewayFinish = onGateway && mode === 'mock';
  const realGateway = mode !== 'mock';

  $('#backButton').classList.toggle('hidden', onApplication);
  $('#skipFinishButton').classList.toggle('hidden', !onVerification);
  $('#nextButton').classList.toggle('hidden', mockGatewayFinish || onVerification);
  $('#installButton').classList.toggle('hidden', !(mockGatewayFinish || onVerification));
  $('#installButton').dataset.includeOptional = onVerification ? 'true' : 'false';
  $('#nextButton').disabled = state.submitting ||
    (onGateway && realGateway && (!state.opnsenseTestOk || state.opnsenseTestedSignature !== opnsenseSignature()));
  $('#installButton').disabled = state.submitting;
  $('#backButton').disabled = state.submitting;
  $('#skipFinishButton').disabled = state.submitting;
}

async function generateSecret() {
  const button = $('#generateSecretButton');
  button.disabled = true;
  try {
    const result = await api('/api/install/secret', { method: 'POST', body: '{}' });
    $('#appSecret').value = result.secret || '';
  } catch (error) {
    showNotice(t(error.message || 'Secret could not be generated.'));
  } finally {
    button.disabled = false;
  }
}

function baseSettings() {
  const settings = {
    APP_NAME: $('#appName').value,
    DATABASE_PATH: $('#databasePath').value,
    APP_SECRET: $('#appSecret').value,
    DEFAULT_LANGUAGE: i18n.language || 'en',
    ADMIN_USERNAME: $('#adminUsername').value,
    ADMIN_PASSWORD: $('#adminPassword').value,
    ADMIN_SESSION_HOURS: $('#adminSessionHours').value,
    GATEWAY_MODE: selectedGatewayMode(),
    OPNSENSE_ZONE_ID: $('#opnsenseZoneId').value,
    OPNSENSE_TLS_REJECT_UNAUTHORIZED: $('#opnsenseTls').checked
  };

  if (settings.GATEWAY_MODE !== 'mock') {
    settings.OPNSENSE_BASE_URL = $('#opnsenseBaseUrl').value;
    // TODO(pfSense): Restore OPNSENSE_CAPTIVE_PORTAL_URL when support resumes.
    settings.OPNSENSE_API_KEY = $('#opnsenseApiKey').value;
    settings.OPNSENSE_API_SECRET = $('#opnsenseApiSecret').value;
  }
  return settings;
}

function optionalSettings() {
  normalizeSmtpTlsFields();
  const settings = {};
  if (selectedGatewayMode() !== 'mock') {
    settings.OPNSENSE_ZONE_MAP = $('#opnsenseZoneMap').value;
  }

  for (const item of verificationGroups) {
    const checkbox = $(`[data-method-enabled="${CSS.escape(item.enabledKey)}"]`);
    if (!checkbox) continue;
    settings[item.enabledKey] = checkbox.checked;
    if (!checkbox.checked) continue;

    const group = settingGroup(item.id);
    for (const field of group?.fields || []) {
      if (field.key === item.enabledKey) continue;
      const element = fieldElement(field.key);
      if (!element || element.disabled) continue;
      settings[field.key] = fieldValue(field);
    }
  }
  return settings;
}

function formSettings({ includeOptional = true } = {}) {
  return {
    ...baseSettings(),
    ...(includeOptional ? optionalSettings() : {})
  };
}

async function submitInstall(event, { includeOptional = null, button = null } = {}) {
  event?.preventDefault();
  clearNotice();

  if (!validateStep(state.currentStep)) return;
  const shouldIncludeOptional = includeOptional ?? ($('#installButton').dataset.includeOptional === 'true');
  const actionButton = button || event?.submitter || $('#installButton');
  const previousText = actionButton.textContent;
  state.submitting = true;
  actionButton.textContent = t('Processing...');
  syncActions();

  try {
    await api('/api/install', {
      method: 'POST',
      body: JSON.stringify({ settings: formSettings({ includeOptional: shouldIncludeOptional }) })
    });
    showNotice(t('Installation completed.'), 'success');
    window.location.replace('/admin');
  } catch (error) {
    showNotice(t(error.message || 'Installation failed.'));
    state.submitting = false;
    actionButton.textContent = previousText;
    syncActions();
  }
}

async function testOpnsenseConnection() {
  clearNotice();
  if (!validateStep(1, { requireOpnsenseTest: false })) return;
  const mode = selectedGatewayMode();
  const button = $('#testOpnsenseButton');
  const previousText = button.textContent;
  button.disabled = true;
  button.textContent = t('Testing...');
  setTestStatus(t('Testing gateway connection...'));
  state.opnsenseTestOk = false;
  state.opnsenseTestedSignature = '';
  syncActions();

  try {
    const signature = opnsenseSignature();
    const result = await api('/api/install/opnsense-test', {
      method: 'POST',
      body: JSON.stringify({ settings: formSettings({ includeOptional: false }) })
    });
    state.opnsenseTestOk = true;
    state.opnsenseTestedSignature = signature;
    setTestStatus(t('Gateway connection test succeeded for zone {zone}.', {
      zone: String(result.zoneId ?? $('#opnsenseZoneId').value)
    }), 'success');
    void loadGatewayNetworks();
    clearNotice();
  } catch (error) {
    const message = t(error.message || 'Gateway connection test failed.');
    setTestStatus(message, 'error');
  } finally {
    button.disabled = false;
    button.textContent = previousText;
    syncActions();
  }
}

function nextStep() {
  if (!validateStep(state.currentStep)) return;
  if (state.currentStep === 0) {
    goToStep(1);
    return;
  }
  if (state.currentStep === 1 && selectedGatewayMode() !== 'mock') {
    goToStep(2);
  }
}

function bindEvents() {
  $('#installLanguage').addEventListener('change', async event => {
    await i18n.setLanguage(event.target.value, 'gh_install_language');
    $('#defaultLanguage').value = i18n.language;
    $('#stepTitle').textContent = t(stepTitles[state.currentStep]);
  });
  $$('#installForm input[name="GATEWAY_MODE"]').forEach(input =>
    input.addEventListener('change', syncGatewayMode)
  );
  for (const selector of [
    '#opnsenseBaseUrl',
    // TODO(pfSense): Restore '#opnsenseCaptivePortalUrl' with its installer field.
    '#opnsenseZoneId',
    '#opnsenseApiKey',
    '#opnsenseApiSecret',
    '#opnsenseTls'
  ]) {
    $(selector).addEventListener('input', resetOpnsenseTest);
    $(selector).addEventListener('change', resetOpnsenseTest);
  }
  $('#generateSecretButton').addEventListener('click', generateSecret);
  $('#testOpnsenseButton').addEventListener('click', testOpnsenseConnection);
  $('#opnsenseNetworkChoices').addEventListener('click', event => {
    const button = event.target.closest('[data-network-choice]');
    if (button) appendZoneMapNetwork(button.dataset.networkChoice);
  });
  $('#nextButton').addEventListener('click', nextStep);
  $('#backButton').addEventListener('click', () => goToStep(state.currentStep - 1));
  $('#skipFinishButton').addEventListener('click', event => {
    submitInstall(event, { includeOptional: false, button: $('#skipFinishButton') });
  });
  $('#installForm').addEventListener('submit', submitInstall);
}

async function preloadInstallFont() {
  if (!document.fonts?.load) return;
  const sample = 'G-Hotspot ABCÇĞİÖŞÜ abcçğıöşü 0123456789';
  await document.fonts.load('400 1em "Inter"', sample).catch(() => []);
}

async function init() {
  await i18n.ready;
  await preloadInstallFont();
  await i18n.setAutomaticLanguage('en', 'gh_install_language');
  $('#installLanguage').value = i18n.language;
  $('#defaultLanguage').value = i18n.language;

  const status = await api('/api/install/status');
  if (status.installed) {
    window.location.replace('/admin');
    return;
  }

  state.settings = await api('/api/install/settings');
  applySettingsDefaults();
  renderVerificationMethods();
  bindEvents();
  syncGatewayMode();
  goToStep(0);
  i18n.reveal();
  if (!$('#appSecret').value) await generateSecret();
}

init().catch(error => {
  i18n.reveal();
  showNotice(t(error.message || 'Installation failed.'));
});
