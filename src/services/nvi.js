import crypto from 'node:crypto';
import https from 'node:https';

const STS_URL = 'https://kimlikdogrulama.nvi.gov.tr/Services/Issuer.svc/IWSTrust13';
const QUERY_URL = 'https://kpsv2.nvi.gov.tr/Services/RoutingService.svc';
const SOAP_NS_12 = 'http://www.w3.org/2003/05/soap-envelope';
const WSU_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
const WSSE_NS = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
const WSA_NS = 'http://www.w3.org/2005/08/addressing';
const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
const TRUST_NS = 'http://docs.oasis-open.org/ws-sx/ws-trust/200512';
const BODY_NS = 'http://kps.nvi.gov.tr/2025/08/01';
const METHOD_URI = 'http://kps.nvi.gov.tr/2025/08/01/TumKutukDogrulaServis/Sorgula';

function xmlEscape(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function normalizeName(value) {
  return String(value || '')
    .replace(/\s+/gu, ' ')
    .trim()
    .toLocaleUpperCase('tr-TR');
}

function redactTckn(value) {
  const text = String(value || '');
  if (text.length <= 4) return '*'.repeat(text.length);
  return `${'*'.repeat(Math.max(0, text.length - 4))}${text.slice(-4)}`;
}

function isoTimestamp(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/u, 'Z');
}

function messageId() {
  return `urn:uuid:${crypto.randomUUID()}`;
}

function tagValue(text, tagName) {
  const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const match = String(text || '').match(new RegExp(
    `<(?:[A-Za-z_][\\w.-]*:)?${escaped}\\b[^>]*>([\\s\\S]*?)<\\/(?:[A-Za-z_][\\w.-]*:)?${escaped}>`,
    'iu'
  ));
  return match ? String(match[1]).replace(/<[^>]+>/gu, ' ').replace(/\s+/gu, ' ').trim() : '';
}

function allTagValues(text, tagName) {
  const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const values = [];
  const re = new RegExp(
    `<(?:[A-Za-z_][\\w.-]*:)?${escaped}\\b[^>]*>([\\s\\S]*?)<\\/(?:[A-Za-z_][\\w.-]*:)?${escaped}>`,
    'giu'
  );
  for (const match of String(text || '').matchAll(re)) {
    values.push(String(match[1]).replace(/<[^>]+>/gu, ' ').replace(/\s+/gu, ' ').trim());
  }
  return values;
}

function innerXml(text, tagName) {
  const escaped = tagName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const match = String(text || '').match(new RegExp(
    `<(?:[A-Za-z_][\\w.-]*:)?${escaped}\\b[^>]*>([\\s\\S]*?)<\\/(?:[A-Za-z_][\\w.-]*:)?${escaped}>`,
    'iu'
  ));
  return match ? match[1].trim() : '';
}

function buildStsRequest(username, password, now = new Date()) {
  const created = isoTimestamp(now);
  const expires = isoTimestamp(new Date(now.getTime() + 5 * 60 * 1000));
  return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="${SOAP_NS_12}" xmlns:a="${WSA_NS}" xmlns:wst="${TRUST_NS}" xmlns:wsse="${WSSE_NS}" xmlns:wsu="${WSU_NS}" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
  <s:Header>
    <a:MessageID>${messageId()}</a:MessageID>
    <a:To>${STS_URL}</a:To>
    <a:Action>http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</a:Action>
    <wsse:Security s:mustUnderstand="1">
      <wsu:Timestamp wsu:Id="_0">
        <wsu:Created>${created}</wsu:Created>
        <wsu:Expires>${expires}</wsu:Expires>
      </wsu:Timestamp>
      <wsse:UsernameToken wsu:Id="Me">
        <wsse:Username>${xmlEscape(username)}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${xmlEscape(password)}</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken>
      <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsp:AppliesTo>
        <a:EndpointReference>
          <a:Address>${QUERY_URL}</a:Address>
        </a:EndpointReference>
      </wsp:AppliesTo>
      <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</wst:KeyType>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>`;
}

function parseStsResponse(text) {
  const binarySecretB64 = tagValue(text, 'BinarySecret');
  const keyIdentifiers = allTagValues(text, 'KeyIdentifier').filter(Boolean);
  const tokenXml = innerXml(text, 'RequestedSecurityToken');
  const assertionId = keyIdentifiers.at(-1) || '';
  if (!binarySecretB64 || !assertionId || !tokenXml) {
    throw new Error('STS response did not include required KPS security artifacts');
  }
  return { binarySecretB64, assertionId, tokenXml };
}

function buildQueryBody({ tckn, firstName, lastName, birthYear, birthMonth = '', birthDay = '' }) {
  const zeroIfEmpty = value => String(value || '').trim() || '0';
  return [
    `<Sorgula xmlns="${BODY_NS}" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">`,
    '<kriterListesi><TumKutukDogrulamaSorguKriteri>',
    `<Ad>${xmlEscape(normalizeName(firstName))}</Ad>`,
    `<DogumAy>${xmlEscape(zeroIfEmpty(birthMonth))}</DogumAy>`,
    `<DogumGun>${xmlEscape(zeroIfEmpty(birthDay))}</DogumGun>`,
    `<DogumYil>${xmlEscape(birthYear)}</DogumYil>`,
    `<KimlikNo>${xmlEscape(tckn)}</KimlikNo>`,
    `<Soyad>${xmlEscape(normalizeName(lastName))}</Soyad>`,
    '</TumKutukDogrulamaSorguKriteri></kriterListesi>',
    '</Sorgula>'
  ].join('');
}

function timestampXml(created, expires) {
  return `<wsu:Timestamp xmlns:wsu="${WSU_NS}" wsu:Id="_0"><wsu:Created>${created}</wsu:Created><wsu:Expires>${expires}</wsu:Expires></wsu:Timestamp>`;
}

function canonicalSignedInfo(digestValue) {
  return `<dsig:SignedInfo xmlns:dsig="${DSIG_NS}"><dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></dsig:CanonicalizationMethod><dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"></dsig:SignatureMethod><dsig:Reference URI="#_0"><dsig:Transforms><dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></dsig:Transform></dsig:Transforms><dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></dsig:DigestMethod><dsig:DigestValue>${digestValue}</dsig:DigestValue></dsig:Reference></dsig:SignedInfo>`;
}

function buildSignature({ binarySecretB64, assertionId }, timestamp) {
  const digestValue = crypto.createHash('sha1').update(timestamp).digest('base64');
  const signedInfo = canonicalSignedInfo(digestValue);
  const key = Buffer.from(String(binarySecretB64 || '').trim(), 'base64');
  const signatureValue = crypto.createHmac('sha1', key).update(signedInfo).digest('base64');
  return `<dsig:Signature xmlns:dsig="${DSIG_NS}">${signedInfo}<dsig:SignatureValue>${signatureValue}</dsig:SignatureValue><dsig:KeyInfo><wsse:SecurityTokenReference xmlns:wsse="${WSSE_NS}"><wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID">${xmlEscape(assertionId)}</wsse:KeyIdentifier></wsse:SecurityTokenReference></dsig:KeyInfo></dsig:Signature>`;
}

function buildSignedServiceEnvelope(artifacts, bodyXml, now = new Date()) {
  const created = isoTimestamp(now);
  const expires = isoTimestamp(new Date(now.getTime() + 5 * 60 * 1000));
  const timestamp = timestampXml(created, expires);
  const signature = buildSignature(artifacts, timestamp);
  const header = [
    `<a:MessageID xmlns:a="${WSA_NS}">${messageId()}</a:MessageID>`,
    `<a:To xmlns:a="${WSA_NS}" s:mustUnderstand="1">${QUERY_URL}</a:To>`,
    `<a:Action xmlns:a="${WSA_NS}" s:mustUnderstand="1">${METHOD_URI}</a:Action>`,
    `<wsse:Security xmlns:wsse="${WSSE_NS}" xmlns:wsu="${WSU_NS}" s:mustUnderstand="1">`,
    timestamp,
    artifacts.tokenXml,
    signature,
    '</wsse:Security>'
  ].join('');
  return `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="${SOAP_NS_12}">
  <s:Header>${header}</s:Header>
  <s:Body>${bodyXml}</s:Body>
</s:Envelope>`;
}

function postSoap(url, body, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const payload = Buffer.from(String(body));
    const req = https.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method: 'POST',
      timeout: timeoutMs,
      family: 4,
      headers: {
        'content-type': 'application/soap+xml; charset=utf-8',
        accept: 'application/soap+xml, text/xml, application/xml, */*',
        'content-length': payload.length
      }
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        if ((response.statusCode || 500) >= 400) {
          reject(new Error(`KPS service returned HTTP ${response.statusCode}: ${text.slice(0, 500)}`));
          return;
        }
        resolve(text);
      });
    });
    req.on('timeout', () => req.destroy(new Error('KPS service request timed out')));
    req.on('error', reject);
    req.end(payload);
  });
}

function parseKpsResult(text) {
  const fault = tagValue(text, 'faultstring') || tagValue(text, 'Reason') || tagValue(text, 'Text');
  if (fault) throw new Error(`KPS service returned a SOAP fault: ${fault}`);

  const legacy = tagValue(text, 'TCKimlikNoDogrulaResult').toLowerCase();
  if (legacy === 'true') return true;
  if (legacy === 'false') return false;

  const codes = allTagValues(text, 'Kod')
    .map(value => Number.parseInt(value, 10))
    .filter(Number.isInteger);
  if (codes.includes(1)) return true;
  if (codes.some(code => code === 2 || code === 3)) return false;
  throw new Error('KPS service response did not include a verification result');
}

export async function verifyNviIdentity(nvi, identity) {
  if (!nvi?.enabled) throw new Error('NVI verification is disabled');
  const username = String(nvi.username || '').trim();
  const password = String(nvi.password || '').trim();
  if (!username || !password) throw new Error('KPS username and password are required');

  const timeoutMs = Number(nvi.timeoutSeconds || 30) * 1000;
  if (process.env.NVI_DEBUG === 'true') {
    console.log('KPSv2 NVI request', {
      stsUrl: STS_URL,
      queryUrl: QUERY_URL,
      tckn: redactTckn(identity?.tckn),
      birthYear: identity?.birthYear
    });
  }

  const rawSts = await postSoap(STS_URL, buildStsRequest(username, password), timeoutMs);
  const artifacts = parseStsResponse(rawSts);
  const bodyXml = buildQueryBody(identity);
  const rawService = await postSoap(QUERY_URL, buildSignedServiceEnvelope(artifacts, bodyXml), timeoutMs);
  return parseKpsResult(rawService);
}

export const nviInternals = {
  buildQueryBody,
  buildSignature,
  buildSignedServiceEnvelope,
  buildStsRequest,
  canonicalSignedInfo,
  normalizeName,
  parseKpsResult,
  parseStsResponse,
  redactTckn,
  tagValue,
  timestampXml,
  xmlEscape
};
