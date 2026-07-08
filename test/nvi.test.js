import test from 'node:test';
import assert from 'node:assert/strict';
import { nviInternals } from '../src/services/nvi.js';

test('KPSv2 query body contains normalized identity fields', () => {
  const body = nviInternals.buildQueryBody({
    tckn: '10000000146',
    firstName: 'veli',
    lastName: 'yilmaz',
    birthYear: 1990
  });
  assert.match(body, /<Sorgula xmlns="http:\/\/kps\.nvi\.gov\.tr\/2025\/08\/01"/u);
  assert.match(body, /<KimlikNo>10000000146<\/KimlikNo>/u);
  assert.match(body, /<Ad>VELİ<\/Ad>/u);
  assert.match(body, /<Soyad>YİLMAZ<\/Soyad>/u);
  assert.match(body, /<DogumYil>1990<\/DogumYil>/u);
  assert.match(body, /<DogumAy>0<\/DogumAy>/u);
  assert.match(body, /<DogumGun>0<\/DogumGun>/u);
});

test('KPSv2 query body escapes XML input', () => {
  const body = nviInternals.buildQueryBody({
    tckn: '10000000146',
    firstName: 'A&B',
    lastName: 'Y<Z',
    birthYear: 1990
  });
  assert.match(body, /<Ad>A&amp;B<\/Ad>/u);
  assert.match(body, /<Soyad>Y&lt;Z<\/Soyad>/u);
});

test('KPSv2 STS request contains username token and routing target', () => {
  const body = nviInternals.buildStsRequest('user&1', 'pass<1', new Date('2026-01-01T00:00:00Z'));
  assert.match(body, /<wsse:Username>user&amp;1<\/wsse:Username>/u);
  assert.match(body, /<wsse:Password[^>]*>pass&lt;1<\/wsse:Password>/u);
  assert.match(body, /<a:Address>https:\/\/kpsv2\.nvi\.gov\.tr\/Services\/RoutingService\.svc<\/a:Address>/u);
  assert.match(body, /<wsu:Created>2026-01-01T00:00:00Z<\/wsu:Created>/u);
});

test('KPSv2 STS response parser extracts security artifacts', () => {
  const parsed = nviInternals.parseStsResponse(`
    <s:Envelope>
      <s:Body>
        <wst:RequestedSecurityToken>
          <xenc:EncryptedData Id="token-1">token</xenc:EncryptedData>
        </wst:RequestedSecurityToken>
        <wst:RequestedAttachedReference>
          <wsse:SecurityTokenReference><wsse:KeyIdentifier>attached-id</wsse:KeyIdentifier></wsse:SecurityTokenReference>
        </wst:RequestedAttachedReference>
        <wst:RequestedUnattachedReference>
          <wsse:SecurityTokenReference><wsse:KeyIdentifier>assertion-id</wsse:KeyIdentifier></wsse:SecurityTokenReference>
        </wst:RequestedUnattachedReference>
        <wst:BinarySecret>c2VjcmV0</wst:BinarySecret>
      </s:Body>
    </s:Envelope>
  `);
  assert.equal(parsed.binarySecretB64, 'c2VjcmV0');
  assert.equal(parsed.assertionId, 'assertion-id');
  assert.match(parsed.tokenXml, /<xenc:EncryptedData Id="token-1">token<\/xenc:EncryptedData>/u);
});

test('KPSv2 signed service envelope includes timestamp, SAML token and signature', () => {
  const envelope = nviInternals.buildSignedServiceEnvelope({
    binarySecretB64: 'c2VjcmV0',
    assertionId: 'assertion-id',
    tokenXml: '<xenc:EncryptedData>token</xenc:EncryptedData>'
  }, '<Sorgula/>', new Date('2026-01-01T00:00:00Z'));
  assert.match(envelope, /<a:Action[^>]*>http:\/\/kps\.nvi\.gov\.tr\/2025\/08\/01\/TumKutukDogrulaServis\/Sorgula<\/a:Action>/u);
  assert.match(envelope, /<wsu:Created>2026-01-01T00:00:00Z<\/wsu:Created>/u);
  assert.match(envelope, /<xenc:EncryptedData>token<\/xenc:EncryptedData>/u);
  assert.match(envelope, /<dsig:SignatureValue>[A-Za-z0-9+/=]+<\/dsig:SignatureValue>/u);
  assert.match(envelope, /<wsse:KeyIdentifier[^>]*>assertion-id<\/wsse:KeyIdentifier>/u);
});

test('NVI debug helper redacts TCKN values', () => {
  assert.equal(nviInternals.redactTckn('10000000146'), '*******0146');
  assert.equal(nviInternals.redactTckn('123'), '***');
});

test('KPSv2 result parser reads successful and failed responses', () => {
  assert.equal(nviInternals.parseKpsResult(`
    <TCVatandasiKisiKutukleri>
      <KisiBilgisi>
        <DurumBilgisi><Durum><Kod>1</Kod><Aciklama>Açık</Aciklama></Durum></DurumBilgisi>
      </KisiBilgisi>
    </TCVatandasiKisiKutukleri>
  `), true);
  assert.equal(nviInternals.parseKpsResult(`
    <TCVatandasiKisiKutukleri>
      <KisiBilgisi>
        <DurumBilgisi><Durum><Kod>2</Kod><Aciklama>Bulunamadı</Aciklama></Durum></DurumBilgisi>
      </KisiBilgisi>
    </TCVatandasiKisiKutukleri>
  `), false);
  assert.equal(nviInternals.parseKpsResult(`
    <TCVatandasiKisiKutukleri>
      <KisiBilgisi>
        <DurumBilgisi><Durum><Kod>3</Kod><Aciklama>Ölüm</Aciklama></Durum></DurumBilgisi>
      </KisiBilgisi>
    </TCVatandasiKisiKutukleri>
  `), false);
});

test('KPSv2 result parser reports provider faults and missing results', () => {
  assert.throws(() => nviInternals.parseKpsResult(`
    <soap:Fault>
      <faultcode>soap:Client</faultcode>
      <faultstring>Server was unable to read request.</faultstring>
    </soap:Fault>
  `), /SOAP fault: Server was unable/u);
  assert.throws(() => nviInternals.parseKpsResult('<xml/>'), /verification result/u);
});
