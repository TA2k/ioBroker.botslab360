'use strict';

const crypto = require('crypto');
const { expect } = require('chai');
const quc = require('./lib/quc');
const api = require('./lib/api');

describe('QUC login crypto', () => {
  it('computes sig as md5 of sorted key=value pairs (uppercase before lowercase)', () => {
    const params = { b: '2', A: '1', a: '3' };
    const expected = crypto.createHash('md5').update('A=1a=3b=2', 'utf8').digest('hex');

    expect(quc.computeSig(params)).to.equal(expected);
  });

  it('excludes an existing sig field from the signature base', () => {
    const withSig = { z: '1', sig: 'ignored' };
    const withoutSig = { z: '1' };

    expect(quc.computeSig(withSig)).to.equal(quc.computeSig(withoutSig));
  });

  it('round-trips a DES-CBC payload with the same 8-byte key and IV', () => {
    const key8 = 'AZReT8jb';
    const plain = 'loginType=801&username=test%40example.com&password=abc';

    const encrypted = quc.desEncryptB64(plain, key8);
    expect(quc.desDecryptUtf8(encrypted, key8)).to.equal(plain);
  });

  it('creates a stable device identity with the expected field widths', () => {
    const device = quc.createDeviceIdentity();

    expect(device.mid).to.match(/^[0-9a-f]{32}$/);
    expect(device.androidid).to.match(/^[0-9a-f]{16}$/);
    expect(device.m2).to.match(/^[0-9a-f-]{36}$/);
  });
});

describe('v1 sign params', () => {
  it('signs with md5(appkey + m2 + sign_ts + sign_no + appSecret)', () => {
    const m2 = 'e05620b5-858f-4c2d-b990-d79dc276f636';
    const params = api.signParams(m2);
    const expected = crypto
      .createHash('md5')
      .update(api.APPKEY + m2 + params.sign_ts + params.sign_no + api.APPSECRET, 'utf8')
      .digest('hex');

    expect(params.sign).to.equal(expected);
    expect(params.m2).to.equal(m2);
    expect(params.sign_no).to.match(/^[0-9a-f]{32}$/);
  });

  it('packs Q, T and sid into the jws Authorization header', () => {
    const header = api.jwsHeader({ q: 'Q1', t: 'T1', sid: 'S1' });
    const decoded = JSON.parse(Buffer.from(header.replace(/^jws /, ''), 'base64').toString('utf8'));

    expect(decoded).to.deep.equal({ Q: 'Q1', T: 'T1', sid: 'S1' });
  });

  it('omits sid from the header when minting a session', () => {
    const header = api.jwsHeader({ q: 'Q1', t: 'T1' });
    const decoded = JSON.parse(Buffer.from(header.replace(/^jws /, ''), 'base64').toString('utf8'));

    expect(decoded).to.deep.equal({ Q: 'Q1', T: 'T1' });
  });

  it('reports a non-zero code when the mint response has code 0 but no sid', async () => {
    const http = async () => ({ data: { code: 0, data: {} } });
    const res = await api.mintSid(http, { region: 'eu1', session: { q: 'Q', t: 'T' }, m2: 'm2' });

    expect(res.code).to.not.equal(0);
    expect(res.sid).to.be.undefined;
  });

  it('returns the sid on a successful mint', async () => {
    const http = async () => ({ data: { code: 0, data: { sid: 'SID123' } } });
    const res = await api.mintSid(http, { region: 'eu1', session: { q: 'Q', t: 'T' }, m2: 'm2' });

    expect(res.code).to.equal(0);
    expect(res.sid).to.equal('SID123');
  });
});
