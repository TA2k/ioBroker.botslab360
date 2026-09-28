'use strict';

const crypto = require('crypto');
const { expect } = require('chai');
const quc = require('./lib/quc');
const api = require('./lib/api');
const china = require('./lib/china');

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

  it('appends a backend secret to the sig base when provided', () => {
    const params = { b: '2', a: '1' };
    const expected = crypto.createHash('md5').update('a=1b=2secret', 'utf8').digest('hex');

    expect(quc.computeSig(params, 'secret')).to.equal(expected);
  });

  it('exposes distinct international and china backend descriptors', () => {
    expect(quc.BACKENDS.international.from).to.equal('mpl_cloudsmartoem_and');
    expect(quc.BACKENDS.international.sigSecret).to.equal('');
    expect(quc.BACKENDS.china.from).to.equal('mpl_smarthome_and');
    expect(quc.BACKENDS.china.sigSecret).to.equal('i7v2m5x6q');
    expect(quc.BACKENDS.china.loginUrl()).to.equal('https://passport.360.cn/request.php');
    expect(quc.backendFor('china').id).to.equal('china');
    expect(quc.backendFor(undefined).id).to.equal('international');
  });
});

describe('China device API', () => {
  it('builds the session cookie only when all fields are present', () => {
    expect(china.sessionCookie({ q: 'Q', t: 'T', qid: '1', sid: 'S' })).to.equal('q=Q;t=T;qid=1;sid=S');
    expect(china.sessionCookie({ q: 'Q', t: 'T', qid: '1' })).to.equal(null);
  });

  it('maps a "<name>-<infoType>" command to a cmd payload', () => {
    expect(china.buildCommand('start-21012')).to.deep.equal({ infoType: '21012', data: '{"cmd":"start"}' });
  });

  it('uses the numeric key itself as infoType for a poll command', () => {
    expect(china.buildCommand('20001')).to.deep.equal({ infoType: '20001', data: '' });
  });

  it('emits the special smartClean payload for infoType 21005', () => {
    const cmd = china.buildCommand('smartClean-21005');
    expect(cmd.infoType).to.equal('21005');
    expect(JSON.parse(cmd.data)).to.deep.equal({ mode: 'smartClean', globalCleanTimes: 1 });
  });

  it('reports the errno when the sid mint is rejected', async () => {
    const http = async () => ({ data: { errno: 102, errmsg: 'expired' } });
    const res = await china.mintSid(http, { session: { q: 'Q', t: 'T', qid: '1' } });

    expect(res.errno).to.equal(102);
    expect(res.sid).to.be.undefined;
  });

  it('returns the sid and pushKey on a successful mint', async () => {
    const http = async () => ({ data: { errno: 0, data: { sid: 'SID', pushKey: 'PK' } } });
    const res = await china.mintSid(http, { session: { q: 'Q', t: 'T', qid: '1' } });

    expect(res.errno).to.equal(0);
    expect(res.sid).to.equal('SID');
    expect(res.pushKey).to.equal('PK');
  });

  it('rejects a mint that has a sid but no pushKey', async () => {
    const http = async () => ({ data: { errno: 0, data: { sid: 'SID' } } });
    const res = await china.mintSid(http, { session: { q: 'Q', t: 'T', qid: '1' } });

    expect(res.errno).to.not.equal(0);
    expect(res.sid).to.be.undefined;
  });

  it('maps an HTTP 401 to the session-expired errno', async () => {
    const http = async () => ({ status: 401, data: '' });
    const res = await china.getDevices(http, { session: { q: 'Q', t: 'T', qid: '1', sid: 'S' } });

    expect(res.errno).to.equal(china.ERRNO_SESSION_EXPIRED);
  });

  it('decodes a push frame into the device sn and status', () => {
    const pushKey = '0123456789abcdefEXTRA';
    const keyIv = Buffer.from(pushKey, 'utf8').subarray(0, 16);
    const status = { battery: 90, mode: 'auto' };
    // The decrypted envelope wraps the status one level below its own data field.
    const envelope = JSON.stringify({ sn: 'SN1', data: JSON.stringify({ data: status }) });
    const cipher = crypto.createCipheriv('aes-128-cbc', keyIv, keyIv);
    const b64 = Buffer.concat([cipher.update(envelope, 'utf8'), cipher.final()]).toString('base64');
    const frame = `\x00\x05\x00\x04{"ack":1, "data": "${b64}", "x":1}`;

    const decoded = china.decodePush(frame, pushKey);
    expect(decoded.sn).to.equal('SN1');
    expect(decoded.status).to.deep.equal(status);
  });

  it('returns null for a push frame without a data payload', () => {
    expect(china.decodePush('{"ack":1}', 'anykey1234567890')).to.equal(null);
    expect(china.decodePush('', 'anykey1234567890')).to.equal(null);
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
