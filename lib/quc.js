'use strict';

// Headless 360 QUC account login ("So" envelope protocol, com.qihoo360.accounts SDK
// v3.2.4.6). Email/password are encrypted into a DES envelope whose key is delivered
// RSA-encrypted, yielding the Q/T session cookies. DES is done with jscrypto so no
// OpenSSL legacy provider is required at runtime; RSA and MD5 use the default provider.
const crypto = require('crypto');
const JsCrypto = require('jscrypto');

// QUC 1024-bit RSA public key (X.509 DER), exponent 65537.
const RSA_DER_HEX =
  '30819f300d06092a864886f70d010101050003818d0030818902818100bda0d6470d7c86c4d35f0617e4ffe580b635444f5b0b590ada0c12c7774f36d4ec38ca9ea9fb3bc707ac9749412ddbf94b556ed0d3f4551eec67c2d83a70a61d0c89ea3339d22c82a35cf91de837dfb7c9f3f2f90e752525cd0b44dd3e1dbda6a06c7efa941181db0b8b34e5740f651c532bd1bb6a6e2ad623803366fced1aa50203010001';
const RSA_KEY = crypto.createPublicKey({ key: Buffer.from(RSA_DER_HEX, 'hex'), format: 'der', type: 'spki' });

const QUC_UA = '360accounts andv3.2.4.6 mpl_cloudsmartoem_and';
const FROM = 'mpl_cloudsmartoem_and';
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// Server errno signalling that a graphic captcha must be solved.
const ERRNO_CAPTCHA = 5010;
// Server errno for "the account does not exist" on this region's login host.
const ERRNO_ACCOUNT_NOT_FOUND = 1036;

function md5Hex(str) {
  return crypto.createHash('md5').update(Buffer.from(str, 'utf8')).digest('hex');
}

function randomAscii(len) {
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += ALPHA[bytes[i] % ALPHA.length];
  return out;
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

// sig = md5(all params except sig, sorted by key, joined as key=value with no separator,
// raw decoded values). Uppercase sorts before lowercase (default code-point order).
function computeSig(params) {
  const keys = Object.keys(params)
    .filter((k) => k !== 'sig')
    .sort();
  let base = '';
  for (const key of keys) base += key + '=' + params[key];
  return md5Hex(base);
}

function desEncryptB64(plainText, key8) {
  const kw = JsCrypto.Utf8.parse(key8);
  const enc = JsCrypto.DES.encrypt(JsCrypto.Utf8.parse(plainText), kw, {
    iv: kw,
    mode: JsCrypto.mode.CBC,
    padding: JsCrypto.pad.Pkcs7,
  });
  return enc.cipherText.toString(JsCrypto.Base64);
}

function desDecryptUtf8(b64, key8) {
  const kw = JsCrypto.Utf8.parse(key8);
  const dec = JsCrypto.DES.decrypt(new JsCrypto.CipherParams({ cipherText: JsCrypto.Base64.parse(b64) }), kw, {
    iv: kw,
    mode: JsCrypto.mode.CBC,
    padding: JsCrypto.pad.Pkcs7,
  });
  return dec.toString(JsCrypto.Utf8);
}

// Wrap login params into the transport envelope: parad (DES payload) + key (RSA-wrapped
// DES key). The DES key/IV are the last 8 bytes of a random ASCII key string.
function buildEnvelope(params) {
  const paramString = Object.keys(params)
    .map((k) => k + '=' + encodeURIComponent(params[k]))
    .join('&');
  const keyString = randomAscii(106) + randomAscii(8);
  const desKey = keyString.slice(-8);
  const parad = desEncryptB64(paramString, desKey);
  const key = crypto
    .publicEncrypt({ key: RSA_KEY, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(keyString, 'utf8'))
    .toString('base64');
  return { parad, key, desKey };
}

// Stable per-install device fingerprint. Randomising this on every request makes the
// risk engine treat each login as a new device and forces a captcha, so it is generated
// once and persisted by the caller.
function createDeviceIdentity() {
  return {
    mid: randomHex(16),
    androidid: randomHex(8),
    m2: crypto.randomUUID(),
  };
}

function baseDeviceParams(device) {
  return {
    os_sdk_version: 'android_33',
    mid: device.mid,
    quc_sdk_version: 'v3.2.4.6',
    mname: '',
    ua: 'Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.240213.009)',
    os_manufacturer: 'Google',
    mSystemVersion: 'android 13',
    os_board: 'goldfish_arm64',
    os_model: 'sdk_gphone64_arm64',
    quc_lang: 'en',
    sh: '2337.0',
    from: FROM,
    oaid: '',
    app: 'Botslab',
    ui_ver: '4.3.4.1-alert-ui',
    res_mode: '1',
    sw: '1080.0',
    format: 'json',
    qh_id: '',
    device_os: 'android',
    device_lang: 'zh-CN',
    v: '2.24.0',
    androidid: device.androidid,
    sdpi: '2.625',
  };
}

function loginUrl(region) {
  return `https://${region}-sapp-login.botslab.com/request.php`;
}

/**
 * Perform an email/password QUC login.
 * @param {import('axios').AxiosInstance} http
 * @param {{ region: string, email: string, password: string, device: { mid: string, androidid: string, m2: string }, needDeviceCheck?: number, captcha?: { sc: string, code: string }, debug?: (msg: string) => void }} opts
 * @returns {Promise<object>} { errno, errmsg, captchaRequired, captchaType, q, t, qid }
 */
async function login(http, opts) {
  const debug = opts.debug || (() => {});
  const nowMs = Date.now();
  const params = {
    ...baseDeviceParams(opts.device),
    loginType: '801',
    vt_guid: String(nowMs),
    is_keep_alive: '1',
    needDeviceCheck: String(opts.needDeviceCheck != null ? opts.needDeviceCheck : 0),
    trace_id: 'src_and_1916_' + nowMs,
    method: 'UserIntf.login',
    head_type: 'q',
    sec_type: 'bool',
    fields: 'qid,username,nickname,loginemail,head_pic,mobile',
    username: opts.email,
    password: md5Hex(opts.password),
  };
  if (opts.captcha && opts.captcha.sc && opts.captcha.code) {
    params.sc = opts.captcha.sc;
    params.uc = opts.captcha.code;
    params.captchaType = 'graph';
  }
  params.sig = computeSig(params);

  const env = buildEnvelope(params);
  const body = new URLSearchParams({
    device_lang: 'zh-CN',
    trace_id: params.trace_id,
    quc_lang: 'en',
    method: 'UserIntf.login',
    from: FROM,
    parad: env.parad,
    key: env.key,
  }).toString();

  const res = await http({
    method: 'post',
    url: loginUrl(opts.region),
    data: body,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': QUC_UA, Connection: 'close' },
    validateStatus: () => true,
  });
  debug(`QUC login POST ${loginUrl(opts.region)} needDeviceCheck=${params.needDeviceCheck} captcha=${!!(opts.captcha && opts.captcha.code)} HTTP ${res.status} hasRet=${!!(res.data && res.data.ret)}`);
  if (!res.data || !res.data.ret) {
    return { errno: -1, errmsg: 'empty login response' };
  }
  const decoded = JSON.parse(desDecryptUtf8(res.data.ret, env.desKey));
  const errno = Number(decoded.errno);
  debug(`QUC login response errno=${errno}${decoded.errmsg ? ' errmsg=' + decoded.errmsg : ''}`);
  if (errno === ERRNO_CAPTCHA) {
    return {
      errno,
      errmsg: decoded.errmsg,
      captchaRequired: true,
      captchaType: (decoded.errdetail && decoded.errdetail.captchaType) || 'graph',
    };
  }
  if (errno !== 0 || !decoded.user) {
    return { errno, errmsg: decoded.errmsg || 'login failed' };
  }
  return {
    errno: 0,
    q: decodeURIComponent(decoded.user.q),
    t: decodeURIComponent(decoded.user.t),
    qid: String(decoded.user.qid),
  };
}

/**
 * Fetch a graphic captcha image. The token is returned in the response header and must
 * be echoed back (together with the user-entered code) on the next login attempt.
 * @param {import('axios').AxiosInstance} http
 * @param {{ region: string, device: { mid: string, androidid: string, m2: string }, debug?: (msg: string) => void }} opts
 * @returns {Promise<{ image: Buffer, sc: string }>}
 */
async function getCaptcha(http, opts) {
  const debug = opts.debug || (() => {});
  const nowMs = Date.now();
  const params = {
    ...baseDeviceParams(opts.device),
    vt_guid: String(nowMs),
    trace_id: 'src_and_1916_' + nowMs,
    method: 'UserIntf.getCaptcha',
  };
  params.sig = computeSig(params);
  const env = buildEnvelope(params);
  const body = new URLSearchParams({
    device_lang: 'zh-CN',
    trace_id: params.trace_id,
    quc_lang: 'en',
    method: 'UserIntf.getCaptcha',
    from: FROM,
    parad: env.parad,
    key: env.key,
  }).toString();

  const res = await http({
    method: 'post',
    url: loginUrl(opts.region),
    data: body,
    responseType: 'arraybuffer',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': QUC_UA, Connection: 'close' },
    validateStatus: () => true,
  });
  const rawSc = res.headers['sc'] || res.headers['Sc'] || '';
  const image = Buffer.from(res.data);
  debug(`QUC getCaptcha POST ${loginUrl(opts.region)} HTTP ${res.status} bytes=${image.length} sc=${rawSc ? 'yes' : 'no'}`);
  return { image, sc: decodeURIComponent(rawSc) };
}

module.exports = {
  login,
  getCaptcha,
  createDeviceIdentity,
  computeSig,
  desEncryptB64,
  desDecryptUtf8,
  ERRNO_CAPTCHA,
  ERRNO_ACCOUNT_NOT_FOUND,
};
