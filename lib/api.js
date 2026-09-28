'use strict';

// Signed access to the modern botslab /v1 IoT API. Every request carries sign query
// params (appkey + md5 signature over a stable device UUID) and an Authorization header
// that packs the QUC Q/T session plus the server-minted sid as a base64 "jws" blob.
const crypto = require('crypto');

const APPKEY = 'botslabadr';
const APPSECRET = 'qihu_adr_3afg139513ksgnlah1951365saa351a9z_360';

function md5Hex(str) {
  return crypto.createHash('md5').update(Buffer.from(str, 'utf8')).digest('hex');
}

function apiHost(region) {
  return `https://${region}-sapp-api.botslab.com`;
}

// sign = md5(appkey + m2 + sign_ts + sign_no + appSecret); sign/ts/no are added to the
// query only after hashing.
function signParams(m2) {
  const signTs = String(Math.floor(Date.now() / 1000));
  const signNo = crypto.randomUUID().replace(/-/g, '');
  const sign = md5Hex(APPKEY + m2 + signTs + signNo + APPSECRET);
  return {
    appkey: APPKEY,
    m2,
    sign,
    sign_ts: signTs,
    sign_no: signNo,
    ci_net: 'wifi',
    ci_model: 'sdk_gphone64_arm64',
    ci_lang: 'en',
    appver: '2.24.0',
    ci_cy: 'US',
    appch: 'formal',
    app_type_id: '1',
    ci_brand: 'google',
    ci_osver: '13',
    appflag: 'botslab',
    ci_tz: 'UTC+0',
  };
}

function jwsHeader(session) {
  const payload = { Q: session.q, T: session.t };
  if (session.sid) payload.sid = session.sid;
  return 'jws ' + Buffer.from(JSON.stringify(payload)).toString('base64');
}

/**
 * Exchange a fresh Q/T session for a sid.
 * @returns {Promise<{ code: number, sid?: string, msg?: string }>}
 */
async function mintSid(http, { region, session, m2, debug }) {
  const log = debug || (() => {});
  const qs = new URLSearchParams(signParams(m2)).toString();
  const res = await http({
    method: 'post',
    url: `${apiHost(region)}/v1/app/login?${qs}`,
    data: '',
    headers: { Authorization: jwsHeader({ q: session.q, t: session.t }), 'Content-Length': '0', 'User-Agent': 'okhttp/4.9.3' },
    validateStatus: () => true,
  });
  const code = Number(res.data && res.data.code);
  log(`mintSid POST ${apiHost(region)}/v1/app/login HTTP ${res.status} code=${code}`);
  if (code !== 0 || !res.data.data || !res.data.data.sid) {
    // A missing sid on an otherwise-ok response must not be reported as success.
    return { code: code || -1, msg: (res.data && res.data.msg) || 'sid mint failed' };
  }
  return { code: 0, sid: res.data.data.sid };
}

/**
 * Perform a signed /v1 request. `session` must carry q, t and sid.
 */
async function request(http, { region, method, path, session, m2, data, debug }) {
  const log = debug || (() => {});
  const qs = new URLSearchParams(signParams(m2)).toString();
  const res = await http({
    method,
    url: `${apiHost(region)}${path}${path.includes('?') ? '&' : '?'}${qs}`,
    data: data != null ? data : undefined,
    headers: {
      Authorization: jwsHeader(session),
      'Content-Type': 'application/json',
      'User-Agent': 'okhttp/4.9.3',
    },
    validateStatus: () => true,
  });
  log(`${String(method).toUpperCase()} ${path} region=${region} HTTP ${res.status} code=${res.data && res.data.code}`);
  return res.data;
}

module.exports = { signParams, jwsHeader, mintSid, request, APPKEY, APPSECRET };
