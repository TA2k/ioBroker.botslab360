'use strict';

// China 360 smart-home device API (q.smart.360.cn). Auth is cookie-based (the QUC Q/T/qid
// session plus a server-minted sid); requests are NOT md5-signed. This mirrors the device
// surface the adapter used before the international /v1 migration.
const crypto = require('crypto');

const BASE = 'https://q.smart.360.cn';
const UA = 'QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)';
// The sid mint endpoint expects the app's login User-Agent rather than the browsing UA.
const MINT_UA = 'qhsa-iphone-11.1.0';
const LANG = 'de_DE';
const COUNTRY = 'DE';
const FROM = 'mpc_ios';
// v1 SDK login errnos meaning the session is no longer accepted and a fresh QUC login is
// required. 102 and 103 are both returned for an expired/invalid session.
const ERRNO_SESSION_EXPIRED = 102;
const SESSION_EXPIRED_ERRNOS = [102, 103];

function isSessionExpired(errno) {
  return SESSION_EXPIRED_ERRNOS.includes(Number(errno));
}

// Live device state is delivered asynchronously over a persistent TCP push socket, not in
// the /clean/cmd/send response (which only acknowledges). The cmd calls (20001, 21015,
// 30000, ...) trigger the device to emit a push frame on this channel.
const PUSH_HOST = '47.254.151.104';
const PUSH_PORT = 443;

// Remote command states exposed per device. A key of the form "<name>-<infoType>" sends
// {"cmd":"<name>"} with that infoType; a purely numeric key is itself the infoType (a
// read/poll command). Special payloads are handled in buildCommand().
const REMOTE_COMMANDS = [
  { command: 'Refresh', name: 'True = Refresh' },
  { command: 'start-21012', name: 'Start Charging' },
  { command: 'smartClean-21005', name: 'Start Cleaning' },
  { command: 'pause-21017', name: 'Pause' },
  { command: 'continue-21017', name: 'Continue' },
  { command: 'auto-21022', name: 'Auto Mode' },
  { command: 'quiet-21022', name: 'Quiet Mode' },
  { command: 'strong-21022', name: 'Strong Mode' },
  { command: '21015', name: 'getConsumableInfo' },
  { command: '20001', name: 'getStatus' },
  { command: '30000', name: 'getMap' },
];

function baseHeaders(cookie, ua) {
  return {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: '*/*',
    Connection: 'keep-alive',
    Cookie: cookie,
    'User-Agent': ua || UA,
    'Accept-Language': 'de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8',
  };
}

// Cookie for calls after the sid has been minted.
function sessionCookie(session) {
  if (!session || !session.q || !session.t || !session.qid || !session.sid) {
    return null;
  }
  return `q=${session.q};t=${session.t};qid=${session.qid};sid=${session.sid}`;
}

/**
 * Exchange a QUC Q/T/qid session for a smart-home sid.
 * @returns {Promise<{ errno: number, sid?: string, pushKey?: string, errmsg?: string }>}
 */
async function mintSid(http, { session, debug }) {
  const log = debug || (() => {});
  const res = await http({
    method: 'post',
    url: `${BASE}/common/user/login`,
    headers: baseHeaders(`q=${session.q};t=${session.t};qid=${session.qid}`, MINT_UA),
    data: new URLSearchParams({
      clientInfo: JSON.stringify({
        release: 'appstore',
        brand: 'iPhone',
        model: 'iPhone10,5',
        notifyId: 'aa0ad645269de676a5ee6a728ba13b777ed3d4aa4d0e08a578097fbe78768b02',
        lang: LANG,
        imei: 'f3bc82b802bd91a51d0dcc6499efeba3',
      }),
      lang: LANG,
      phoneNum: '',
      taskid: crypto.randomUUID(),
    }).toString(),
    validateStatus: () => true,
  });
  const errno = Number(res.data && res.data.errno);
  log(`China mintSid POST /common/user/login HTTP ${res.status} errno=${errno}`);
  if (res.status === 401) {
    return { errno: ERRNO_SESSION_EXPIRED, errmsg: 'unauthorized' };
  }
  const data = res.data && res.data.data;
  if (errno !== 0 || !data || !data.sid || !data.pushKey) {
    // errno 0 with a missing sid or pushKey is still a failure: without the pushKey every
    // push update would be acknowledged and then silently dropped (no decryption key).
    return { errno: Number.isFinite(errno) && errno !== 0 ? errno : -1, errmsg: (res.data && res.data.errmsg) || 'sid mint failed' };
  }
  return { errno: 0, sid: data.sid, pushKey: data.pushKey };
}

/**
 * List the account's devices.
 * @returns {Promise<{ errno: number, list: object[], errmsg?: string }>}
 */
async function getDevices(http, { session, debug }) {
  const log = debug || (() => {});
  const cookie = sessionCookie(session);
  const res = await http({
    method: 'post',
    url: `${BASE}/common/dev/GetList`,
    headers: baseHeaders(cookie),
    data: new URLSearchParams({
      countryId: COUNTRY,
      devType: '3',
      from: FROM,
      lang: LANG,
      taskid: crypto.randomUUID(),
    }).toString(),
    validateStatus: () => true,
  });
  const errno = Number(res.data && res.data.errno);
  log(`China getDevices POST /common/dev/GetList HTTP ${res.status} errno=${errno}`);
  if (res.status === 401) {
    return { errno: ERRNO_SESSION_EXPIRED, list: [], errmsg: 'unauthorized' };
  }
  if (errno !== 0) {
    return { errno: Number.isFinite(errno) ? errno : -1, list: [], errmsg: res.data && res.data.errmsg };
  }
  return { errno: 0, list: (res.data.data && res.data.data.list) || [] };
}

// Translate a remote command key into the {infoType, data} pair the cmd endpoint expects.
function buildCommand(commandKey) {
  const parts = commandKey.split('-');
  const name = parts[0];
  let infoType = parts[1];
  let data = '';
  if (isNaN(Number(name))) {
    data = JSON.stringify({ cmd: name });
  } else {
    infoType = name;
  }
  if (infoType === '21005') {
    data = JSON.stringify({ mode: 'smartClean', globalCleanTimes: 1 });
  } else if (infoType === '30000') {
    data = JSON.stringify({
      cmds: [
        { data: {}, infoType: '20001' },
        { data: {}, infoType: '21014' },
        { data: { mask: 0, startPos: 0, userId: 0 }, infoType: '21011' },
      ],
      mainCmds: [],
    });
  }
  return { infoType, data };
}

/**
 * Decode one push frame's text into the device state it carries.
 * The frame embeds an AES-128-CBC (key=IV=first 16 bytes of pushKey), PKCS7-padded, base64
 * payload in its `data` field. The decrypted plaintext is JSON `{ sn, data }`, where `data`
 * is itself a JSON string wrapping the status object as `{ data: { ...status } }`.
 * @returns {{ sn: string, status: object } | null}
 */
function decodePush(dataString, pushKey) {
  if (!dataString || !pushKey) {
    return null;
  }
  // Tolerate optional whitespace after the colon; the binary frame header precedes the JSON.
  const match = dataString.match(/"data"\s*:\s*"([^"]*)"/);
  if (!match || !match[1]) {
    return null;
  }
  const keyIv = Buffer.from(pushKey, 'utf8').subarray(0, 16);
  if (keyIv.length !== 16) {
    return null;
  }
  const decipher = crypto.createDecipheriv('aes-128-cbc', keyIv, keyIv);
  const plain = Buffer.concat([decipher.update(Buffer.from(match[1], 'base64')), decipher.final()]).toString('utf8');
  const frame = JSON.parse(plain);
  if (!frame || !frame.sn) {
    return null;
  }
  const body = typeof frame.data === 'string' ? JSON.parse(frame.data) : frame.data;
  // The status object sits one level below the envelope's own `data` wrapper.
  const status = body && body.data != null ? body.data : body;
  return { sn: frame.sn, status };
}

/**
 * Send a device command (or a status poll: infoType 20001, data empty).
 * @returns {Promise<{ errno: number, errmsg?: string, data?: object }>}
 */
async function sendCommand(http, { session, sn, infoType, data, debug }) {
  const log = debug || (() => {});
  const cookie = sessionCookie(session);
  const res = await http({
    method: 'post',
    url: `${BASE}/clean/cmd/send`,
    headers: baseHeaders(cookie),
    data: new URLSearchParams({
      countryId: COUNTRY,
      data: data || '',
      devType: '3',
      from: FROM,
      infoType: infoType,
      lang: LANG,
      sn: sn,
      taskid: crypto.randomUUID(),
    }).toString(),
    validateStatus: () => true,
  });
  const errno = Number(res.data && res.data.errno);
  log(`China sendCommand POST /clean/cmd/send sn=${sn} infoType=${infoType} HTTP ${res.status} errno=${errno}`);
  if (res.status === 401) {
    return { errno: ERRNO_SESSION_EXPIRED, errmsg: 'unauthorized' };
  }
  return { errno: Number.isFinite(errno) ? errno : -1, errmsg: res.data && res.data.errmsg, data: res.data && res.data.data };
}

module.exports = {
  mintSid,
  getDevices,
  sendCommand,
  buildCommand,
  decodePush,
  sessionCookie,
  isSessionExpired,
  REMOTE_COMMANDS,
  ERRNO_SESSION_EXPIRED,
  PUSH_HOST,
  PUSH_PORT,
};
