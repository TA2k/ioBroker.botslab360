'use strict';

// China 360 smart-home device API (q.smart.360.cn). Auth is cookie-based (the QUC Q/T/qid
// session plus a server-minted sid); requests are NOT md5-signed. This mirrors the device
// surface the adapter used before the international /v1 migration.
const crypto = require('crypto');

const BASE = 'https://q.smart.360.cn';
const UA = 'QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)';
const LANG = 'de_DE';
const COUNTRY = 'DE';
const FROM = 'mpc_ios';
// v1 SDK login errno meaning the session expired and a fresh QUC login is required.
const ERRNO_SESSION_EXPIRED = 102;

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

function baseHeaders(cookie) {
  return {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: '*/*',
    Connection: 'keep-alive',
    Cookie: cookie,
    'User-Agent': UA,
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
    headers: baseHeaders(`q=${session.q};t=${session.t};qid=${session.qid}`),
    data: new URLSearchParams({
      clientInfo: JSON.stringify({ release: 'appstore', brand: 'iPhone', model: 'iPhone10,5', lang: LANG }),
      lang: LANG,
      phoneNum: '',
      taskid: crypto.randomUUID(),
    }).toString(),
    validateStatus: () => true,
  });
  const errno = Number(res.data && res.data.errno);
  log(`China mintSid POST /common/user/login HTTP ${res.status} errno=${errno}`);
  if (errno !== 0 || !res.data.data || !res.data.data.sid) {
    // errno 0 with a missing sid is still a failure and must not read as success.
    return { errno: Number.isFinite(errno) && errno !== 0 ? errno : -1, errmsg: (res.data && res.data.errmsg) || 'sid mint failed' };
  }
  return { errno: 0, sid: res.data.data.sid, pushKey: res.data.data.pushKey };
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
 * Decode one push frame's JSON text into the device state it carries.
 * The frame body embeds an AES-128-CBC (key=IV=first 16 bytes of pushKey), PKCS7-padded,
 * base64 payload as `data":"<b64>",`. The decrypted plaintext is JSON `{ sn, data }`, where
 * `data` is itself a JSON string of the status object.
 * @returns {{ sn: string, status: object } | null}
 */
function decodePush(dataString, pushKey) {
  if (!dataString || !pushKey) {
    return null;
  }
  const marker = dataString.split('data":"');
  if (marker.length < 2) {
    return null;
  }
  const b64 = marker[1].split('",')[0];
  if (!b64) {
    return null;
  }
  const keyIv = Buffer.from(pushKey.substring(0, 16));
  const decipher = crypto.createDecipheriv('aes-128-cbc', keyIv, keyIv);
  const plain = Buffer.concat([decipher.update(Buffer.from(b64, 'base64')), decipher.final()]).toString('utf8');
  const frame = JSON.parse(plain);
  if (!frame || !frame.sn) {
    return null;
  }
  const status = typeof frame.data === 'string' ? JSON.parse(frame.data) : frame.data;
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
  return { errno: Number.isFinite(errno) ? errno : -1, errmsg: res.data && res.data.errmsg, data: res.data && res.data.data };
}

module.exports = {
  mintSid,
  getDevices,
  sendCommand,
  buildCommand,
  decodePush,
  sessionCookie,
  REMOTE_COMMANDS,
  ERRNO_SESSION_EXPIRED,
  PUSH_HOST,
  PUSH_PORT,
};
