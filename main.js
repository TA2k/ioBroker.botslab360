'use strict';

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

const net = require('net');
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const Json2iob = require('json2iob');
const quc = require('./lib/quc');
const api = require('./lib/api');
const china = require('./lib/china');

const REGIONS = ['na1', 'eu1', 'ap1'];
// v1 codes that mean the session is no longer accepted and a fresh login is required.
const AUTH_FAILURE_CODES = [100003];

class Botslab360 extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: 'botslab360',
    });
    this.on('ready', this.onReady.bind(this));
    this.on('stateChange', this.onStateChange.bind(this));
    this.on('unload', this.onUnload.bind(this));
    this.deviceArray = [];
    this.session = {};
    this.device = null;
    this.pendingCaptcha = null;
    this.started = false;
    this.pushClient = null;
    this.pushBuffer = '';
    this.pushReconnecting = false;
    this.unloaded = false;
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create();
  }

  async onReady() {
    this.setState('info.connection', false, true);

    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    this.isChina = this.config.server === 'china';
    if (!this.isChina && !REGIONS.includes(this.config.region)) {
      this.config.region = 'eu1';
    }
    if (!this.config.email || !this.config.password) {
      this.log.error('Please enter your 360/Botslab account email and password in the instance settings');
      return;
    }

    this.subscribeStates('*');
    await this.ensureInfoObjects();
    this.device = await this.loadDeviceIdentity();
    this.log.debug(`Configured server=${this.isChina ? 'china' : 'international'}, region=${this.config.region}, interval=${this.config.interval} min`);
    this.log.debug(`Device identity mid=${this.device.mid} androidid=${this.device.androidid} m2=${this.device.m2}`);

    if (!(await this.login())) {
      return;
    }
  }

  // Discovery, polling and session refresh. Runs once after the first successful login
  // (initial or after a solved captcha), so recovering from a captcha resumes the adapter
  // while the periodic re-login does not restart discovery.
  async startOnce() {
    if (this.started) {
      return;
    }
    this.started = true;
    await this.getDeviceList();
    await this.updateDevices();
    this.updateInterval = setInterval(
      async () => {
        await this.updateDevices();
      },
      this.config.interval * 60 * 1000,
    );
    // Refresh the session periodically; the sid is cheap to re-mint with the stable device.
    this.refreshTokenInterval = setInterval(
      () => {
        this.login();
      },
      12 * 60 * 60 * 1000,
    );
  }

  async ensureInfoObjects() {
    await this.setObjectNotExistsAsync('info.deviceId', {
      type: 'state',
      common: { name: 'Persisted device fingerprint', type: 'string', role: 'text', read: true, write: false },
      native: {},
    });
    await this.setObjectNotExistsAsync('info.captchaImage', {
      type: 'state',
      common: { name: 'Captcha image (data URL) to solve', type: 'string', role: 'text', read: true, write: false },
      native: {},
    });
    await this.setObjectNotExistsAsync('info.captchaRequest', {
      type: 'state',
      common: { name: 'Write the solved captcha code here to continue login', type: 'string', role: 'text', read: true, write: true },
      native: {},
    });
  }

  // A stable device fingerprint avoids the risk engine treating every login as a new
  // device (which forces a captcha). It is generated once and kept across restarts.
  async loadDeviceIdentity() {
    const state = await this.getStateAsync('info.deviceId');
    if (state && typeof state.val === 'string' && state.val) {
      try {
        const parsed = JSON.parse(state.val);
        if (parsed && parsed.mid && parsed.androidid && parsed.m2) {
          return parsed;
        }
      } catch {
        // fall through and regenerate
      }
    }
    const device = quc.createDeviceIdentity();
    await this.setStateAsync('info.deviceId', JSON.stringify(device), true);
    return device;
  }

  /**
   * Log in with email/password and mint a session id. When a captcha is required the
   * image is exposed via info.captchaImage and the solved code is read back from
   * info.captchaRequest.
   * @param {string} [captchaCode]
   */
  async login(captchaCode) {
    // A captcha is already waiting for the user; suppress automatic logins (periodic
    // refresh, auth-failure retries) that would overwrite its image and sc token.
    if (this.pendingCaptcha && !captchaCode) {
      this.log.debug('Captcha pending; deferring login until the solved code is provided');
      return false;
    }
    const backend = quc.backendFor(this.config.server);
    const opts = {
      backend: backend.id,
      email: String(this.config.email).trim(),
      password: String(this.config.password),
      device: this.device,
      needDeviceCheck: 0,
      debug: (m) => this.log.debug(m),
    };
    if (this.pendingCaptcha && captchaCode) {
      opts.captcha = { sc: this.pendingCaptcha.sc, code: String(captchaCode).trim() };
    }

    // China logs in against a single host (no region). International tries the configured
    // region first and falls through the others on a "account does not exist" errno, since
    // the login host is region-scoped. On a captcha retry the region is already fixed.
    const regionsToTry = !backend.regional
      ? [null]
      : this.pendingCaptcha && captchaCode
        ? [this.config.region]
        : [this.config.region, ...REGIONS.filter((r) => r !== this.config.region)];

    let result;
    let usedRegion = this.config.region;
    for (let i = 0; i < regionsToTry.length; i++) {
      const region = regionsToTry[i];
      this.log.debug(`Login attempt server=${backend.id} region=${region} email=${opts.email} captchaCode=${captchaCode ? 'yes' : 'no'}`);
      try {
        result = await quc.login(this.requestClient, { ...opts, region });
      } catch (error) {
        this.log.error(`360 login request failed (${this.getRequestFailure(error)})`);
        return false;
      }
      usedRegion = region;
      if (backend.regional && result.errno === backend.errnoAccountNotFound && i < regionsToTry.length - 1) {
        this.log.info(`Account not found on region ${region}, trying the next region`);
        continue;
      }
      break;
    }

    // Adopt the region that answered, so mintSid and every later /v1 call use the same
    // host. This is a session switch; update the instance setting to make it permanent.
    if (backend.regional && usedRegion !== this.config.region) {
      this.log.info(`Account found on region ${usedRegion}; using it for this session. Set region=${usedRegion} in the instance settings to make it permanent.`);
      this.config.region = usedRegion;
    }
    const region = this.config.region;

    if (result.captchaRequired) {
      await this.requestCaptcha(region);
      return false;
    }
    if (result.errno !== 0) {
      this.log.error(`360 login failed (errno ${result.errno}${result.errmsg ? ': ' + result.errmsg : ''})`);
      this.setState('info.connection', false, true);
      return false;
    }

    this.pendingCaptcha = null;
    if (!(await this.mintSession(result))) {
      return false;
    }

    this.setState('info.connection', true, true);
    this.log.info('360 login successful');
    await this.startOnce();
    return true;
  }

  // Exchange the QUC Q/T/qid for a session id on the active backend and store the session.
  async mintSession(result) {
    if (this.isChina) {
      let mint;
      try {
        mint = await china.mintSid(this.requestClient, { session: { q: result.q, t: result.t, qid: result.qid }, debug: (m) => this.log.debug(m) });
      } catch (error) {
        this.log.error(`Session mint request failed (${this.getRequestFailure(error)})`);
        return false;
      }
      if (mint.errno !== 0) {
        this.log.error(`Session mint was rejected (errno ${mint.errno}${mint.errmsg ? ': ' + mint.errmsg : ''})`);
        return false;
      }
      this.session = { q: result.q, t: result.t, qid: result.qid, sid: mint.sid, pushKey: mint.pushKey };
      this.connectChinaPush();
      return true;
    }

    let mint;
    try {
      mint = await api.mintSid(this.requestClient, { region: this.config.region, session: { q: result.q, t: result.t }, m2: this.device.m2, debug: (m) => this.log.debug(m) });
    } catch (error) {
      this.log.error(`Session mint request failed (${this.getRequestFailure(error)})`);
      return false;
    }
    if (mint.code !== 0) {
      this.log.error(`Session mint was rejected (code ${mint.code}${mint.msg ? ': ' + mint.msg : ''})`);
      return false;
    }
    this.session = { q: result.q, t: result.t, qid: result.qid, sid: mint.sid };
    return true;
  }

  async requestCaptcha(region) {
    try {
      const captcha = await quc.getCaptcha(this.requestClient, { backend: this.config.server, region, device: this.device, debug: (m) => this.log.debug(m) });
      this.pendingCaptcha = { sc: captcha.sc };
      const b64 = captcha.image.toString('base64');
      await this.setStateAsync('info.captchaImage', 'data:image/jpeg;base64,' + b64, true);
      this.log.debug(`Captcha fetched: image ${captcha.image.length} bytes, sc length ${captcha.sc ? captcha.sc.length : 0}`);
      this.log.warn(
        'A captcha is required to log in. Open the image stored in state info.captchaImage (paste the data URL into a browser) and write the solved code to state info.captchaRequest.',
      );
      // Also emit the image inline in the log, so it can be read straight from the
      // downloaded log file without opening the state.
      this.log.info('Press on Log download/Protokolle -> Log herunterladen to see the captcha:');
      this.log.warn("<html><img src='data:image/jpeg;base64," + b64 + "' /></html>");
    } catch (error) {
      this.log.error(`Could not fetch captcha (${this.getRequestFailure(error)})`);
    }
  }

  getRequestFailure(error) {
    if (error && error.response && Number.isInteger(error.response.status)) {
      return `HTTP ${error.response.status}`;
    }
    if (error && typeof error.code === 'string' && /^[A-Z0-9_]+$/.test(error.code)) {
      return error.code;
    }
    return 'request failed';
  }

  // Re-login on an authentication failure, then run the given retry once.
  async handleAuthFailure(retry) {
    this.log.info('Session rejected, logging in again');
    if (await this.login()) {
      if (retry) {
        await retry();
      }
    } else {
      this.setState('info.connection', false, true);
      if (this.pendingCaptcha) {
        this.log.warn('Re-login needs a captcha: the pending request was dropped and must be repeated after solving info.captchaRequest');
      }
    }
  }

  async getDeviceList(retried = false) {
    if (this.isChina) {
      return this.getDeviceListChina();
    }
    let res;
    try {
      res = await api.request(this.requestClient, {
        region: this.config.region,
        method: 'get',
        path: '/v1/iot/device/list',
        session: this.session,
        m2: this.device.m2,
        debug: (m) => this.log.debug(m),
      });
    } catch (error) {
      this.log.error(`Device list request failed (${this.getRequestFailure(error)})`);
      return;
    }
    if (res && AUTH_FAILURE_CODES.includes(Number(res.code))) {
      if (!retried) {
        await this.handleAuthFailure(() => this.getDeviceList(true));
      } else {
        this.log.error('Device list still unauthorized after re-login');
      }
      return;
    }
    if (!res || Number(res.code) !== 0) {
      this.log.error(`Device list failed (code ${res && res.code}${res && res.msg ? ': ' + res.msg : ''})`);
      return;
    }

    this.log.debug(`Device list raw response: ${JSON.stringify(res)}`);
    const devices = (res.data && res.data.devices) || [];
    this.log.info(`Found ${devices.length} devices`);
    for (const device of devices) {
      const id = String(device.sn || device.did || device.device_id || '').trim();
      if (!id) {
        this.log.debug('Skipping device without an id: ' + JSON.stringify(device));
        continue;
      }
      this.deviceArray.push(id);
      const name = device.nickname || device.device_name || device.model || id;

      await this.setObjectNotExistsAsync(id, {
        type: 'device',
        common: { name },
        native: {},
      });
      await this.setObjectNotExistsAsync(id + '.remote', {
        type: 'channel',
        common: { name: 'Remote Controls' },
        native: {},
      });

      const remoteArray = [
        { command: 'Refresh', name: 'True = Refresh', type: 'boolean', role: 'button', def: false },
        {
          command: 'set_property',
          name: 'Set properties (JSON array, e.g. [{"siid":2,"piid":2,"value":1}])',
          type: 'string',
          role: 'json',
          def: '',
        },
        {
          command: 'invoke_service',
          name: 'Invoke a service (JSON, e.g. {"siid":2,"aiid":1,"params":[]})',
          type: 'string',
          role: 'json',
          def: '',
        },
      ];
      for (const remote of remoteArray) {
        await this.setObjectNotExistsAsync(id + '.remote.' + remote.command, {
          type: 'state',
          common: {
            name: remote.name,
            type: remote.type,
            role: remote.role,
            def: remote.def,
            write: true,
            read: true,
          },
          native: {},
        });
      }
      this.json2iob.parse(id + '.general', device, { forceIndex: true, channelName: 'Device information' });
    }
  }

  async updateDevices(retried = false) {
    if (this.isChina) {
      return this.updateDevicesChina();
    }
    for (const id of this.deviceArray) {
      let res;
      try {
        res = await api.request(this.requestClient, {
          region: this.config.region,
          method: 'post',
          path: '/v1/iot/device/get_info',
          session: this.session,
          m2: this.device.m2,
          data: JSON.stringify({ device_id: id }),
          debug: (m) => this.log.debug(m),
        });
      } catch (error) {
        this.log.error(`Update request failed (${this.getRequestFailure(error)})`);
        continue;
      }
      if (res && AUTH_FAILURE_CODES.includes(Number(res.code))) {
        if (!retried) {
          await this.handleAuthFailure(() => this.updateDevices(true));
        } else {
          this.log.error('Device update still unauthorized after re-login');
        }
        return;
      }
      if (!res || Number(res.code) !== 0) {
        this.log.debug(`Update for ${id} returned code ${res && res.code}`);
        continue;
      }
      this.log.debug(`get_info raw response for ${id}: ${JSON.stringify(res)}`);
      this.json2iob.parse(id + '.status', res.data, { forceIndex: true, channelName: 'Status of the device' });
    }
  }

  async getDeviceListChina(retried = false) {
    let res;
    try {
      res = await china.getDevices(this.requestClient, { session: this.session, debug: (m) => this.log.debug(m) });
    } catch (error) {
      this.log.error(`Device list request failed (${this.getRequestFailure(error)})`);
      return;
    }
    if (res.errno === china.ERRNO_SESSION_EXPIRED) {
      if (!retried) {
        await this.handleAuthFailure(() => this.getDeviceListChina(true));
      } else {
        this.log.error('Device list still unauthorized after re-login');
      }
      return;
    }
    if (res.errno !== 0) {
      this.log.error(`Device list failed (errno ${res.errno}${res.errmsg ? ': ' + res.errmsg : ''})`);
      return;
    }

    this.log.info(`Found ${res.list.length} devices`);
    for (const device of res.list) {
      const id = String(device.sn || '').trim();
      if (!id) {
        this.log.debug('Skipping device without an id: ' + JSON.stringify(device));
        continue;
      }
      this.deviceArray.push(id);
      const name = [device.title, device.hardware].filter(Boolean).join(' ') || id;

      await this.setObjectNotExistsAsync(id, {
        type: 'device',
        common: { name },
        native: {},
      });
      await this.setObjectNotExistsAsync(id + '.remote', {
        type: 'channel',
        common: { name: 'Remote Controls' },
        native: {},
      });
      for (const remote of china.REMOTE_COMMANDS) {
        await this.setObjectNotExistsAsync(id + '.remote.' + remote.command, {
          type: 'state',
          common: { name: remote.name, type: 'boolean', role: 'button', def: false, write: true, read: true },
          native: {},
        });
      }
      this.json2iob.parse(id + '.general', device, { forceIndex: true, channelName: 'Device information' });
    }
  }

  // Poll trigger only: the /clean/cmd/send response is a bare ACK. The device answers
  // asynchronously on the push socket (see connectChinaPush), which publishes the state.
  async updateDevicesChina(retried = false) {
    for (const id of this.deviceArray) {
      let res;
      try {
        res = await china.sendCommand(this.requestClient, { session: this.session, sn: id, infoType: '20001', data: '', debug: (m) => this.log.debug(m) });
      } catch (error) {
        this.log.error(`Update request failed (${this.getRequestFailure(error)})`);
        continue;
      }
      if (res.errno === china.ERRNO_SESSION_EXPIRED) {
        if (!retried) {
          await this.handleAuthFailure(() => this.updateDevicesChina(true));
        } else {
          this.log.error('Device update still unauthorized after re-login');
        }
        return;
      }
      if (res.errno !== 0) {
        this.log.debug(`Update for ${id} returned errno ${res.errno}`);
      }
    }
  }

  async sendCommandChina(deviceId, commandKey, retried) {
    const { infoType, data } = china.buildCommand(commandKey);
    let res;
    this.log.debug(`China command ${commandKey} for ${deviceId} infoType=${infoType} data=${data}`);
    try {
      res = await china.sendCommand(this.requestClient, { session: this.session, sn: deviceId, infoType, data, debug: (m) => this.log.debug(m) });
    } catch (error) {
      this.log.error(`${commandKey} for ${deviceId} failed (${this.getRequestFailure(error)})`);
      return;
    }
    if (res.errno === china.ERRNO_SESSION_EXPIRED) {
      if (!retried) {
        await this.handleAuthFailure(() => this.sendCommandChina(deviceId, commandKey, true));
      } else {
        this.log.error(`${commandKey} for ${deviceId} still unauthorized after re-login`);
      }
      return;
    }
    if (res.errno !== 0) {
      this.log.error(`${commandKey} for ${deviceId} failed (errno ${res.errno}${res.errmsg ? ': ' + res.errmsg : ''})`);
    }
  }

  // China device state is not returned by the cmd endpoint; it is pushed asynchronously
  // over a persistent TCP socket. Connect, handshake with the sid, keep alive with a ping,
  // and publish each decoded frame to <sn>.status. Reconnects on close.
  connectChinaPush() {
    this.log.debug('connectChinaPush');
    const sid = this.session && this.session.sid;
    if (!sid) {
      this.log.error('Cannot connect to device updates because session data is missing');
      return;
    }
    if (this.pushClient) {
      // Re-use the socket object across reconnects, as the original implementation did.
      this.pushClient.destroy();
      this.pushClient.connect(china.PUSH_PORT, china.PUSH_HOST);
      return;
    }
    const client = new net.Socket();
    this.pushClient = client;
    client.connect(china.PUSH_PORT, china.PUSH_HOST);

    client.on('connect', () => {
      this.log.debug('China push connected');
      const activeSid = this.session && this.session.sid;
      if (!activeSid) {
        this.log.error('Cannot connect to device updates because session data is missing');
        client.destroy();
        return;
      }
      this.pushReconnecting = false;
      this.pushReconnectTimeout && clearTimeout(this.pushReconnectTimeout);
      client.write('\x00\x05\x00\x02\x00Ecv:1.7\n');
      client.write('t:30\n');
      client.write(`u:${activeSid}@60009\n`);
      client.write(`ts:${Date.now()}`);
      this.pushPingInterval && clearInterval(this.pushPingInterval);
      this.pushPingInterval = setInterval(() => {
        client.write('\x00\x05\x00\x00');
      }, 25000);
    });

    client.on('data', (data) => {
      let dataString = data.toString();
      if (!dataString.includes('ack:') && !this.pushBuffer) {
        return;
      }
      try {
        // Frames can arrive split across reads; buffer until a full JSON body is seen.
        if (dataString.includes('}')) {
          dataString = (this.pushBuffer || '') + dataString;
          this.pushBuffer = '';
        } else {
          this.pushBuffer = (this.pushBuffer || '') + dataString;
          return;
        }
        // Echo the frame header back as an ack (byte 3 set to 4).
        const ack = Buffer.from(dataString.substring(0, dataString.indexOf('\x00', 5)));
        ack[3] = 4;
        client.write(ack.toString('latin1'), 'latin1');

        const pushKey = this.session && this.session.pushKey;
        if (!pushKey) {
          this.log.error('Cannot decrypt device update because session data is missing');
          return;
        }
        const decoded = china.decodePush(dataString, pushKey);
        if (decoded) {
          this.json2iob.parse(decoded.sn + '.status', decoded.status, { forceIndex: true, channelName: 'Status of the device' });
        }
      } catch (error) {
        this.log.error(`Could not process device update: ${error instanceof Error ? error.message : String(error)}`);
      }
    });

    client.on('close', () => {
      this.log.debug('China push closed');
      if (this.pushReconnecting || this.unloaded) {
        return;
      }
      this.pushReconnectTimeout && clearTimeout(this.pushReconnectTimeout);
      this.pushReconnectTimeout = setTimeout(() => {
        this.pushReconnecting = true;
        this.connectChinaPush();
      }, 10000);
    });

    client.on('error', (error) => {
      this.log.error(`China push error: ${error.message}`);
    });
  }

  async onUnload(callback) {
    try {
      this.unloaded = true;
      this.setState('info.connection', false, true);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      this.pushPingInterval && clearInterval(this.pushPingInterval);
      this.pushReconnectTimeout && clearTimeout(this.pushReconnectTimeout);
      this.pushClient && this.pushClient.destroy();
      callback();
    } catch {
      callback();
    }
  }

  /**
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (!state || state.ack) {
      return;
    }

    if (id.endsWith('info.captchaRequest')) {
      const code = String(state.val || '').trim();
      if (code && this.pendingCaptcha) {
        this.log.info('Retrying login with the provided captcha code');
        await this.login(code);
      }
      return;
    }

    const deviceId = id.split('.')[2];
    const command = id.split('.')[4];
    if (!deviceId || !command) {
      return;
    }

    if (command === 'Refresh') {
      await this.updateDevices();
      return;
    }

    if (this.isChina) {
      // China remote states are boolean buttons keyed by the command name.
      await this.sendCommandChina(deviceId, command, false);
      return;
    }

    let payload;
    try {
      payload = JSON.parse(String(state.val));
    } catch {
      this.log.error(`${command} expects a valid JSON value`);
      return;
    }

    let path;
    let data;
    if (command === 'set_property') {
      path = '/v1/iot/device/set_property';
      data = { device_id: deviceId, properties: payload };
    } else if (command === 'invoke_service') {
      path = '/v1/iot/device/invoke_service';
      // device_id comes from the state path and must win over any device_id in the payload.
      data = { ...payload, device_id: deviceId };
    } else {
      return;
    }

    await this.sendCommand(deviceId, command, path, data, false);
  }

  async sendCommand(deviceId, command, path, data, retried) {
    let res;
    this.log.debug(`${command} for ${deviceId} payload: ${JSON.stringify(data)}`);
    try {
      res = await api.request(this.requestClient, {
        region: this.config.region,
        method: 'post',
        path,
        session: this.session,
        m2: this.device.m2,
        data: JSON.stringify(data),
        debug: (m) => this.log.debug(m),
      });
    } catch (error) {
      this.log.error(`${command} for ${deviceId} failed (${this.getRequestFailure(error)})`);
      return;
    }
    if (res && AUTH_FAILURE_CODES.includes(Number(res.code))) {
      if (!retried) {
        await this.handleAuthFailure(() => this.sendCommand(deviceId, command, path, data, true));
      } else {
        this.log.error(`${command} for ${deviceId} still unauthorized after re-login`);
      }
      return;
    }
    if (!res || Number(res.code) !== 0) {
      this.log.error(`${command} for ${deviceId} failed (code ${res && res.code}${res && res.msg ? ': ' + res.msg : ''})`);
      return;
    }
    this.log.debug(`${command} response: ${JSON.stringify(res)}`);
  }
}

if (require.main !== module) {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Botslab360(options);
} else {
  new Botslab360();
}
