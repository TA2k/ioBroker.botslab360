'use strict';

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const Json2iob = require('json2iob');
const quc = require('./lib/quc');
const api = require('./lib/api');

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
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create();
  }

  async onReady() {
    this.setState('info.connection', false, true);

    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (!REGIONS.includes(this.config.region)) {
      this.config.region = 'eu1';
    }
    if (!this.config.email || !this.config.password) {
      this.log.error('Please enter your 360/Botslab account email and password in the instance settings');
      return;
    }

    this.subscribeStates('*');
    await this.ensureInfoObjects();
    this.device = await this.loadDeviceIdentity();

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
    const region = this.config.region;
    const opts = {
      region,
      email: String(this.config.email).trim(),
      password: String(this.config.password),
      device: this.device,
      needDeviceCheck: 0,
    };
    if (this.pendingCaptcha && captchaCode) {
      opts.captcha = { sc: this.pendingCaptcha.sc, code: String(captchaCode).trim() };
    }

    let result;
    try {
      result = await quc.login(this.requestClient, opts);
    } catch (error) {
      this.log.error(`360 login request failed (${this.getRequestFailure(error)})`);
      return false;
    }

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
    let mint;
    try {
      mint = await api.mintSid(this.requestClient, { region, session: { q: result.q, t: result.t }, m2: this.device.m2 });
    } catch (error) {
      this.log.error(`Session mint request failed (${this.getRequestFailure(error)})`);
      return false;
    }
    if (mint.code !== 0) {
      this.log.error(`Session mint was rejected (code ${mint.code}${mint.msg ? ': ' + mint.msg : ''})`);
      return false;
    }

    this.session = { q: result.q, t: result.t, qid: result.qid, sid: mint.sid };
    this.setState('info.connection', true, true);
    this.log.info('360 login successful');
    await this.startOnce();
    return true;
  }

  async requestCaptcha(region) {
    try {
      const captcha = await quc.getCaptcha(this.requestClient, { region, device: this.device });
      this.pendingCaptcha = { sc: captcha.sc };
      const dataUrl = 'data:image/jpeg;base64,' + captcha.image.toString('base64');
      await this.setStateAsync('info.captchaImage', dataUrl, true);
      this.log.warn(
        'A captcha is required to log in. Open the image stored in state info.captchaImage (paste the data URL into a browser) and write the solved code to state info.captchaRequest.',
      );
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
    let res;
    try {
      res = await api.request(this.requestClient, {
        region: this.config.region,
        method: 'get',
        path: '/v1/iot/device/list',
        session: this.session,
        m2: this.device.m2,
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
      this.json2iob.parse(id + '.status', res.data, { forceIndex: true, channelName: 'Status of the device' });
    }
  }

  async onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
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
    try {
      res = await api.request(this.requestClient, {
        region: this.config.region,
        method: 'post',
        path,
        session: this.session,
        m2: this.device.m2,
        data: JSON.stringify(data),
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
