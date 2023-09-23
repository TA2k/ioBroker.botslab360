'use strict';

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require('@iobroker/adapter-core');
const axios = require('axios').default;
const crypto = require('crypto');
const qs = require('qs');
const Json2iob = require('./lib/json2iob');
const JsCrypto = require('jscrypto');
const { v4: uuidv4 } = require('uuid');
const net = require('net');

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
    this.mid = this.randomString(32);
    this.m2 = this.randomString(32);
    this.key = 'Y2ZTXk0wb3U=';
    this.postKey =
      'HSadyl6XNcuI/ZONGFle0v24qDnm2ln9gXSDH5+X86quoFd9+CAlC3LGF682CycmulYGWDcb2LmooVITfiqOuMVFTPKrKVzVglifYOpTimnxS0lkta9sN/Rfr7kR2U5k6SeHx18qk8PaYNkzs77qh2bgVQFisJVy51dY5Gnc7dw';
    this.buffer = '';
    this.json2iob = new Json2iob(this);
    this.requestClient = axios.create();
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState('info.connection', false, true);
    if (this.config.interval < 0.5) {
      this.log.info('Set interval to minimum 0.5');
      this.config.interval = 0.5;
    }
    if (!this.config.captcha) {
      await this.getCaptcha();
      this.log.error('Please read the captcha in ioBroker Log->Log Download and set captcha in the instance settings');
      return;
    }

    if (!this.config.username || !this.config.password) {
      this.log.error('Please set username and password in the instance settings');
      return;
    }

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates('*');

    this.log.info('Login to 360');
    await this.login();
    if (this.session.username) {
      await this.getDeviceList();
      await this.updateDevices();
      this.updateInterval = setInterval(
        async () => {
          await this.updateDevices();
        },
        this.config.interval * 60 * 1000,
      );
    }
    this.refreshTokenInterval = setInterval(
      () => {
        this.refreshToken();
      },
      12 * 60 * 60 * 1000,
    );
  }
  async login() {
    const timestamp = Date.now();
    const signature =
      'app=360RobotcaptchaType=graphdimei=dimsi=dmac=fields=qid,username,nickname,loginemail,head_pic,mobileformat=jsonfrom=mpl_smarthome_andhead_type=qis_keep_alive=1m2=' +
      this.m2 +
      'method=UserIntf.loginmid=' +
      this.mid +
      'os_board=ANEos_manufacturer=HUAWEIos_model=ANE-LX1os_sdk_version=android_28password=' +
      crypto.createHash('md5').update(this.config.password).digest('hex') +
      'qh_id=' +
      this.m2 +
      'quc_lang=de_DEquc_sdk_version=v1.5.16res_mode=1sdpi=3.0sec_type=boolsh=2060.0simsn=sw=1080.0ua=Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)uc=' +
      this.config.captcha +
      'ui_ver=2.6.2.1-alert-uiusername=' +
      this.config.username +
      'v=6.7.0.0vt_guid=' +
      timestamp +
      'x=' +
      this.config.password +
      'i7v2m5x6q';

    const sig = crypto.createHash('md5').update(signature).digest('hex');
    const loginQuery = {
      dmac: '',
      os_sdk_version: 'android_28',
      mid: this.mid,
      quc_sdk_version: 'v1.5.16',
      ua: 'Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)',
      os_manufacturer: 'HUAWEI',
      head_type: 'q',
      os_board: 'ANE',
      sig: sig,
      os_model: 'ANE-LX1',
      password: crypto.createHash('md5').update(this.config.password).digest('hex'),
      quc_lang: 'de_DE',
      sh: '2060.0',
      vt_guid: timestamp,
      is_keep_alive: '1',
      from: 'mpl_smarthome_and',
      dimei: '',
      app: '360Robot',
      ui_ver: '2.6.2.1-alert-ui',
      method: 'UserIntf.login',
      res_mode: '1',
      sw: '1080.0',
      m2: this.m2,
      format: 'json',
      qh_id: this.m2,
      dimsi: '',
      sec_type: 'bool',
      v: '6.7.0.0',
      simsn: '',
      x: this.config.password,
      fields: 'qid,username,nickname,loginemail,head_pic,mobile',
      username: this.config.username,
      sdpi: '3.0',
      uc: this.config.captcha,
      captchaType: 'graph',
    };

    const encryptedLoginQuery = JsCrypto.DES.encrypt(
      JsCrypto.Utf8.parse(qs.stringify(loginQuery)),
      JsCrypto.Base64.parse(this.key),
      {
        iv: JsCrypto.Base64.parse(this.key),
        mode: JsCrypto.mode.CBC,
        padding: JsCrypto.pad.Pkcs7,
      },
    );

    await this.requestClient({
      method: 'post',
      url: 'http://passport.360.cn/request.php',
      headers: {
        'User-Agent': '360accounts andv1.5.16 mpl_smarthome_and',
        Host: 'passport.360.cn',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: qs.stringify({
        quc_lang: 'de_DE',
        method: 'UserIntf.login',
        from: 'mpl_smarthome_and',
        parad: encryptedLoginQuery.toString().replace('==', ''),
        key: this.postKey,
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));

        if (res.data && res.data.errno !== '0') {
          this.log.error('Login failed: ' + res.data.errmsg);
          return;
        }
        try {
          const decrypteds = JsCrypto.DES.decrypt(
            new JsCrypto.CipherParams({ cipherText: JsCrypto.Base64.parse(res.data.ret) }),
            JsCrypto.Base64.parse(this.key),
            { iv: JsCrypto.Base64.parse(this.key), mode: JsCrypto.mode.CBC, padding: JsCrypto.pad.Pkcs7 },
          );
          this.log.debug(decrypteds.toString(JsCrypto.Utf8));
          const decryptRes = JSON.parse(decrypteds.toString(JsCrypto.Utf8));
          if (decryptRes.errno !== '0') {
            this.log.error('Login failed: ' + res.data.errmsg);
            return;
          }
          this.session = decryptRes.user;
          // this.cookieJar.store.idx["360.cn"]["/"].T.httpOnly = false;
        } catch (error) {
          this.log.error(error);
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });

    await this.requestClient({
      method: 'post',
      url: 'https://q.smart.360.cn/common/user/login',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: '*/*',
        Connection: 'keep-alive',
        Cookie:
          'q=' +
          decodeURIComponent(this.session.q) +
          ';t=' +
          decodeURIComponent(this.session.t) +
          ';qid=' +
          this.session.qid,
        'User-Agent': 'qhsa-iphone-11.1.0',
        'Accept-Language': 'de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8',
      },
      data: qs.stringify({
        clientInfo:
          '{"release":"appstore","brand":"iPhone","model":"iPhone10,5","notifyId":"aa0ad645269de676a5ee6a728ba13b777ed3d4aa4d0e08a578097fbe78768b02","lang":"de_DE","imei":"f3bc82b802bd91a51d0dcc6499efeba3"}',
        lang: 'de_DE',
        phoneNum: '',
        taskid: uuidv4(),
      }),
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data && res.data.errno !== 0) {
          this.log.error('Login failed: ' + res.data.errmsg);
          return;
        }
        this.log.info(`Login successful: ${this.session.username}`);
        this.session.sid = res.data.data.sid;
        this.session.pushKey = res.data.data.pushKey;
        await this.connectTcp();
        this.setState('info.connection', true, true);
      })
      .catch(async (error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }
  async getCaptcha() {
    const timestamp = Date.now();
    const signature =
      'app=360Robotdimei=dimsi=dmac=format=jsonfrom=mpl_smarthome_andhead_type=qis_keep_alive=1m2=' +
      this.m2 +
      'method=UserIntf.getCaptchamid=' +
      this.mid +
      'os_board=ANEos_manufacturer=HUAWEIos_model=ANE-LX1os_sdk_version=android_28qh_id=' +
      this.m2 +
      'quc_lang=de_DEquc_sdk_version=v1.5.16res_mode=1sdpi=3.0sec_type=boolsh=2060.0simsn=sw=1080.0ua=Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)ui_ver=2.6.2.1-alert-uiv=6.7.0.0vt_guid=' +
      timestamp +
      'i7v2m5x6q';

    const sig = crypto.createHash('md5').update(signature).digest('hex');
    const loginQuery = {
      dmac: '',
      os_sdk_version: 'android_28',
      mid: this.mid,
      quc_sdk_version: 'v1.5.16',
      ua: 'Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)',
      os_manufacturer: 'HUAWEI',
      head_type: 'q',
      os_board: 'ANE',
      sig: sig,
      os_model: 'ANE-LX1',

      quc_lang: 'de_DE',
      sh: '2060.0',
      vt_guid: timestamp,
      is_keep_alive: '1',
      from: 'mpl_smarthome_and',
      dimei: '',
      app: '360Robot',
      ui_ver: '2.6.2.1-alert-ui',
      method: 'UserIntf.getCaptcha',
      res_mode: '1',
      sw: '1080.0',
      m2: this.m2,
      format: 'json',
      qh_id: this.m2,
      dimsi: '',
      sec_type: 'bool',
      v: '6.7.0.0',
      simsn: '',

      sdpi: '3.0',
    };

    const encryptedLoginQuery = JsCrypto.DES.encrypt(
      JsCrypto.Utf8.parse(qs.stringify(loginQuery)),
      JsCrypto.Base64.parse(this.key),
      {
        iv: JsCrypto.Base64.parse(this.key),
        mode: JsCrypto.mode.CBC,
        padding: JsCrypto.pad.Pkcs7,
      },
    );

    await this.requestClient({
      method: 'post',
      responseType: 'arraybuffer',
      url: 'http://passport.360.cn/request.php',
      headers: {
        'User-Agent': '360accounts andv1.5.16 mpl_smarthome_and',
        Host: 'passport.360.cn',
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      data: qs.stringify({
        quc_lang: 'de_DE',
        method: 'UserIntf.getCaptcha',
        from: 'mpl_smarthome_and',
        parad: encryptedLoginQuery.toString().replace('==', ''),
        key: this.postKey,
      }),
    })
      .then(async (res) => {
        // this.log.debug(JSON.stringify(res.data))
        //convert to base64
        const b64 = Buffer.from(res.data).toString('base64');

        this.log.info('Press on Log download/Protokolle -> Log herunterladen to see the captcha:');
        this.log.warn("<html><img src='data:image/jpeg;base64," + b64 + "' /></html>");
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async connectTcp() {
    this.log.debug('connectTcp');
    //https://47.254.151.104:443
    if (this.client) {
      this.client.destroy();
      this.client.connect(443, '47.254.151.104');
      return;
    } else {
      this.client = new net.Socket();
      this.client.connect(443, '47.254.151.104');
    }
    this.client.on('connect', () => {
      this.log.debug('connect');
      this.reconnecting = false;
      clearTimeout(this.reconnectTCP);
      this.client.write(`\x00\x05\x00\x02\x00Ecv:1.7\n`);
      this.client.write(`t:30\n`);
      this.client.write(`u:${this.session.sid}@60009\n`);
      this.client.write(`ts:${Date.now()}`);
      // this.client.write(`\x00\x05\x00\x00\n`);
      this.pingInterval && clearInterval(this.pingInterval);
      this.pingInterval = setInterval(() => {
        this.log.debug('ping');
        this.client.write(`\x00\x05\x00\x00`);
      }, 25000);
    });
    this.client.on('data', (data) => {
      this.log.debug('data');
      let dataString = data.toString();
      this.log.debug(dataString);
      if (dataString.includes('ack:') || this.buffer) {
        try {
          if (dataString.includes('}')) {
            dataString = this.buffer + dataString;
            this.buffer = '';
          } else {
            this.buffer += dataString;
            return;
          }
          const ack = Buffer.from(dataString.substring(0, dataString.indexOf('\x00', 5)));
          ack[3] = 4;
          const payload = dataString.split('data":"')[1].split('",')[0];

          this.log.debug(ack);
          this.client.write(ack);
          // this.client.write(`\x00\x05\x00\x04\x00\x09ack:${ack}`);
          // this.client.write(`\x00\x05\x00\x04\x00	ack:${ack}`);
          // this.client.write(`\x00\x05\x00\x00`);
          const key = Buffer.from(this.session.pushKey.substring(0, 16)).toString('base64');
          const decrypteds = JsCrypto.AES.decrypt(
            new JsCrypto.CipherParams({ cipherText: JsCrypto.Base64.parse(payload) }),
            JsCrypto.Base64.parse(key),
            { iv: JsCrypto.Base64.parse(key), mode: JsCrypto.mode.CBC, padding: JsCrypto.pad.Pkcs7 },
          );
          this.log.debug(decrypteds.toString(JsCrypto.Utf8));
          const decryptRes = JSON.parse(decrypteds.toString(JsCrypto.Utf8));
          const body = JSON.parse(decryptRes.data);
          this.json2iob.parse(decryptRes.sn + '.status', body.data, {
            forceIndex: true,
            channelName: 'Status of the device',
          });
        } catch (error) {
          this.log.error(error);
          this.log.error(error.stack);
        }
      }
    });
    this.client.on('close', () => {
      this.log.debug('close');
      if (this.reconnecting) {
        return;
      }
      this.reconnectTCP && clearTimeout(this.reconnectTCP);
      this.reconnectTCP = setTimeout(() => {
        this.log.debug('reconnect');
        this.connectTcp();
        this.reconnecting = true;
      }, 10000);
    });
    this.client.on('error', (error) => {
      this.log.debug('error');
      this.log.error(error);
    });
  }
  async getDeviceList() {
    await this.requestClient({
      method: 'post',
      url: 'https://q.smart.360.cn/common/dev/GetList',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: '*/*',
        Connection: 'keep-alive',
        Cookie:
          'q=' +
          decodeURIComponent(this.session.q) +
          ';t=' +
          decodeURIComponent(this.session.t) +
          ';qid=' +
          this.session.qid +
          ';sid=' +
          this.session.sid,
        'User-Agent': 'QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)',
        'Accept-Language': 'de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8',
      },
      data: qs.stringify({
        countryId: 'DE',
        devType: '3',
        from: 'mpc_ios',
        lang: 'de_DE',
        taskid: uuidv4(),
      }),
    })
      .then(async (res) => {
        if (res.data && res.data.errno !== 0) {
          this.log.error('Device list failed: ' + res.data.errmsg);
          return;
        }
        this.log.debug(JSON.stringify(res.data));
        if (res.data.data && res.data.data.list) {
          this.log.info(`Found ${res.data.data.list.length} devices`);
          for (const device of res.data.data.list) {
            this.log.debug(JSON.stringify(device));
            const id = device.sn;

            this.deviceArray.push(id);
            const name = device.title + ' ' + device.hardware;

            await this.setObjectNotExistsAsync(id, {
              type: 'device',
              common: {
                name: name,
              },
              native: {},
            });
            await this.setObjectNotExistsAsync(id + '.remote', {
              type: 'channel',
              common: {
                name: 'Remote Controls',
              },
              native: {},
            });

            const remoteArray = [
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
            remoteArray.forEach((remote) => {
              this.setObjectNotExists(id + '.remote.' + remote.command, {
                type: 'state',
                common: {
                  name: remote.name || '',
                  type: remote.type || 'boolean',
                  role: remote.role || 'boolean',
                  def: remote.def || false,
                  write: true,
                  read: true,
                },
                native: {},
              });
            });
            this.json2iob.parse(id + '.general', device, { forceIndex: true });
          }
        }
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async updateDevices() {
    const statusArray = [
      {
        url: 'https://q.smart.360.cn/clean/cmd/',
        path: 'status',
        desc: 'Status of the device',
      },
    ];

    for (const element of statusArray) {
      for (const device of this.deviceArray) {
        // const url = element.url.replace("$id", id);

        await this.requestClient({
          method: 'post',
          url: 'https://q.smart.360.cn/clean/cmd/send',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: '*/*',
            Connection: 'keep-alive',
            Cookie:
              'q=' +
              decodeURIComponent(this.session.q) +
              ';t=' +
              decodeURIComponent(this.session.t) +
              ';qid=' +
              this.session.qid +
              ';sid=' +
              this.session.sid,
            'User-Agent': 'QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)',
            'Accept-Language': 'de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8',
          },
          data: qs.stringify({
            countryId: 'DE',
            data: '',
            devType: '3',
            from: 'mpc_ios',
            infoType: 20001,
            lang: 'de_DE',
            sn: device,
            taskid: uuidv4(),
          }),
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            if (res.data && res.data.errno !== 0) {
              this.log.error('Update failed: ' + res.data.errmsg);
              return;
            }
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + ' receive 401 error. Refresh Token in 60 seconds');
                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                this.refreshTokenTimeout = setTimeout(() => {
                  this.refreshToken();
                }, 1000 * 60);

                return;
              }
            }
            this.log.error(element.url);
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      }
    }
  }
  randomString(length) {
    let result = '';
    const characters = 'abcdef0123456789';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
  }
  async refreshToken() {
    this.log.debug('Refresh token');
    await this.login();
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState('info.connection', false, true);
      this.refreshTimeout && clearTimeout(this.refreshTimeout);
      this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
      this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
      this.updateInterval && clearInterval(this.updateInterval);
      this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
      callback();
    } catch (e) {
      callback();
    }
  }

  /**
   * Is called if a subscribed state changes
   * @param {string} id
   * @param {ioBroker.State | null | undefined} state
   */
  async onStateChange(id, state) {
    if (state) {
      if (!state.ack) {
        const deviceId = id.split('.')[2];
        let command = id.split('.')[4];
        let type = command.split('-')[1];
        command = command.split('-')[0];

        if (id.split('.')[4] === 'Refresh') {
          this.updateDevices();
          return;
        }
        let data = '';
        if (isNaN(Number(command))) {
          data = '{"cmd":"' + command + '"}';
        } else {
          type = command;
        }
        if (type === '21005') {
          data = '{"mode":"smartClean","globalCleanTimes":1}';
        }
        if (type === '30000') {
          data =
            '{"cmds":[{"data":{},"infoType":"20001"},{"data":{},"infoType":"21014"},{"data":{"mask":0,"startPos":0,"userId":0},"infoType":"21011"}],"mainCmds":[]}';
        }
        await this.requestClient({
          method: 'post',
          url: 'https://q.smart.360.cn/clean/cmd/send',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: '*/*',
            Connection: 'keep-alive',
            Cookie:
              'q=' +
              decodeURIComponent(this.session.q) +
              ';t=' +
              decodeURIComponent(this.session.t) +
              ';qid=' +
              this.session.qid +
              ';sid=' +
              this.session.sid,
            'User-Agent': 'QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)',
            'Accept-Language': 'de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8',
          },
          data: qs.stringify({
            countryId: 'DE',
            data: data,
            devType: '3',
            from: 'mpc_ios',
            infoType: type,
            lang: 'de_DE',
            sn: deviceId,
            taskid: uuidv4(),
          }),
        })
          .then((res) => {
            if (res.data && res.data.errno === 102) {
              this.log.warn(res.data.errmsg);
              this.log.info('Relogin in 10 seconds');
              this.reLoginTimeout = setTimeout(async () => {
                this.log.info('Start relogin');
                await this.login();
                this.log.info('Retry command');
                this.setStateAsync(id, true, false);
              }, 1000 * 10);
              return;
            }
            this.log.info(JSON.stringify(res.data));
          })
          .catch(async (error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
      } else {
        const resultDict = {
          auto_target_humidity: 'setTargetHumidity',
          enabled: 'setSwitch',
          display: 'setDisplay',
          child_lock: 'setChildLock',
          level: 'setLevel-wind',
        };
        const idArray = id.split('.');
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split('.')[2];
        if (resultDict[stateName]) {
          const value = state.val;
          await this.setStateAsync(deviceId + '.remote.' + resultDict[stateName], value, true);
        }
      }
    }
  }
}
if (require.main !== module) {
  // Export the constructor in compact mode
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  module.exports = (options) => new Botslab360(options);
} else {
  // otherwise start the instance directly
  new Botslab360();
}
