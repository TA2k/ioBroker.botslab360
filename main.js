"use strict";

/*
 * Created with @iobroker/create-adapter v2.3.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios");
const crypto = require("crypto");
const qs = require("qs");
const Json2iob = require("./lib/json2iob");
const JsCrypto = require("jscrypto");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");

class Botslab360 extends utils.Adapter {
  /**
   * @param {Partial<utils.AdapterOptions>} [options={}]
   */
  constructor(options) {
    super({
      ...options,
      name: "botslab360",
    });
    this.on("ready", this.onReady.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.deviceArray = [];
    this.key = "Y2ZTXk0wb3U=";

    this.json2iob = new Json2iob(this);
    this.cookieJar = new tough.CookieJar();
    this.requestClient = axios.create({
      withCredentials: true,
      httpsAgent: new HttpsCookieAgent({
        cookies: {
          jar: this.cookieJar,
        },
      }),
    });
  }

  /**
   * Is called when databases are connected and adapter received configuration.
   */
  async onReady() {
    // Reset the connection indicator during startup
    this.setState("info.connection", false, true);
    if (this.config.interval < 0.5) {
      this.log.info("Set interval to minimum 0.5");
      this.config.interval = 0.5;
    }
    if (!this.config.username || !this.config.password) {
      this.log.error("Please set username and password in the instance settings");
      return;
    }

    this.updateInterval = null;
    this.reLoginTimeout = null;
    this.refreshTokenTimeout = null;
    this.session = {};
    this.subscribeStates("*");

    this.log.info("Login to 360");
    await this.login();
    if (this.session.token) {
      await this.getDeviceList();
      await this.updateDevices();
      this.updateInterval = setInterval(async () => {
        await this.updateDevices();
      }, this.config.interval * 60 * 1000);
    }
    this.refreshTokenInterval = setInterval(() => {
      this.refreshToken();
    }, 12 * 60 * 60 * 1000);
  }
  async login() {
    const timestamp = Date.now();
    const signature =
      "app=360Robotdimei=dimsi=dmac=fields=qid,username,nickname,loginemail,head_pic,mobileformat=jsonfrom=mpl_smarthome_andhead_type=qis_keep_alive=1m2=92f74f207ad7066bf3890e2c3c29cce1method=UserIntf.loginmid=11aa8d2c762f3b0b56e9e9ed8d4015f0os_board=ANEos_manufacturer=HUAWEIos_model=ANE-LX1os_sdk_version=android_28password=" +
      crypto.createHash("md5").update(this.config.password).digest("hex") +
      "qh_id=92f74f207ad7066bf3890e2c3c29cce1quc_lang=de_DEquc_sdk_version=v1.5.16res_mode=1sdpi=3.0sec_type=boolsh=2060.0simsn=sw=1080.0ua=Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)ui_ver=2.6.2.1-alert-uiusername=" +
      this.config.username +
      "v=6.7.0.0vt_guid=" +
      timestamp +
      "x=" +
      this.config.password +
      "i7v2m5x6q";
    const sig = crypto.createHash("md5").update(signature).digest("hex");
    const loginQuery = {
      dmac: "",
      os_sdk_version: "android_28",
      mid: "11aa8d2c762f3b0b56e9e9ed8d4015f0",
      quc_sdk_version: "v1.5.16",
      ua: "Dalvik/2.1.0 (Linux; U; Android 9; ANE-LX1 Build/HUAWEIANE-L21)",
      os_manufacturer: "HUAWEI",
      head_type: "q",
      os_board: "ANE",
      sig: sig,
      os_model: "ANE-LX1",
      password: crypto.createHash("md5").update(this.config.password).digest("hex"),
      quc_lang: "de_DE",
      sh: "2060.0",
      vt_guid: timestamp,
      is_keep_alive: "1",
      from: "mpl_smarthome_and",
      dimei: "",
      app: "360Robot",
      ui_ver: "2.6.2.1-alert-ui",
      method: "UserIntf.login",
      res_mode: "1",
      sw: "1080.0",
      m2: "92f74f207ad7066bf3890e2c3c29cce1",
      format: "json",
      qh_id: "92f74f207ad7066bf3890e2c3c29cce1",
      dimsi: "",
      sec_type: "bool",
      v: "6.7.0.0",
      simsn: "",
      x: this.config.password,
      fields: "qid,username,nickname,loginemail,head_pic,mobile",
      username: this.config.username,
      sdpi: "3.0",
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
      method: "post",
      url: "http://passport.360.cn/request.php",
      headers: {
        "User-Agent": "360accounts andv1.5.16 mpl_smarthome_and",
        Host: "passport.360.cn",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      data: qs.stringify({
        quc_lang: "de_DE",
        method: "UserIntf.login",
        from: "mpl_smarthome_and",
        parad: encryptedLoginQuery.toString().replace("==", ""),
        key: "HSadyl6XNcuI/ZONGFle0v24qDnm2ln9gXSDH5+X86quoFd9+CAlC3LGF682CycmulYGWDcb2LmooVITfiqOuMVFTPKrKVzVglifYOpTimnxS0lkta9sN/Rfr7kR2U5k6SeHx18qk8PaYNkzs77qh2bgVQFisJVy51dY5Gnc7dw",
      }),
    })
      .then((res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data && res.data.errno !== "0") {
          this.log.error("Login failed: " + res.data.errmsg);
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
          if (decryptRes.errno !== "0") {
            this.log.error("Login failed: " + res.data.errmsg);
            return;
          }
          this.session = decryptRes.user;
        } catch (error) {
          this.log.error(error);
        }

        this.setState("info.connection", true, true);
      })
      .catch((error) => {
        this.log.error(error);
        error.response && this.log.error(JSON.stringify(error.response.data));
      });
  }

  async getDeviceList() {
    await this.requestClient({
      method: "post",
      url: "https://smartapi.vesync.com/cloud/v2/deviceManaged/devices",
      headers: {
        tk: this.session.token,
        accountid: this.session.accountID,
        "content-type": "application/json",
        tz: "Europe/Berlin",
        "user-agent": "ioBroker",
      },
      data: JSON.stringify({
        acceptLanguage: "de",
        accountID: this.session.accountID,
        appVersion: "1.1",
        method: "devices",
        pageNo: 1,
        pageSize: 1000,
        phoneBrand: "ioBroker",
        phoneOS: "ioBroker",
        timeZone: "Europe/Berlin",
        token: this.session.token,
        traceId: "",
      }),
    })
      .then(async (res) => {
        this.log.debug(JSON.stringify(res.data));
        if (res.data.result && res.data.result.list) {
          this.log.info(`Found ${res.data.result.list.length} devices`);
          for (const device of res.data.result.list) {
            this.log.debug(JSON.stringify(device));
            const id = device.cid;
            // if (device.subDeviceNo) {
            //   id += "." + device.subDeviceNo;
            // }

            this.deviceArray.push(device);
            const name = device.deviceName;

            await this.setObjectNotExistsAsync(id, {
              type: "device",
              common: {
                name: name,
              },
              native: {},
            });
            await this.setObjectNotExistsAsync(id + ".remote", {
              type: "channel",
              common: {
                name: "Remote Controls",
              },
              native: {},
            });

            const remoteArray = [
              { command: "Refresh", name: "True = Refresh" },
              { command: "setSwitch", name: "True = Switch On, False = Switch Off" },
              { command: "setDisplay", name: "True = On, False = Off" },
              { command: "setChildLock", name: "True = On, False = Off" },
              { command: "setPurifierMode", name: "sleep or auto", def: "auto", type: "string", role: "text" },
              { command: "setTargetHumidity", name: "set Target Humidity", type: "number", def: 65, role: "level" },
              { command: "setLevel-mist", name: "set Level Mist", type: "number", def: 10, role: "level" },
              { command: "setLevel-wind", name: "set Level Wind", type: "number", def: 10, role: "level" },
            ];
            remoteArray.forEach((remote) => {
              this.setObjectNotExists(id + ".remote." + remote.command, {
                type: "state",
                common: {
                  name: remote.name || "",
                  type: remote.type || "boolean",
                  role: remote.role || "boolean",
                  def: remote.def || false,
                  write: true,
                  read: true,
                },
                native: {},
              });
            });
            this.json2iob.parse(id + ".general", device, { forceIndex: true });
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
        url: "https://smartapi.vesync.com/cloud/v2/deviceManaged/bypassV2",
        path: "status",
        desc: "Status of the device",
      },
    ];

    for (const element of statusArray) {
      for (const device of this.deviceArray) {
        // const url = element.url.replace("$id", id);

        await this.requestClient({
          method: "post",
          url: element.url,
          headers: {
            "content-type": "application/json",
            "user-agent": "ioBroker",
            accept: "*/*",
          },
          data: JSON.stringify({
            accountID: this.session.accountID,
            method: "bypassV2",
            deviceRegion: "EU",
            phoneOS: "iOS 14.8",
            timeZone: "Europe/Berlin",
            debugMode: false,
            cid: device.cid,
            payload: {
              method: this.deviceIdentifier(device),
              data: {},
              source: "APP",
            },
            configModule: "",
            traceId: Date.now(),
            phoneBrand: "iPhone 8 Plus",
            acceptLanguage: "de",
            appVersion: "VeSync 4.1.10 build2",
            userCountryCode: "DE",
            token: this.session.token,
          }),
        })
          .then(async (res) => {
            this.log.debug(JSON.stringify(res.data));
            if (!res.data) {
              return;
            }
            if (res.data.code != 0) {
              this.log.error(JSON.stringify(res.data));
              return;
            }
            let data = res.data.result;
            if (data.result) {
              data = data.result;
            }

            const forceIndex = true;
            const preferedArrayName = null;

            this.json2iob.parse(device.cid + "." + element.path, data, {
              forceIndex: forceIndex,
              write: true,
              preferedArrayName: preferedArrayName,
              channelName: element.desc,
            });
            // await this.setObjectNotExistsAsync(element.path + ".json", {
            //   type: "state",
            //   common: {
            //     name: "Raw JSON",
            //     write: false,
            //     read: true,
            //     type: "string",
            //     role: "json",
            //   },
            //   native: {},
            // });
            // this.setState(element.path + ".json", JSON.stringify(data), true);
          })
          .catch((error) => {
            if (error.response) {
              if (error.response.status === 401) {
                error.response && this.log.debug(JSON.stringify(error.response.data));
                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
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

  async refreshToken() {
    this.log.debug("Refresh token");
    await this.login();
  }

  /**
   * Is called when adapter shuts down - callback has to be called under any circumstances!
   * @param {() => void} callback
   */
  onUnload(callback) {
    try {
      this.setState("info.connection", false, true);
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
        const deviceId = id.split(".")[2];
        let command = id.split(".")[4];
        const type = command.split("-")[1];
        command = command.split("-")[0];

        if (id.split(".")[4] === "Refresh") {
          this.updateDevices();
          return;
        }
        let data = {
          enabled: state.val,
          id: 0,
        };
        if (command === "setTargetHumidity") {
          data = {
            target_humidity: state.val,
          };
        }
        if (command === "setDisplay") {
          data = {
            state: state.val,
          };
        }
        if (command === "setPurifierMode") {
          data = {
            mode: state.val,
          };
        }
        if (command === "setChildLock") {
          data = {
            child_lock: state.val,
          };
        }
        if (command === "setLevel") {
          data = {
            level: state.val,
            type: type,
            id: 0,
          };
        }
        await this.requestClient({
          method: "post",
          url: "https://smartapi.vesync.com/cloud/v2/deviceManaged/bypassV2",
          headers: {
            Host: "smartapi.vesync.com",
            accept: "*/*",
            "content-type": "application/json",
            "user-agent": "VeSync/4.1.10 (com.etekcity.vesyncPlatform; build:2; iOS 14.8.0) Alamofire/5.2.1",
            "accept-language": "de-DE;q=1.0, uk-DE;q=0.9, en-DE;q=0.8",
          },
          data: JSON.stringify({
            traceId: Date.now(),
            debugMode: false,
            acceptLanguage: "de",
            method: "bypassV2",
            cid: deviceId,
            timeZone: "Europe/Berlin",
            accountID: this.session.accountID,
            payload: {
              data: data,
              source: "APP",
              method: command,
            },
            appVersion: "VeSync 4.1.10 build2",
            deviceRegion: "EU",
            phoneBrand: "iPhone 8 Plus",
            token: this.session.token,
            phoneOS: "iOS 14.8",
            configModule: "",
            userCountryCode: "DE",
          }),
        })
          .then((res) => {
            this.log.info(JSON.stringify(res.data));
          })
          .catch(async (error) => {
            this.log.error(error);
            error.response && this.log.error(JSON.stringify(error.response.data));
          });
        this.refreshTimeout = setTimeout(async () => {
          this.log.info("Update devices");
          await this.updateDevices();
        }, 10 * 1000);
      } else {
        const resultDict = {
          auto_target_humidity: "setTargetHumidity",
          enabled: "setSwitch",
          display: "setDisplay",
          child_lock: "setChildLock",
          level: "setLevel-wind",
        };
        const idArray = id.split(".");
        const stateName = idArray[idArray.length - 1];
        const deviceId = id.split(".")[2];
        if (resultDict[stateName]) {
          const value = state.val;
          await this.setStateAsync(deviceId + ".remote." + resultDict[stateName], value, true);
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
