'use strict';

import { Datastore } from "@google-cloud/datastore";
import defaultAxios, { AxiosInstance } from "axios";
import qs from "qs";
import { UserEntity } from "./authController";

const moment = require('moment');

const DEXCOM_TIMESTAMP_FORMAT = "YYYY-MM-DDTHH:mm:ss";

export interface Dexcom {
  // TODO(tjohns): Collapse these two functions into one
  // TODO(tjohns): Make (or get) TypeScript for Dexcom 'latest'
  getLatestEGVS(access_token: string): Promise<any>;
  getLatestEGVSWithTokenRefresh(userEntity: UserEntity): Promise<any>
};

export type DexcomParams = {
  dexcomAPIUrl: string,
  dexcomClientId: string,
  dexcomClientSecret: string,
  dexcomRedirectUri: string,
  dexcomEVGSLookbackHours: number,
  datastore: Datastore,
  axios?: AxiosInstance,
};

export function createDexcom(params: DexcomParams) {
  return new DexcomImpl(params);
};

class DexcomImpl implements Dexcom {
  private axios: AxiosInstance;
  private dexcomAPIUrl: string;
  private dexcomClientId: string;
  private dexcomClientSecret: string;
  private dexcomRedirectUri: string;
  private datastore: Datastore;
  private dexcomEVGSLookbackHours: number;

  constructor(
    params: DexcomParams
    ) {
      this.dexcomAPIUrl = params.dexcomAPIUrl;
      this.dexcomClientId = params.dexcomClientId;
      this.dexcomClientSecret = params.dexcomClientSecret;
      this.dexcomRedirectUri = params.dexcomRedirectUri;
      this.datastore = params.datastore;
      this.dexcomEVGSLookbackHours = params.dexcomEVGSLookbackHours;
      this.axios = params.axios || defaultAxios;
    };

    async getLatestEGVSWithTokenRefresh(userEntity: UserEntity) {
      const self = this;
      const axios = this.axios;
      const dexcomAPIUrl = this.dexcomAPIUrl;
      const dexcomClientId = this.dexcomClientId;
      const dexcomClientSecret = this.dexcomClientSecret;
      const dexcomRedirectUri = this.dexcomRedirectUri;
      const datastore = this.datastore;

      async function refreshDexcomAccessToken(userEntity: UserEntity) {
        // call dexcom
        const refreshResponse = await axios(
          {
          method: 'post',
          url: `${dexcomAPIUrl}/v2/oauth2/token`,
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'cache-control': 'no-cache'
          },
          data: qs.stringify({
            client_id: dexcomClientId,
            client_secret: dexcomClientSecret,
            grant_type: 'refresh_token',
            redirect_uri: dexcomRedirectUri,
            refresh_token: userEntity.dexcom.refresh_token
          })
        });

        // TODO(tjohns) Remove this log statement.
        console.log(JSON.stringify({refreshResponse: refreshResponse.data}));

        // write it down.
        userEntity.dexcom = refreshResponse.data;

        await datastore.update(userEntity);
      }

      try {
        return await self.getLatestEGVS(userEntity.dexcom.access_token);
      } catch(error) {

        if (error.response.status != 401) {
          throw error;
        }

        // If at first you don't succeed, you're access_token is probably expired.

        // Get a new access_token (and save it)
        await refreshDexcomAccessToken(userEntity);

        // Try again.
        return await self.getLatestEGVS(userEntity.dexcom.access_token);
      }
    };


  async getLatestEGVS(access_token: string) {
    const axios = this.axios;
    const dexcomEVGSLookbackHours = this.dexcomEVGSLookbackHours;
    const dexcomAPIUrl = this.dexcomAPIUrl;

    const rangeResponse = await axios(
      {
      method: 'get',
      url: `${dexcomAPIUrl}/v2/users/self/dataRange`,
      headers: {
        'authorization': `Bearer ${access_token}`,
      }
    });

    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({rangeResponse: rangeResponse.data}));

    const rangeEnd = moment.utc(rangeResponse.data.egvs.end.systemTime);
    const rangeStart = moment.utc(rangeResponse.data.egvs.end.systemTime).subtract(dexcomEVGSLookbackHours, 'hours');

    const egvsURL = `${dexcomAPIUrl}/v2/users/self/egvs?startDate=${rangeStart.format(DEXCOM_TIMESTAMP_FORMAT)}&endDate=${rangeEnd.format(DEXCOM_TIMESTAMP_FORMAT)}`;

    console.log(`egvsURL: ${egvsURL}`);

    const dataResponse = await axios(
      {
      method: 'get',
      url: egvsURL,
      headers: {
        'authorization': `Bearer ${access_token}`,
      }
    });

    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({dataResponse: dataResponse.data}));

    const latest = dataResponse.data.egvs[dataResponse.data.egvs.length - 1];

    latest.unit = dataResponse.data.unit;

    return latest;
  }
};


