import defaultAxios, { AxiosInstance } from "axios";
import qs from "qs";
import { Request, Response } from "express";
import { Datastore } from "@google-cloud/datastore";
import { DatastoreStore } from "@google-cloud/connect-datastore";
import { Dexcom } from "./dexcom";

const GoogleStrategy = require('passport-google-oauth20').Strategy;

// TODO(tjohns): pass the 'process.env' constants into the constructor
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;
const DEXCOM_API_URL = process.env.DEXCOM_API_URL;
const DEXCOM_REDIRECT_URI = process.env.DEXCOM_REDIRECT_URI;
const SESSION_COOKIE_NAME = "whatsmybg.sid";

// TODO(tjohns): Better define User and UserEntity, and move it to a model or similar
export interface UserEntity {
  dexcom: {
    access_token: string,
    refresh_token: string
  }
};

interface User {
  key: any,
  data: UserEntity
};

export interface AuthedRequest extends Request {
  user: User
};

export interface AuthController {
  // TODO(tjohns): Find or create a session middleware type
  getSessionMiddleware(): any;
  // TODO(tjohns): Find or create a passport middleware type
  initializePassport(): any;
  // TODO(tjohns): Find or create a passport session middleware type
  getPassportSessionMiddleware(): any;
  // TODO(tjohns): Find or create a passport handler type
  getPassportGoogleAuthHandler(): any;
  // TODO(tjohns): Find or create a passport callback type
  getPassportGoogleAuthCallback(): any;
  handleGETDexcomAuthCallback(req: Request, res: Response): Promise<void>;
  handleGETAuthSuccess(req: Request, res: Response): Promise<void>;
  handleGETAuthFailed(req: Request, res: Response): Promise<void>;
};

export type AuthControllerParams = {
  googleClientId: string,
  googleClientSecret: string,
  dexcomClientId: string,
  dexcomClientSecret: string,
  sessionSecret: string,
  dexcom: Dexcom,
  datastore: Datastore,
  axios?: AxiosInstance,
  // TODO(tjohns): Find or create TS for passport instance
  passport?: any
  // TODO(tjohns): Find or create TS for session instance
  session?: any
};

export function createAuthController(params: AuthControllerParams) {
  return new AuthControllerImpl(params);
};

class AuthControllerImpl implements AuthController {
  private googleClientId: string;
  private googleClientSecret: string;
  private dexcomClientId: string;
  private dexcomClientSecret: string;
  private sessionSecret: string;
  private dexcom: Dexcom;
  private datastore: Datastore;
  private datastorestore: DatastoreStore;
  private axios: AxiosInstance;
  // TODO(tjohns): Find or create TS for passport instance
  private passport: any;
  // TODO(tjohns): Find or create TS for session instance
  private session: any;

  constructor(
    params: AuthControllerParams
    ) {
      this.googleClientId = params.googleClientId;
      this.googleClientSecret = params.googleClientSecret;
      this.dexcomClientId = params.dexcomClientId;
      this.dexcomClientSecret = params.dexcomClientSecret;
      this.sessionSecret = params.sessionSecret;
      this.dexcom = params.dexcom;
      this.axios = params.axios || defaultAxios;
      this.passport = params.passport || require('passport');
      this.session = params.session || require('express-session');
      this.datastore = params.datastore;

      const datastore = this.datastore;

      this.datastorestore = new DatastoreStore({
        dataset: datastore
      });

      this.passport.use(new GoogleStrategy({
        clientID: this.googleClientId,
        clientSecret: this.googleClientSecret,
        callbackURL: GOOGLE_CALLBACK_URL
      },
      // TODO(tjohns): get or create a type for this callback
      function(accessToken: any, refreshToken: any, profile: any, cb: any) {
        const query = datastore
          .createQuery('User')
          .filter('google.profile.id', profile.id)
          .limit(1);

        datastore.runQuery(query)
          .then(([userEntities]) => {
            console.log(JSON.stringify({verifyUserEntities: userEntities}));
            if (userEntities && userEntities[0]) {
              return cb(null, {key: userEntities[0][datastore.KEY], data: userEntities[0]});
            } else {
              const userKey = datastore.key('User');
              const user = {
                google: {
                  accessToken,
                  refreshToken,
                  profile
                }
              };

              const entity = {
                key: userKey,
                data: user,
              };

              console.log(JSON.stringify({insertEntity: entity}));
              datastore.insert(entity).then(() => {
                return cb(null, entity);
              }).catch((err) => {
                console.error('Error saving new user.', err);
                return cb(err);
              });

            }
          })
          .catch((err => {
            console.error('Error looking up user.', err);
            return cb(err);
          }));
      }
      ));

      // TODO(tjohns): Find or create TS for this passport serialize function
      this.passport.serializeUser(function(user: any, cb: any) {
        console.log(JSON.stringify({serializeUser: user}));
        cb(null, user.key.id);
      });

      this.passport.deserializeUser(function(id: any, cb: any) {
        console.log(JSON.stringify({deserializeUserId: id}));
        const key = datastore.key(['User', datastore.int(id)]);
        datastore.get(key)
        .then(([userEntity]) => {
          console.log(JSON.stringify({deserializeUserEntity: userEntity}));
          cb(null, {key, data: userEntity});
        })
        .catch((err) => {
          console.error('Error retrieving user while deserializing from session:', err);
          cb(err);
        });
      });
  };

  getSessionMiddleware() {
    const sessionSecret = this.sessionSecret;
    const datastorestore = this.datastorestore;

    return this.session({
      cookie: {
        httpOnly: true,
        secure: true,
      },
      name: SESSION_COOKIE_NAME,
      resave: false,
      saveUninitialized: false,
      store: datastorestore,
      secret: sessionSecret
    })
  };

  initializePassport() {
    return this.passport.initialize();
  };

  getPassportSessionMiddleware() {
    return this.passport.session();
  };

  getPassportGoogleAuthHandler() {
    return this.passport.authenticate('google', { scope: ['profile'] });
  }

  getPassportGoogleAuthCallback() {
    return this.passport.authenticate('google', { failureRedirect: '/' });
  }

  async handleGETDexcomAuthCallback(req: AuthedRequest, res: Response) {
    const axios = this.axios;
    const dexcomClientId = this.dexcomClientId;
    const dexcomClientSecret = this.dexcomClientSecret;
    const datastore = this.datastore;
    const dexcom = this.dexcom;

    if (req.query.error) {
      console.warn(`Auth failed: ${req.query.error}`);
      res.redirect(`/authfailed?${qs.stringify({error: req.query.error})}`);
      return;
    }

    const exchangeResponse = await axios(
      {
      method: 'post',
      url: `${DEXCOM_API_URL}/v2/oauth2/token`,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'cache-control': 'no-cache'
      },
      data: qs.stringify({
        client_id: dexcomClientId,
        client_secret: dexcomClientSecret,
        grant_type: 'authorization_code',
        redirect_uri: DEXCOM_REDIRECT_URI,
        code: req.query.code
      })
    });

    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({exchangeResponse: exchangeResponse.data}));

    req.user.data.dexcom = exchangeResponse.data;

    console.log(JSON.stringify({updateUser: req.user}));

    await datastore.update(req.user);

    // TODO(tjohns): This is a canary, but we should probably do some check OTHER
    // than get the latest evgs here, which is misleading. (Since the user will be
    // authed, we could certainly do so when rendering the page itself)
    const latestEGVS = await dexcom.getLatestEGVS(req.user.data.dexcom.access_token);

    res.redirect(`/authsuccess?${qs.stringify({value: latestEGVS.value})}`);
};

  async handleGETAuthSuccess(req: Request, res: Response) {
    res.render('authsuccess', {value: req.query.value || "Unknown BG"});
  };

  async handleGETAuthFailed(req: Request, res: Response) {
    res.render('authfailed', {error: req.query.error || "Unknown Error"});
  };

}