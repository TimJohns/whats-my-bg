'use strict';

const DEXCOM_API_URL = process.env.DEXCOM_API_URL;
const DEXCOM_CLIENT_ID = process.env.DEXCOM_CLIENT_ID;
const DEXCOM_REDIRECT_URI = process.env.DEXCOM_REDIRECT_URI;
const GOOGLE_ACTIONS_CLIENT_ID = process.env.GOOGLE_ACTIONS_CLIENT_ID;

// TODO(tjohns): Move DEXCOM_EVGS_LOOKBACK_HOURS and/or the text formatter that uses it into the Dexcom module
const DEXCOM_EVGS_LOOKBACK_HOURS = 4;

import { default as express, Request, Response, NextFunction } from "express";
import path from "path";
import bodyParser from "body-parser";
import { Datastore } from "@google-cloud/datastore";

import { createSecretsCache } from "./secrets";
import { createAuthController, AuthController, AuthedRequest as DecoratedRequest } from "./authController";
import { createDexcom, Dexcom } from "./dexcom";
import { createDialogFlowFulfillmentController, DialogFlowFulfillmentController } from "./dialogFlowFullfilmentController";

declare var process : {
  env: {
    PORT: number,
    GOOGLE_CLIENT_ID: string,
    GOOGLE_CALLBACK_URL: string,
    DEXCOM_CLIENT_ID: string,
    DEXCOM_REDIRECT_URI: string,
    DEXCOM_API_URL: string,
    GOOGLE_ACTIONS_CLIENT_ID: string
  }
}

declare global {
  // Shouldn't Express do this?
  //
  // Per https://expressjs.com/en/guide/error-handling.html:
  //
  //    When an error is written, the following information is added to the response:
  //
  //    The res.statusCode is set from err.status (or err.statusCode). If this value is
  //      outside the 4xx or 5xx range, it will be set to 500.
  //    The res.statusMessage is set according to the status code.
  //    The body will be the HTML of the status code message when in production
  //      environment, otherwise will be err.stack.
  //    Any headers specified in an err.headers object.
  //
  interface Error {
    status?: number
    statusCode?: number
  }

  // Adding SessionData to Express is a workaround;
  // see https://github.com/googleapis/nodejs-datastore-session/issues/246
  namespace Express {
    interface SessionData {
      cookie: any
    }
  }

}

class WhatsMyBGApp {

  private app: any;
  private authController: AuthController;
  private dialogFlowFulfillmentController: DialogFlowFulfillmentController;
  private port: number;

  constructor(
    app: any,
    authController: AuthController,
    dialogFlowFulfillmentController: DialogFlowFulfillmentController) {
    this.app = app;
    this.authController = authController;
    this.dialogFlowFulfillmentController = dialogFlowFulfillmentController;
    this.port = process.env.PORT || 8080;
  }

  setupExpress() {
    const app = this.app;
    const authController = this.authController;
    const dialogFlowFulfillmentController = this.dialogFlowFulfillmentController;
    const port = this.port;

    app.use(bodyParser.urlencoded({extended: true}));
    app.use(bodyParser.json());

    app.set( "views", path.join( __dirname, "views" ) );
    app.set('view engine', 'ejs');

    app.get('/_ah/warmup', (req: Request, res: Response) => {
      // We don't actually need to DO anything here, currently, but we must handle this request
      // in order for GCP App Engine to pay attention to our min_instances in app.yaml.
      res.sendStatus(200);
    });

    app.set('trust proxy', 1); // trust first proxy (app engine terminates TLS before us)

    app.get('/privacy', async (req: Request, res: Response, next: NextFunction) => {
      try {
        res.render('privacy');
      } catch(error) {
        next(error);
      }
    });
    app.get('/support', async (req: Request, res: Response, next: NextFunction) => {
      try {
        res.render('support');
      } catch(error) {
        next(error);
      }
    });

    // TODO(tjohns): Get an initialized 'session' object from the AuthController
    app.use(authController.getSessionMiddleware());
    app.use(authController.initializePassport())
    app.use(authController.getPassportSessionMiddleware());

    app.get('/', async (req: DecoratedRequest, res: Response, next: NextFunction) => {
      console.log(JSON.stringify({installUser: req.user}));
      try {
        const dexcomAuthURL = `${DEXCOM_API_URL}/v2/oauth2/login?client_id=${encodeURIComponent(DEXCOM_CLIENT_ID)}&redirect_uri=${encodeURIComponent(DEXCOM_REDIRECT_URI)}&response_type=code&scope=offline_access`;
        res.render('install', {user: req.user, dexcomAuthURL});
      } catch(error) {
        next(error);
      }
    });

    app.get('/auth/google', authController.getPassportGoogleAuthHandler());
    app.get('/auth/google/callback', authController.getPassportGoogleAuthCallback(),
      function(req: Request, res: Response) {
        // Successful authentication, redirect home.
        res.redirect('/');
      }
    );

    app.get('/auth/dexcom/callback', async (req: DecoratedRequest, res: Response, next: NextFunction) => {
      // If we're not logged in, this makes no sense to us, let someone else handle it (or not).
      if (!req.user) { next(); return; }

      try {
        await this.authController.handleGETDexcomAuthCallback(req, res);
      } catch(error) {
        next(error);
      }
    });

    app.get('/authsuccess', async (req: Request, res: Response, next: NextFunction) => {
      try {
        await this.authController.handleGETAuthSuccess(req, res);
      } catch(error) {
        next(error);
      }
    });

    app.get('/authfailed', async (req: Request, res: Response, next: NextFunction) => {
      try {
        await this.authController.handleGETAuthFailed(req, res);
      } catch(error) {
        next(error);
      }
    });


    app.post('/fulfill', async (req: DecoratedRequest, res: Response, next: NextFunction) => {
      try {
        await this.dialogFlowFulfillmentController.handleGETFulfill(req, res);
      } catch(error) {
        next(error);
      }
    });


    // Start the server
    app.listen(port, () => {
      console.log(`App listening on port ${port}`);
      console.log('Press Ctrl+C to quit.');
    });
  };
};

async function init() {

  const app = express();
  const secrets = createSecretsCache();
  const datastore = new Datastore();

  const dexcomEVGSLookbackHours = DEXCOM_EVGS_LOOKBACK_HOURS;
  const dexcomClientSecret = await secrets.getSecret('dexcom_client_secret');
  const dexcomRedirectUri = process.env.DEXCOM_REDIRECT_URI;

  const dexcom: Dexcom = createDexcom({
    dexcomAPIUrl: DEXCOM_API_URL,
    dexcomClientId: DEXCOM_CLIENT_ID,
    dexcomClientSecret,
    dexcomRedirectUri,
    dexcomEVGSLookbackHours,
    datastore
  });

  const authController = createAuthController({
    googleClientId: process.env.GOOGLE_CLIENT_ID,
    googleClientSecret: await secrets.getSecret('google_client_secret'),
    dexcomClientId: process.env.DEXCOM_CLIENT_ID,
    dexcomClientSecret,
    sessionSecret: await secrets.getSecret('session_secret'),
    dexcom,
    datastore
  });

  const dialogFlowFulfillmentController = createDialogFlowFulfillmentController({
    audience: GOOGLE_ACTIONS_CLIENT_ID,
    dexcom,
    datastore,
    dexcomEVGSLookbackHours
  });

  return new WhatsMyBGApp(app, authController, dialogFlowFulfillmentController);
}

init().then((app) => {
  app.setupExpress();
});
