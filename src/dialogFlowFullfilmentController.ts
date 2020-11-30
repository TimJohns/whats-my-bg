import { Request, Response } from "express";
import { Datastore } from "@google-cloud/datastore";
import { Dexcom } from "./dexcom";
import { GoogleAuth } from "google-auth-library";

const moment = require('moment');

export interface DialogFlowFulfillmentController {
  handleGETFulfill(req: Request, res: Response): Promise<void>;
};

export type DialogFlowFulfillmentControllerParams = {
  audience: string,
  dexcom: Dexcom,
  dexcomEVGSLookbackHours: number,
  datastore: Datastore,
  auth?: GoogleAuth,
};

export function createDialogFlowFulfillmentController(params: DialogFlowFulfillmentControllerParams) {
  return new DialogFlowFulfillmentControllerImpl(params);
};

class DialogFlowFulfillmentControllerImpl implements DialogFlowFulfillmentController {
  private audience: string;
  private dexcom: Dexcom;
  private dexcomEVGSLookbackHours: number;
  private datastore: Datastore;
  private auth: GoogleAuth;

  constructor(
    params: DialogFlowFulfillmentControllerParams
    ) {
      this.dexcom = params.dexcom;
      this.audience = params.audience;
      this.dexcomEVGSLookbackHours = params.dexcomEVGSLookbackHours;
      this.datastore = params.datastore;
      this.auth = params.auth || new GoogleAuth();
    };

  async handleGETFulfill(req: Request, res: Response) {
    const auth = this.auth;
    const audience = this.audience;
    const datastore = this.datastore;
    const dexcom = this.dexcom;
    const dexcomEVGSLookbackHours = this.dexcomEVGSLookbackHours;

    console.log(JSON.stringify({headers: req.headers}));
    console.log(JSON.stringify({WebhookRequest: req.body}));

    const idToken = req.body.originalDetectIntentRequest.payload.user.idToken;
    const client = await auth.getClient();

    const ticket = await client.verifyIdToken({
        idToken,
        audience,
    });
    const payload = ticket.getPayload();

    // TODO(tjohns): Delete this log message
    console.log(JSON.stringify({payload}));

    const userid = payload['sub'];

    // TODO(tjohns): Would 'sub' be more appropriate than google.profile.id?
    const query = datastore
      .createQuery('User')
      .filter('google.profile.id', userid)
      .limit(1);

    const [userEntities] = await datastore.runQuery(query);

    // TODO(tjohns): Delete this log message
    console.log(JSON.stringify({userEntities}));

    const userEntity = userEntities[0];

    // TODO(tjohns): Delete this log message
    console.log(JSON.stringify({userEntity}));

    if (!userEntity) {
      console.error(`Error: Google User not found: ${userid}`);
      // TODO(tjohns): Return an appropriate fulfillment message here
      res.status(200).json({
        "payload": {
          "google": {
            "expectUserResponse": true,
            "richResponse": {
              "items": [
                {
                  "simpleResponse": {
                    "textToSpeech": "I don't know you."
                  }
                }
              ]
            }
          }
        }
      });

    } else {

      const latestEGVS = await dexcom.getLatestEGVSWithTokenRefresh(userEntity);

      // TODO(tjohns): Delete this log message
      console.log(JSON.stringify({latestEGVS}));

      let textToSpeech = `I didn't get an estimated glucose value from Dexcom that was within the last ${dexcomEVGSLookbackHours} hours. Please confirm your sensor is working and try again.`;
      if (latestEGVS && latestEGVS.value) {
        textToSpeech = latestEGVS.value;
        if (latestEGVS.unit) {
          textToSpeech += " " + latestEGVS.unit;
        }
        if (latestEGVS.displayTime) {
          textToSpeech += " at " + moment(latestEGVS.displayTime).format("h:mm a [on] dddd, MMMM Do");
        }
      }

      res.status(200).json({
        "payload": {
          "google": {
            "expectUserResponse": false,
            "richResponse": {
              "items": [
                {
                  "simpleResponse": {
                    textToSpeech
                  }
                }
              ]
            }
          }
        }
      });

    }
  };
}
