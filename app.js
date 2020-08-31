'use strict';

const express = require('express');
const {PubSub} = require('@google-cloud/pubsub');
const bodyParser = require('body-parser');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const {verifyRequestSignature} = require('@slack/events-api');
const {GoogleAuth} = require('google-auth-library');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
const {Datastore} = require('@google-cloud/datastore');
const moment = require('moment');

const pubSubClient = new PubSub();
const secretManagerServiceClient = new SecretManagerServiceClient();
const auth = new GoogleAuth();
const datastore = new Datastore();

const secrets = new Map();
async function getSecret(secretName) {
  let secret = secrets.get(secretName);

  if (!secret) {
    console.log(`No cached secret found, fetching ${secretName} from secret manager`);

    const projectId = await auth.getProjectId();

    const [accessResponse] = await secretManagerServiceClient.accessSecretVersion({
      name: `projects/${projectId}/secrets/${secretName}/versions/latest`,
    });

    secret = accessResponse.payload.data.toString('utf8')
    secrets.set(secretName, secret);
  }
  return secret;
}

async function createCipher() {

  const key = await getSecret('cipher_key');
  const algorithm = 'aes-256-cbc';
  const iv = process.env.CIPHER_IV;

  return crypto.createCipheriv(algorithm, key, iv);
};

async function createDecipher() {

  const key = await getSecret('cipher_key');
  const algorithm = 'aes-256-cbc';
  const iv = process.env.CIPHER_IV;

  return crypto.createDecipheriv(algorithm, key, iv);
};

const app = express();

// TODO(tjohns): rawBodySaver, while a prolific hack, is still a hack
// Consider a PR for body-parser that leaves the rawBody in place, or
// make the 'verify' async
function rawBodySaver (req, res, buf, encoding) {
  if (buf && buf.length) {
    req.rawBody = buf.toString(encoding || 'utf8')
  }
}

app.use(bodyParser.urlencoded({ extended: true, verify: rawBodySaver}));
app.set('view engine', 'ejs');


app.get('/', async (req, res, next) => {
  try {
    res.render('install', {dexcom_client_id: process.env.DEXCOM_CLIENT_ID});
  } catch(error) {
    next(error);
  }
})



app.get('/slackappprivacy', async (req, res, nex) => {
  try {
    res.render('privacy');
  } catch(error) {
    next(error);
  }
})

app.get('/slackappsupport', async (req, res, nex) => {
  try {
    res.render('support');
  } catch(error) {
    next(error);
  }
})


app.get('/auth', async (req, res, next) => {

  try {

    if (req.query.error) {
      console.warn(`Auth failed: ${req.query.error}`);
      res.redirect(`/authfailed?${qs.stringify({error: req.query.error})}`);
      return;
    }

    // TODO(tjohns): Parameterize URL
    const exchangeResponse = await axios(
      {
      method: 'post',
      url: 'https://sandbox-api.dexcom.com/v2/oauth2/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        'cache-control': 'no-cache'
      },
      data: qs.stringify({
        client_id: process.env.DEXCOM_CLIENT_ID,
        client_secret: await getSecret('dexcom_client_secret'),
        grant_type: 'authorization_code',
        redirect_uri: 'https://whatsmybg.uc.r.appspot.com/auth',
        code: req.query.code
      })
    });

    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({exchangeResponse: exchangeResponse.data}));

    // TODO(tjohns): Everyting from here down should be somewhere else rather than in the
    // authorization response path
    const access_token = exchangeResponse.data.access_token;
    const refresh_token = exchangeResponse.data.refresh_token;

    const rangeResponse = await axios(
      {
      method: 'get',
      url: 'https://sandbox-api.dexcom.com/v2/users/self/dataRange',
      headers: {
        'authorization': `Bearer ${access_token}`,
      }
    });
    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({rangeResponse: rangeResponse.data}));

    const rangeEnd = moment.utc(rangeResponse.data.egvs.end.systemTime);
    const rangeStart = moment.utc(rangeResponse.data.egvs.end.systemTime).subtract(3, 'hours');

    const DEXCOM_TIMESTAMP_FORMAT = "YYYY-MM-DDTHH:mm:ss";

    const egvsURL = `https://sandbox-api.dexcom.com/v2/users/self/egvs?startDate=${rangeStart.format(DEXCOM_TIMESTAMP_FORMAT)}&endDate=${rangeEnd.format(DEXCOM_TIMESTAMP_FORMAT)}`;

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

    var latestEGVS = dataResponse.data.egvs[dataResponse.data.egvs.length - 1];

    // TODO(tjohns): Provide some context on how the installation was handled;
    // in other words, let the user know which of these scenarios they're in:
    //   Installed with no API token specified
    //      With the default token only
    //      With an existing team-wide token
    //   Installed with an individual API token specified
    //   Installed with a team-wide API token specified
    //      With an existing team-wide API token
    //      With the specified token now used for tean-wide access
    // Provide the user some instruction on how to fix what they did, if
    // it wasn't what they intended.
    res.redirect(`/authsuccess?${qs.stringify({value: latestEGVS.value})}`);

  } catch(error) {
    next(error);
  }
});

app.get('/authsuccess', async (req, res, next) => {
  try {
    res.render('authsuccess', {value: req.query.value || "Unknown BG"});
  } catch(error) {
    next(error);
  }
});

app.get('/authfailed', async (req, res, next) => {
  try {
    res.render('authfailed', {error: req.query.error || "Unknown Error"});
  } catch(error) {
    next(error);
  }
});



// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});

module.exports = app;
