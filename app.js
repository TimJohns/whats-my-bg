'use strict';

const CIPHER_ALGORITHM = 'aes-256-cbc';
const CIPHER_KEY_SECRET_NAME = 'cipher_key';
const CIPHER_IV = process.env.CIPHER_IV;

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
// TODO(tjohns): Figure out a good way to 'await' GOOGLE_CLIENT_SECRET from Secret Manager
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL;
const GOOGLE_ACTIONS_CLIENT_ID = process.env.GOOGLE_ACTIONS_CLIENT_ID;

const SESSION_COOKIE_NAME = "whatsmybg.sid";
// TODO(tjohns): Figure out a good way to 'await' SESSION_SECRET from Secret Manager
const SESSION_SECRET = process.env.SESSION_SECRET;

const DEXCOM_CLIENT_ID = process.env.DEXCOM_CLIENT_ID;
const DEXCOM_API_URL = process.env.DEXCOM_API_URL;
const DEXCOM_REDIRECT_URI = process.env.DEXCOM_REDIRECT_URI;
const DEXCOM_TIMESTAMP_FORMAT = "YYYY-MM-DDTHH:mm:ss";
const DEXCOM_EVGS_LOOKBACK_HOURS = 4;

const express = require('express');
const {PubSub} = require('@google-cloud/pubsub');
const bodyParser = require('body-parser');
const {SecretManagerServiceClient} = require('@google-cloud/secret-manager');
const {GoogleAuth} = require('google-auth-library');
const axios = require('axios');
const qs = require('qs');
const crypto = require('crypto');
const {Datastore} = require('@google-cloud/datastore');
const {DatastoreStore} = require('@google-cloud/connect-datastore');
const moment = require('moment');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { text } = require('body-parser');

const pubSubClient = new PubSub();
const secretManagerServiceClient = new SecretManagerServiceClient();
const auth = new GoogleAuth();
const datastore = new Datastore();
const datastorestore = new DatastoreStore({
  dataset: datastore
});

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
  const key = await getSecret(CIPHER_KEY_SECRET_NAME);
  return crypto.createCipheriv(CIPHER_ALGORITHM, key, CIPHER_IV);
};

async function createDecipher() {
  const key = await getSecret(CIPHER_KEY_SECRET_NAME);
  return crypto.createDecipheriv(CIPHER_ALGORITHM, key, CIPHER_IV);
};

const app = express();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.set('view engine', 'ejs');

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: GOOGLE_CALLBACK_URL
},
function(accessToken, refreshToken, profile, cb) {
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

passport.serializeUser(function(user, cb) {
  console.log(JSON.stringify({serializeUser: user}));
  cb(null, user.key.id);
});

passport.deserializeUser(function(id, cb) {
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

app.set('trust proxy', 1) // trust first proxy (app engine terminates TLS before us)

app.use(session({
  cookie: {
    httpOnly: true,
    secure: true,
  },
  name: SESSION_COOKIE_NAME,
  resave: false,
  saveUninitialized: false,
  store: datastorestore,
  secret: SESSION_SECRET
}));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', async (req, res, next) => {
  console.log(JSON.stringify({installUser: req.user}));
  try {
    const dexcomAuthURL = `${DEXCOM_API_URL}/v2/oauth2/login?client_id=${encodeURIComponent(DEXCOM_CLIENT_ID)}&redirect_uri=${encodeURIComponent(DEXCOM_REDIRECT_URI)}&response_type=code&scope=offline_access`;
    res.render('install', {user: req.user, dexcomAuthURL});
  } catch(error) {
    next(error);
  }
})

app.get('/privacy', async (req, res, nex) => {
  try {
    res.render('privacy');
  } catch(error) {
    next(error);
  }
})

app.get('/support', async (req, res, nex) => {
  try {
    res.render('support');
  } catch(error) {
    next(error);
  }
})

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });

app.get('/auth/dexcom/callback', async (req, res, next) => {

  // If we're not logged in, this makes no sense to us, let someone else handle it (or not).
  if (!req.user) { next(); return; }

  try {

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
        client_id: DEXCOM_CLIENT_ID,
        client_secret: await getSecret('dexcom_client_secret'),
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

    const latestEGVS = await getLatestEGVS(req.user.data.dexcom.access_token);

    res.redirect(`/authsuccess?${qs.stringify({value: latestEGVS.value})}`);

  } catch(error) {
    next(error);
  }
});

async function getLatestEGVS(access_token) {

    const rangeResponse = await axios(
      {
      method: 'get',
      url: `${DEXCOM_API_URL}/v2/users/self/dataRange`,
      headers: {
        'authorization': `Bearer ${access_token}`,
      }
    });
    // TODO(tjohns) Remove this log statement.
    console.log(JSON.stringify({rangeResponse: rangeResponse.data}));

    const rangeEnd = moment.utc(rangeResponse.data.egvs.end.systemTime);
    const rangeStart = moment.utc(rangeResponse.data.egvs.end.systemTime).subtract(DEXCOM_EVGS_LOOKBACK_HOURS, 'hours');

    const egvsURL = `${DEXCOM_API_URL}/v2/users/self/egvs?startDate=${rangeStart.format(DEXCOM_TIMESTAMP_FORMAT)}&endDate=${rangeEnd.format(DEXCOM_TIMESTAMP_FORMAT)}`;

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


app.post('/fulfill', async (req, res, next) => {
  try {
    console.log(JSON.stringify({headers: req.headers}));
    console.log(JSON.stringify({WebhookRequest: req.body}));

    const idToken = req.body.originalDetectIntentRequest.payload.user.idToken;
    const client = await auth.getClient();

    const ticket = await client.verifyIdToken({
        idToken,
        audience: GOOGLE_ACTIONS_CLIENT_ID,
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
      console.error(`Error: Google User not found: ${userId}`);
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

      async function getLatestEGVSWithTokenRefresh(userEntity) {

        async function refreshDexcomAccessToken(userEntity) {
          // call dexcom
          const refreshResponse = await axios(
            {
            method: 'post',
            url: `${DEXCOM_API_URL}/v2/oauth2/token`,
            headers: {
              'content-type': 'application/x-www-form-urlencoded',
              'cache-control': 'no-cache'
            },
            data: qs.stringify({
              client_id: DEXCOM_CLIENT_ID,
              client_secret: await getSecret('dexcom_client_secret'),
              grant_type: 'refresh_token',
              redirect_uri: DEXCOM_REDIRECT_URI,
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
          return await getLatestEGVS(userEntity.dexcom.access_token);
        } catch(error) {

          if (error.response.status != 401) {
            throw error;
          }

          // If at first you don't succeed, you're access_token is probably expired.

          // Get a new access_token (and save it)
          await refreshDexcomAccessToken(userEntity);

          // Try again.
          return await getLatestEGVS(userEntity.dexcom.access_token);
        }
      };

      const latestEGVS = await getLatestEGVSWithTokenRefresh(userEntity);

      // TODO(tjohns): Delete this log message
      console.log(JSON.stringify({latestEGVS}));

      let textToSpeech = `I didn't get an estimated glucose value from Dexcom that was within the last ${DEXCOM_EVGS_LOOKBACK_HOURS} hours. Please confirm your sensor is working and try again.`;
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
            "expectUserResponse": true,
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
