'use strict';

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


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.set('view engine', 'ejs');


// TODO(tjohns): Figure out how to 'await' the secret
// TODO(tjohns): Parameterize URL
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "https://whatsmybg.uc.r.appspot.com/auth/google/callback"
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

// TODO(tjohns): Figure out how to 'await' the secret
app.use(session({
  cookie: {
    httpOnly: true,
    secure: true,
  },
  name: "whatsmybg.sid",
  resave: false,
  saveUninitialized: false,
  store: datastorestore,
  secret: process.env.SESSION_SECRET
}));

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

app.get('/', async (req, res, next) => {
  console.log(JSON.stringify({installUser: req.user}));
  try {
    res.render('install', {user: req.user, dexcom_client_id: process.env.DEXCOM_CLIENT_ID});
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
        redirect_uri: 'https://whatsmybg.uc.r.appspot.com/auth/dexcom/callback',
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

    return dataResponse.data.egvs[dataResponse.data.egvs.length - 1];
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

    const idToken = reg.body.originalDetectIntentRequest.payload.user.idToken;


    res.status(200).json({
      "fulfillmentMessages": [
        {
          "text": {
            "text": [
              "120 on the Money Honey"
            ]
          }
        }
      ]
    });
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
