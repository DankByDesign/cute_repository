// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import express from 'express';
import crypto from 'crypto';
import {SecretManagerServiceClient} from '@google-cloud/secret-manager';
import axios from 'axios';
import {Logging} from '@google-cloud/logging';

const app = express();
const client = new SecretManagerServiceClient();
const logging = new Logging();

async function accessSecretVersion(secretName) {
  const [version] = await client.accessSecretVersion({
    name: `projects/YOUR_PROJECT_ID/secrets/${secretName}/versions/latest`,
  });

  // Extract the payload as a string.
  const payload = version.payload.data.toString('utf8');

  return payload;
}

// Parse raw body
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

// Your webhook endpoint
app.post('/webhook-endpoint', async (req, res) => {
  const signatureHeader = req.headers['x-kws-signature'];
  const { t: timestamp, v1: receivedSignature } = signatureHeader.split(',').reduce((acc, part) => {
    const [key, value] = part.split('=');
    acc[key] = value;
    return acc;
  }, {});

  const secretKey = await accessSecretVersion('KWS_WEBHOOK_SECRET'); // get secret key from Google Cloud Secret Manager
  const body = req.rawBody; // raw request body as UTF-8 string

  const signature = crypto
    .createHmac('sha256', secretKey)
    .update(`${timestamp}.${body}`)
    .digest('hex');

  if (signature === receivedSignature) {
    // Signature is valid, process the webhook
    const { name, time, orgId, productId, environmentId, payload } = req.body;

    // Log the request
    const log = logging.log('my-log');
    const metadata = {
      resource: {type: 'global'},
    };
    const entry = log.entry(metadata, req.body);
    await log.write(entry);

    // Notify Unity game
    const unityGameUrl = 'http://your-unity-game-url.com'; // replace with your Unity game's URL
    const unityServiceAccountCredentials = await accessSecretVersion('UNITY_SERVICE_ACCOUNT_CREDENTIALS'); // get Unity service account credentials from Google Cloud Secret Manager
    const message = { 
      approved: true, 
      playerId: payload.externalPayload // extract player ID from the payload
    }; 
    axios.post(unityGameUrl, message, {
      headers: {
        'Authorization': `Bearer ${unityServiceAccountCredentials}` // use Unity service account credentials for authentication
      }
    });

    res.sendStatus(200);
  } else {
    // Invalid signature, respond with an error
    res.status(403).send('Invalid signature');
  }
});

export default app;
