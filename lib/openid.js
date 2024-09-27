import { Issuer, custom } from 'openid-client';
import fs from 'node:fs/promises';

const discoveryUrl = process.env.MU_APPLICATION_AUTH_DISCOVERY_URL;
const clientId = process.env.MU_APPLICATION_AUTH_CLIENT_ID;
const clientSecret = process.env.MU_APPLICATION_AUTH_CLIENT_SECRET;
const privateKeyPath = process.env.MU_APPLICATION_AUTH_JWK_PRIVATE_KEY;

const requestTimeout = parseInt(process.env.MU_APPLICATION_AUTH_REQUEST_TIMEOUT) || 5000;

custom.setHttpOptionsDefaults({ timeout: requestTimeout });

async function getOpenIdClient(issuer) {
  if (clientSecret) {
    return new issuer.Client({
      client_id: clientId,
      token_endpoint_auth_method: 'client_secret_basic',
      client_secret: clientSecret
    });
  } else {
    try {
      const privateKeyString = await fs.readFile(privateKeyPath, 'utf8');
      const privateKey = JSON.parse(privateKeyString);
      return new issuer.Client({
        client_id: clientId,
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: 'RS256',
      }, { keys: [privateKey] });
    } catch (e) {
      console.log(`Failed to read private key from ${privateKeyPath}: ${e}`);
    }
  }

  throw new Error('Unable to create OpenID Client. Make sure either client secret or JWK private key are configured. Check the docs for more info.');
}

const checkAccessToken = async function (authorizationCode) {
  const issuer = await Issuer.discover(discoveryUrl);
  const client = await getOpenIdClient(issuer);

  try {
    const tokenSet = await client.introspect(authorizationCode, "access_token");
    return tokenSet;
  } catch (e) {
    console.log(`Error while introspecting  token from OpenId Provider: ${e}`);
    throw new Error(`Something went wrong while introspecting the  token: ${e}`);
  }
};
export {
  checkAccessToken
}
