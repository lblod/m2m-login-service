import { app, query } from 'mu';
import { checkAccessToken } from './lib/openid';
import { removeSessions, insertSession } from './lib/session';
import httpContext from 'express-http-context';

/**
 * Configuration validation on startup
 */
const requiredEnvironmentVariables = [
  'MU_APPLICATION_AUTH_DISCOVERY_URL',
  'MU_APPLICATION_AUTH_CLIENT_ID',
];

function error(res, message, status = 400) {
  return res.status(status).json({errors: [ { title: message } ] });
};

requiredEnvironmentVariables.forEach(key => {
  if (!process.env[key]) {
    console.log(`Environment variable ${key} must be configured`);
    process.exit(1);
  }
});

app.post('/sessions', async function (req, res, next) {
  const sessionUri = req.get('mu-session-id');
  if (!sessionUri)
    return error(res, 'Session header is missing');

  const authorizationCode = req.body['authorizationCode'];
  if (!authorizationCode)
    return error(res, 'Authorization code is missing');

  try {
    let token;
    try {
      token = await checkAccessToken(authorizationCode);
      if (!token.active) {
        throw "Token not active";
      }
    } catch (e) {
      console.log(`Failed to introspect token for authorization code: ${e.message || e}`);
      return res.status(401).end();
    }

    await removeSessions(sessionUri);

    if (process.env['DEBUG_LOG_TOKENSETS']) {
      console.log(`Received token ${JSON.stringify(token)}`);
    }

    await insertSession( sessionUri, token );

    // TODO: Templates could offer a way to execute this
    httpContext.get('response').removeHeader('mu-auth-allowed-groups');

    // This sets our mu-auth-allowed-groups with cached access rights,
    // leading to a more efficient cookie
    await query("SELECT * WHERE { ?s ?p ?o. } LIMIT 1");

    return res.status(201).send({
      links: {
        self: '/sessions/current'
      },
      data: {
        type: 'sessions',
        id: sessionUri,
        attributes: { }
      }
    });
  } catch (e) {
    return next(new Error(e.message));
  }
});

/**
 * Log out from the current session, i.e. detaching the session from the user's account.
 *
 * @return [204] On successful logout
 * @return [400] If the session header is missing or invalid
*/
app.delete('/sessions/current', async function (req, res, next) {
  const sessionUri = req.get('mu-session-id');
  if (!sessionUri)
    return error(res, 'Session header is missing');

  try {
    await removeSessions(sessionUri);

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(204).end();
  } catch (e) {
    return next(new Error(e.message));
  }
});

/**
 * Error handler translating thrown Errors to 500 HTTP responses
 */
app.use(function (err, req, res, next) {
  console.log(`Error: ${err.message}`);
  res.status(500);
  res.json({
    errors: [{ title: err.message }]
  });
});
