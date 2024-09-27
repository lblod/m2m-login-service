import { app } from 'mu';
import { getSessionIdHeader, error } from './utils';
import { saveLog } from './logs';
import { checkAccessToken } from './lib/openid';
import {
  applicationName, groupIdClaim, removeOldSessions, removeCurrentSession,
  ensureUserAndAccount, insertNewSessionForAccount,
  selectAccountBySession,
  selectBestuurseenheidByNumber
} from './lib/session';

const logsGraph = process.env.LOGS_GRAPH || 'http://mu.semte.ch/graphs/public';

/**
 * Configuration validation on startup
 */
const requiredEnvironmentVariables = [
  'MU_APPLICATION_AUTH_DISCOVERY_URL',
  'MU_APPLICATION_AUTH_CLIENT_ID',
];
requiredEnvironmentVariables.forEach(key => {
  if (!process.env[key]) {
    console.log(`Environment variable ${key} must be configured`);
    process.exit(1);
  }
});

app.post('/sessions', async function (req, res, next) {
  const sessionUri = getSessionIdHeader(req);
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

    await removeOldSessions(sessionUri);


    if (process.env['DEBUG_LOG_TOKENSETS']) {
      console.log(`Received token ${JSON.stringify(token)}`);
    }


    const { groupUri, groupId } = await selectBestuurseenheidByNumber(token);

    if (!groupUri || !groupId) {
      console.log(`Application is not allowed to login. No bestuurseenheid found.`);
      saveLog(
        logsGraph,
        `http://data.lblod.info/class-names/no-bestuurseenheid-for-role`,
        `Application is not allowed to login. No bestuurseenheid found`,
        sessionUri,
        token[groupIdClaim]);
      return res.header('mu-auth-allowed-groups', 'CLEAR').status(403).end();
    }

    const { accountUri, accountId } = await ensureUserAndAccount(token, groupId);

    const { sessionId } = await insertNewSessionForAccount(accountUri, sessionUri, groupUri, token);

    return res.header('mu-auth-allowed-groups', 'CLEAR').status(201).send({
      links: {
        self: '/sessions/current'
      },
      data: {
        type: 'sessions',
        id: sessionId,
        attributes: {
          roles: [token[applicationName]] // probably not needed
        }
      },
      relationships: {
        account: {
          links: { related: `/accounts/${accountId}` },
          data: { type: 'accounts', id: accountId }
        },
        group: {
          links: { related: `/bestuurseenheden/${groupId}` },
          data: { type: 'bestuurseenheden', id: groupId }
        }
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
  const sessionUri = getSessionIdHeader(req);
  if (!sessionUri)
    return error(res, 'Session header is missing');

  try {
    const { accountUri } = await selectAccountBySession(sessionUri);
    if (!accountUri)
      return error(res, 'Invalid session');

    await removeCurrentSession(sessionUri);

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
