import { uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeInt, sparqlEscapeDateTime } from 'mu';
import { querySudo as query, updateSudo as update } from '@lblod/mu-auth-sudo';
import {
  USER_ID_CLAIM as userIdClaim,
  ACCOUNT_ID_CLAIM as accountIdClaim,
  GROUP_ID_CLAIM as groupIdClaim,
  APPLICATION_NAME as applicationName,
  RESOURCE_BASE_URI as resourceBaseUri,
  USER_GRAPH_TEMPLATE,
  ACCOUNT_GRAPH_TEMPLATE,
  SESSION_GRAPH,
  ORGANIZATION_TYPE
} from '../config';

const serviceHomepage = 'https://github.com/lblod/acmidm-login-service';
const personResourceBaseUri = `${resourceBaseUri}id/persoon/`;
const accountResourceBaseUri = `${resourceBaseUri}id/account/`;
const identifierResourceBaseUri = `${resourceBaseUri}id/identificator/`;


function accountGraphFor(params) {
  return ACCOUNT_GRAPH_TEMPLATE.replace('{{groupId}}', params.groupId);
}

function userGraphFor(params) {
  return USER_GRAPH_TEMPLATE.replace('{{groupId}}', params.groupId);
}
const removeOldSessions = async function (sessionUri) {
  await update(
    `PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX session: <http://mu.semte.ch/vocabularies/session/>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
     PREFIX dcterms: <http://purl.org/dc/terms/>

     DELETE WHERE {
       GRAPH ${sparqlEscapeUri(SESSION_GRAPH)} {
           ${sparqlEscapeUri(sessionUri)} ?p ?o .
       }
     }`);
};

const removeCurrentSession = async function (sessionUri) {
  await removeOldSessions(sessionUri);
};

const ensureUserAndAccount = async function (token, groupId) {
  const userGraph = userGraphFor({ groupId });
  const accountGraph = accountGraphFor({ groupId });
  const { personUri } = await ensureUser(token, userGraph);
  const { accountUri, accountId } = await ensureAccountForUser(personUri, token, accountGraph);
  return { accountUri, accountId };
};

const ensureUser = async function (token, graph) {
  const userId = token[userIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?person ?personId
    FROM <${graph}> {
      ?person a foaf:Person ;
            mu:uuid ?personId ;
            adms:identifier ?identifier .
      ?identifier skos:notation ${sparqlEscapeString(userId)} .
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { personUri: result.person.value, personId: result.personId.value };
  } else {
    const { personUri, personId } = await insertNewUser(token, graph);
    return { personUri, personId };
  }
};

const insertNewUser = async function (token, graph) {
  const personId = uuid();
  const person = `${personResourceBaseUri}${personId}`;
  const identifierId = uuid();
  const identifier = `${identifierResourceBaseUri}${identifierId}`;

  let insertData = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(person)} a foaf:Person ;
                                 mu:uuid ${sparqlEscapeString(personId)} ;
                                 adms:identifier ${sparqlEscapeUri(identifier)} .
        ${sparqlEscapeUri(identifier)} a adms:Identifier ;
                                       mu:uuid ${sparqlEscapeString(identifierId)} ;
                                       skos:notation ${sparqlEscapeString(token[userIdClaim])} .
      }
    }
    `;


  await update(insertData);

  return { personUri: person, personId: personId };
};

const ensureAccountForUser = async function (personUri, token, graph) {
  const accountId = token[accountIdClaim];

  const queryResult = await query(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?account ?accountId
    FROM <${graph}> {
      ${sparqlEscapeUri(personUri)} foaf:account ?account .
      ?account a foaf:OnlineAccount ;
               mu:uuid ?accountId ;
               dcterms:identifier ${sparqlEscapeString(accountId)} .
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { accountUri: result.account.value, accountId: result.accountId.value };
  } else {
    const { accountUri, accountId } = await insertNewAccountForUser(personUri, token, graph);
    return { accountUri, accountId };
  }
};


const insertNewAccountForUser = async function (person, token, graph) {
  const accountId = uuid();
  const account = `${accountResourceBaseUri}${accountId}`;
  const now = new Date();

  let insertData = `
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>
    PREFIX acmidm: <http://mu.semte.ch/vocabularies/ext/acmidm/>

    INSERT DATA {
      GRAPH <${graph}> {
        ${sparqlEscapeUri(person)} foaf:account ${sparqlEscapeUri(account)} .
        ${sparqlEscapeUri(account)} a foaf:OnlineAccount ;
                                 mu:uuid ${sparqlEscapeString(accountId)} ;
                                 foaf:accountServiceHomepage ${sparqlEscapeUri(serviceHomepage)} ;
                                 dcterms:identifier ${sparqlEscapeString(token[accountIdClaim])} ;
                                 dcterms:created ${sparqlEscapeDateTime(now)} .
      }
    }
    `;

  await update(insertData);

  return { accountUri: account, accountId: accountId };
};

const insertNewSessionForAccount = async function (accountUri, sessionUri, groupUri, token) {
  const sessionId = uuid();
  const now = new Date();
  const exp = token.exp;
  const issuedAt = token.iat;
  const appName = token[applicationName];

  const insertData = `
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    INSERT DATA {
      GRAPH ${sparqlEscapeUri(SESSION_GRAPH)} {
        ${sparqlEscapeUri(sessionUri)} mu:uuid ${sparqlEscapeString(sessionId)} ;
                                 session:account ${sparqlEscapeUri(accountUri)} ;
                                 ext:sessionGroup ${sparqlEscapeUri(groupUri)}  ;
                                 dcterms:modified ${sparqlEscapeDateTime(now)}  ;
                                 ext:exp ${sparqlEscapeInt(exp)};
                                 ext:iat ${sparqlEscapeInt(issuedAt)};
                                 ext:applicationName ${sparqlEscapeString(appName)}.
      }
    }
    `;

  await update(insertData);
  return { sessionUri, sessionId };
};

const selectBestuurseenheidByNumber = async function (token) {
  if (token[groupIdClaim]) {
    const identifier = token[groupIdClaim];

    const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX dcterms: <http://purl.org/dc/terms/>

    SELECT ?group ?groupId
    FROM <${process.env.MU_APPLICATION_GRAPH}>
    WHERE {
      ?group a ${sparqlEscapeUri(ORGANIZATION_TYPE)} ;
             mu:uuid ?groupId ;
             dcterms:identifier ${sparqlEscapeString(identifier)} .
    }`);

    if (queryResult.results.bindings.length) {
      const result = queryResult.results.bindings[0];
      return { groupUri: result.group.value, groupId: result.groupId.value };
    }
  }

  return { groupUri: null, groupId: null };
};

async function getGroupIdForSession(session) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    SELECT DISTINCT ?groupId WHERE {
       GRAPH ${sparqlEscapeUri(SESSION_GRAPH)} {
          ${sparqlEscapeUri(session)} ext:sessionGroup ?group .
      }
      GRAPH <${process.env.MU_APPLICATION_GRAPH}> {
      ?group a ${sparqlEscapeUri(ORGANIZATION_TYPE)} ;
             mu:uuid ?groupId .
      }
      }
  `);
  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return result.groupId.value;
  }
  else
    return null;
}

async function selectAccountBySession(session) {
  const groupId = await getGroupIdForSession(session);
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX besluit: <http://data.vlaanderen.be/ns/besluit#>

    SELECT ?account ?accountId
    WHERE {
       GRAPH ${sparqlEscapeUri(SESSION_GRAPH)} {
          ${sparqlEscapeUri(session)} session:account ?account.
      }
      GRAPH ${sparqlEscapeUri(accountGraphFor({ groupId }))} {
          ?account a foaf:OnlineAccount ;
                   mu:uuid ?accountId .
      }
    }`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return { accountUri: result.account.value, accountId: result.accountId.value };
  } else {
    return { accountUri: null, accountId: null };
  }
};

const selectCurrentSession = async function (account) {
  const queryResult = await query(`
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX session: <http://mu.semte.ch/vocabularies/session/>
    PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>

    SELECT ?session ?sessionId ?group ?groupId (GROUP_CONCAT(?role; SEPARATOR = ',') as ?roles)
    WHERE {
       GRAPH ${sparqlEscapeUri(SESSION_GRAPH)} {
          ?session session:account ${sparqlEscapeUri(account)} ;
                   mu:uuid ?sessionId ;
                   ext:sessionGroup ?group ;
                   ext:sessionRole ?role .
      }
      GRAPH <${process.env.MU_APPLICATION_GRAPH}> {
          ?group mu:uuid ?groupId .
      }
    } GROUP BY ?session ?sessionId ?group ?groupId`);

  if (queryResult.results.bindings.length) {
    const result = queryResult.results.bindings[0];
    return {
      sessionUri: result.session.value,
      sessionId: result.sessionId.value,
      groupUri: result.group.value,
      groupId: result.groupId.value,
      roles: result.roles.value.split(',')
    };
  } else {
    return { sessionUri: null, sessionId: null, groupUri: null, groupId: null, roles: null };
  }
};

export {
  removeOldSessions,
  removeCurrentSession,
  ensureUserAndAccount,
  insertNewSessionForAccount,
  selectBestuurseenheidByNumber,
  selectAccountBySession,
  selectCurrentSession,
  userIdClaim,
  accountIdClaim,
  groupIdClaim,
  applicationName
}
