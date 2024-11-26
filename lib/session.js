import { update, uuid, sparqlEscapeUri, sparqlEscapeString, sparqlEscapeDateTime } from 'mu';

import {
  USER_ID_CLAIM as userIdClaim,
  APPLICATION_NAME as applicationName,
  RESOURCE_BASE_URI as resourceBaseUri,
} from '../config';

async function removeSessions (sessionUri) {
  await update(
    `PREFIX foaf: <http://xmlns.com/foaf/0.1/>
     PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
     PREFIX muSession: <http://mu.semte.ch/vocabularies/session/>
     PREFIX muAccount: <http://mu.semte.ch/vocabularies/account/>
     PREFIX adms: <http://www.w3.org/ns/adms#>
     PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
     PREFIX ext: <http://mu.semte.ch/vocabularies/ext/>

     DELETE WHERE {
       ${sparqlEscapeUri(sessionUri)}
         muSession:account ?account.
       ?account
         a foaf:OnlineAccount;
         mu:uuid ?accountUuid;
         muAccount:createdAt ?date.
       ?agent
         a foaf:Agent;
         mu:uuid ?agentUuid;
         adms:identifier ?identifier;
         foaf:account ?account.
       ?identifier
         a adms:Identifier;
         mu:uuid ?identifierUuid;
         skos:notation ?notation.
     }`);
};

async function insertSession (sessionId, token) {
  const agentUuid = uuid();
  const agentUri = `${resourceBaseUri}m2m-agents/${agentUuid}`;
  const claimUuid = uuid();
  const claimUri = `${resourceBaseUri}m2m-claims/${claimUuid}`;
  const accountUuid = uuid();
  const accountUri = `${resourceBaseUri}accounts/${accountUuid}`;

  await update(`
    PREFIX foaf: <http://xmlns.com/foaf/0.1/>
    PREFIX mu: <http://mu.semte.ch/vocabularies/core/>
    PREFIX muSession: <http://mu.semte.ch/vocabularies/session/>
    PREFIX muAccount: <http://mu.semte.ch/vocabularies/account/>
    PREFIX adms: <http://www.w3.org/ns/adms#>
    PREFIX skos: <http://www.w3.org/2004/02/skos/core#>

    INSERT DATA {
      ${sparqlEscapeUri(sessionId)}
        muSession:account ${sparqlEscapeUri(accountUri)}.
      ${sparqlEscapeUri(accountUri)}
        a foaf:OnlineAccount;
        mu:uuid ${sparqlEscapeString(accountUuid)};
        muAccount:createdAt ${sparqlEscapeDateTime(new Date())}.
      ${sparqlEscapeUri(agentUri)}
        a foaf:Agent;
        mu:uuid ${sparqlEscapeString(agentUuid)};
        adms:identifier ${sparqlEscapeUri(claimUri)};
        foaf:account ${sparqlEscapeUri(accountUri)}.
      ${sparqlEscapeUri(claimUri)}
        a adms:Identifier;
        mu:uuid ${sparqlEscapeString(claimUuid)};
        skos:notation ${sparqlEscapeString(token[userIdClaim])}.
    }`);

  return { agentUri, agentUuid, accountUri, accountUuid };
};

export {
  removeSessions,
  insertSession,

  applicationName
}
