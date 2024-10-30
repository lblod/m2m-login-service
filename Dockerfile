FROM semtech/mu-javascript-template:feature-query-meta

LABEL maintainer="info@redpencil.io"

ENV MU_APPLICATION_GRAPH http://mu.semte.ch/graphs/public
ENV MU_APPLICATION_AUTH_USERID_CLAIM client_id
ENV MU_APPLICATION_AUTH_ACCOUNTID_CLAIM sub
ENV MU_APPLICATION_AUTH_JWK_PRIVATE_KEY /config/jwk_private_key.json
