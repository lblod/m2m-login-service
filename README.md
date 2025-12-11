# ACM/IDM m2m microservice

Microservice running on [mu.semte.ch](http://mu.semte.ch) providing the necessary endpoints to programmatically authenticate using ACMIDM 
Beheerportaal.

## Usage

See [M2M example](https://github.com/lblod/app-m2m-example/) for an example using a python client.

```yaml
  m2m:
    image: lblod/m2m-login-service
    environment:
      MU_APPLICATION_GRAPH: "http://mu.semte.ch/graphs/public"
      MU_APPLICATION_AUTH_DISCOVERY_URL: "https://authenticatie-ti.vlaanderen.be/.well-known/oauth-authorization-server/op"
      MU_APPLICATION_AUTH_CLIENT_ID: "myClientID"
      MU_APPLICATION_AUTH_CLIENT_SECRET: "mySecret"
```

## Environment variables:

| Variable                             | Default Value                                                      | Description                                                    |
|--------------------------------------|--------------------------------------------------------------------|--------------------------------------------------------------- |
| SESSION_GRAPH                        | 'http://mu.semte.ch/graphs/sessions'                               | graph where the session data are stored                        |
| BH_APPLICATION_NAME                  | application/client name in the jwt                                 | the app name. will be used as `ext:sessionRole`                |
| MU_APPLICATION_AUTH_DISCOVERY_URL    | (required)                                                         | the discovery url of the acmidm endpoint                       |
| MU_APPLICATION_AUTH_CLIENT_ID        | (required)                                                         | client id                                                      |
| MU_APPLICATION_AUTH_CLIENT_SECRET    | (required)                                                         | client secret                                                  |

