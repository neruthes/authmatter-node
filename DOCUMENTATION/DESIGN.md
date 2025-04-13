---
author: Neruthes
date: 2025-04-13
---


# AuthMatter Design Document


## Introduction

Existing SSO solutions (like Zitadel and Keycloak) are often too heavy for small autonomous organizations to manage.
And they lack a modern peer roaming feature.
AuthMatter is designed to be a KISS solution.



## Features

- **Domain Simplicity**: An instance is an authoritative IdP for one domain only. One instance shall not represent multiple domains. No need to be neutral. One instance, one organization, one domain.
- **OpenID Provider**: Show OpenID to consumers (e.g. GitLab).
- **OpenID Consumer**: Get OpenID from providers (e.g. another AuthMatter instance).
- **User Roaming**: A clear boundary between domestic users and roaming users. Can only roam from its home instance, i.e. the OpenID `email` scope value and the instance authoritative domain (`org_domain`) must match. Instance admin cannot edit roaming user info; when necessary, it can instruct instance server to forget a roaming user (i.e. to stop caching it).
- **Instance Peering**: Allow guest instances to endorse its users to roam here. Zero configuration between AuthMatter instances using PKCE. Admin should maintain a whitelist of domains. Use DNS TXT record to authorize `am.example.com` to represent the entirety of `example.com` domain and `*@example.com` users.
- **Tiered User Info Supply**: Only supply domestic users profile info to the OpenID consumer; roaming users show blank profile (preserving cached `email` only) to the OpenID consumer.
- **Passwordless Login**: Instance admin can easily add/remove TOTP credentials for users. No password is allowed. Use upstream IdP (like GitHub and Google) and cryptographic technologies (like TOTP and Passkey).




## Deployment and Configuration

We should optimize for Docker Compose with mount points.
Upon startup, read config JSON file path (`AM_CONFIG_PATH`) and SQLite file path (`AM_SQLITE_PATH`) from env.

Necessary startup configuration entries:

| Key                  | Description                                     |
| -------------------- | ----------------------------------------------- |
| (Required)           |                                                 |
| `site_hostname`      | Site hostname for HTTP/HTTPS interactions.      |
| `org_domain`         | Organization domain name.                       |
| (Nullable)           |                                                 |
| `wellknown_static`   | Static entries for RFC 8615 (`/.well-known/*`). |
| `wellknown_upstream` | Dynamic entries, relaying between upstream.     |




### Sample Plain Deployment

```sh
AM_CONFIG_PATH=examples/dev1.json \
  AM_SQLITE_PATH=examples/dev1.sqlite \
  PORT=8080 \
  node src/am-server.js
```



### Sample Docker Deployment

```yaml
services:
  authmatter:
    restart: 'always'
    image: '...'
    command: 'authmatter-docker-entry.sh'
    volumes:            # Mount single files into container
      - ./examples/dev1.json:/config.json
      - ./examples/dev1.sqlite:/db.sqlite
    ports:
      - '13579:8080'    # outer:inner
```


## Initial Demo

We use `Express.js` to handle HTTP interactions.
For OIDC implementation, we use the `node-oidc-provider` package.



## Further Development

We may consider migrating to a different stack after we fully validate major design decisions.



## Architecture

Server daemon script contains 5 components:

- OIDC Provider
- OIDC Consumer
- Database Manager
- User APIs (`POST /api/webcmd`)
- RFC 8615 (`GET /.well-known/*`)

### OIDC Provider
Use `node-oidc-provider` library to handle requests.

Use HTTP paths that are used by Zitadel.

### OIDC Consumer
Use `openid-client` library to welcome roaming users.

### Database Manager
Use SQLite to keep data, including domestic users, roaming users, domains whitelist, external IdP client secrets, etc.

### User APIs
We will make a modern single-page application (SPA) that interacts with the server.
We prefer CLI-like JSON RPC (command name and argv object) over HTTP with bearer token.

```
POST /api/webcmd
Request:
{
    "cmd": "whoami",
    "argv": {}
}
Response:
{
    "cmd": "user.whoami",
    "error": 0,
    "stdout": {
        "uid": 1234,
        "username": "john@example.com",
        "display_name": "John Appleseed",
        "user_roles": [ "staff", "admin", "is_domestic" ],
        "home": "am.example.com",
        "org_domain": "example.com"
    },
    "stderr": null
}
```

### RFC 8615
Upon request, first try finding the path in `wellknown_static` in startup config JSON.
It should be a key-value map from URI suffixes to JSON subtrees.

If not found, try reverse proxying to an upstream hostname `wellknown_upstream`.





## Peer Verification

A peer at `id.example.com` may claim to be the AuthMatter instance for `example.com` domain.
We will support several ways to set up proof.

- RFC 8615: Point `idp_site` to `id.example.com` in `authmatter.json`.
- DNS: Have a TXT record `AuthMatterSite=id.example.com` at `example.com`.





## Technical Notes

- OIDC traditionally requires a `client_secret` which is usually configured manually by an admin. However, we can use PKCE so zero-configuration for peering is possible.




## Further Thinking

- Will it be easily enough to use an AuthMatter instance as an OIDC provider with a Zitadel instance?
- Using `node-oidc-provider` library, how do we reload Provider config?



