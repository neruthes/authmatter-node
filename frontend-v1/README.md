# Frontend V1

This is a simple web frontend for AuthMatter. We use this frontend to debug.


## Serving

A single `app.html` is used. It will be served at most human-fronting HTTP endpoints.

These include:

- GET /oidc/auth
- GET /oidc/auth/:uid
- POST /oidc/interaction/:uid



## Using

This single page application (SPA) will interact with `/api/webcmd` APIs to allow the following operations:

- Login with email address and TOTP
- Keep token in local storage (?)
- Validate token with server and show whoami to user (?)


