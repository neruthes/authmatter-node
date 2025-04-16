# AuthMatter (Nodejs edition)

SSO IdP peering with OIDC.





## Features

- [x] OIDC Provider (OP) compatibility.
- [x] TOTP user authentication
- [ ] OIDC Consumer (RP) compatibility.
- [ ] Web UI management
- [x] Static user data in configuration file.
- [ ] Dynamic user data in SQLite.





## Deployment

- Clone repo and `yarn`.
- Have a config JSON like `examples/dev1.json`.
- Run `PORT=8080 node src/am-server.js path/to/config.json`






## Copyright

Copyright (c) 2025 Neruthes. https://neruthes.xyz/

Released with the GNU GPL 2.0 license.


