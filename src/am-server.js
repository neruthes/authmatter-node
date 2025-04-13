// 
// import { createRequire } from "module";
// const require = createRequire(import.meta.url);

import fs from 'fs';
import { Provider } from 'oidc-provider';
// const fs = require('fs');
// const Provider = require('oidc-provider').Provider;







let AuthMatterStartupConfig = {
    startup_config_path: process.argv[2] || process.env.AM_CONFIG_PATH,
    startup_config_dict_in_memory: {},
};



const AuthMatterRuntimeConfigManager = {
    get_startup_config: function () {
        AuthMatterStartupConfig.startup_config_dict_in_memory = JSON.parse(fs.readFileSync(AuthMatterStartupConfig.startup_config_path));
        return AuthMatterStartupConfig.startup_config_dict_in_memory;
    },
    save_startup_config: function () {
        // Hope we never need it!
        fs.writeFileSync(AuthMatterStartupConfig.startup_config_path, JSON.stringify(AuthMatterStartupConfig.startup_config_dict_in_memory, '\t', 4));
    },
};







// const oidc = new Provider('http://10.0.233.127:26666', AuthMatterRuntimeConfigManager.get_startup_config());

const clients = []; // empty! you can allow dynamic or override `findById`

const oidc = new Provider(AuthMatterRuntimeConfigManager.get_startup_config().site_hostname, {
    clients,
    features: {
        // pkce: { required: true }, // Enforce PKCE for all
        devInteractions: { enabled: true }, // or false if you provide your own UI
        clientCredentials: { enabled: false },
        introspection: { enabled: false },
        revocation: { enabled: false },
    },
    // Optional: customize how clients are found
    clients: [], // empty list for now
    findClient: async function (clientId) {
        // Return a simple public client object
        return {
            client_id: clientId,
            redirect_uris: [`${AuthMatterRuntimeConfigManager.get_startup_config().site_hostname}/callback/${clientId}`], // you can generalize or load from DB
            response_types: ['code'],
            grant_types: ['authorization_code'],
            token_endpoint_auth_method: 'none', // public client
        };
    },
});

oidc.listen(process.env.PORT || 8080);








// Gracefully shutdown?
let IS_GRACEFULLY_SHUTTING_DOWN = false;

process.on('SIGINT', function () {
    IS_GRACEFULLY_SHUTTING_DOWN = true;
    console.error('\nGracefully shutting down...')
    setTimeout(process.exit, 1200);
});

