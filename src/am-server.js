// ==========================================================================
//
// DEVELOPER NOTES
//
// How to reset dev database: sqlite3 examples/dev1.sqlite "VACUUM;"
//
// ==========================================================================





import fs from 'fs';
import express from 'express';
import { Provider } from 'oidc-provider';


const fancy_stringify_json = function (obj) {
    return JSON.stringify(obj, '\t', 4);
};
const end_res_with_json = function (res, obj) {
    res.end(fancy_stringify_json(obj));
}





// Use mock database before the database structure is fully decided
const DevMockDatabase = {
    uid_autoincremental_heap: 1,

    users: {
        // UID 0 and lower are reserved for error handling
        1: {
            uid: 1,
            username_short: 'root', // Really stored in database
            username: 'root@localhost', // Computed from `username_short` and `org_domain`
            display_name: 'AuthMatterRootUser',
            user_roles: ['staff', 'admin'],
            is_domestic: true,
            org_domain: '!', // Show '!' when is domestic
            home: '!', // Computed via domain verification, if not domestic
            is_frozen: false,
        }
    },
    roaming_from_domains: [
        'shinonometn.com',
        'nekostein.com',
    ]
};



// Rewrite implementation when migrating to SQLite
const DatabaseService = {
    get_user_by_uid: function (uid) {
        if (DevMockDatabase.users[uid]) {
            return DevMockDatabase.users[uid];
        } else {
            throw (new Error('ERR10004: User does not exist for given UID'));
        };
    },
    get_roaming_peers_domain_whitelist: function () {
        return DevMockDatabase.roaming_from_domains;
    },
};


const SystemReservedRuntimeConstants = {
    roles: [
        'staff', 'admin'
    ]
};






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






// Empty config?
// const oidc = new Provider('AuthMatterRuntimeConfigManager.get_startup_config().site_hostname', {});

const clients = []; // empty! you can allow dynamic or override `findById`

// Example config copied from lib
// const oidc = new Provider(AuthMatterRuntimeConfigManager.get_startup_config().site_hostname, {
//     clients,
//     features: {
//         // pkce: { required: true }, // Enforce PKCE for all
//         devInteractions: { enabled: true }, // or false if you provide your own UI
//         clientCredentials: { enabled: false },
//         introspection: { enabled: false },
//         revocation: { enabled: false },
//     },
//     // Optional: customize how clients are found
//     clients: [], // empty list for now
//     findClient: async function (clientId) {
//         // Return a simple public client object
//         return {
//             client_id: clientId,
//             redirect_uris: [`${AuthMatterRuntimeConfigManager.get_startup_config().site_hostname}/callback/${clientId}`], // you can generalize or load from DB
//             response_types: ['code'],
//             grant_types: ['authorization_code'],
//             token_endpoint_auth_method: 'none', // public client
//         };
//     },
// });
// oidc.listen(process.env.PORT || 8080);







// =================================================
// WebCmd user-server authenticated interactions
// =================================================
const validate_web_token = function (token) {
    // TODO
    // Always true for now
    return {
        err: 0,
        err_msg: 'OK',
        uid: 1
    };
};


// Every command should receive: argv, safe_env, req, res
const RealCommands = {
    'user.whoami': function (argv, safe_env, req, res) {
        // Test: curl --request POST --data '{ "cmd":"user.whoami","argv":{} }' http://localhost:18800/api/webcmd
        end_res_with_json(res, {
            error: 0,
            stderr: '',
            stdout: DatabaseService.get_user_by_uid(safe_env.uid),
        });
    },
    'admin.useradd': function (argv, safe_env, req, res) {
        // Test: curl --request POST --data '{ "cmd":"admin.useradd","argv":{"username":"neruthes@localhost"} }' http://localhost:18800/api/webcmd
        end_res_with_json(res, {
            error: 0,
            stderr: '',
            stdout: {}
        });
    },
};

const BusinessLogicHelpers = {
    check_is_admin: function (uid) {
        if (!BusinessLogicHelpers.check_is_good_standing_user(uid)) {
            return false;
        };
        let user_obj = DatabaseService.get_user_by_uid(uid);
        if (user_obj) {
            return user_obj.roles.indexOf('admin') >= 0;
        };
        return false;
    },
    check_is_existing_user: function (uid) {
        try {
            DatabaseService.get_user_by_uid(uid);
        } catch (e) {
            return false;
        };
        return true; // No error caught
    },
    check_is_good_standing_user: function (uid) {
        if (!BusinessLogicHelpers.check_is_existing_user(uid)) {
            return false;
        };
        let user_obj = DatabaseService.get_user_by_uid(uid);
        if (
            user_obj.org_domain !== AuthMatterRuntimeConfigManager.get_startup_config().org_domain && // Not domestic
            DatabaseService.get_roaming_peers_domain_whitelist().indexOf(user_obj) < 0 // Not in whitelist
        ) {
            // Possibly stale user from removed peer?
            return false;
        };
    },
};

const default_json_res_headers = { 'content-type': 'application/json' };
const AcceptIncomingRequest = function (cmd, argv, safe_env, req, res) {
    if (RealCommands[cmd] instanceof Function) {
        RealCommands[cmd](argv, safe_env, req, res)
    } else {
        res.writeHead(200, default_json_res_headers);
        res.end(JSON.stringify({
            error: 10003,
            stderr: `Command "${cmd}" not found`
        }));
    };
};







// =================================================
// Express.js gateway setup
// =================================================
let express_gateway = express();
express_gateway.post('/api/webcmd', function (req, res) {
    // console.log('11111');
    let req_post_body = '';
    req.on('data', function (req_new_data) { req_post_body += req_new_data });
    req.on('end', function () {
        let parsed_req_body = null;
        try {
            parsed_req_body = JSON.parse(req_post_body);
        } catch (e) {
            res.writeHead(200, default_json_res_headers);
            res.end(JSON.stringify({ error: 10001, stderr: 'Invalid payload format', stdout: {} }));
            return;
        };
        const token_result = validate_web_token(req.headers.authorization);
        let safe_env = {
            uid: token_result.uid
        };
        if (!token_result.err) {
            // Is valid token!
            res.writeHead(200, default_json_res_headers);
            AcceptIncomingRequest(parsed_req_body.cmd, parsed_req_body.argv, safe_env, req, res);
        } else {
            res.writeHead(200, default_json_res_headers);
            res.end(JSON.stringify({ error: 10002, stderr: 'Invalid token', stdout: {} }));
        }
    });
});

let port = process.env.PORT || 18800;
express_gateway.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});














// Gracefully shutdown?
let IS_GRACEFULLY_SHUTTING_DOWN = false;

process.on('SIGINT', function () {
    IS_GRACEFULLY_SHUTTING_DOWN = true;
    console.error('\nGracefully shutting down...')
    setTimeout(process.exit, 100);
});



