// ==========================================================================
//
// DEVELOPER NOTES
//
// How to reset dev database: sqlite3 examples/dev1.sqlite "VACUUM;"
//
// ==========================================================================





import fs from 'fs';
import { Provider } from 'oidc-provider';
import express from 'express';
import bodyParser from 'body-parser';
import * as OTPAuth from "otpauth";







let express_gateway = express();
express_gateway.use(bodyParser.urlencoded());






// Bring object definitions to top
const TmpClientIdMapRedirUriMap = {};








let AuthMatterStartupConfig = {
    startup_config_path: process.argv[2] || process.env.AM_CONFIG_PATH,
    startup_config_dict_in_memory: {},
};
const AuthMatterRuntimeConfigManager = {
    load_startup_config: function () {
        // TODO: Better dynamic config reloading?
        AuthMatterStartupConfig.startup_config_dict_in_memory = JSON.parse(fs.readFileSync(AuthMatterStartupConfig.startup_config_path));
    }
};
AuthMatterRuntimeConfigManager.load_startup_config();
setInterval(AuthMatterRuntimeConfigManager.load_startup_config, 1000 * 600); // Reload per 10 min

function get_config() {
    return AuthMatterStartupConfig.startup_config_dict_in_memory;
};




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
            username: 'root@' + get_config().org_domain, // Computed from `username_short` and `org_domain`
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














// ==================================================================================
// MySuperAdapter (slightly modified from library example)
// ==================================================================================

import QuickLRU from 'quick-lru';
import epochTime from 'oidc-provider/lib/helpers/epoch_time.js';

let storage = new QuickLRU({ maxSize: 1000 });

function grantKeyFor(id) {
    return `grant:${id}`;
}

function sessionUidKeyFor(id) {
    return `sessionUid:${id}`;
}

function userCodeKeyFor(userCode) {
    return `userCode:${userCode}`;
}

const grantable = new Set([
    'AccessToken',
    'AuthorizationCode',
    'RefreshToken',
    'DeviceCode',
    'BackchannelAuthenticationRequest',
]);

class MySuperAdapter {
    constructor(model) {
        this.model = model;
    }

    key(id) {
        return `${this.model}:${id}`;
    }

    async destroy(id) {
        const key = this.key(id);
        storage.delete(key);
    }

    async consume(id) {
        storage.get(this.key(id)).consumed = epochTime();
    }

    async find(id) {
        console.log(this.key(id));
        if (this.model === 'Client') {
            // My own logic
            console.log('MySuperAdapter.find(id): ' + id);
            let redir_uri = TmpClientIdMapRedirUriMap['Client:' + id];
            console.log(`redir_uri = ${redir_uri}`);
            return {
                client_id: id,
                client_name: 'PublicClient',
                redirect_uris: [redir_uri],
                response_types: ['id_token', 'code'],
                grant_types: ['authorization_code', 'implicit'],
                token_endpoint_auth_method: 'none', // public client
            };
        };
        return storage.get(this.key(id));
    }

    async findByUid(uid) {
        const id = storage.get(sessionUidKeyFor(uid));
        return this.find(id);
    }

    async findByUserCode(userCode) {
        const id = storage.get(userCodeKeyFor(userCode));
        return this.find(id);
    }

    async upsert(id, payload, expiresIn) {
        const key = this.key(id);

        if (this.model === 'Session') {
            storage.set(sessionUidKeyFor(payload.uid), id, expiresIn * 1000);
        }

        const { grantId, userCode } = payload;
        if (grantable.has(this.model) && grantId) {
            const grantKey = grantKeyFor(grantId);
            const grant = storage.get(grantKey);
            if (!grant) {
                storage.set(grantKey, [key]);
            } else {
                grant.push(key);
            }
        }

        if (userCode) {
            storage.set(userCodeKeyFor(userCode), id, expiresIn * 1000);
        }

        storage.set(key, payload, expiresIn * 1000);
    }

    async revokeByGrantId(grantId) { // eslint-disable-line class-methods-use-this
        const grantKey = grantKeyFor(grantId);
        const grant = storage.get(grantKey);
        if (grant) {
            grant.forEach((token) => storage.delete(token));
            storage.delete(grantKey);
        }
    }
}



















// Example config copied from lib
const oidc = new Provider(get_config().site_hostname + '/oidc', {
    async findAccount(ctx, sub, token) {
        return {
            accountId: sub,
            async claims(use, scope, claims, rejected) {
                return { 'sub': sub };
            },
        };
    },
    clientDefaults: {
        response_types: ['code id_token'],
        grant_types: ['authorization_code', 'implicit'],
    },
    claims: {
        openid: ['sub'],
        email: ['email', 'email_verified'],
        profile: ['name', 'preferred_username'],
    },
    proxy: true,
    pkce: { required: false }, // Enforce PKCE for all?
    features: {
        devInteractions: { enabled: true }, // or false if you provide your own UI
        clientCredentials: { enabled: false },
        introspection: { enabled: false },
        revocation: { enabled: false },
    },
    clients: [],
    adapter: MySuperAdapter,
});

function handleClientAuthErrors(ctx, error) {
    console.log(error);
    // console.log(ctx.request);
    // console.log(ctx.request.header);
}
// oidc.on("authorization.accepted", handleClientAuthErrors);
oidc.on("authorization.error", handleClientAuthErrors);







// Custom middleware to intercept auth requests
express_gateway.use('/oidc/auth', (req, res, next) => {
    console.log(`\n\n=====================`);
    console.log(`express_gateway.use('/oidc/auth'  ...`);
    console.log(`req.url = ${req.url}`);
    if (req.query.client_id && req.query.redirect_uri) {
        // console.log('Intercepted auth request:', req.query);
        console.log('req.query.client_id:', req.query.client_id);
        console.log('req.query.redirect_uri:', req.query.redirect_uri);

        // On-demand ephemeral registration?
        TmpClientIdMapRedirUriMap['Client:' + req.query.client_id] = req.query.redirect_uri;
    }
    // Continue to OIDC provider
    next();
});















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
            user_obj.org_domain !== get_config().org_domain && // Not domestic
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
const TmpInteractionMap = {};
const TmpLoginResultMap = {};
async function get_login_result(interaction, simple_credentials) {
    // let is_legit_user = true;

    // User not found?
    if (!get_config().totp_secrets.hasOwnProperty(simple_credentials.email)) {
        // is_legit_user = false;
        return {
            error: 'invalid_user',
            error_description: `No such user ${simple_credentials.email}`,
        };
    };

    // Check TOTP
    const totp = new OTPAuth.TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: get_config().totp_secrets[simple_credentials.email]
    });
    const isValid = totp.validate({ token: simple_credentials.totp, window: 1 });
    if (isValid > 1.1) { // Lower is better
        console.log(`isValid = ${isValid}`);
        // is_legit_user = false;
        return {
            error: 'invalid_credential',
            error_description: `TOTP is incorrect`,
        };
    };

    // Only legit users reach here
    // console.log(`[interaction.params]`);
    // console.log(interaction.params);
    // TODO: Really authenticate input credentials with database
    const accountId = simple_credentials.email;
    // Working with grant?
    const Grant = oidc.Grant;

    const grant = new Grant({
        accountId,
        clientId: interaction.params.client_id,
    });
    // console.log(`[grant]`);
    // console.log(grant);

    grant.addOIDCScope('openid email profile');
    grant.addOIDCClaims(['email', 'email_verified']);
    grant.addResourceScope('urn:example:resource-server', 'read write');
    const grantId = await grant.save();
    // console.log(`[grantId]`);
    // console.log(grantId);

    let result = {
        login: {
            accountId, // logged-in account id
            acr: '', // acr value for the authentication
            amr: [], // amr values for the authentication
            remember: true, // true if authorization server should use a persistent cookie rather than a session one, defaults to true
        },
        consent: {
            grantId, // the identifer of Grant object you saved during the interaction, resolved by Grant.prototype.save()
        },
    };
    console.log('[result]');
    console.log(result);
    return result;

}


express_gateway.post("/oidc/interaction/:uid", async (req, res) => {
    console.log("/oidc/interaction/:uid");
    console.log(`>>>    uid is ${req.params.uid}`);
    // console.log('[req.body]');
    // console.log(req.body);

    // I should verify credentials here...
    let interaction = await oidc.interactionDetails(req, res);
    // console.log(`[interactionDetails]`);
    // console.log(interaction);
    // console.log('TmpInteractionMap[interaction.jti] = interaction;')
    TmpInteractionMap[interaction.jti] = interaction;
    let result = await get_login_result(interaction, {
        // Using embeded plain login form so we use the password field for TOTP
        // TODO: Make our own web frontend app
        email: req.body.login,
        totp: req.body.password
    });
    // console.log(`[result]`);
    // console.log(result);
    TmpLoginResultMap[interaction.jti] = result;

    // If credential is valid, the user will be redirected to consent page
    let redirectTo = await oidc.interactionResult(req, res, result);
    if (!false) { // Config?
        redirectTo = redirectTo.replace(/^http/, 'https');
    };


    // console.log(`[redirectTo]`);
    // console.log(redirectTo);
    res.writeHead(302, {
        Location: redirectTo,
    });
    // res.send({ redirectTo });
    res.end(`Redirecting to  ${redirectTo}  `);
    console.log(`Ending...`);
    console.log(`===================================================`);
});

express_gateway.use('/oidc', oidc.callback());












// Real user commands
express_gateway.post('/api/webcmd', function (req, res) {
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
            // res.writeHead(200, default_json_res_headers); // Commands do this?
            AcceptIncomingRequest(parsed_req_body.cmd, parsed_req_body.argv, safe_env, req, res);
        } else {
            res.writeHead(200, default_json_res_headers);
            res.end(JSON.stringify({ error: 10002, stderr: 'Invalid token', stdout: {} }));
        }
    });
});









// Start HTTP server!
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



