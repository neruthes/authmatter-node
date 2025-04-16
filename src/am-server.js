// ==========================================================================
//
// DEVELOPER NOTES
//
// We do not need SQLite at this moment. Will add support later.
// How to reset dev database: sqlite3 examples/dev1.sqlite "VACUUM;"
//
// ==========================================================================





import fs from 'fs';
import path from 'path';
import { Provider } from 'oidc-provider';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser'; // For non-webcmd request bodies
import * as OTPAuth from "otpauth";



let express_gateway = express();
// express_gateway.use(bodyParser.urlencoded()); // Not needed when we use JSON only?


// Allow CORS on some endpoints
express_gateway.use('/oidc/.well-known/openid-configuration', cors());
express_gateway.use('/oidc/token', cors());
express_gateway.use('/oidc/userinfo', cors());






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
import { stderr } from 'process';

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

function kill_session(id) { // Not working?
    // Remove session to avoid a strange bug
    let session_model = new MySuperAdapter('Session');
    session_model.destroy(id);
}

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
            console.log(`Adapter.upsert : Session : id=${id} (payload=${payload}) expiresIn=${expiresIn}`);
            kill_session(id);
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
    // async findAccount(ctx, sub, token) {
    //     return {
    //         accountId: sub,
    //         async claims(use, scope, claims, rejected) {
    //             return { 'sub': sub };
    //         },
    //     };
    // },
    clientDefaults: {
        response_types: ['code', 'id_token'],
        grant_types: ['authorization_code', 'implicit'],
    },
    claims: {
        openid: ['sub'],
        email: ['email', 'email_verified'],
        profile: ['name', 'preferred_username'],
    },
    // ttl: {
    //     Session: 120,
    // },
    // interactions: { // Causing bug?
    //     async url(ctx, interaction) { // Will it work well?
    //         let interaction_url = `/ui/interaction/${interaction.uid}`;
    //         console.log('[interaction_url]');
    //         console.log(interaction_url);
    //         return interaction_url;
    //     }
    // },
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






// Add internal middleware to Provider instance to insert my own GUI? (Or, avoid double middlewares?)
// Does not seem right; using internal '/oidc/auth' handler with `interactions.url` method to redirect
// oidc.use(async (ctx, next) => {
//     const { req, res } = ctx;
//     console.log(`>>        Provider internal middleware, ctx.path = ${ctx.path}`);
//     if (ctx.path === '/auth') {
//         // On-demand ephemeral registration?
//         if (req.query.client_id && req.query.redirect_uri) {
//             console.log('Intercepted auth request:', req.query);
//             console.log('req.query.client_id:', req.query.client_id);
//             console.log('req.query.redirect_uri:', req.query.redirect_uri);
//             TmpClientIdMapRedirUriMap['Client:' + req.query.client_id] = req.query.redirect_uri;
//         };

//         console.log('// Use library method to extract Interaction object from req-to-res lifecycle context');
//         // Use library method to extract Interaction object from req-to-res lifecycle context
//         console.log('[oidc.interactionDetails]');
//         console.log(oidc.interactionDetails);
//         try {

//             const result = await oidc.interactionDetails(ctx.req, ctx.res);
//             const { uid } = result;
//             console.log('[result]');
//             console.log(result);
//         }catch(e){
//             console.error(e);
//         };

//         // Redirect to your custom login page, including the interaction UID
//         // ctx.redirect(`/ui/interaction?id=${uid}`);
//         // return;
//     }
//     await next();
// });






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
    'guest.get_interaction_info': async function (argv, safe_env, req, res) {
        res.writeHead(200, default_json_res_headers);
        if (TmpInteractionMap.hasOwnProperty(argv.interaction_id)) {
            end_res_with_json(res, {
                error: 0,
                stderr: '',
                stdout: {
                    interaction_id: argv.interaction_id,
                    interaction: TmpInteractionMap[argv.interaction_id],
                },
            });
            return;
        };
    },
    'guest.login_totp_and_authorize_interaction': async function (argv, safe_env, req, res) {
        res.writeHead(200, default_json_res_headers);
        let totp_lookup_result = BusinessLogicHelpers.load_user_totp_secret(argv.login_name);
        if (totp_lookup_result.err) {
            end_res_with_json(res, {
                error: 1,
                stderr: 'User not found',
                stdout: {}
            });
            return;
        };
        // console.log(`totp_lookup_result`);
        // console.log(totp_lookup_result);
        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: totp_lookup_result.secret
        });
        const isValid = totp.validate({ token: argv.login_totp, window: 1 });
        console.log(`isValid`);
        console.log(isValid);
        if (Math.abs(isValid) > 1 || isValid === null) {
            end_res_with_json(res, {
                error: 2,
                stderr: 'Bad TOTP value for user',
                stdout: {},
            });
            return;
        };
        console.log(`Retrieving [interaction] (id=${argv.interaction_id}) ...`);
        try {
            let interaction = TmpInteractionMap[argv.interaction_id];
            console.log('[interaction]');
            console.log(interaction);

            // No need saving again?
            // console.log('Saving interaction info to TmpInteractionMap ...');
            // console.log('TmpInteractionMap[interaction.jti] = interaction;');
            // TmpInteractionMap[interaction.jti] = interaction;
            let result = await get_login_result(interaction, {
                email: argv.login_name,
                totp: argv.login_totp
            });
            console.log(`[result]`);
            console.log(result);
            console.log(`TmpLoginResultMap[${interaction.jti}] = result;`)
            TmpLoginResultMap[interaction.jti] = result;

            
            // ----------------------------------------------------------
            // The `oidc.interactionResult` method does not accept interaction_id or interaction_obj,
            // so we mimic its behavior in our own code.
            async function interactionResult_alt(interaction, result, { mergeWithLastSubmission = true } = {}) {
                if (mergeWithLastSubmission && !('error' in result)) {
                    interaction.result = { ...interaction.lastSubmission, ...result };
                } else {
                    interaction.result = result;
                }
                await interaction.save(interaction.exp - epochTime());
                return interaction.returnTo;
            }
            // END
            // ----------------------------------------------------------



            // If credential is valid, the user will be redirected to consent page
            // let redirectTo = await oidc.interactionResult(req, res, result); // Original way
            let redirectTo = await interactionResult_alt(interaction, result); // Alternative way
            if (!false) { // Config?
                redirectTo = redirectTo.replace(/^http/, 'https');
            };
            console.log(`[redirectTo]`);
            console.log(redirectTo);
            // res.writeHead(302, {
            //     Location: redirectTo,
            // });
            // res.end(`Redirecting to  ${redirectTo}  `);

            // Authenticated successfully!
            end_res_with_json(res, {
                error: 0,
                stderr: '',
                stdout: {
                    interaction_id: argv.interaction_id,
                    login_name: argv.login_name,
                    interaction,
                    redirectTo
                },
            });
        } catch (e) {
            console.error(e);
            end_res_with_json(res, {
                error: 3,
                stderr: 'Interaction not found',
                stdout: {},
            });
        };
    },
    'user.whoami': function (argv, safe_env, req, res) { // How actually in use now
        // Test: curl --request POST --data '{ "cmd":"user.whoami","argv":{} }' http://localhost:18800/api/webcmd
        end_res_with_json(res, {
            error: 0,
            stderr: '',
            stdout: DatabaseService.get_user_by_uid(safe_env.uid),
        });
    },
    'admin.useradd': function (argv, safe_env, req, res) { // How actually in use now
        // Test: curl --request POST --data '{ "cmd":"admin.useradd","argv":{"username":"neruthes@localhost"} }' http://localhost:18800/api/webcmd
        end_res_with_json(res, {
            error: 0,
            stderr: '',
            stdout: {}
        });
    },
};

const BusinessLogicHelpers = {
    load_user_totp_secret: function (login_name) {
        if (!get_config().totp_secrets.hasOwnProperty(login_name)) {
            return { err: 'no_user' };
        }
        return {
            err: 0,
            secret: get_config().totp_secrets[login_name]
        };
    },
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
    // Does cmd exist?
    if (RealCommands[cmd] instanceof Function) {
        // Is cmd open for guests?
        if (safe_env.is_guest && !cmd.startsWith('guest.')) {
            res.writeHead(200, default_json_res_headers);
            res.end(JSON.stringify({
                error: 10004,
                stderr: `Guest access not allowed`
            }));
        }
        // Legit command invocation, allow execution
        console.log(`RealCommands[${cmd}] ${JSON.stringify(argv)}`);
        RealCommands[cmd](argv, safe_env, req, res);
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
    // User not found?
    if (!get_config().totp_secrets.hasOwnProperty(simple_credentials.email)) {
        return {
            error: 'invalid_user',
            error_description: `No such user ${simple_credentials.email}`,
        };
    };

    console.log(`simple_credentials.email = ${simple_credentials.email}`);
    console.log(`simple_credentials.totp = ${simple_credentials.totp}`);

    // Check TOTP
    const totp = new OTPAuth.TOTP({
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        secret: get_config().totp_secrets[simple_credentials.email]
    });
    const isValid = totp.validate({ token: simple_credentials.totp, window: 1 });
    if (Math.abs(isValid) > 1 || isValid === null) { // Lower is better but null is worst
        console.log(`isValid = ${isValid}`);
        return {
            error: 'invalid_credential',
            error_description: `TOTP is incorrect`,
        };
    };

    // Only legit users reach here
    console.log(`[interaction.params]`);
    console.log(interaction.params);
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
    // grant.addResourceScope('urn:example:resource-server', 'read write');
    const grantId = await grant.save();
    // console.log(`[grantId]`);
    // console.log(grantId);

    let result = {
        login: {
            accountId, // logged-in account id
            acr: '', // acr value for the authentication
            amr: [], // amr values for the authentication
            remember: false, // true if authorization server should use a persistent cookie rather than a session one, defaults to true
        },
        consent: {
            grantId, // the identifer of Grant object you saved during the interaction, resolved by Grant.prototype.save()
        },
    };
    console.log('[result]');
    console.log(result);
    return result;
}



// My own Interaction login_and_consent page
express_gateway.get("/oidc/interaction/:uid", async (req, res) => {
    console.log("/oidc/interaction/:uid");
    console.log(`>>>    uid is ${req.params.uid}`);

    let interaction = await oidc.interactionDetails(req, res); // Dynamically constructed, safe enough?
    console.log(`[interactionDetails]`);
    console.log(interaction);

    console.log('Saving interaction info to TmpInteractionMap ...');
    console.log(`TmpInteractionMap[${interaction.jti}] = interaction;`);
    TmpInteractionMap[interaction.jti] = interaction;
    setTimeout(function () {
        delete TmpInteractionMap[interaction.jti];
    }, 1000 * 60 * 12); // Remove entry from indexing after 20 minutes // TODO: Memory leak?

    // Give back GUI
    res.writeHead(200);
    res.end(fs.readFileSync(path.resolve('./frontend-v1/src/app.html')).toString());
});


// Deprecated login method
express_gateway.post("/oidc/interaction/:uid", async (req, res) => {
    res.writeHead(404);
    res.end('404');
    return;

    console.log("/oidc/interaction/:uid");
    console.log(`>>>    uid is ${req.params.uid}`);
    // console.log('[req.body]');
    // console.log(req.body);

    // I should verify credentials here...
    let interaction = await oidc.interactionDetails(req, res); // Dynamically constructed, safe enough?
    console.log(`[interactionDetails]`);
    console.log(interaction);

    let extracted_email_from_session = 'lastresort@example.com';
    try {
        // Does the lib really retrieve accountId from server cookie validation?
        extracted_email_from_session = interaction.session.accountId;
    } catch (e) { };
    console.log(`extracted_email_from_session = ${extracted_email_from_session}`);

    console.log('Saving interaction info to TmpInteractionMap ...');
    console.log('TmpInteractionMap[interaction.jti] = interaction;');
    TmpInteractionMap[interaction.jti] = interaction;
    let result = await get_login_result(interaction, {
        // Using embeded plain login form so we use the password field for TOTP
        // TODO: Make our own web frontend app
        email: req.body.login || extracted_email_from_session,
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

// console.log(`==================================`);
// console.log(`oidc.use`);
// console.log(oidc.use);


// Web frontend?
// express_gateway.get('/ui/', function (req, res) {
//     res.writeHead(200);
//     res.end(fs.readFileSync(path.resolve('./frontend-v1/src/app.html')).toString());
// });









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
express_gateway.post('/api/webcmd-guest', function (req, res) { // Guest version, limit to 'guest.*' namespace
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
        let safe_env = {
            is_guest: true
        };
        // console.log('AcceptIncomingRequest (guest)', parsed_req_body.cmd, parsed_req_body.argv, safe_env, req, res);
        AcceptIncomingRequest(parsed_req_body.cmd, parsed_req_body.argv, safe_env, req, res);
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
    setTimeout(process.exit, 200);
});



