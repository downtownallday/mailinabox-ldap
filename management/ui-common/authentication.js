import { AuthenticationError } from './exceptions.js';
import AuthInfo from './AuthInfo.js';

export class Me {
    /* 
     * construct with return value from any of:
     *   POST /auth/user/login
     *   GET /auth/user/me?mfa_state=[y/n]
     *
     * This class should only be used by OAuth server client
     * components (which currently is part of the mail server, but
     * doesn't have to be). These routes are currently /auth/user/ and
     * /auth/oauth/.
     *
     */
    constructor(me) {
        /*
         * @see daemon_sessions.py:get_session_me()
         *
         * me: {
         *   server_hostname: String,
         *   user_id: String,
         *   email: String,
         *   name: String,
         *   enabled_mfa: [ // iff ?mfa_state=y
         *      {
         *        type: "totp",
         *        label: String,
         *      },
         *   ],
         *   new_mfa: {  // iff ?mfa_state=y
         *      totp: {
         *        qr_code_base64: String
         *      }
         *   }
         * }
         */
        Object.assign(this, me);
    }

    is_authenticated() {
        return this.user_id ? true : false;
    }

    get_email() {
        return this.email;
    }

    get_user_id() {
        return this.user_id;
    }
};


/*
 * axios interceptors for authentication
 */

export function init_oauth_api(inst) {
    // oauth server uses sessions, we just check for authentication
    // errors
    inst.interceptors.response.use(
        response => {
            return response;
        },
        
        error => {
            if (! error.response) {
                throw error;
            }
            
            if (error.response.status == 403 &&
                error.response.data &&
                error.response.data.status == 'error')
            {
                // auth-checking wrappers return json:
                //
                //  { status:"error", reason:"..." }
                //
                throw new AuthenticationError(error, error.response.data.reason);
            }
            else if (error.response.status == 401 ||
                     error.response.status == 403) {
                throw new AuthenticationError(error, "Login required");
            }
            throw error;
        }
    );

    return inst;
}

export function init_miab_api(inst) {
    // requests: attach authorization header
    inst.interceptors.request.use(request => {
        const auth = new AuthInfo();
        request.headers.authorization = auth.authorization_header;
        return request;
    });


    // reponses: handle authorization failures by throwing exceptions
    // users should catch AuthenticationError exceptions and require
    // users to re-login
    inst.interceptors.response.use(
        response => {
            if (response.data && response.data.status == 'invalid')
            {
                var url = axios_url(response.config);
                if (url == '/admin/login') {
                    // non-flask-session/admin login, which always
                    // returns 200, even for failed logins
                    throw new AuthenticationError(
                        null,
                        response.data.reason,
                        response
                    );
                }
            }
            // else if (response.data && response.data.status == 'expired_token')
            // {
            //     const promise = refresh_access_token(inst, response.config);
            //     if (promise) {
            //         return promise;
            //     }
            //     else {
            //         throw new AuthenticationError(error, "Login required");
            //     }
            // }
            
            return response;
        },
        
        error => {
            if (! error.response) {
                throw error;
            }
            
            if (error.response.status == 403 ||
                error.response.status == 401)
            {
                if (error.response.data &&
                    error.response.data.status == 'error')
                {
                    // auth-checking wrappers return json:
                    //
                    //  { status:"error", reason:"..." }
                    //
                    throw new AuthenticationError(error, error.response.data.reason);
                }
                else if (error.response.data &&
                         error.response.data.status == 'expired_token')
                {
                    // refresh the access token
                    const promise = refresh_access_token(inst, error.config);
                    if (promise) {
                        return promise;
                    }
                    else {
                        throw new AuthenticationError(error, "Login required");
                    }
                }
                else  {
                    throw new AuthenticationError(error, "Login required");
                }
            }
            
            throw error;
        }
    );

    return inst;
}

function axios_url(config) {
    var url = config.url;
    if (config.baseURL) {
        var sep = ( config.baseURL.substr(-1) != '/' ? '/' : '' );
        url = config.baseURL + sep + url;
    }
    return url;
}

var ongoing_refresh_promise = null;

function refresh_access_token(axios_inst, config) {
    var auth = new AuthInfo();
    if (! auth.is_refreshable()) return null;

    if (ongoing_refresh_promise === null) {    
        ongoing_refresh_promise = axios_inst.post('/oauth-refresh', {
            refresh_token: auth.refresh_token
        }).then(response => {
            auth.refresh(response.data);
            auth.remember();
            // reissue request
            return axios_inst(config);
        }).finally( () => {
            ongoing_refresh_promise = null;
        });
        return ongoing_refresh_promise;
    }
    else {
        return ongoing_refresh_promise.then(response => {
            return axios_inst(config);
        });
    }
}
