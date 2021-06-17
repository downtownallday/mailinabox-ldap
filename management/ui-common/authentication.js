import { AuthenticationError } from './exceptions.js';
import AuthInfo from './AuthInfo.js';

export class Me {
    /* construct with return value from GET /me */
    constructor(me) {
        Object.assign(this, me);
    }

    is_authenticated() {
        return this.api_key || this.user_id;
    }

    get_email() {
        return this.user_email || this.user_id;
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
                throw new AuthenticationError(error, error.response.data.status.reason);
            }
            else if (error.response.status == 401) {
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
                if (url == '/admin/me') {
                    // non-session/admin login
                    throw new AuthenticationError(
                        null,
                        response.data.reason,
                        response
                    );
                }
            }
            else if (response.data && response.data.status == 'token-expired')
            {
                const promise = refresh_access_token(inst, response.config);
                if (promise) {
                    return promise;
                }
                else {
                    throw new AuthenticationError(error, "Login required");
                }
            }
            
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
                throw new AuthenticationError(error, error.response.data.status.reason);
            }
            else if (error.response.status == 403) {
                    throw new AuthenticationError(error, "Login required");
            }
            else if (error.response.status == 401) {
                // refresh the access token
                const promise = refresh_access_token(inst, error.config);
                if (promise) {
                    return promise;
                }
                else {
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
