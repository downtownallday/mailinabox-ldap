import { AuthenticationError } from './exceptions.js';


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

export function init_authentication_interceptors() {

    // requests: attach non-session based auth (admin panel)
    axios.interceptors.request.use(request => {
        var api_credentials = null;
        // code from templates/index.html for "recall saved user
        // credentials"
        if (typeof sessionStorage != 'undefined' && sessionStorage.getItem("miab-cp-credentials"))
            api_credentials = sessionStorage.getItem("miab-cp-credentials").split(':');
        else if (typeof localStorage != 'undefined' && localStorage.getItem("miab-cp-credentials"))
            api_credentials = localStorage.getItem("miab-cp-credentials").split(':');
        // end

        if (api_credentials) {
            if (api_credentials.length == 2)
                request.headers.authorization = 'Basic ' + window.btoa(api_credentials[0] + ':' + api_credentials[1]);
            else
                request.headers.authorization = 'Bearer ' + api_credentials[1];
        }
        return request;
    });


    // reponses: handle authorization failures by throwing exceptions
    // users should catch AuthenticationError exceptions
    axios.interceptors.response.use(
        response => {
            if (response.data &&
                response.data.status === 'invalid')
            {
                var url = response.config.url;
                if (response.config.baseURL) {
                    var sep = ( response.config.baseURL.substr(-1) != '/' ?
                                '/' : '' );
                    url = response.config.baseURL + sep + url;
                }
            
                if (url == '/admin/me')
                {
                    // non-session/admin login
                    throw new AuthenticationError(
                        null,
                        'not authenticated',
                        response
                    );
                }
            }
            return response;
        },
        
        error => {
            const auth_required_msg = 'Authentication required - you have been logged out of the server';
            if (! error.response) {
                throw error;
            }
            
            if (error.response.status == 403 &&
                error.response.data == 'login_required')
            {
                // session login
                throw new AuthenticationError(error, auth_required_msg);
            }
            else if ((error.response.status == 403 ||
                      error.response.status == 401) &&
                     error.response.data &&
                     error.response.data.status == 'error')
            {
                // admin
                throw new AuthenticationError(error, auth_required_msg);
            }
            throw error;
        }
    );
}

