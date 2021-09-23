// This is the classic script version of AuthInfo.js - which is a
// duplicate of AuthInfo.js but without ES6 module export
// declarations ("export default" removed).

class AuthInfo {
    constructor(credentials) {
        if (credentials === undefined)
            credentials = AuthInfo.recall();

        if (credentials instanceof AuthInfo)
            Object.assign(this, credentials)

        else if (credentials)
            this.load_object(credentials);
    }

    /*
     * get credentials from session storage
     * returns: credentials object (see AuthInfo.as_object())
     */
    static recall() {
        // code is from templates/index.html for "recall saved user
        // credentials"
        var cred = null;
        try {
            if (typeof sessionStorage != 'undefined' && sessionStorage.getItem("miab-cp-credentials")) {
                cred = JSON.parse(sessionStorage.getItem("miab-cp-credentials"));
                // stay signed in
                cred.state_ssi = false;
            }
            else if (typeof localStorage != 'undefined' && localStorage.getItem("miab-cp-credentials")) {
                cred = JSON.parse(localStorage.getItem("miab-cp-credentials"));
                // stay signed in
                cred.state_ssi = true;
            }
        } catch (e) {
            console.log(e);
        }
        return cred;
    }

    _load_oauth_credentials_object(oauthinfo, refresh) {
        if (! refresh) this.user_id = oauthinfo.user_id;
        this.access_token = oauthinfo.token;
        this.refresh_token = oauthinfo.refresh_token;
        this.privileges = oauthinfo.privileges || [];
        this.privileges.sort();
        this.scheme = 'Bearer';
        this.expires_in = oauthinfo.expires_in;
        this.expires = oauthinfo.expires;
        if (this.expires === null || this.expires === undefined)
            this.expires = Date.now()/1000 + this.expires_in;
        if (! refresh) this.state_ssi = oauthinfo.state_ssi;
    }

    _load_api_credentials_object(cred) {
        Object.assign(this, {
            user_id: cred.username,
            password: cred.session_key,
            privileges: cred.privileges || [],
            scheme: 'Basic',
            expires: 0,
            state_ssi: cred.state_ssi
        });
        this.privileges.sort();
    }

    load_object(credentials) {
        if (! credentials) {
            this.scheme = null;
            this.user_id = null;
            this.password = null;
            this.access_token = null;
            this.refresh_token = null;
            this.privileges = [];
            this.expires = null;
        }
        else if (credentials.session_key !== undefined) {
            this._load_api_credentials_object(credentials);
        }
        else if (credentials.token !== undefined) {
            this._load_oauth_credentials_object(credentials);
        }
        else {
            throw new Error("Invalid credentials object");
        }
    }

    refresh(oauthinfo) {
        // refresh this class with new tokens from the server
        this._load_oauth_credentials_object(oauthinfo, true);
    }

    is_bearer() {
        return this.scheme == 'Bearer';
    }

    is_refreshable() {
        return this.is_bearer() && this.refresh_token;
    }

    is_set() {
        if (this.scheme == 'Bearer')
            return this.user_id && this.access_token;

        else if (this.scheme == 'Basic')
            return this.user_id && this.password;

        else
            return false;
    }

    is_valid() {
        return this.is_set() && ! this.is_expired();
    }

    is_expired() {
        if (this.expires === null || this.expires === undefined) return true;
        if (this.expires == 0) return false;
        return Date.now()/1000 >= this.expires;
    }

    is_admin() {
        var r = false;
        this.privileges.forEach(priv => {
            if (priv === 'admin') r = true;
        });
        return r;
    }

    is_same(credentials) {
        const y = new AuthInfo(credentials);
        if (this.scheme != y.scheme) return false;
        if (this.user_id != y.user_id) return false;
        if (this.is_bearer())
            return this.access_token == y.access_token;
        else
            return this.password == y.password;
        if (this.privileges.length != y.privileges.length)
            return false;
        for (var i=0; i<this.privileges.length; i++) {
            if (this.privileges[i] != y.privileges[i]) return false;
        }
    }

    get authorization_header() {
        if (this.scheme == 'Basic')
            return 'Basic ' + window.btoa(this.user_id + ':' + this.password);

        else if (this.scheme == 'Bearer')
            return `${this.scheme} ${this.access_token}`;
    }

    as_object() {
        if (this.is_bearer()) {
            return {
                user_id: this.user_id,
                token: this.access_token,
                refresh_token: this.refresh_token,
                scheme: this.scheme,
                expires: this.expires,
                privileges: this.privileges,
                state_ssi: this.state_ssi
            };
        }
        else if (this.user_id) {
            return {
                username: this.user_id,
                session_key: this.password,
                state_ssi: this.state_ssi
            };
        }
        else {
            return null;
        }
    }

    static has_local_storage() {
        return ( typeof localStorage != 'undefined' && 
                 typeof sessionStorage != 'undefined' );
    }

    remember(opts) {
        var credentials = this.as_object();
        if (! credentials) {
            AuthInfo.forget();
            return null;
        }

        // Remember the credentials
        if (AuthInfo.has_local_storage()) {
            if (this.state_ssi) {
                // stay signed in
                localStorage.setItem(
                    "miab-cp-credentials",
                    JSON.stringify(credentials)
                );
                sessionStorage.removeItem(
                    "miab-cp-credentials"
                );
            }
            else {
                sessionStorage.setItem(
                    "miab-cp-credentials",
                    JSON.stringify(credentials)
                );
                localStorage.removeItem(
                    "miab-cp-credentials"
                );
            }
        }

        // Authentication for munin pages. We use a cookie, which is
        // the only way to accomplish this. The CSRF exposure is
        // mitigated by samesite=Strict
        if (opts && opts.munin && this.is_bearer()) {
            document.cookie = `auth-bearer=${this.access_token}; Path=/admin/munin/; Secure; SameSite=Strict`;
        }
        
        return credentials;
    }

    static forget() {
        if (typeof localStorage != 'undefined')
            localStorage.removeItem("miab-cp-credentials");
        if (typeof sessionStorage != 'undefined')
            sessionStorage.removeItem("miab-cp-credentials");
        document.cookie = 'auth-bearer=; Path=/admin/munin/; expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=Strict';
    }
};

