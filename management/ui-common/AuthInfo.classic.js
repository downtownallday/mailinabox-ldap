// This is the classic script version of AuthInfo.js - which is a
// duplicate of AuthInfo.js but without ES6 module export
// declarations.

class AuthInfo {
    constructor(credentials) {
        if (!credentials) 
            credentials = AuthInfo.recall();

        if (Array.isArray(credentials)) 
            this._loadCredentialsArray(credentials);

        else if (credentials instanceof AuthInfo)
            Object.assign(this, credentials)

        else if (credentials) 
            this._loadOAuth(credentials);
    }

    static recall() {
        if (typeof sessionStorage != 'undefined' && sessionStorage.getItem("miab-cp-credentials"))
            return sessionStorage.getItem("miab-cp-credentials").split(":");

        else if (typeof localStorage != 'undefined' && localStorage.getItem("miab-cp-credentials"))
            return localStorage.getItem("miab-cp-credentials").split(":");

        return ["", ""];
    }

    _loadOAuth(oauthinfo, refresh) {
        if (! refresh) this.user_id = oauthinfo.user_id;
        this.access_token = oauthinfo.token;
        this.refresh_token = oauthinfo.refresh_token;
        this.isadmin = oauthinfo.isadmin;
        this.scheme = 'Bearer';
        this.expires_in = oauthinfo.expires_in;
        this.expires = oauthinfo.expires;
        if (this.expires === null || this.expires === undefined)
            this.expires = Date.now()/1000 + this.expires_in;
        if (! refresh) this.state_ssi = oauthinfo.state_ssi;
    }

    _loadCredentialsArray(credentials) {
        if (!credentials || ! credentials[0]) return;
        if (credentials.length == 2) {
            Object.assign(this, {
                user_id: credentials[0],
                password: credentials[1],
                scheme: 'Basic',
                expires: 0,
            });
        }
        else {
            Object.assign(this, {
                user_id: credentials[0],
                access_token: credentials[1],
                refresh_token: credentials[2],
                scheme: credentials[3],
                expires: Number(credentials[4]),
                state_ssi: Number(credentials[5])
            });
        }
    }

    refresh(oauthinfo) {
        // refresh this class with new tokens from the server
        this._loadOAuth(oauthinfo, true);
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
        return this.isadmin ? true : false;
    }

    is_same(credentials) {
        const y = new AuthInfo(credentials);
        if (! y.is_set()) return true;
        if (this.scheme != y.scheme) return false;
        if (this.user_id != y.user_id) return false;
        if (this.is_bearer())
            return this.access_token == y.access_token;
        else
            return this.password == y.password;
    }

    get authorization_header() {
        if (this.scheme == 'Basic')
            return 'Basic ' + window.btoa(this.user_id + ':' + this.password);

        else if (this.scheme == 'Bearer')
            return `${this.scheme} ${this.access_token}`;
    }

    as_array() {
        if (this.scheme == 'Basic') {
            return [
                this.user_id || "",
                this.password || ""
            ];
        }
        else if (this.scheme == 'Bearer') {
            return [
                this.user_id,
                this.access_token,
                this.refresh_token,
                this.scheme,
                this.expires,
                this.state_ssi
            ];
        }
        else {
            throw new Error('Not supported');
        }
    }

    remember(opts) {
        var credentials = this.as_array();

        // Remember the credentials
        if (typeof localStorage != 'undefined' && 
            typeof sessionStorage != 'undefined') 
        {
            if (this.state_ssi) {
                // stay signed in
                localStorage
                    .setItem("miab-cp-credentials", credentials.join(":"));
                sessionStorage
                    .removeItem("miab-cp-credentials");
            }
            else {
                sessionStorage
                    .setItem("miab-cp-credentials", credentials.join(":"));
                localStorage
                    .removeItem("miab-cp-credentials");
            }
        }

        // Authentication for munin pages. We use a cookie, which is
        // the only way to accomplish this. The CSRF exposure is
        // mitigated by samesite=Strict, plus it's not a very
        // dangerous service.
        if (opts && opts.munin) {
            document.cookie = `auth-bearer=${this.access_token}; Path=/admin/munin/; Secure; SameSite=Strict`;
        }
    }

    static forget() {
        if (typeof localStorage != 'undefined')
            localStorage.removeItem("miab-cp-credentials");
        if (typeof sessionStorage != 'undefined')
            sessionStorage.removeItem("miab-cp-credentials");
        document.cookie = 'auth-bearer=; Path=/admin/munin/; expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=Strict';
    }
};

