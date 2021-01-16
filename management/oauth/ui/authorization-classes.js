class Me {
    /* construct with return value from GET /oauth/me or /user/me */
    constructor(me) {
        Object.assign(this, me);
    }

    is_authenticated() {
        return this.user_id || false;
    }
};


class XhrErrorHandler {
    static handle(error, vuejs_component_instance) {
        /* handle some axios errors - call this in your .catch()
         * handler if the server logged the user out, this will
         * redirect to the login page
         *
         * returns true if handled, otherwise false
         */
        if (error.response.status == 403 &&
            error.response.data == 'login_required')
        {
            error.message = 'Authentication required - you have been logged out of the server';
            window.location.reload();
            return true;
        }
        return false;
    }
};

