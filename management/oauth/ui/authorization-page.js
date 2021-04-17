/*
 * login and consent page for OAuth2 authorization requests
 */ 

import { Me, init_authentication_interceptors } from "../../ui-common/authentication.js";
import page_layout from "../../ui-common/page-layout.js";
import page_header from "../../ui-common/page-header.js";
import bi from "../../ui-common/bi-components.js";
import error_msgs from "../../ui-common/error-msgs-component.js";
import login from "../../ui-common/login-component.js";


/* setup */
init_authentication_interceptors();


/* create vue */
export default new Vue({
    el: '#auth_page',
    
    components: {
        'page-layout': page_layout,
        'page-header': page_header,
        'bi': bi,
        'error-msgs': error_msgs,
        'login': login
    },
        
    data: {
        /* oauth state from server */
        me: null,
        clientinfo: null,
        
        /* other ui state */
        loading: 0,
    },

    beforeMount: function() {
        /* $refs is unavailable unless setTimeout is called */
        this.retrieve_state();
    },
        
    methods: {
        /*
         * get a query string parameter
         */
        get_param: function(name, default_value) {
            let params = new URLSearchParams(document.location.search);
            return params.has(name) ? params.get(name) : default_value;
        },

        
        /*
         * Retrieve the authentication state of the server for the
         * session and obtain other display info. Is the user logged
         * in? What is the descriptive name of the client_id from the
         * request url?  What are the allowed scopes and what are
         * their descriptive names? Are the scopes "dangerous"?
         */
        retrieve_state: function() {
            ++this.loading;
            Promise.all([
                axios.get('oauth/me'),
                axios.post('oauth/clientinfo', {
                    client_id: this.get_param('client_id', null),
                    scope: this.get_param('scope', '')
                })
            ]).then((values) => {
                this.me = new Me(values[0].data);
                this.clientinfo = values[1].data;
            }).catch((error) => {
                var msg = (error.response && error.response.data) || ''+error;
                setTimeout(() => {
                    this.$refs.error_msgs.set_error(msg);
                }, 500);
            }).finally(() => {
                --this.loading;
            });
        },
        
        /* 
         * POST back to /oauth/authorize with the user's consent. The
         * user must be logged in. The server will redirect the
         * browser to the OAuth2 client (eg. roundcube) with an OAuth2
         * authorization code.
         */
        do_consent: function(evt) {
            var postback_form = this.$el.querySelector('.authorize-postback');
            postback_form.submit()
        }
    }
});
