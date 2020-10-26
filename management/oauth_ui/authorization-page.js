/*
 * login and consent page for OAuth2 authorization requests
 */ 

const auth_page = {
    el: '#auth_page',
    
    components: {
        'page-layout': Vue.component('page-layout'),
        'bi': Vue.component('bi'),
        'error-msgs': Vue.component('error-msgs'),
        'login': Vue.component('login')
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
                axios.get('me'),
                axios.post('clientinfo', {
                    client_id: this.get_param('client_id', null),
                    scope: this.get_param('scope', '')
                })
            ]).then((values) => {
                this.me = new Me(values[0].data);
                this.clientinfo = values[1].data;
            }).catch((error) => {
                if (! XhrErrorHandler.handle(error, this)) {
                    setTimeout(() => {
                        this.$refs.error_msgs.set_error('' + error);
                    }, 500);
                }
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
};


