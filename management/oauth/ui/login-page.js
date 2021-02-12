/*
 * login and consent page for OAuth2 authorization requests
 */ 

const login_page = {
    el: '#login_page',
    
    components: {
        'page-layout': Vue.component('page-layout'),
        'bi': Vue.component('bi'),
        'error-msgs': Vue.component('error-msgs'),
        'login': Vue.component('login')
    },
        
    data: {
        /* login state from server */
        me: null,
        
        /* other ui state */
        loading: 0,
    },

    updated: function() {
        if (this.me==null && this.loading==0) {
            this.retrieve_state();
        }
    },
        
    methods: {
        /*
         * get a query string parameter
         */
        get_param: function(name, default_value) {
            let params = new URLSearchParams(document.location.search);
            return params.has(name) ? params.get(name) : default_value;
        },

        login_success: function() {
            var redirect_to = this.get_param('redirect_to', 'user/profile');
            window.location = redirect_to;
        },
        
        retrieve_state: function() {
            ++this.loading;
            axios.get('user/me').then((response) => {
                this.me = new Me(response.data);
                if (this.me.is_authenticated()) {
                    this.login_success();
                }
                
            }).catch((error) => {
                this.$refs.error_msgs.set_error('' + error);
                
            }).finally(() => {
                --this.loading;
            });
        },
        
    }
};


