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
    el: '#login_page',
    
    components: {
        'page-layout': page_layout,
        'page-header': page_header,
        'bi': bi,
        'error-msgs': error_msgs,
        'login': login
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
});
