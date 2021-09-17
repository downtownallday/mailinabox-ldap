/*
 * reports index page
 */ 

import page_settings from "./page-settings.js";
import page_reports_main from "./page-reports-main.js";
import { Me, init_miab_api } from "../../ui-common/authentication.js";
import { AuthenticationError } from "../../ui-common/exceptions.js";
import UserSettings from "./settings.js";


const api = init_miab_api(axios.create());

const app = {
    router: new VueRouter({
        routes: [
            { path: '/', component: page_reports_main },
            { path: '/settings', component: page_settings },
            { path: '/:panel', component: page_reports_main },
        ],
        scrollBehavior: function(to, from, savedPosition) {
            if (savedPosition) {
                return savedPosition
            }
        },
    }),
    
    components: {
        'page-settings': page_settings,
        'page-reports-main': page_reports_main,
    },
        
    data: {
        /* axios */
        api,
    },

    mounted: function() {
        this.ensure_authenticated();
    },
        
    methods: {
        ensure_authenticated: function() {
            this.api.get('reports/uidata/user-list')
                .catch(error => {
                    this.handleError(error);
                });
        },
        
        handleError: function(error) {
            if (error instanceof AuthenticationError) {
                console.log(error);
                window.location = '/admin';
                return;
            }
            
            console.error(error);
            if (error instanceof ReferenceError) {
                // uncaught coding bug, ignore
                return;
            }
            if (error.status && error.reason)
            {
                // axios
                error = error.reason;
            }
            this.$nextTick(() => {alert(''+error) });
        }
    }
};



    
UserSettings.load().then(settings => {
    new Vue(app).$mount('#app');
}).catch(error => {
    alert('' + error);
});

