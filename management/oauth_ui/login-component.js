/*
 * authenticate users with the server
 *
 * To determine whether a user is already authenticated, in which case
 * no login is necessary, issue a "GET /oauth/me" or "GET /user/me" to
 * the server
 *
 * props: 
 *   error_handler [optional] - instance of an 'error-msgs' component
 *   login_message [optional] - text to display above credential input form
 *   
 * events:
 *    loading(n)  - advance loading spinner counter by n
 *    success     - login was successful, $event is a Me instance
 *    
 */

Vue.component('login', function(resolve, reject) {
    axios.get('ui/login-component.html').then((response) => { resolve({

        components: {
            'error-msgs': Vue.component('error-msgs')
        },

        props: {
            error_handler: { type: Object, default: null },
            login_message: { type: String, default: 'Enter your credentials:' },
            history_link: { type: String, default: null }
        },

        template: response.data,
        
        data: function() {
            return {
                login_step: null,
                login_help: null,
                
                /* input models */
                username: '',
                password: '',
                totp_token: '',
                stay_signed_in: false,
                
                /* errors */
                error_ref: null
            };
        },

        mounted: function() {
            this.error_ref =
                this.error_handler ||  // user-supplied
                this.$refs.error_msgs;  // default
        },
        
        watch: {
            'login_step': function() {
                // reset errors between steps
                this.error_ref.clear_errors();
            }
        },
        
        methods: {
            /*
             * login to the server and if successful, emit 'success'
             */        
            do_login: function(evt) {
                
                this.$emit('loading', 1);
                
                /*
                 * to avoid server changes with auth.py:check_user_auth(), which
                 * does not accept the totp token as an argument, place the
                 * totp token in a request header
                 */
                var request_headers = {}            
                if (this.login_step == 'missing-totp-token') {
                    request_headers['X-Auth-Token'] = this.totp_token;
                    if (this.totp_token.trim() == '') {
                        this.$emit('loading', -1);
                        this.error_ref.set_error('Please enter a code');
                        return;
                    }
                }
                
                axios.post('login', {
                    username: this.username,
                    password: this.password,
                    stay_signed_in: this.stay_signed_in
                }, {
                    headers: request_headers
                }).then((response) => {
                    const status = response.data.status;
                    const reason = response.data.reason;
                    if (status == 'ok') {
                        if (this.history_link) {
                            window.history.replaceState(null, '', this.history_link);
                        }
                        this.$emit('success', new Me(response.data.me));
                    }
                    else if (status == 'missing-totp-token') {
                        /*
                         * The user is configured for TOTP, so they will
                         * have to enter their 6-digit OTP, and try again
                         */
                        this.login_step = status;
                        this.login_help = [];
                        response.data.labels.forEach(label => {
                            if (label.trim() != '') this.login_help.push(label);
                        })
                    }
                    else {
                        if (reason == 'invalid-totp-token') {
                            this.totp_token = '';
                            this.error_ref.set_error('The code is not valid, please try again');
                        }
                        else {
                            this.error_ref.set_error(response.data.reason);
                        }
                    }
                    
                }).catch((error) => {
                    this.error_ref.set_error('' + error);
                    
                }).finally(() => {
                    this.$emit('loading', -1);
                });
                
            },
            
            
        }
    })}).catch((e) => {
        reject(e);
    });

});


