Vue.component('error-msgs', function(resolve, reject) {
    axios.get('ui/error-msgs-component.html').then((response) => { resolve({

        template: response.data,
        
        data: function() {
            return {
                errors: [],
                errors_hide: false
            };
        },
        
        methods: {
            set_error: function(txt, reset) {
                if (reset || reset === undefined)
                    this.errors = [];
                if (txt !== null && txt !== undefined)
                    this.errors.push(txt);
                this.errors_hide = false;
            },

            hide_errors: function() {
                this.errors_hide = true;
            },

            clear_errors: function() {
                this.set_error(null);
            }
        }
        
    })}).catch((e) => {
        reject(e);
    });

});
