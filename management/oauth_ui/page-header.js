Vue.component('page-header', function(resolve, reject) {
    axios.get('ui/page-header.html').then((response) => { resolve({

        props: {
            header_text: { type: String, required: true },
            loading_counter: { type: Number, required: true }
        },
        
        template: response.data
                        
    })}).catch((e) => {
        reject(e);
    });

});
