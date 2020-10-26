Vue.component('page-layout', function(resolve, reject) {
    axios.get('ui/page-layout.html').then((response) => { resolve({

        template: response.data,
        
    })}).catch((e) => {
        reject(e);
    });

});
