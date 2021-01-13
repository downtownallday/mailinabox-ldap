Vue.component('page-layout', function(resolve, reject) {
    var ax = axios.create({ baseURL: '/admin/' });
    ax.get('ui-common/page-layout.html').then((response) => { resolve({

        template: response.data,
        
    })}).catch((e) => {
        reject(e);
    });

});
