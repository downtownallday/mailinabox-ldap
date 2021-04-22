import { BvTable, ConnectionDisposition, DateFormatter } from "./charting.js";
import { spinner } from "../../ui-common/page-header.js";

export default Vue.component('capture-db-stats', {
    props: {
    },

    components: {
        spinner,
    },

    template:'<div>'+
        '<template v-if="stats">'+
           '<caption class="text-nowrap">Database date range</caption><div class="ml-2">First: {{stats.db_stats.connect_time.min_str}}</div><div class="ml-2">Last: {{stats.db_stats.connect_time.max_str}}</div>'+
           '<div class="mt-2">'+
           '  <b-table-lite small caption="Connections by disposition" caption-top :fields="row_counts.fields" :items=row_counts.items></b-table-lite>'+
           '</div>'+
        '</template>'+
        '<spinner v-else></spinner>'+
        '</div>'
    ,

    data: function() {
        return {
            stats: null,
            stats_time: null,
            row_counts: {}
        };
    },

    created: function() {
        this.getStats();
    },

    methods: {
        getStats: function() {
            this.$root.api.get('/reports/capture/db/stats')
                .then(response => {
                    this.stats = response.data;
                    this.stats_time = Date.now();

                    // convert dates
                    var parser = d3.utcParse(this.stats.date_parse_format);
                    [ 'min', 'max' ].forEach( k => {
                        var d = parser(this.stats.db_stats.connect_time[k]);
                        this.stats.db_stats.connect_time[k] = d;
                        this.stats.db_stats.connect_time[k+'_str'] =
                            d==null ? '-' : DateFormatter.dt_long(d);
                    });

                    // make a small bvTable of row counts
                    this.row_counts = {
                        items: [],
                        fields: [ 'name', 'count', 'percent' ],
                        field_types: [
                            { type:'text/plain', label:'Disposition' },
                            'number/plain',
                            { type: 'number/percent', label:'Pct', places:1 },
                        ],
                    };
                    BvTable.setFieldDefinitions(
                        this.row_counts.fields,
                        this.row_counts.field_types
                    );
                    this.row_counts.fields[0].formatter = (v, key, item) => {
                        return new ConnectionDisposition(v).short_desc
                    };
                    this.row_counts.fields[0].tdClass = 'text-capitalize';


                    const total = this.stats.db_stats.count;
                    for (var name in this.stats.db_stats.disposition)
                    {
                        const count =
                              this.stats.db_stats.disposition[name].count;
                        this.row_counts.items.push({
                            name: name,
                            count: count,
                            percent: count / total
                        });
                    }
                    this.row_counts.items.sort((a,b) => {
                        return a.count > b.count ? -1 :
                            a.count < b.count ? 1 : 0;
                    })
                    this.row_counts.items.push({
                        name:'Total',
                        count:this.stats.db_stats.count,
                        percent:1,
                        '_rowVariant': 'primary'
                    });

                    
                })
                .catch(error => {
                    this.$root.handleError(error);
                });
        },
    }
});
