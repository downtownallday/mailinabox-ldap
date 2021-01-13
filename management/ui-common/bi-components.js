/*
 * vue components for bootstrap-image svg's
 * see: https://icons.getbootstrap.com
 */

Vue.component('bi', {
    props: {
        width: { default: '1em' },
        height: { default: '1em' },
        name: { type: String, required: true }
    },
    render: function(ce) {
        var svg_children = [];
        
        if (this.name === 'exclamation-diamond-fill') {
            var path = ce('path', {
                attrs: {
                    'fill-rule':"evenodd",
                    d:"M9.05.435c-.58-.58-1.52-.58-2.1 0L.436 6.95c-.58.58-.58 1.519 0 2.098l6.516 6.516c.58.58 1.519.58 2.098 0l6.516-6.516c.58-.58.58-1.519 0-2.098L9.05.435zM8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"
                }});
            svg_children.push(path);
        }
        
        else if (this.name == 'chevron-bar-expand') {
            svg_children.push(ce('path', {
                attrs: {
                    'fill-rule':"evenodd",
                    d:"M3.646 10.146a.5.5 0 0 1 .708 0L8 13.793l3.646-3.647a.5.5 0 0 1 .708.708l-4 4a.5.5 0 0 1-.708 0l-4-4a.5.5 0 0 1 0-.708zm0-4.292a.5.5 0 0 0 .708 0L8 2.207l3.646 3.647a.5.5 0 0 0 .708-.708l-4-4a.5.5 0 0 0-.708 0l-4 4a.5.5 0 0 0 0 .708zM1 8a.5.5 0 0 1 .5-.5h13a.5.5 0 0 1 0 1h-13A.5.5 0 0 1 1 8z"
                }}));
        }
        
        else if (this.name == 'exclamation-circle') {
            svg_children.push(ce('path', {
                attrs: {
                    'fill-rule':"evenodd",
                    d: "M8 15A7 7 0 1 0 8 1a7 7 0 0 0 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"
                }}));
            svg_children.push(ce('path', {
                attrs: {
                    d: "M7.002 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 4.995z"
                }}));
        }

        else if (this.name == 'box-arrow-up-right') {
            svg_children.push(ce('path', {
                attrs: {
                    'fill-rule':"evenodd",
                    d: "M8.636 3.5a.5.5 0 0 0-.5-.5H1.5A1.5 1.5 0 0 0 0 4.5v10A1.5 1.5 0 0 0 1.5 16h10a1.5 1.5 0 0 0 1.5-1.5V7.864a.5.5 0 0 0-1 0V14.5a.5.5 0 0 1-.5.5h-10a.5.5 0 0 1-.5-.5v-10a.5.5 0 0 1 .5-.5h6.636a.5.5 0 0 0 .5-.5z"
                }}));
            svg_children.push(ce('path', {
                attrs: {
                    'fill-rule': "evenodd",
                    d: "M16 .5a.5.5 0 0 0-.5-.5h-5a.5.5 0 0 0 0 1h3.793L6.146 9.146a.5.5 0 1 0 .708.708L15 1.707V5.5a.5.5 0 0 0 1 0v-5z"
                }}));
        }
        
        else {
            throw new Error("No such image named: " + this.name);
        }

        var svg = ce('svg', {
            attrs: {
                width: this.width,
                height: this.height,
                viewBox: '0 0 16 16',
                fill: 'currentColor',
                xmlns: 'http://www.w3.org/2000/svg'
            }}, svg_children);

        return svg;
    }
});
