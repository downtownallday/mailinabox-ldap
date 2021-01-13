# -*- indent-tabs-mode: t; tab-width: 4; python-indent-offset: 4; -*-

import os
from flask import send_from_directory

common_ui_dir = os.path.join(os.path.dirname(__file__), 'ui-common')

def send_common_ui_file(filename):
	return send_from_directory(common_ui_dir, filename)

		
def add_ui_common(app):
	'''call this function to add an endpoint that delivers common ui
	files. `app` is a Flask instance

	'''

	@app.route("/ui-common/<path:filename>", methods=['GET'])
	def get_common_ui_file(filename):
		return send_common_ui_file(filename)
