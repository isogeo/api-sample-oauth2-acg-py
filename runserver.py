# -*- coding: UTF-8 -*-
#! python3

"""
    This script runs the IsogeoFlask application using a development server.
"""

import logging
from os import environ, urandom
from IsogeoFlask import app

if __name__ == '__main__':
    # check running env
    if "WEBSITE_SITE_NAME" not in environ:
        environ['DEBUG'] = "1"
        # ONLY IN DEBUG MODE - NO MAINTAIN THIS OPTION IN PRODUCTION #############
        environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    else:
        logging.info(environ.get("WEBSITE_SITE_NAME"))

    # set host
    if environ.get("DOCKER_CONTAINER"):
        print("Executed from Docker container")
        HOST = "0.0.0.0"
    else:
        HOST = environ.get('SERVER_HOST', 'localhost')
    # set port
    try:
        PORT = int(environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    # app secret
    app.secret_key = urandom(24)
    # app launch
    app.run(host=HOST, port=PORT, debug=environ.get("DEBUG"))
