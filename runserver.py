# -*- coding: UTF-8 -*-
#! python3

"""
    This script runs the IsogeoFlask application using a development server.
"""

import logging
from logging.handlers import RotatingFileHandler
from os import environ, urandom
from IsogeoFlask import app

# LOGGING
logger = logging.getLogger("IsogeoFlask")
logging.captureWarnings(True)
logger.setLevel(logging.DEBUG)
log_form = logging.Formatter("%(asctime)s || %(levelname)s "
                             "|| %(module)s - %(lineno)d ||"
                             " %(funcName)s || %(message)s")
logfile = RotatingFileHandler("log_IsogeoFlask.log", "a", 3000000, 1)
logfile.setLevel(logging.DEBUG)
logfile.setFormatter(log_form)
logger.addHandler(logfile)
logger.info('================ Isogeo Flask ===============')


if __name__ == '__main__':
    # check running env
    if environ.get("WEBSITE_SITE_NAME"):
        logger.debug("Localhost server used. Debug mode enabled and SSL disabled.")
        environ['DEBUG'] = "1"
        # ONLY IN DEBUG MODE - NO MAINTAIN THIS OPTION IN PRODUCTION #############
        environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    else:
        logger.info(environ.get("WEBSITE_SITE_NAME"))

    # set host
    if environ.get("DOCKER_CONTAINER"):
        logger.info("Executed from Docker container")
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
