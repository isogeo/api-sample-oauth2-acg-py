# GLOBALS
FLASK_APP=runserver.py
FLASK_ENV=development
FLASK_DEBUG=1
DOCKER_CONTAINER=0

# RUN
FLASK_RUN_HOST=localhost
FLASK_RUN_PORT=3000

# HTTPS
FLASK_RUN_CERT=certs/server.cert
FLASK_RUN_KEY=certs/server.key
OAUTHLIB_INSECURE_TRANSPORT=1

# MISC
STATIC_FOLDER="./IsogeoFlask/static"
UPLOAD_FOLDER="./IsogeoFlask/upload"
ALLOWED_EXTENSIONS = set(["csv", "png"])

# ISOGEO
CREDENTIALS_FILE=client_secrets.json
