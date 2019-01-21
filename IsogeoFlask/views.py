# -*- coding: UTF-8 -*-
#! python3

"""
    Sample Isogeo User Authentication - Authorization Code Grant based on Flask
"""

# Standard library
import json
from datetime import datetime
import logging
from os import environ
from random import randint

# 3rd party library
from flask import render_template, request, redirect, session, url_for
from flask.json import jsonify
from isogeo_pysdk import IsogeoUtils as utils
from requests_oauthlib import OAuth2Session

# webapp
from IsogeoFlask import app


# ############################################################################
# ########## Globals ###############
# ##################################
# logging
logger = logging.getLogger("IsogeoFlask")

# oAuth2 settings from client_secrets.json
utils = utils()
try:
    api = utils.credentials_loader("client_secrets.json")
    ISOGEO_API_URL_BASE = api.get('uri_base')
    ISOGEO_OAUTH_CLIENT_ID = api.get('client_id')
    ISOGEO_OAUTH_CLIENT_SECRET = api.get('client_secret')
    ISOGEO_OAUTH_URL_301 = api.get('uri_redirect')
    ISOGEO_OAUTH_URL_AUTH = api.get('uri_auth')
    ISOGEO_OAUTH_URL_TOKEN = api.get('uri_token')
    ISOGEO_OAUTH_URL_TOKEN_REFRESH = ISOGEO_OAUTH_URL_TOKEN
    ISOGEO_OAUTH_CREDENTIALS = 1
except OSError as e:
    logger.error(e)
    ISOGEO_OAUTH_CREDENTIALS = 0

# SSL verify
if environ.get("OAUTHLIB_INSECURE_TRANSPORT"):
    ssl_opt = 0
else:
    ssl_opt = 1

# ############################################################################
# ########## Functions #############
# ##################################
@app.route('/')
@app.route('/home')
def home():
    """Renders the home page."""
    logger.debug("Route called: HOMEPAGE.")
    # alert box according to the authentication status
    if ISOGEO_OAUTH_CREDENTIALS:
        auth_status = "success"
        auth_msg = "Des paramètres d'authentification ont bien été trouvés."
    else:
        auth_status = "warning"
        auth_msg = "Paramètres d'authentification manquants. L'authentification Isogeo de fonctionnera pas. Consulter l'aide du projet."
    return render_template(
        'index.html',
        title="Page d'accueil",
        year=datetime.now().year,
        auth_status=auth_status,
        auth_msg=auth_msg
    )


@app.route('/contact')
def contact():
    """Renders the contact page."""
    logger.debug("Route called: CONTACT")
    return render_template(
        'contact.html',
        title='Contact',
        year=datetime.now().year,
        message='Contact Isogeo to get your developper credentials'
    )


# AUTHENTICATION ----------------------------------------------------------
@app.route("/login")
def login():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider = Isogeo ID
    using an URL with a few key OAuth parameters.
    """
    logger.debug("Route called: LOGIN")
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID)
    authorization_url, state = isogeo.authorization_url(ISOGEO_OAUTH_URL_AUTH)
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    logger.debug("Auth request: {}".format(authorization_url))
    return redirect(authorization_url)


@app.route("/login/oauth/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.

    set https://localhost:5000/login/oauth/callback
    """
    logger.debug("Route called: CALLBACK")
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID,
                           state=session.get('oauth_state', None))
    token = isogeo.fetch_token(ISOGEO_OAUTH_URL_TOKEN,
                               client_secret=ISOGEO_OAUTH_CLIENT_SECRET,
                               authorization_response=request.url,
                               verify=ssl_opt)
    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /search.
    session['oauth_token'] = token

    return redirect(url_for('.menu'))


@app.route("/menu", methods=["GET"])
def menu():
    """
        # Step 4: User pick an option
    """
    logger.debug("Route called: MENU")
    if not session.get("oauth_token"):
        return redirect(url_for('.login'))

    return render_template(
        'menu.html',
        title='Menu utilisateur authentifié',
        year=datetime.now().year,
        token_oauth=session['oauth_token'],
    )


# TOKEN MANAGEMENT -----------------------------------------------------------
@app.route("/automatic_refresh", methods=["GET"])
def automatic_refresh():
    """Refreshing an OAuth 2 token using a refresh token.
    """
    logger.debug("Route called: TOKEN AUTO REFRESH")
    token = session['oauth_token']

    # We force an expiration by setting expired at in the past.
    # This will trigger an automatic refresh next time we interact with
    # Isogeo API.
    token['expires_at'] = 0

    extra = {
        'client_id': ISOGEO_OAUTH_CLIENT_ID,
        'client_secret': ISOGEO_OAUTH_CLIENT_SECRET,
    }

    def token_updater(token):
        session['oauth_token'] = token

    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID,
                           token=token,
                           auto_refresh_kwargs=extra,
                           auto_refresh_url=ISOGEO_OAUTH_URL_TOKEN_REFRESH,
                           token_updater=token_updater)

    # search url
    search_url = "{}/resources/search?".format(ISOGEO_API_URL_BASE)

    # Trigger the automatic refresh
    jsonify(isogeo.get(search_url, verify=ssl_opt) .json())
    return jsonify(session['oauth_token'])


@app.route("/manual_refresh", methods=["GET"])
def manual_refresh():
    """Refreshing an OAuth 2 token using a refresh token.
    """
    logger.debug("Route called: TOKEN MANUAL REFRESH")
    token = session['oauth_token']

    extra = {
        'client_id': ISOGEO_OAUTH_CLIENT_ID,
        'client_secret': ISOGEO_OAUTH_CLIENT_SECRET,
    }

    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=token)
    session['oauth_token'] = isogeo.refresh_token(ISOGEO_OAUTH_URL_TOKEN_REFRESH, **extra)
    return jsonify(session['oauth_token'])


# SEARCH AND PROFILE ----------------------------------------------------------
@app.route("/search", methods=["GET"])
def search():
    """Fetching a protected resource using an OAuth 2 token.
    """
    logger.debug("Route called: SEARCH")
    if not session.get("oauth_token"):
        return redirect(url_for('.login'))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session['oauth_token'])

    # request parameters
    payload = {"_limit": 0,
               # "_include":"conditions,contacts,coordinate-system,feature-attributes,layers",
               }
    search_url = "{}/resources/search?".format(ISOGEO_API_URL_BASE)
    search_req = isogeo.get(search_url,
                            # headers=head,
                            params=payload,
                            verify=ssl_opt)

    return jsonify(search_req.json())


@app.route("/profile", methods=["GET"])
def profile():
    """
        Displaying basic metrics about authenticated user
    """
    logger.debug("Route called: PROFILE")
    if not session.get("oauth_token"):
        return redirect(url_for('.login'))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session['oauth_token'])
    url_search = "{}/resources/search?lang=FR&_limit=100".format(ISOGEO_API_URL_BASE)
    req_search = isogeo.get(url_search, verify=ssl_opt).json()

    # some calculations
    ct_tags = len(req_search.get("tags"))
    ct_workgroups = len([i for i in req_search.get("tags")
                         if i.startswith("owner:")])
    ct_catalogs = len([i for i in req_search.get("tags")
                       if i.startswith("catalog:")])
    # random metadata
    ct_rez = len(req_search.get("results", ["No results"]))
    a, b = randint(0, ct_rez), randint(0, ct_rez)
    md1, md2 = req_search.get("results")[a], req_search.get("results")[b]
    mds = {"md1": [md1.get("title"), md1.get("abstract", "Pas de résumé")],
           "md2": [md2.get("title"), md2.get("abstract", "Pas de résumé")], }

    # pie chart
    url_search_type = "{}/resources/search?_limit=0&q=type:".format(ISOGEO_API_URL_BASE)
    stats_types = [isogeo.get("{}vector-dataset".format(url_search_type), verify=ssl_opt).json().get("total", 0),
                   isogeo.get("{}raster-dataset".format(url_search_type), verify=ssl_opt).json().get("total", 0),
                   isogeo.get("{}service".format(url_search_type), verify=ssl_opt).json().get("total", 0),
                   isogeo.get("{}resource".format(url_search_type), verify=ssl_opt).json().get("total", 0),
                   ]

    # to display
    return render_template(
        'metrics.html',
        title='Métriques utilisateur',
        year=datetime.now().year,
        ct_mds=req_search.get("total"),
        ct_wgs=ct_workgroups,
        ct_cats=ct_catalogs,
        ct_tags=ct_tags,
        ct_rez=ct_rez,
        mds=mds,
        stats_types=stats_types,
    )


@app.route("/group/stats", methods=["GET", "PUT"])
def wg_stats():
    """
        Displaying workgroup statistics
    """
    logger.debug("Route called: GROUP STATS")
    if not session.get("oauth_token"):
        return redirect(url_for('.login'))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID,
                           token=session['oauth_token'])

    # request parameters
    payload = {"_lang": "fr",
               "gid": "32f7e95ec4e94ca3bc1afda960003882"
               }
    wg_test_stats_url = "{}/groups/32f7e95ec4e94ca3bc1afda960003882/statistics?".format(ISOGEO_API_URL_BASE)
    stats_req = isogeo.get(wg_test_stats_url,
                           # headers=head,
                           params=payload,
                           verify=ssl_opt)

    print(stats_req.url)
    return jsonify(stats_req.json())


@app.route("/test", methods=["GET", "PUT"])
def edit():
    """
        Trying to edit a metadata
    """
    if not session.get("oauth_token"):
        return redirect(url_for('.login'))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID,
                           token=session['oauth_token'])

    # try put
    payload = {"_id": "fdbf2c7de1094bfbb20eec7162b41241", }
    search_url = "https://v1.api.isogeo.com/resources/search?"
    search_req = isogeo.get(search_url,
                            params=payload)
    md_test = search_req.json().get("results")[0]
    print(md_test.get("abstract", "no abstract"))

    #
    payload = {"abtract": "JAJAJA", }
    put_url = "https://app.isogeo.com/api/v1/resources/fdbf2c7de1094bfbb20eec7162b41241"
    pupute = isogeo.put(put_url, params=payload)
    print(pupute)

    return """{}""".format(md_test.get("abstract", "no abstract"))
