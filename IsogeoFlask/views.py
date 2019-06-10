# -*- coding: UTF-8 -*-
#! python3

"""
    Sample Isogeo User Authentication - Authorization Code Grant based on Flask
"""

# Standard library
import csv
import json
from datetime import datetime
import logging
from os import environ, urandom
from pathlib import Path
from random import randint
import webbrowser

# 3rd party library
from flask import (
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask.json import jsonify
from isogeo_pysdk import IsogeoUtils as utils
from requests_oauthlib import OAuth2Session
from werkzeug.utils import secure_filename

# webapp
from IsogeoFlask import app
from .forms import LoginForm, ImportForm


# ############################################################################
# ########## Globals ###############
# ##################################

# secret key
app.secret_key = urandom(24)

#  upload
Path(environ.get("UPLOAD_FOLDER")).mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = Path(environ.get("UPLOAD_FOLDER"))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# logging
logger = logging.getLogger("IsogeoFlask")

# oAuth2 settings from client_secrets.json
utils = utils()
try:
    api = utils.credentials_loader(environ.get("CREDENTIALS_FILE"))
    ISOGEO_API_URL_BASE = api.get("uri_base")
    ISOGEO_OAUTH_CLIENT_ID = api.get("client_id")
    ISOGEO_OAUTH_CLIENT_SECRET = api.get("client_secret")
    ISOGEO_OAUTH_URL_301 = "https://localhost:3000/login/callback"
    ISOGEO_OAUTH_URL_AUTH = api.get("uri_auth")
    ISOGEO_OAUTH_URL_TOKEN = api.get("uri_token")
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

## utils
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in environ.get(
        "ALLOWED_EXTENSIONS"
    )


# ############################################################################
# ########## Functions #############
# ##################################
@app.route("/")
@app.route("/home")
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
    # display homepage
    return render_template(
        "index.html",
        title="Page d'accueil",
        year=datetime.now().year,
        auth_status=auth_status,
        auth_msg=auth_msg,
    )


@app.route("/contact")
def contact():
    """Renders the contact page."""
    logger.debug("Route called: CONTACT")
    return render_template(
        "contact.html",
        title="Contact",
        year=datetime.now().year,
        message="Contact Isogeo to get your developper credentials",
    )


# AUTHENTICATION ----------------------------------------------------------
@app.route("/login")
def login():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider = Isogeo ID
    using an URL with a few key OAuth parameters.
    """
    logger.debug("Route called: LOGIN")
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, redirect_uri=ISOGEO_OAUTH_URL_301)
    authorization_url, state = isogeo.authorization_url(ISOGEO_OAUTH_URL_AUTH)
    # State is used to prevent CSRF, keep this for later.
    session["oauth_state"] = state
    logger.debug("Auth request: {}".format(authorization_url))
    return redirect(authorization_url)


@app.route("/login/callback", methods=["GET"])
def callback():
    """ Step 3: Retrieving an access token.

    The user has been redirected back from the provider to your registered
    callback URL. With this redirection comes an authorization code included
    in the redirect URL. We will use that to obtain an access token.

    set https://localhost:5000/login/oauth/callback
    """
    logger.debug("Route called: CALLBACK")
    print(ISOGEO_OAUTH_URL_301)
    isogeo = OAuth2Session(
        ISOGEO_OAUTH_CLIENT_ID,
        state=session.get("oauth_state", None),
        redirect_uri=ISOGEO_OAUTH_URL_301,
    )
    token = isogeo.fetch_token(
        token_url=ISOGEO_OAUTH_URL_TOKEN,
        client_secret=ISOGEO_OAUTH_CLIENT_SECRET,
        authorization_response=request.url,
        verify=ssl_opt,
    )
    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /search.
    session["oauth_token"] = token

    return redirect(url_for(".menu"))


@app.route("/menu", methods=["GET"])
def menu():
    """
        # Step 4: User pick an option
    """
    logger.debug("Route called: MENU")
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))

    # get account details
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    # account details - profile
    url_account = "{}/account".format(ISOGEO_API_URL_BASE)
    req_account = isogeo.get(
        url_account,
        # headers=head,
        # params=payload,
        verify=ssl_opt,
    )
    if req_account.status_code > 200:
        logger.debug("Application credentials do not allow to read user account.")
        isStaff = 0
        username = ""
    else:
        user_account = req_account.json()
        isStaff = user_account.get("staff")
        username = user_account.get("contact").get("name")

    # account details - memberships
    url_memberships = "{}/account/memberships".format(ISOGEO_API_URL_BASE)
    req_memberships = isogeo.get(
        url_memberships,
        # headers=head,
        # params=payload,
        verify=ssl_opt,
    )
    if req_memberships.status_code > 200:
        logger.debug("Application credentials do not allow to read user memberships.")
    else:
        user_memberships = req_memberships.json()
        wgsCount = len(user_memberships)
        wgEditorAdmin = {}
        for mb in user_memberships:
            if mb.get("role") in ("admin", "editor"):
                wg = mb.get("group")
                wgEditorAdmin[wg.get("_id")] = [
                    wg.get("contact").get("name", "Worgroup - unamed"),
                    mb.get("role"),
                ]

    return render_template(
        "menu.html",
        # basics
        title="Menu utilisateur authentifié",
        year=datetime.now().year,
        # auth and user
        token_oauth=session["oauth_token"],
        isStaff=isStaff,
        username=username,
        # user workgroups
        workgroups=list(wgEditorAdmin.keys()),
    )


# TOKEN MANAGEMENT -----------------------------------------------------------
@app.route("/automatic_refresh", methods=["GET"])
def automatic_refresh():
    """Refreshing an OAuth 2 token using a refresh token.
    """
    logger.debug("Route called: TOKEN AUTO REFRESH")
    token = session.get("oauth_token")

    # We force an expiration by setting expired at in the past.
    # This will trigger an automatic refresh next time we interact with
    # Isogeo API.
    token["expires_at"] = 0

    extra = {
        "client_id": ISOGEO_OAUTH_CLIENT_ID,
        "client_secret": ISOGEO_OAUTH_CLIENT_SECRET,
    }

    def token_updater(token):
        session["oauth_token"] = token

    isogeo = OAuth2Session(
        ISOGEO_OAUTH_CLIENT_ID,
        token=token,
        auto_refresh_kwargs=extra,
        auto_refresh_url=ISOGEO_OAUTH_URL_TOKEN_REFRESH,
        token_updater=token_updater,
        redirect_uri=ISOGEO_OAUTH_URL_301,
    )

    # search url
    search_url = "{}/resources/search?".format(ISOGEO_API_URL_BASE)

    # Trigger the automatic refresh
    jsonify(isogeo.get(search_url, verify=ssl_opt).json())
    return jsonify(session["oauth_token"])


@app.route("/manual_refresh", methods=["GET"])
def manual_refresh():
    """Refreshing an OAuth 2 token using a refresh token.
    """
    logger.debug("Route called: TOKEN MANUAL REFRESH")
    token = session["oauth_token"]

    extra = {
        "client_id": ISOGEO_OAUTH_CLIENT_ID,
        "client_secret": ISOGEO_OAUTH_CLIENT_SECRET,
    }

    isogeo = OAuth2Session(
        ISOGEO_OAUTH_CLIENT_ID, token=token, redirect_uri=ISOGEO_OAUTH_URL_301
    )
    session["oauth_token"] = isogeo.refresh_token(
        ISOGEO_OAUTH_URL_TOKEN_REFRESH, **extra
    )
    return jsonify(session["oauth_token"])


# SEARCH AND PROFILE ----------------------------------------------------------
@app.route("/search", methods=["GET"])
def search():
    """Fetching a protected resource using an OAuth 2 token.
    """
    logger.debug("Route called: SEARCH")
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    # request parameters
    payload = {
        "_limit": 0,
        # "_include":"conditions,contacts,coordinate-system,feature-attributes,layers",
    }
    search_url = "{}/resources/search?".format(ISOGEO_API_URL_BASE)
    search_req = isogeo.get(
        search_url,
        # headers=head,
        params=payload,
        verify=ssl_opt,
    )

    return jsonify(search_req.json())


@app.route("/profile", methods=["GET"])
def profile():
    """
        Displaying basic metrics about authenticated user
    """
    logger.debug("Route called: PROFILE")
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])
    url_search = "{}/resources/search?lang=FR&_limit=100".format(ISOGEO_API_URL_BASE)
    req_search = isogeo.get(url_search, verify=ssl_opt).json()

    # some calculations
    ct_tags = len(req_search.get("tags"))
    ct_workgroups = len([i for i in req_search.get("tags") if i.startswith("owner:")])
    ct_catalogs = len([i for i in req_search.get("tags") if i.startswith("catalog:")])
    # random metadata
    ct_rez = len(req_search.get("results", ["No results"]))
    a, b = randint(0, ct_rez), randint(0, ct_rez)
    md1, md2 = req_search.get("results")[a], req_search.get("results")[b]
    mds = {
        "md1": [md1.get("title"), md1.get("abstract", "Pas de résumé")],
        "md2": [md2.get("title"), md2.get("abstract", "Pas de résumé")],
    }

    # pie chart
    url_search_type = "{}/resources/search?_limit=0&q=type:".format(ISOGEO_API_URL_BASE)
    stats_types = [
        isogeo.get("{}vector-dataset".format(url_search_type), verify=ssl_opt)
        .json()
        .get("total", 0),
        isogeo.get("{}raster-dataset".format(url_search_type), verify=ssl_opt)
        .json()
        .get("total", 0),
        isogeo.get("{}service".format(url_search_type), verify=ssl_opt)
        .json()
        .get("total", 0),
        isogeo.get("{}resource".format(url_search_type), verify=ssl_opt)
        .json()
        .get("total", 0),
    ]

    # to display
    return render_template(
        "metrics.html",
        title="Métriques utilisateur",
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
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    # request parameters
    payload = {
        "_lang": "fr",
        #    "gid": "32f7e95ec4e94ca3bc1afda960003882"
    }
    wg_test_stats_url = "{}/groups/32f7e95ec4e94ca3bc1afda960003882/statistics?".format(
        ISOGEO_API_URL_BASE
    )
    stats_req = isogeo.get(
        wg_test_stats_url,
        # headers=head,
        params=payload,
        verify=ssl_opt,
    )

    print(stats_req.url)
    return jsonify(stats_req.json())


@app.route("/test", methods=["GET", "POST", "PUT"])
def edit():
    """
        Trying to edit a metadata
    """
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    # try put
    payload = {"_id": "fdbf2c7de1094bfbb20eec7162b41241"}
    search_url = "{}/groups/?"
    search_req = isogeo.get(search_url, params=payload)
    md_test = search_req.json().get("results")[0]
    print(md_test.get("abstract", "no abstract"))

    #
    payload = {"abtract": "JAJAJA"}
    put_url = "https://app.isogeo.com/api/v1/resources/fdbf2c7de1094bfbb20eec7162b41241"
    pupute = isogeo.put(put_url, params=payload)
    print(pupute)

    return """{}""".format(md_test.get("abstract", "no abstract"))


@app.route("/create", methods=["GET", "POST"])
def create():
    """
        Create a metadata
    """
    logger.debug("Route called: CREATE")
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    data = {
        "bbox": [],
        "dataType": 1,
        "formatVersion": None,
        "precision": None,
        "scale": None,
        "series": False,
        "title": "TEST CREATION DEPUIS SCRIPT",
        "type": "vectorDataset",
    }

    url_metadata_create = "{}/groups/32f7e95ec4e94ca3bc1afda960003882/resources".format(
        ISOGEO_API_URL_BASE
    )

    req_create = isogeo.post(
        url=url_metadata_create,
        #  headers=head,
        #  payload=payload,
        data=data,
        verify=ssl_opt,
    )
    logger.debug(req_create.headers)
    logger.debug(req_create.url)
    logger.debug(req_create.status_code)
    md_created = req_create.json()

    # add attributes
    data = {
        "name": "TEST ATTRIBUT",
        "alias": "ATTR_TEST",
        "dataType": "Char",
        "description": "Hop hop **hop**",
        "language": "fr",
    }
    url_md_add_attributes = "{}/resources/{}/feature-attributes".format(
        ISOGEO_API_URL_BASE, md_created.get("_id")
    )

    req_md_add_attributes = isogeo.post(
        url=url_md_add_attributes,
        #  headers=head,
        #  payload=payload,
        data=data,
        verify=ssl_opt,
    )
    logger.debug(req_md_add_attributes.headers)
    logger.debug(req_md_add_attributes.url)
    logger.debug(req_md_add_attributes.status_code)

    # open on a new tab
    webbrowser.open_new_tab(
        "https://qa-isogeo-app.azurewebsites.net/groups/32f7e95ec4e94ca3bc1afda960003882/resources/{}".format(
            md_created.get("_id")
        )
    )

    return redirect(url_for(".menu"))


@app.route("/create/contact", methods=["GET", "POST"])
def create_contact():
    """
        Create a contact
    """
    logger.debug("Route called: CREATE CONTACT")
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    data = {
        "addressLine1": "sdhsdh1",
        "addressLine2": "sdhsdh2",
        "addressLine3": "shsdfh3",
        "city": "Bordeaux",
        "countrycode": "FR",
        "email": "plop@test.com",
        "faxnumber": "+12131584654",
        "name": "A_GO",
        "organizationname": "TEST API WRITE",
        "phonenumber": "+33666791299",
        "zipcode": "33000",
    }

    url_contact_create = "{}/groups/32f7e95ec4e94ca3bc1afda960003882/contacts".format(
        ISOGEO_API_URL_BASE
    )

    req_create = isogeo.post(
        url=url_contact_create,
        #  headers=head,
        #  payload=payload,
        data=data,
        verify=ssl_opt,
    )
    logger.debug(req_create.headers)
    logger.debug(req_create.url)
    logger.debug(req_create.status_code)
    ct_created = req_create.json()
    logger.debug(ct_created)

    # open on a new tab
    webbrowser.open_new_tab(
        "https://qa-isogeo-app.azurewebsites.net/groups/32f7e95ec4e94ca3bc1afda960003882/admin/address-book/{}".format(
            ct_created.get("_id")
        )
    )

    return redirect(url_for(".menu"))


# FORMS
@app.route("/create/form", methods=["GET", "POST"])
def formCreateMd():
    logger.debug("Route called: CREATE FORM")
    form = LoginForm()
    if form.validate_on_submit():
        flash(
            "Login requested for user {}, remember_me={}".format(
                form.username.data, form.remember_me.data
            )
        )
        return redirect("/menu")
    return render_template("form_create.html", title="Sign In", form=form)


# Upload
@app.route("/upload")
def upload_file():
    logger.debug(app.config.get("UPLOAD_FOLDER"))
    return render_template("form_batch_attributes.html", title="Batch import")


@app.route("/uploader", methods=["GET", "POST"])
def uploader():
    if request.method == "POST":
        # check if the post request has the file part
        if "upload_csv" not in request.files:
            flash("No file part")
            logger.error("No file found into request.")
            return redirect(request.url)
        file = request.files.get("upload_csv")
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = Path(
                app.config.get("UPLOAD_FOLDER"), secure_filename(file.filename)
            )
            file.save(str(filename.resolve()))
            flash("File has been uploaded")
            logger.debug("Uploaded file: " + str(filename))
    return redirect("/upload")


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config.get("UPLOAD_FOLDER"), filename)


# Attributes import
@app.route("/import/attributes", methods=["GET", "POST"])
def formImportAttributes():
    logger.debug("Route called: IMPORT")
    form = ImportForm()
    # oauth2 session
    if not session.get("oauth_token"):
        return redirect(url_for(".login"))

    # get account details
    isogeo = OAuth2Session(ISOGEO_OAUTH_CLIENT_ID, token=session["oauth_token"])

    if request.method == "GET":
        # account details - memberships
        url_memberships = "{}/account/memberships".format(ISOGEO_API_URL_BASE)
        req_memberships = isogeo.get(
            url_memberships,
            # headers=head,
            # params=payload,
            verify=ssl_opt,
        )
        if req_memberships.status_code > 200:
            logger.debug(
                "Application credentials do not allow to read user memberships."
            )
            return redirect("/menu")
        else:
            user_memberships = req_memberships.json()
            wgsCount = len(user_memberships)
            wgEditorAdmin = {}
            for mb in user_memberships:
                if mb.get("role") in ("admin", "editor"):
                    wg = mb.get("group")
                    wgEditorAdmin[wg.get("_id")] = [
                        wg.get("contact").get("name", "Worgroup - unamed"),
                        mb.get("role"),
                    ]

        # li_input_csvs = sorted(Path(r"./import").glob("**/*.tab"))

        form.workgroup.choices = [
            (key, value[0]) for key, value in wgEditorAdmin.items()
        ]
    if request.method == "POST":
        logger.debug("Selected workgroup: " + form.workgroup.data)
        wg_dir = [
            x
            for x in Path(r"./IsogeoFlask/import").iterdir()
            if x.is_dir() and x.name == form.workgroup.data
        ]
        # check if directory exists
        if not wg_dir:
            logger.error(
                "Input directory not found for workgroup: " + form.workgroup.data
            )
            return redirect("/import/attributes")
        # if exist import
        li_csv = sorted(Path(wg_dir[0]).glob("**/*.csv"))
        for i in li_csv:
            print(i.name)
            with i.open("r", newline="") as input_csv:
                reader = csv.DictReader(
                    input_csv,
                    fieldnames=["alias", "dataType", "description", "language", "name"],
                )
                next(reader)
                for row in reader:
                    print(row)
                    url_md_add_attributes = "{}/resources/{}/feature-attributes".format(
                        ISOGEO_API_URL_BASE, i.name[:-4]
                    )

                    req_md_add_attributes = isogeo.post(
                        url=url_md_add_attributes,
                        #  headers=head,
                        #  payload=payload,
                        data=row,
                        verify=ssl_opt,
                    )
                    logger.debug(req_md_add_attributes.status_code)
        return redirect("/import/attributes")

    return render_template(
        "form_batch_attributes.html",
        title="Import feature attribute",
        wgsCount=wgsCount,
        workgroups=wgEditorAdmin,
        form=form,
    )


@app.route("/import/attributes/load", methods=["GET", "POST"])
def formImportAttributesLoadfromCsv():
    logger.debug("Route called: ATTRIBUTES LOAD")
    logger.debug("Selected workgroup: " + form.workgroup.data)
