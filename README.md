# Isogeo User oAuth2 example - Website with Flask

Sample project to illustrate how to authentifiy to Isogeo API with Authorization Code Grant flow

> *DO NOT USE THIS CODE IN PRODUCTION*

## Usage

Install:

1. Clone/download this [repository](https://github.com/isogeo/api-sample-oauth2-agf-py),
2. Open a prompt (bash, powershell...),
3. Paste your `client_secrets.json` file

### With your installed Python

1. Create a virtualenv and install prerequisites:

    ```powershell
    py -3 -m  venv env
    pip install --upgrade -r requirements.txt
    # or if you have pipenv
    pipenv
    ```

2. Run it:

    ```powershell
    Set-Item Env:FLASK_APP ".\runserver.py"
    flask run
    ```

3. Open your favorite browser to [http://localhost:5000](http://localhost:5000)

### With Docker

```powershell
# build the container
docker build -t isogeo-api-sample-oauth2-agf-py:latest .
# launch it in detached mode
docker run --rm --name isogeo-websample -d -p 5000:5000 isogeo-oauth2-sample
```

Then, open your favorite browser to [http://localhost:5000](http://localhost:5000)
