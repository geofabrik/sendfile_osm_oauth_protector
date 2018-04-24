#! /usr/bin/env python3

import urllib.parse
import base64
import json
import nacl.utils
import requests
from requests_oauthlib import OAuth1

from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.oauth_error import OAuthError

config = Config()
key_manager = KeyManager(config.KEY_DIR)


def respond_error(http_error_message, start_response, message):
    msg = message.encode("utf8")
    response_headers = [("Content-type", "text/plain; charset=utf-8"),
                        ("Content-Length", str(len(msg)))]
    start_response(http_error_message, response_headers)
    return [msg]


def get_request_token(environ, start_response):
    oauth = OAuth1(config.CLIENT_KEY, client_secret=config.CLIENT_SECRET)
    try:
        r = requests.post(url=config.REQUEST_TOKEN_URL, auth=oauth, timeout=15)
    except requests.exceptions.RequestException as err:
        respond_error("502 Bad Gateway", start_response, str(err))
    parts = urllib.parse.parse_qs(r.text)

    crypto_box = key_manager.boxes[config.KEY_NAME]
    token_secret = parts["oauth_token_secret"][0]
    nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
    token_secret_encr = base64.b64encode(crypto_box.encrypt(token_secret.encode("utf8"), nonce)).decode("ascii")

    result = {"oauth_token": parts["oauth_token"][0],
              "oauth_token_secret_encr": token_secret_encr,
              "authorization_url": config.AUTHORIZATION_URL}
    result_enc = json.dumps(result).encode("utf-8")
    response_headers = [("Content-type", "application/json, charset=utf-8"),
                        ("Content-Length", str(len(result_enc)))]
    start_response("200 OK", response_headers)
    return [result_enc]


def get_access_token(environ, start_response):
    # parse POST data
    try:
        request_body_size = int(environ.get("CONTENT_LENGTH", 0))
    except ValueError:
        request_body_size = 0
    if request_body_size <= 0:
        return respond_error("400 Bad Request", start_response, "Missing or unreadable 'Content-Length' header")
    request_body = environ["wsgi.input"].read(request_body_size).decode()

    new_environ = {"QUERY_STRING": request_body}
    oauth_data_cookie = OAuthDataCookie(config, new_environ, key_manager)
    try:
        oauth_data_cookie.get_access_token_from_api()
        if not oauth_data_cookie.check_with_osm_api():
            return respond_error("502 Bad Gateway", start_response, "Failed to verify if you are allowed to access the protected resources")
    except OAuthError as err:
        respond_error("500 Internal Server Error", start_response, str(err))
    cookie = oauth_data_cookie.output().encode("ascii")

    response_headers = [("Content-type", "text/plain; charset=ascii"),
                        ("Content-length", str(len(cookie)))]
    start_response("200 OK", response_headers)
    return [cookie]


def application(environ, start_response):
    if environ["REQUEST_METHOD"] != "POST":
        return respond_error("400 Bad Request", start_response, "Only POST requests are permitted")
    params = urllib.parse.parse_qs(environ["QUERY_STRING"])
    action = params.get("action", None)
    if action is None:
        return respond_error("400 Bad Request", start_response, "Parameter 'action' is missing")
    if action[0] == "request_token":
        return get_request_token(environ, start_response)
    elif action[0] == "get_access_token_cookie":
        return get_access_token(environ, start_response)
    return respond_error("400 Bad Request", start_response, "The requested 'action' is not supported.")
