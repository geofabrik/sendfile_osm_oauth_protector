#! /usr/bin/env python3

import urllib.parse
import json

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


def get_authorization_url(environ, start_response):
    oauth_cookie = OAuthDataCookie(config, environ, True)
    oauth = oauth_cookie.get_oauth_session()
    redirect_uri = oauth.redirect_uri
    authorization_url, state = oauth.authorization_url(config.AUTHORIZATION_URL)

    result = {
        "authorization_url": authorization_url,
        "state": state,
        "client_id": config.CLIENT_ID,
        "redirect_uri": redirect_uri,
    }
    result_enc = json.dumps(result).encode("utf-8")
    response_headers = [("Content-type", "application/json, charset=utf-8"),
                        ("Content-Length", str(len(result_enc)))]
    start_response("200 OK", response_headers)
    return [result_enc]


def get_access_token(params, environ, start_response):
    # parse query string data
    if len(params) == 0:
        return respond_error("400 Bad Request", start_response, "Query string is missing.")
    output_format = params.get("format", ["http"])[0]
    if output_format not in ["http", "netscape"]:
        return respond_error("400 Bad Request", start_response, "Unsupported output format. Valid vaulues: http, netscape")

    oauth_data_cookie = OAuthDataCookie(config, environ, True, key_manager)
    try:
        oauth_data_cookie.get_access_token_from_api()
        if not oauth_data_cookie.check_with_osm_api():
            return respond_error("502 Bad Gateway", start_response, "Failed to verify if you are allowed to access the protected resources")
    except OAuthError as err:
        respond_error("500 Internal Server Error", start_response, str(err))
    cookie = oauth_data_cookie.output(output_format).encode("ascii")

    response_headers = [("Content-type", "text/plain; charset=ascii"),
                        ("Content-length", str(len(cookie)))]
    start_response("200 OK", response_headers)
    return [cookie]


def application(environ, start_response):
    params = urllib.parse.parse_qs(environ["QUERY_STRING"])
    action = params.get("action", None)
    if action is None:
        return respond_error("400 Bad Request", start_response, "Parameter 'action' is missing")
    if environ["REQUEST_METHOD"] == "POST" and action[0] == "get_authorization_url":
        return get_authorization_url(environ, start_response)
    elif environ["REQUEST_METHOD"] == "GET" and action[0] == "get_access_token_cookie":
        return get_access_token(params, environ, start_response)
    return respond_error("400 Bad Request", start_response, "The requested 'action' and/or HTTP method is not supported.")
