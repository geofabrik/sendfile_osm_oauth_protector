#! /usr/bin/env python3

import json
import datetime
from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.oauth_error import OAuthError

config = Config()
key_manager = KeyManager(config.KEY_DIR)


def build_json(code, message, description, expires=None):
    valid_until = None
    if expires is not None:
        valid_until = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    response = {"http_status_code": code, "cookie_status": message, "description": description, "valid_until": valid_until}
    return json.dumps(response, indent=2)


def cookie_outdated(start_response, expires):
    return respond_error("401 Unauthorized", start_response, "expired", "Your cookie is expired.", expires)


def cookie_valid(start_response, expires):
    return respond_error("200 OK", start_response, "valid", "Your cookie is valid.", expires)


def respond_error(status_code, start_response, message, description, expires=None):
    data = build_json(status_code, message, description, expires)
    msg = data.encode("utf8")
    response_headers = [("Content-type", "text/json; charset=utf-8"),
                        ("Content-Length", str(len(msg)))]
    start_response(status_code, response_headers)
    return [msg]


def application(environ, start_response):
    if "HTTP_COOKIE" not in environ:
        return respond_error("400 Bad Request", start_response, "no_cookie_provided", "No cookie provided.")
    try:
        oauth_cookie = OAuthDataCookie(config, environ, True, key_manager)
    except OAuthError:
        return respond_error("400 Bad Request", start_response, "cookie_verification_failed", "Cookie verification failed. Your cookie was signed using a key which is not available on the server.")

    auth_state = oauth_cookie.get_state()
    if auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_VALID:
        return cookie_valid(start_response, oauth_cookie.valid_until)
    elif auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_RECHECK and config.RECHECK:
        if oauth_cookie.check_with_osm_api():
            return cookie_valid(start_response, oauth_cookie.valid_until)
        return respond_error("403 Forbidden", start_response, "access_token_use_failed", "We are unable to verify if you are a member of the OSM community. Your OSM account is blocked or you revoked our OAuth access token.")
    elif oauth_cookie.valid_until < datetime.datetime.utcnow():
        return cookie_outdated(start_response, oauth_cookie.valid_until)
    return respond_error("400 Bad Request", start_response, "unknown", "We don't know but we are sure that your cookie doesn't work.")
