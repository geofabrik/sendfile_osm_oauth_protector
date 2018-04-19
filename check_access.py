#! /usr/bin/env python3

import urllib.parse
from requests_oauthlib import OAuth1Session
import nacl.utils
import base64
import nacl.public
import nacl.utils
from http.cookies import SimpleCookie

from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager


config = Config()
key_manager = KeyManager(config.KEY_DIR)


def reconstruct_url(environ, with_query_string=False):
    """
    Reconstruct the URL.

    The implementation was taken from PEP 0333

    Args:
        environ (Dictionary): contains CGI environment variables (see PEP 0333)
        with_query_string (Boolean): add the query string if any

    Returns:
        str: the URL
    """
    url = environ["wsgi.url_scheme"] + "://"

    if environ.get("HTTP_HOST"):
        url += environ["HTTP_HOST"]
    else:
        url += environ["SERVER_NAME"]

        if environ["wsgi.url_scheme"] == "https":
            if environ["SERVER_PORT"] != "443":
                url += ":" + environ["SERVER_PORT"]
        else:
            if environ["SERVER_PORT"] != "80":
                url += ":" + environ["SERVER_PORT"]

    url += urllib.parse.quote(environ.get("SCRIPT_NAME", ""))
    url += urllib.parse.quote(environ.get("PATH_INFO", ""))
    if with_query_string and environ.get('QUERY_STRING'):
        url += '?' + environ['QUERY_STRING']
    return url


def grant_access(oauth_cookie, start_response, path):
    """
    Return code 200 and tell Apache to send the file using the X-Sendfile header.
    This function also sets the authentication cookie.

    Args:
        oauth_cookie (OAuthDataCookie)
        start_response: the start_response() callable
        path (str): the requested path

    Returns:
        list: a empty list because data is sent by Apache
    """
    status = "200 OK"
    response_headers = [("X-Sendfile", "{}/{}".format(config.DOCUMENT_ROOT, path)),
                        ("Set-Cookie", oauth_cookie.output())]
    #TODO set Content-type
    start_response(status, response_headers)
    return []


def deny_access(oauth_cookie, start_response, message):
    """
    Return code 403.

    A message is sent as text/plain. A logout cookie will be
    set. Any further request by that client will end in the usual
    authentication and authorisation procedure if the client has a proper
    cookie handling (is a browser and not curl/wget with default parameters).

    Args:
        oauth_cookie (OAuthDataCookie)
        start_response: the start_response() callable
        path (str): the requested path

    Returns:
        list: list of bytes (the message)
    """
    #TODO return rendered HTML page with link to log-in again
    status = "403 Forbidden"
    msg = message.encode("utf8")
    # We always set a logout cookie if we deny access, so the user will be faced the OSM login form
    # if he requests the resource again.
    response_headers = [("Content-type", "text/plain; charset=utf-8"),
                        ("Set-Cookie", oauth_cookie.logout_cookie()),
                        ("Content-Length", str(len(msg)))]
    start_response(status, response_headers)
    return [msg]


def redirect(status, location, start_response):
    """
    Return a redirect code. This function does not set any cookie.

    Args:
        status (str): code and verbal representation (e.g. `302 Found`)
        location (str): the location the client should be redirected to (a URL)
        start_response: the start_response() callable

    Returns:
        list: an empty list
    """
    response_headers = [("location", location)]
    start_response(status, response_headers)
    return []



def request_oauth_token(environ, crypto_box):
    """
    Get a request_token from the OSM API and prepare the authroization URL the use should be redirected to.

    Args:
        crypto_box (nacl.public.Box): encryption used to encrypt oauth_token_secret

    Returns:
        str: authorization URL
    """
    oauth = OAuth1Session(config.CLIENT_KEY, client_secret=config.CLIENT_SECRET)
    fetch_response = oauth.fetch_request_token(config.REQUEST_TOKEN_URL)
    resource_owner_secret = fetch_response.get('oauth_token_secret')
    # encrypt secret
    nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
    oauth_token_secret_encr = base64.urlsafe_b64encode(crypto_box.encrypt(resource_owner_secret.encode("utf8"), nonce)).decode("ascii")

    authorization_url = oauth.authorization_url(config.AUTHORIZATION_URL)
    # append callback URL (our callback URL is dynamic)
    callback_url = urllib.parse.quote(reconstruct_url(environ))
    if environ.get("QUERY_STRING"):
        callback_url += urllib.parse.quote("?{}".format(environ["QUERY_STRING"]))
        callback_url += urllib.parse.quote("&oauth_token_secret_encr={}".format(oauth_token_secret_encr))
    else:
        callback_url += urllib.parse.quote("?oauth_token_secret_encr={}".format(oauth_token_secret_encr))
    authorization_url += "&oauth_callback={}".format(callback_url)
    return authorization_url


def application(environ, start_response):
    path_info = environ["PATH_INFO"]

    # We have to key pairs for encryption because we want to be able to decrypt cookies using
    # the old key pair but use the new key pair for any cookies we sent back to the client.
    # Otherwise all users would have to re-authenticate and re-authorize access again at the
    # moment we change our keys.
    # The old key is determined using a property of the cookie sent by the user.

    oauth_cookie = OAuthDataCookie(config, environ, key_manager, config.KEY_NAME)
    auth_state = oauth_cookie.get_state()

    if auth_state == AuthenticationState.LOGGED_IN:
        # second visit
        oauth_cookie.get_access_token_from_api()
        if oauth_cookie.check_with_osm_api():
            return grant_access(oauth_cookie, start_response, path_info)
        return deny_access(oauth_cookie, start_response, "It was not possible to check if you are an OSM contributor. Did you revoke OAuth access for this application?")
    elif auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_VALID:
        return grant_access(oauth_cookie, start_response, path_info)
    elif auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_RECHECK:
        if oauth_cookie.check_with_osm_api():
            return grant_access(oauth_cookie, start_response, path_info)
        return deny_access(oauth_cookie, start_response, "It was not possible to check if you are still entitled to download the requested resource.")
    elif auth_state == AuthenticationState.SIGNATURE_VERIFICATION_FAILED:
        return deny_access(oauth_cookie, start_response, "The authentication cookie is tampered or otherwise corrupted.")
    else:
        # first visit, authentication missing
        authorization_url = request_oauth_token(environ, key_manager.boxes[config.KEY_NAME])
        return redirect("302 Found (Moved Temporarily)", authorization_url, start_response)
