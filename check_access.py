#! /usr/bin/env python3

import os.path
import urllib.parse
from requests_oauthlib import OAuth1Session
import nacl.utils
import base64
import nacl.public
import nacl.utils
import xdg.Mime
from http.cookies import SimpleCookie
import jinja2

from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_error import OAuthError


config = Config()
key_manager = KeyManager(config.KEY_DIR)
jinja2_version = jinja2.__version__.split(".")
env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=config.TEMPLATES_PATH),
                         trim_blocks=True,
                         autoescape=True
                         )


def reconstruct_url(environ, with_query_string=False, append_to_query_string=None, skip_key=None):
    """
    Reconstruct the URL.

    The implementation was taken from PEP 0333

    Args:
        environ (Dictionary): contains CGI environment variables (see PEP 0333)
        with_query_string (Boolean): add the query string if any
        append_to_query_string (str): append this ESCAPED string to the query string. No leading `&` character required.
        skip_keys (str): keys of the old query string which should not be appended to the query string

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
        qs = environ['QUERY_STRING'].split("&")
        # remove skip_key and its value from query_string
        if skip_key is not None:
            for p in qs:
                if p.startswith("{}=".format(skip_key)):
                    qs.remove(p)
        if append_to_query_string is not None:
            qs.append(append_to_query_string)
        url += '?' + "&".join(qs)
    else:
        if append_to_query_string is not None:
            url += '?' + append_to_query_string
    return url


def look_for_index_file(search_directory):
    """
    Look for a file like index.html located in a directory.

    Args:
        search_directory: directory where to search

    Returns:
        str: absolute path to the file if any was found and search_directory otherwise

    Raises:
    """
    for filename in config.INDEX_PAGES:
        filepath = os.path.join(search_directory, filename)
        if os.path.isfile(filepath):
            return filepath
    return search_directory


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
    # if path is empty (i.e. directory requested), return index.html or whatever is defined in
    # config.INDEX_PAGES
    response_headers = [("Set-Cookie", oauth_cookie.output())]
    if path.endswith("/"):
        try:
            path = look_for_index_file("{}/{}".format(config.DOCUMENT_ROOT, path))
        except:
            return respond_error("404 Not Found", start_response,
                                 "The requested resource could not be found or is not accessible.")
        if path.endswith("/"):
            return respond_error("404 Not Found", start_response,
                                 "The requested resource could not be found or is not accessible.")
        response_headers.append(("X-Sendfile", path))
    else:
        response_headers.append(("X-Sendfile", "{}/{}".format(config.DOCUMENT_ROOT, path)))
    # set Content-type
    mime_type = str(xdg.Mime.get_type(path))
    response_headers.append(("Content-type", mime_type))
    start_response(status, response_headers)
    return []

def show_landing_page(environ, start_response):
    template = env.get_template(config.LANDING_PAGE_TMPL)
    url = reconstruct_url(environ, True, "landing_page=true", config.LANDING_PAGE_URL_PARAM)
    site = template.render(link_url=url).encode("utf-8")
    status = "200 OK"
    response_headers = [("Content-type", "text/html"),
                        ("Content-length", str(len(site)))]
    start_response(status, response_headers)
    return [site]


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


def respond_error(http_error_message, start_response, exception_message):
    msg = exception_message.encode("utf8")
    response_headers = [("Content-type", "text/plain; charset=utf-8"),
                        ("Content-Length", str(len(msg)))]
    start_response(http_error_message, response_headers)
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

    Raises:
        OAuthError: error sending a request to the OSM API or failed to parse its response
    """
    oauth = OAuth1Session(config.CLIENT_KEY, client_secret=config.CLIENT_SECRET)

    try:
        fetch_response = oauth.fetch_request_token(config.REQUEST_TOKEN_URL)
    except ValueError as err:
        raise OAuthError(err.message, "500 Internal Server Error")
    resource_owner_secret = fetch_response.get('oauth_token_secret')

    # encrypt secret
    nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
    oauth_token_secret_encr = base64.urlsafe_b64encode(crypto_box.encrypt(resource_owner_secret.encode("utf8"), nonce)).decode("ascii")

    authorization_url = oauth.authorization_url(config.AUTHORIZATION_URL)
    # append callback URL because our callback URL is dynamic and cannot be configured in the consumer settings of osm.org
    query_str_appendix = "oauth_token_secret_encr={}".format(urllib.parse.quote(oauth_token_secret_encr))
    callback_url = urllib.parse.quote(reconstruct_url(environ, True, query_str_appendix, config.LANDING_PAGE_URL_PARAM))
    authorization_url += "&oauth_callback={}".format(callback_url)
    return authorization_url


def application(environ, start_response):
    path_info = environ["PATH_INFO"]

    # We have to key pairs for encryption because we want to be able to decrypt cookies using
    # the old key pair but use the new key pair for any cookies we sent back to the client.
    # Otherwise all users would have to re-authenticate and re-authorize access again at the
    # moment we change our keys.
    # The old key is determined using a property of the cookie sent by the user.

    oauth_cookie = OAuthDataCookie(config, environ, key_manager)
    auth_state = oauth_cookie.get_state()

    if auth_state == AuthenticationState.LOGGED_IN:
        # second visit
        try:
            oauth_cookie.get_access_token_from_api()
            if oauth_cookie.check_with_osm_api():
                return grant_access(oauth_cookie, start_response, path_info)
        except OAuthError as err:
            return respond_error(err.error_message, start_response, str(err))
        return deny_access(oauth_cookie, start_response, "It was not possible to check if you are an OSM contributor. Did you revoke OAuth access for this application?")
    elif auth_state == AuthenticationState.SHOW_LANDING_PAGE:
        return show_landing_page(environ, start_response)
    elif auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_VALID:
        return grant_access(oauth_cookie, start_response, path_info)
    elif auth_state == AuthenticationState.OAUTH_ACCESS_TOKEN_RECHECK and config.RECHECK:
        if oauth_cookie.check_with_osm_api():
            return grant_access(oauth_cookie, start_response, path_info)
        return deny_access(oauth_cookie, start_response, "It was not possible to check if you are still entitled to download the requested resource.")
    elif auth_state == AuthenticationState.SIGNATURE_VERIFICATION_FAILED:
        return deny_access(oauth_cookie, start_response, "The authentication cookie is tampered or otherwise corrupted.")
    else:
        # first visit, authentication missing
        authorization_url = request_oauth_token(environ, key_manager.boxes[config.KEY_NAME])
        return redirect("302 Found (Moved Temporarily)", authorization_url, start_response)
