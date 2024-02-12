#! /usr/bin/env python3

import os
import os.path
import mimetypes
import jinja2
import urllib.parse

from sendfile_osm_oauth_protector.oauth_data_cookie import OAuthDataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.config import Config
from sendfile_osm_oauth_protector.key_manager import KeyManager
from sendfile_osm_oauth_protector.oauth_error import OAuthError
from sendfile_osm_oauth_protector.internal_error import InternalError


config = Config()
key_manager = KeyManager(config.KEY_DIR)
jinja2_version = jinja2.__version__.split(".")
env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=config.TEMPLATES_PATH),
                         trim_blocks=True,
                         autoescape=True
                         )


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
    return None


def handle_directory_without_trailing_slash(start_response, path):
    """
    Respond to requests which point to a directory but where the URL does not end with a slash.
    """
    return redirect('302 Found', '{}/'.format(path), start_response)


def index_listing(path_on_disk, path, start_response):
    template = env.get_template(config.INDEX_LISTING_TEMPLATE)
    files = os.listdir(path_on_disk)
    files = [ f for f in files if not f.startswith('.') ]
    is_dir = [ os.path.isdir(os.path.join(path_on_disk, f)) for f in files ]
    site = template.render(files=files, is_dir=is_dir, path=path).encode("utf-8")
    status = "200 OK"
    response_headers = [("Content-type", "text/html"),
                        ("Content-length", str(len(site)))]
    start_response(status, response_headers)
    return [site]


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
    document_root = config.DOCUMENT_ROOT
    if document_root.endswith("/"):
        document_root = document_root[:-1]
    path_on_disk = ""
    if path.startswith("/") and len(path) > 1:
        path_on_disk = os.path.join(document_root, path[1:])
    else:
        path_on_disk = document_root
    if os.path.isdir(path_on_disk) and not path.endswith('/'):
        return handle_directory_without_trailing_slash(start_response, path)
    if os.path.isdir(path_on_disk):
        try:
            index_file_path = look_for_index_file(path_on_disk)
        except:
            return respond_error("404 Not Found", start_response,
                                 "The requested resource could not be found or is not accessible.",
                                 response_headers)
        if index_file_path is None and config.INDEX_LISTING:
            return index_listing(path_on_disk, path, start_response)
        elif index_file_path is None:
            return respond_error("404 Not Found", start_response,
                                 "The requested resource could not be found.",
                                 response_headers)
        path_on_disk = index_file_path
    elif not os.path.isfile(path_on_disk):
        return respond_error("404 Not Found", start_response,
                             "The requested resouce could not be found or is not accessible.",
                             response_headers)
    response_headers.append(("X-Sendfile", path_on_disk))
    # set Content-type
    mime_type = mimetypes.guess_type(path_on_disk, False)
    if not mime_type[0]:
        mime_type = [config.MIME_TYPES.get(os.path.splitext(path_on_disk)[1], "application/octet-stream"), None]
    response_headers.append(("Content-type", mime_type[0]))
    start_response(status, response_headers)
    return []


def show_landing_page(environ, start_response, path):
    template = env.get_template(config.LANDING_PAGE_TMPL)
    url = OAuthDataCookie.reconstruct_url(environ, True, "landing_page=true", [config.LANDING_PAGE_URL_PARAM])
    public_url = "https://{}{}".format(config.PUBLIC_HOST, path)
    site = template.render(link_url=url, public_url=public_url).encode("utf-8")
    status = "403 Forbidden"
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


def respond_error(http_error_message, start_response, exception_message, response_headers=[]):
    msg = exception_message.encode("utf8")
    response_headers.extend([("Content-type", "text/plain; charset=utf-8"),
                             ("Content-Length", str(len(msg)))]
                           )
    start_response(http_error_message, response_headers)
    return [msg]


def redirect(status, location, start_response, oauth_cookie=False):
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
    if oauth_cookie:
        response_headers.append(("Set-Cookie", oauth_cookie.output()))
    start_response(status, response_headers)
    return []


def application(environ, start_response):
    path_info = environ["PATH_INFO"]

    # We have to key pairs for encryption because we want to be able to decrypt cookies using
    # the old key pair but use the new key pair for any cookies we sent back to the client.
    # Otherwise all users would have to re-authenticate and re-authorize access again at the
    # moment we change our keys.
    # The old key is determined using a property of the cookie sent by the user.

    try:
        oauth_cookie = OAuthDataCookie(config, environ, key_manager)
    except InternalError:
        return respond_error("400 Bad Request", start_response, "Cookie verification failed. Your cookie was signed using a key which is not available on the server.")
    auth_state = oauth_cookie.get_state()

    if auth_state == AuthenticationState.LOGGED_IN:
        # second visit
        try:
            oauth_cookie.get_access_token_from_api()
            if oauth_cookie.check_with_osm_api():
                url = urllib.parse.quote(oauth_cookie.query_params.get("path", ["/"])[0])
                return redirect("302 Found (Moved Temporarily)", url, start_response, oauth_cookie)
        except OAuthError as err:
            return respond_error(err.error_message, start_response, str(err))
        return deny_access(oauth_cookie, start_response, "It was not possible to check if you are an OSM contributor. Did you revoke OAuth access for this application?")
    elif auth_state == AuthenticationState.SHOW_LANDING_PAGE:
        return show_landing_page(environ, start_response, path_info)
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
        authorization_url = oauth_cookie.get_authorization_url()
        return redirect("302 Found (Moved Temporarily)", authorization_url, start_response)
