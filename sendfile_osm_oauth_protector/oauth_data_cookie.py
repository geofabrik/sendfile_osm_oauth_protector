import datetime
import base64
import urllib.parse
import requests
from requests_oauthlib import OAuth2Session
import nacl.exceptions
import wsgiref.util

from sendfile_osm_oauth_protector.data_cookie import DataCookie
from sendfile_osm_oauth_protector.authentication_state import AuthenticationState
from sendfile_osm_oauth_protector.oauth_error import OAuthError
from sendfile_osm_oauth_protector.internal_error import InternalError


class OAuthDataCookie(DataCookie):
    def __init__(self, config, environ, cookie_api=False, key_manager=None):
        """
        Args:
            config (Config): configuration
            environ (Dictionary): contains CGI environment variables (see PEP 0333)
            key_manager (KeyManager): key store holding keys for encryption and signatures
        """
        super(OAuthDataCookie, self).__init__(config)
        self.read_cookie(environ)
        self.query_params = urllib.parse.parse_qs(environ["QUERY_STRING"])
        self.environ = environ
        self.cookie_api = cookie_api
        self.path_info = environ["PATH_INFO"]
        self.script_name = environ["SCRIPT_NAME"]
        self.key_manager = key_manager
        if self.key_manager is not None:
            try:
                self.read_crypto_box = None
                self.write_crypto_box = self.key_manager.boxes[config.KEY_NAME]
                self.verify_key = None
                self.sign_key = self.key_manager.signing_keys[config.KEY_NAME]
            except KeyError as err:
                raise InternalError("key not found") from err
        self.access_token = ""
        self.valid_until = datetime.datetime.utcnow() - datetime.timedelta(hours=config.AUTH_TIMEOUT)

    def get_oauth_session(self, path=None, state=None):
        redirect_uri = self.config.CALLBACK
        if self.cookie_api:
            redirect_uri = "{}?action=get_access_token_cookie".format(self.config.COOKIE_API)
        if path:
            query_str_appendix = "path={}".format(urllib.parse.quote(path))
            redirect_uri = "{}?{}".format(redirect_uri, query_str_appendix)
        return OAuth2Session(self.config.CLIENT_ID, redirect_uri=redirect_uri, scope=["read_prefs"], state=state)

    def reconstruct_url(environ, with_query_string=False, append_to_query_string=None, skip_keys=[]):
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
            for sk in skip_keys:
                for p in qs:
                    if p.startswith("{}=".format(sk)):
                        qs.remove(p)
            if append_to_query_string is not None:
                qs.append(append_to_query_string)
            url += '?' + "&".join(qs)
        else:
            if append_to_query_string is not None:
                url += '?' + append_to_query_string
        return url

    def _load_read_keys(self, key_name):
        """
        Fetch the keys for decrypting and verification of the cookie provided by the client.

        Args:
            key_name (str): name of the key to look up in the key manager
        """
        self.read_crypto_box = self.key_manager.boxes[key_name]
        self.verify_key = self.key_manager.verify_keys[key_name]

    def get_authorization_url(self):
        """
        Get the authorization URL

        Args:
            environ (dict): environ dictionary according to WSGI standard

        Returns:
            str: authorization URL
        """
        # add path to query_string of the redirect URI because the list of paths we protect is very long.
        oauth = self.get_oauth_session(self.environ["PATH_INFO"])
        authorization_url, state = oauth.authorization_url(self.config.AUTHORIZATION_URL)
        return authorization_url

    def get_access_token_from_api(self):
        """
        Retrieve an access_token from the OSM API using the authorization code.

        The resulting tokens will be saved as properties of this class.

        Raises:
            OAuthError: if any OAuth related exception occured
        """
        try:
            state = self.query_params["state"][0]
            path = None
            if not self.cookie_api:
                path = self.query_params["path"][0]
        except KeyError as err:
            raise OAuthError("state or path is missing.", "400 Bad Request") from err
        token = None
        try:
            oauth = self.get_oauth_session(path, state)
            request_uri = wsgiref.util.request_uri(self.environ)
            token = oauth.fetch_token(self.config.TOKEN_URL, authorization_response=request_uri, client_secret=self.config.CLIENT_SECRET)
        except Exception as err:
            raise OAuthError("Authentication Failure: Failed to fetch access token from OSM API", "424 Failed Dependency") from err
        try:
            self.access_token = token["access_token"]
        except KeyError as err:
            raise OAuthError("Incomplete response of OSM API, access_token is missing.", "502 Bad Gateway") from err

    def parse_cookie_step1(self):
        """Get the three main parts of the cookie: state, key name and signed content.

        Returns:
            list of string
        """
        return self.cookie[self.config.COOKIE_NAME].value.split("|")

    def parse_cookie_step2(self, contents):
        """
        Verify the cookie.

        Args:
            contents : result of parse_cookie_step1()

        Returns:
            str : encrypted access tokesn (can be None)

        Throws:
            KeyError : key not found
            nacl.exceptions.BadSignatureError : invalid signature
        """
        key_name = contents[1]
        self._load_read_keys(key_name)
        signed = contents[2].encode("ascii")
        access_tokens_encr = self.verify_key.verify(base64.urlsafe_b64decode(signed))
        return access_tokens_encr

    def parse_cookie_step3(self, access_tokens_encr):
        """
        Get decrypted access tokens and validity date of the cookie. This method sets the
        properties self.access_token, self.access_token_secret and self.valid_until

        Args:
            access_tokens_encr (str) : result of parse_cookie_step2()

        Throws:
            OAuthError : decryption has failed
        """
        try:
            parts = self.read_crypto_box.decrypt(access_tokens_encr).decode("ascii").split("|")
            self.access_token = parts[0]
            #self.access_token_secret = parts[1]
            self.valid_until = datetime.datetime.strptime(parts[2], "%Y-%m-%dT%H:%M:%S")
        except Exception as err:
            raise OAuthError("decryption of tokens failed", "400 Bad Request") from err

    def called_callback_path(self):
        return self.script_name == "/oauth2_callback"

    def get_state(self):
        """
        Check if the signature of the cookie is valid, decrypt the cookie.

        Returns:
            AuthenticationState
        """
        ITERATION2_KEYS = {"code", "state", "path"}
        is_redirected_from_osm = False
        if (ITERATION2_KEYS & set(iter(self.query_params))) == set(ITERATION2_KEYS):
            #return AuthenticationState.LOGGED_IN
            is_redirected_from_osm = self.called_callback_path()
        landing_page = self.query_params.get(self.config.LANDING_PAGE_URL_PARAM, ["false"])
        if self.cookie is None and landing_page[0] == "true":
            return AuthenticationState.NONE
        elif self.cookie is None and is_redirected_from_osm:
            return AuthenticationState.LOGGED_IN
        elif self.cookie is None:
            return AuthenticationState.SHOW_LANDING_PAGE
        try:
            contents = self.parse_cookie_step1()
            if len(contents) < 3 or contents[0] != "login":
                if is_redirected_from_osm:
                    return AuthenticationState.LOGGED_IN
                if landing_page[0] != "true":
                    return AuthenticationState.SHOW_LANDING_PAGE
                # landing page has been seen already
                return AuthenticationState.NONE
            access_tokens_encr = self.parse_cookie_step2(contents)
        except KeyError:
            # if something fails here, they normal authentication-authorization loop should start and
            # users not treated like not having seen the landing page
            return AuthenticationState.NONE
        except Exception:
            return AuthenticationState.SIGNATURE_VERIFICATION_FAILED
        self.parse_cookie_step3(access_tokens_encr)
        # If users sends us an old cookie but it is too old and has parameters like being redirected back to our site,
        # treat him like being redirected from OSM back to our site.
        if is_redirected_from_osm and datetime.datetime.utcnow() > self.valid_until:
            return AuthenticationState.LOGGED_IN
        if datetime.datetime.utcnow() > self.valid_until:
            return AuthenticationState.OAUTH_ACCESS_TOKEN_RECHECK
        return AuthenticationState.OAUTH_ACCESS_TOKEN_VALID

    def check_with_osm_api(self):
        """
        Initiate checking of the authorization and reset the validity of the
        cookie if the check passed.

        Returns:
            boolean: result of _check_with_osm_api()

        Raises:
            OAuthError: as raised by _check_with_osm_api()
        """
        if not self._check_with_osm_api():
            return False
        self.valid_until = datetime.datetime.utcnow() + datetime.timedelta(hours=self.config.AUTH_TIMEOUT)
        return True

    def _check_with_osm_api(self):
        """
        Recheck the authorization by requesting a protected resource from the OSM API.

        Returns:
            boolean: True if the source could be request, False if the request
                     failed (repsonse code other than 200)

        Raises:
            OAuthError: failed to get a connection to the OSM API or the API responded with code 500
        """
        try:
            url = "{}user/details".format(self.config.API_URL_BASE)
            r = requests.get(url=url, headers={"Authorization": "Bearer {}".format(self.access_token)})
        except ConnectionError as err:
            raise OAuthError("failed to (re)check the authorization", "502 Bad Gateway") from err
        if r.status_code == 200:
            return True
        if r.status_code == 500:
            raise OAuthError("received error 500 when (re)checking the authorization", "502 Bad Gateway")
        return False

    def output(self, output_format="http"):
        """
        Return an instance of http.cookies.SimpleCookie.

        See doc/cookie.md for a description of the contents of the cookie.

        This method concatenates the access token and date
        when the next full check has to be done. This concatenated string is
        encrypted, signed and handed over to _output_cookie() whose result will
        be returned.
        """
        nonce = nacl.utils.random(nacl.public.Box.NONCE_SIZE)
        valid_until = self.valid_until.strftime("%Y-%m-%dT%H:%M:%S")
        tokens = "{}|oauth2|{}".format(self.access_token, valid_until)
        access_tokens_encr = self.write_crypto_box.encrypt(tokens.encode("ascii"), nonce)
        access_tokens_encr_signed = base64.urlsafe_b64encode(self.sign_key.sign(access_tokens_encr)).decode("ascii")
        if output_format == "http":
            return self._output_cookie_http(True, access_tokens_encr_signed)
        return self._output_cookie_netscape(True, access_tokens_encr_signed)
